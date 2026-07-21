import io
import os
import re
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import contextmanager


os.environ['APP_ENV'] = 'test'
os.environ['SECRET_KEY'] = 'test-secret-key-for-product-management'

import app as market_app


VALID_PASSWORD = 'Fjord9!K'


class ProductManagementTestCase(unittest.TestCase):
    def setUp(self):
        test_temp_root = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'tmp',
        )
        os.makedirs(test_temp_root, exist_ok=True)
        self.temporary_directory = tempfile.TemporaryDirectory(dir=test_temp_root)
        self.original_database = market_app.DATABASE
        market_app.DATABASE = os.path.join(
            self.temporary_directory.name,
            'test-market.db',
        )
        market_app.app.config.update(
            TESTING=True,
            PROPAGATE_EXCEPTIONS=True,
            SECRET_KEY='test-secret-key-for-product-management',
            SESSION_COOKIE_SECURE=False,
            WTF_CSRF_ENABLED=True,
            MAX_CONTENT_LENGTH=6 * 1024 * 1024,
            PRODUCT_IMAGE_UPLOAD_FOLDER=os.path.join(
                self.temporary_directory.name,
                'product-images',
            ),
        )
        market_app.init_db()
        self.client = market_app.app.test_client()

    def tearDown(self):
        market_app.DATABASE = self.original_database
        self.temporary_directory.cleanup()

    @contextmanager
    def database_connection(self):
        connection = sqlite3.connect(market_app.DATABASE)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def insert_user(self, username):
        user_id = str(uuid.uuid4())
        with self.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO user (id, username, password, session_version)
                VALUES (?, ?, ?, 0)
                """,
                (user_id, username, market_app.hash_password(VALID_PASSWORD)),
            )
        return user_id

    def insert_product(self, seller_id, title):
        product_id = str(uuid.uuid4())
        with self.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO product (id, title, description, price, seller_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (product_id, title, f'{title} 설명', '1000', seller_id),
            )
        return product_id

    def image_upload(self, content, filename):
        return io.BytesIO(content), filename

    def image_path(self, filename):
        return os.path.join(
            market_app.app.config['PRODUCT_IMAGE_UPLOAD_FOLDER'],
            filename,
        )

    def write_product_image(self, filename, content=b'\x89PNG\r\n\x1a\nimage'):
        os.makedirs(market_app.app.config['PRODUCT_IMAGE_UPLOAD_FOLDER'], exist_ok=True)
        with open(self.image_path(filename), 'wb') as image_file:
            image_file.write(content)

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        token = match.group(1).decode('utf-8')
        response.close()
        return token

    def post_with_csrf(self, path, data, token_path=None):
        form_data = dict(data)
        form_data['csrf_token'] = self.csrf_token(token_path or path)
        response = self.client.post(path, data=form_data)
        self.addCleanup(response.close)
        request_stream = response.request.environ.get('wsgi.input')
        if hasattr(request_stream, 'close'):
            self.addCleanup(request_stream.close)
        return response

    def login(self, username):
        token = self.csrf_token('/login')
        response = self.client.post(
            '/login',
            data={
                'csrf_token': token,
                'username': username,
                'password': VALID_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 302)
        response.close()

    def test_management_requires_login(self):
        response = self.client.get('/product/manage')

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login'))

    def test_registration_without_image_remains_supported(self):
        self.insert_user('no-image-owner')
        self.login('no-image-owner')

        response = self.post_with_csrf(
            '/product/new',
            {'title': '이미지 없음', 'description': '설명', 'price': '1000'},
        )

        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT image_filename FROM product WHERE title = ?',
                ('이미지 없음',),
            ).fetchone()
        self.assertIsNone(product['image_filename'])

    def test_supported_image_formats_are_saved_and_served(self):
        self.insert_user('image-owner')
        self.login('image-owner')
        image_cases = [
            ('png', b'\x89PNG\r\n\x1a\ncontent', 'image.png', 'image/png'),
            ('jpeg', b'\xff\xd8\xff\xe0content', 'image.jpeg', 'image/jpeg'),
            ('gif', b'GIF89acontent', 'image.gif', 'image/gif'),
            ('webp', b'RIFF\x08\x00\x00\x00WEBPcontent', 'image.webp', 'image/webp'),
        ]

        for label, content, filename, mime_type in image_cases:
            with self.subTest(image_type=label):
                response = self.post_with_csrf(
                    '/product/new',
                    {
                        'title': f'{label} 상품',
                        'description': '이미지 설명',
                        'price': '1000',
                        'image': self.image_upload(content, filename),
                    },
                )
                self.assertEqual(response.status_code, 302)
                with self.database_connection() as connection:
                    product = connection.execute(
                        'SELECT id, image_filename FROM product WHERE title = ?',
                        (f'{label} 상품',),
                    ).fetchone()
                self.assertRegex(
                    product['image_filename'],
                    r'^[0-9a-f]{32}\.(?:gif|jpg|png|webp)$',
                )
                self.assertTrue(os.path.isfile(self.image_path(product['image_filename'])))

                image_response = self.client.get(f'/product/{product["id"]}/image')
                try:
                    self.assertEqual(image_response.status_code, 200)
                    self.assertEqual(image_response.content_type, mime_type)
                    self.assertEqual(image_response.data, content)
                finally:
                    image_response.close()

    def test_invalid_images_are_rejected_without_product_or_file(self):
        self.insert_user('invalid-image-owner')
        self.login('invalid-image-owner')
        invalid_cases = [
            (b'plain text', 'note.txt'),
            (b'plain text', 'fake.png'),
            (b'\x89PNG\r\n\x1a\ncontent', 'wrong.jpg'),
            (b'', 'empty.png'),
        ]

        for index, (content, filename) in enumerate(invalid_cases):
            with self.subTest(filename=filename):
                response = self.post_with_csrf(
                    '/product/new',
                    {
                        'title': f'잘못된 상품 {index}',
                        'description': '설명',
                        'price': '1000',
                        'image': self.image_upload(content, filename),
                    },
                )
                self.assertEqual(response.status_code, 400)

        with self.database_connection() as connection:
            product_count = connection.execute('SELECT COUNT(*) FROM product').fetchone()[0]
        self.assertEqual(product_count, 0)
        upload_folder = market_app.app.config['PRODUCT_IMAGE_UPLOAD_FOLDER']
        self.assertFalse(os.path.exists(upload_folder) and os.listdir(upload_folder))

    def test_image_larger_than_five_megabytes_is_rejected(self):
        self.insert_user('large-image-owner')
        self.login('large-image-owner')
        oversized_image = (
            b'\x89PNG\r\n\x1a\n'
            + b'a' * market_app.PRODUCT_IMAGE_MAX_BYTES
        )

        response = self.post_with_csrf(
            '/product/new',
            {
                'title': '큰 이미지',
                'description': '설명',
                'price': '1000',
                'image': self.image_upload(oversized_image, 'large.png'),
            },
        )

        self.assertEqual(response.status_code, 400)
        with self.database_connection() as connection:
            product_count = connection.execute('SELECT COUNT(*) FROM product').fetchone()[0]
        self.assertEqual(product_count, 0)

    def test_management_lists_only_current_users_products(self):
        owner_id = self.insert_user('owner-one')
        other_id = self.insert_user('owner-two')
        self.insert_product(owner_id, '내 상품')
        self.insert_product(other_id, '타인 상품')
        self.login('owner-one')

        response = self.client.get('/product/manage')
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('내 상품', page)
        self.assertNotIn('타인 상품', page)
        self.assertIn('수정', page)
        self.assertIn('삭제', page)

    def test_owner_can_edit_product(self):
        owner_id = self.insert_user('edit-owner')
        product_id = self.insert_product(owner_id, '수정 전')
        self.login('edit-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {'title': '수정 후', 'description': '새 설명', 'price': '02500'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/product/manage'))
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title, description, price FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(dict(product), {
            'title': '수정 후',
            'description': '새 설명',
            'price': '2500',
        })

    def test_owner_can_replace_and_remove_product_image(self):
        owner_id = self.insert_user('image-edit-owner')
        product_id = self.insert_product(owner_id, '이미지 수정 상품')
        old_filename = f'{uuid.uuid4().hex}.png'
        self.write_product_image(old_filename)
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE product SET image_filename = ? WHERE id = ?',
                (old_filename, product_id),
            )
        self.login('image-edit-owner')

        replace_response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '이미지 수정 상품',
                'description': '교체 설명',
                'price': '2000',
                'image': self.image_upload(b'GIF89anew-image', 'replacement.gif'),
            },
        )

        self.assertEqual(replace_response.status_code, 302)
        with self.database_connection() as connection:
            replacement_filename = connection.execute(
                'SELECT image_filename FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()['image_filename']
        self.assertNotEqual(replacement_filename, old_filename)
        self.assertTrue(os.path.isfile(self.image_path(replacement_filename)))
        self.assertFalse(os.path.exists(self.image_path(old_filename)))

        remove_response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '이미지 수정 상품',
                'description': '삭제 설명',
                'price': '2000',
                'remove_image': '1',
            },
        )

        self.assertEqual(remove_response.status_code, 302)
        with self.database_connection() as connection:
            image_filename = connection.execute(
                'SELECT image_filename FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()['image_filename']
        self.assertIsNone(image_filename)
        self.assertFalse(os.path.exists(self.image_path(replacement_filename)))

    def test_edit_rejects_simultaneous_image_replacement_and_removal(self):
        owner_id = self.insert_user('image-conflict-owner')
        product_id = self.insert_product(owner_id, '이미지 충돌 상품')
        old_filename = f'{uuid.uuid4().hex}.png'
        self.write_product_image(old_filename)
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE product SET image_filename = ? WHERE id = ?',
                (old_filename, product_id),
            )
        self.login('image-conflict-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '이미지 충돌 상품',
                'description': '설명',
                'price': '1000',
                'remove_image': '1',
                'image': self.image_upload(b'GIF89anew-image', 'replacement.gif'),
            },
        )

        self.assertEqual(response.status_code, 400)
        with self.database_connection() as connection:
            image_filename = connection.execute(
                'SELECT image_filename FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()['image_filename']
        self.assertEqual(image_filename, old_filename)
        self.assertTrue(os.path.isfile(self.image_path(old_filename)))

    def test_owner_can_delete_product(self):
        owner_id = self.insert_user('delete-owner')
        product_id = self.insert_product(owner_id, '삭제 상품')
        self.login('delete-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/delete',
            {},
            token_path='/product/manage',
        )

        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            product_count = connection.execute(
                'SELECT COUNT(*) FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()[0]
        self.assertEqual(product_count, 0)

    def test_deleting_product_removes_its_image(self):
        owner_id = self.insert_user('image-delete-owner')
        product_id = self.insert_product(owner_id, '이미지 삭제 상품')
        image_filename = f'{uuid.uuid4().hex}.png'
        self.write_product_image(image_filename)
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE product SET image_filename = ? WHERE id = ?',
                (image_filename, product_id),
            )
        self.login('image-delete-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/delete',
            {},
            token_path='/product/manage',
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(os.path.exists(self.image_path(image_filename)))

    def test_non_owner_cannot_edit_or_delete_product(self):
        owner_id = self.insert_user('actual-owner')
        self.insert_user('other-user')
        product_id = self.insert_product(owner_id, '보호 상품')
        self.login('other-user')

        edit_response = self.client.get(f'/product/{product_id}/edit')
        delete_response = self.post_with_csrf(
            f'/product/{product_id}/delete',
            {},
            token_path='/product/manage',
        )

        self.assertEqual(edit_response.status_code, 403)
        self.assertEqual(delete_response.status_code, 403)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], '보호 상품')

    def test_missing_product_image_file_returns_not_found(self):
        owner_id = self.insert_user('missing-image-owner')
        product_id = self.insert_product(owner_id, '유실 이미지 상품')
        missing_filename = f'{uuid.uuid4().hex}.png'
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE product SET image_filename = ? WHERE id = ?',
                (missing_filename, product_id),
            )

        response = self.client.get(f'/product/{product_id}/image')

        self.assertEqual(response.status_code, 404)

    def test_edit_rejects_invalid_product_data(self):
        owner_id = self.insert_user('validation-owner')
        product_id = self.insert_product(owner_id, '원래 상품')
        self.login('validation-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {'title': '', 'description': '설명', 'price': '-1'},
        )

        self.assertEqual(response.status_code, 400)
        with self.database_connection() as connection:
            title = connection.execute(
                'SELECT title FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()['title']
        self.assertEqual(title, '원래 상품')

    def test_edit_and_delete_require_csrf_token(self):
        owner_id = self.insert_user('csrf-owner')
        product_id = self.insert_product(owner_id, 'CSRF 상품')
        self.login('csrf-owner')

        edit_response = self.client.post(
            f'/product/{product_id}/edit',
            data={'title': '공격', 'description': '공격', 'price': '1'},
        )
        delete_response = self.client.post(f'/product/{product_id}/delete')

        self.assertEqual(edit_response.status_code, 400)
        self.assertEqual(delete_response.status_code, 400)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], 'CSRF 상품')

    def test_init_db_migrates_existing_product_table(self):
        with self.database_connection() as connection:
            connection.execute('DROP TABLE product')
            connection.execute(
                """
                CREATE TABLE product (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price TEXT NOT NULL,
                    seller_id TEXT NOT NULL
                )
                """
            )

        market_app.init_db()

        with self.database_connection() as connection:
            columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(product)').fetchall()
            }
        self.assertIn('image_filename', columns)


if __name__ == '__main__':
    unittest.main()
