import io
import os
import re
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from unittest.mock import patch


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

    def image_upload(self, content, filename, content_type=None):
        if content_type is not None:
            return io.BytesIO(content), filename, content_type
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

    def test_unauthenticated_users_cannot_change_products(self):
        owner_id = self.insert_user('unauthenticated-owner')
        product_id = self.insert_product(owner_id, '인증 보호 상품')
        token = self.csrf_token('/login')

        create_response = self.client.post(
            '/product/new',
            data={
                'csrf_token': token,
                'title': '무단 생성',
                'description': '설명',
                'price': '1000',
            },
        )
        edit_response = self.client.post(
            f'/product/{product_id}/edit',
            data={
                'csrf_token': token,
                'title': '무단 수정',
                'description': '설명',
                'price': '1000',
                'version': '0',
            },
        )
        delete_response = self.client.post(
            f'/product/{product_id}/delete',
            data={'csrf_token': token, 'version': '0'},
        )
        status_response = self.client.post(
            f'/product/{product_id}/status',
            data={'csrf_token': token, 'status': 'sold', 'version': '0'},
        )

        for response in (
            create_response,
            edit_response,
            delete_response,
            status_response,
        ):
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers['Location'].endswith('/login'))
        with self.database_connection() as connection:
            products = connection.execute(
                'SELECT title FROM product ORDER BY title'
            ).fetchall()
        self.assertEqual([product['title'] for product in products], ['인증 보호 상품'])

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
                'SELECT image_filename, status FROM product WHERE title = ?',
                ('이미지 없음',),
            ).fetchone()
        self.assertIsNone(product['image_filename'])
        self.assertEqual(product['status'], 'selling')

    def test_server_managed_product_fields_cannot_be_overridden(self):
        owner_id = self.insert_user('managed-field-owner')
        other_id = self.insert_user('managed-field-other')
        self.login('managed-field-owner')

        response = self.post_with_csrf(
            '/product/new',
            {
                'title': '서버 관리 필드 상품',
                'description': '설명',
                'price': '1000',
                'seller_id': other_id,
                'image_filename': '../../attack.svg',
                'status': 'sold',
                'version': '999',
            },
        )

        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT seller_id, image_filename, status, version '
                'FROM product WHERE title = ?',
                ('서버 관리 필드 상품',),
            ).fetchone()
        self.assertEqual(product['seller_id'], owner_id)
        self.assertIsNone(product['image_filename'])
        self.assertEqual(product['status'], 'selling')
        self.assertEqual(product['version'], 0)

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

    def test_image_with_mismatched_mime_type_is_rejected(self):
        self.insert_user('mime-owner')
        self.login('mime-owner')

        response = self.post_with_csrf(
            '/product/new',
            {
                'title': 'MIME 위조 상품',
                'description': '설명',
                'price': '1000',
                'image': self.image_upload(
                    b'\x89PNG\r\n\x1a\ncontent',
                    'image.png',
                    'text/plain',
                ),
            },
        )

        self.assertEqual(response.status_code, 400)
        with self.database_connection() as connection:
            product_count = connection.execute('SELECT COUNT(*) FROM product').fetchone()[0]
        self.assertEqual(product_count, 0)

    def test_image_storage_failure_does_not_create_product(self):
        self.insert_user('storage-failure-owner')
        self.login('storage-failure-owner')

        with patch.object(market_app.os, 'makedirs', side_effect=OSError):
            response = self.post_with_csrf(
                '/product/new',
                {
                    'title': '저장 실패 상품',
                    'description': '설명',
                    'price': '1000',
                    'image': self.image_upload(
                        b'\x89PNG\r\n\x1a\ncontent',
                        'image.png',
                    ),
                },
            )

        self.assertEqual(response.status_code, 503)
        with self.database_connection() as connection:
            product_count = connection.execute('SELECT COUNT(*) FROM product').fetchone()[0]
        self.assertEqual(product_count, 0)

    def test_database_failure_removes_newly_saved_image(self):
        self.insert_user('database-failure-owner')
        self.login('database-failure-owner')
        with self.database_connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER force_product_insert_failure
                BEFORE INSERT ON product
                BEGIN
                    SELECT RAISE(ABORT, 'forced product failure');
                END
                """
            )

        with patch.dict(
            market_app.app.config,
            {'PROPAGATE_EXCEPTIONS': False},
        ):
            response = self.post_with_csrf(
                '/product/new',
                {
                    'title': 'DB 실패 상품',
                    'description': '설명',
                    'price': '1000',
                    'image': self.image_upload(
                        b'\x89PNG\r\n\x1a\ncontent',
                        'image.png',
                    ),
                },
            )

        self.assertEqual(response.status_code, 500)
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

    def test_product_status_is_displayed_on_product_pages(self):
        owner_id = self.insert_user('status-display-owner')
        product_ids = {
            'selling': self.insert_product(owner_id, '판매 중 상품'),
            'reserved': self.insert_product(owner_id, '예약 상품'),
            'sold': self.insert_product(owner_id, '판매 완료 상품'),
        }
        with self.database_connection() as connection:
            for status, product_id in product_ids.items():
                connection.execute(
                    'UPDATE product SET status = ? WHERE id = ?',
                    (status, product_id),
                )
        self.login('status-display-owner')

        dashboard = self.client.get('/dashboard').get_data(as_text=True)
        management = self.client.get('/product/manage').get_data(as_text=True)
        for page in (dashboard, management):
            self.assertIn('판매 중', page)
            self.assertIn('예약됨', page)
            self.assertIn('판매 완료', page)
            for status in market_app.PRODUCT_STATUS_LABELS:
                self.assertIn(f'status-{status}', page)

        for status, product_id in product_ids.items():
            detail = self.client.get(f'/product/{product_id}').get_data(as_text=True)
            self.assertIn(market_app.PRODUCT_STATUS_LABELS[status], detail)
            self.assertIn(f'status-{status}', detail)

    def test_product_search_matches_title_and_description(self):
        owner_id = self.insert_user('search-owner')
        self.insert_product(owner_id, '노트북 특가')
        description_match_id = self.insert_product(owner_id, '주변기기 세트')
        self.insert_product(owner_id, '필름 카메라')
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE product SET description = ? WHERE id = ?',
                ('노트북 가방이 포함된 상품', description_match_id),
            )
        self.login('search-owner')

        response = self.client.get('/dashboard', query_string={'q': '노트북'})
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('노트북 특가', body)
        self.assertIn('주변기기 세트', body)
        self.assertNotIn('필름 카메라', body)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Pragma'], 'no-cache')

    def test_product_search_escapes_xss_and_binds_sql_values(self):
        owner_id = self.insert_user('secure-search-owner')
        self.insert_product(owner_id, '일반 상품')
        self.insert_product(owner_id, '리터럴 %_ 상품')
        self.login('secure-search-owner')

        xss_query = '"><img src=x onerror=alert(1)>'
        xss_response = self.client.get('/dashboard', query_string={'q': xss_query})
        xss_body = xss_response.get_data(as_text=True)
        self.assertEqual(xss_response.status_code, 200)
        self.assertNotIn(xss_query, xss_body)
        self.assertNotIn('<img src=x onerror=alert(1)>', xss_body)
        self.assertIn('&lt;img', xss_body)

        wildcard_response = self.client.get('/dashboard', query_string={'q': '%_'})
        wildcard_body = wildcard_response.get_data(as_text=True)
        self.assertIn('리터럴 %_ 상품', wildcard_body)
        self.assertNotIn('일반 상품', wildcard_body)

        injection_response = self.client.get(
            '/dashboard',
            query_string={'q': "' OR 1=1 --"},
        )
        injection_body = injection_response.get_data(as_text=True)
        self.assertEqual(injection_response.status_code, 200)
        self.assertNotIn('일반 상품', injection_body)
        self.assertNotIn('리터럴 %_ 상품', injection_body)
        with self.database_connection() as connection:
            self.assertEqual(
                connection.execute('SELECT COUNT(*) FROM product').fetchone()[0],
                2,
            )

    def test_product_search_rejects_invalid_or_ambiguous_queries(self):
        self.insert_user('invalid-search-owner')
        self.login('invalid-search-owner')

        invalid_urls = (
            '/dashboard?q=' + 'a' * (market_app.PRODUCT_SEARCH_QUERY_MAX_LENGTH + 1),
            '/dashboard?q=valid%00control',
            '/dashboard?q=first&q=second',
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn('valid\x00control', response.get_data(as_text=True))

    def test_owner_can_change_status_without_modifying_other_fields(self):
        owner_id = self.insert_user('status-owner')
        product_id = self.insert_product(owner_id, '상태 변경 상품')
        self.login('status-owner')

        for expected_version, status in enumerate(('reserved', 'sold', 'selling')):
            response = self.post_with_csrf(
                f'/product/{product_id}/status',
                {'status': status, 'version': str(expected_version)},
                token_path='/product/manage',
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers['Location'].endswith('/product/manage'))

        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title, description, price, image_filename, status, version '
                'FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], '상태 변경 상품')
        self.assertEqual(product['description'], '상태 변경 상품 설명')
        self.assertEqual(product['price'], '1000')
        self.assertIsNone(product['image_filename'])
        self.assertEqual(product['status'], 'selling')
        self.assertEqual(product['version'], 3)

    def test_status_change_rejects_invalid_and_stale_values(self):
        owner_id = self.insert_user('status-validation-owner')
        product_id = self.insert_product(owner_id, '상태 검증 상품')
        self.login('status-validation-owner')

        for form_data in (
            {'status': '', 'version': '0'},
            {'status': 'completed', 'version': '0'},
            {'version': '0'},
        ):
            with self.subTest(form_data=form_data):
                response = self.post_with_csrf(
                    f'/product/{product_id}/status',
                    form_data,
                    token_path='/product/manage',
                )
                self.assertEqual(response.status_code, 400)

        valid_response = self.post_with_csrf(
            f'/product/{product_id}/status',
            {'status': 'reserved', 'version': '0'},
            token_path='/product/manage',
        )
        stale_response = self.post_with_csrf(
            f'/product/{product_id}/status',
            {'status': 'sold', 'version': '0'},
            token_path='/product/manage',
        )

        self.assertEqual(valid_response.status_code, 302)
        self.assertEqual(stale_response.status_code, 409)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT status, version FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['status'], 'reserved')
        self.assertEqual(product['version'], 1)

    def test_owner_can_edit_product(self):
        owner_id = self.insert_user('edit-owner')
        product_id = self.insert_product(owner_id, '수정 전')
        self.login('edit-owner')

        response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '수정 후',
                'description': '새 설명',
                'price': '02500',
                'version': '0',
            },
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

    def test_stale_edit_and_delete_are_rejected(self):
        owner_id = self.insert_user('concurrent-owner')
        product_id = self.insert_product(owner_id, '동시 수정 상품')
        self.login('concurrent-owner')

        first_response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '첫 번째 수정',
                'description': '첫 번째 설명',
                'price': '2000',
                'version': '0',
            },
        )
        stale_response = self.post_with_csrf(
            f'/product/{product_id}/edit',
            {
                'title': '뒤늦은 수정',
                'description': '뒤늦은 설명',
                'price': '3000',
                'version': '0',
                'image': self.image_upload(b'GIF89astale-image', 'stale.gif'),
            },
        )
        stale_delete_response = self.post_with_csrf(
            f'/product/{product_id}/delete',
            {'version': '0'},
            token_path='/product/manage',
        )

        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(stale_response.status_code, 409)
        self.assertEqual(stale_delete_response.status_code, 409)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title, description, price, image_filename, version '
                'FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], '첫 번째 수정')
        self.assertEqual(product['description'], '첫 번째 설명')
        self.assertEqual(product['price'], '2000')
        self.assertIsNone(product['image_filename'])
        self.assertEqual(product['version'], 1)
        upload_folder = market_app.app.config['PRODUCT_IMAGE_UPLOAD_FOLDER']
        self.assertFalse(os.path.exists(upload_folder) and os.listdir(upload_folder))

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
                'version': '0',
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
                'version': '1',
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
                'version': '0',
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
            {'version': '0'},
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
            {'version': '0'},
            token_path='/product/manage',
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(os.path.exists(self.image_path(image_filename)))

    def test_non_owner_cannot_edit_delete_or_change_product_status(self):
        owner_id = self.insert_user('actual-owner')
        self.insert_user('other-user')
        product_id = self.insert_product(owner_id, '보호 상품')
        self.login('other-user')

        edit_response = self.client.get(f'/product/{product_id}/edit')
        delete_response = self.post_with_csrf(
            f'/product/{product_id}/delete',
            {'version': '0'},
            token_path='/product/manage',
        )
        status_response = self.post_with_csrf(
            f'/product/{product_id}/status',
            {'status': 'sold', 'version': '0'},
            token_path='/product/manage',
        )

        self.assertEqual(edit_response.status_code, 404)
        self.assertEqual(delete_response.status_code, 404)
        self.assertEqual(status_response.status_code, 404)
        missing_product_id = str(uuid.uuid4())
        missing_edit_response = self.client.get(
            f'/product/{missing_product_id}/edit'
        )
        missing_delete_response = self.post_with_csrf(
            f'/product/{missing_product_id}/delete',
            {'version': '0'},
            token_path='/product/manage',
        )
        missing_status_response = self.post_with_csrf(
            f'/product/{missing_product_id}/status',
            {'status': 'sold', 'version': '0'},
            token_path='/product/manage',
        )
        self.assertEqual(missing_edit_response.status_code, edit_response.status_code)
        self.assertEqual(missing_delete_response.status_code, delete_response.status_code)
        self.assertEqual(missing_status_response.status_code, status_response.status_code)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title, status FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], '보호 상품')
        self.assertEqual(product['status'], 'selling')

    def test_product_output_is_html_escaped_on_all_product_pages(self):
        self.insert_user('xss-product-owner')
        self.login('xss-product-owner')
        title = '<img src=x onerror=alert(1)>'
        description = '<script>alert(1)</script>'

        response = self.post_with_csrf(
            '/product/new',
            {'title': title, 'description': description, 'price': '1000'},
        )
        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            product_id = connection.execute(
                'SELECT id FROM product WHERE title = ?',
                (title,),
            ).fetchone()['id']

        pages = [
            self.client.get('/dashboard'),
            self.client.get('/product/manage'),
            self.client.get(f'/product/{product_id}'),
            self.client.get(f'/product/{product_id}/edit'),
        ]
        for page in pages:
            body = page.get_data(as_text=True)
            self.assertNotIn(title, body)
            self.assertNotIn(description, body)
            self.assertNotIn('<script>alert(1)</script>', body)
            self.assertIn('&lt;img', body)

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
            {'title': '', 'description': '설명', 'price': '-1', 'version': '0'},
        )

        self.assertEqual(response.status_code, 400)
        with self.database_connection() as connection:
            title = connection.execute(
                'SELECT title FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()['title']
        self.assertEqual(title, '원래 상품')

    def test_edit_delete_and_status_change_require_csrf_token(self):
        owner_id = self.insert_user('csrf-owner')
        product_id = self.insert_product(owner_id, 'CSRF 상품')
        self.login('csrf-owner')

        edit_response = self.client.post(
            f'/product/{product_id}/edit',
            data={'title': '공격', 'description': '공격', 'price': '1'},
        )
        delete_response = self.client.post(f'/product/{product_id}/delete')
        status_response = self.client.post(
            f'/product/{product_id}/status',
            data={'status': 'sold', 'version': '0'},
        )

        self.assertEqual(edit_response.status_code, 400)
        self.assertEqual(delete_response.status_code, 400)
        self.assertEqual(status_response.status_code, 400)
        with self.database_connection() as connection:
            product = connection.execute(
                'SELECT title, status FROM product WHERE id = ?',
                (product_id,),
            ).fetchone()
        self.assertEqual(product['title'], 'CSRF 상품')
        self.assertEqual(product['status'], 'selling')

    def test_database_constraints_reject_invalid_product_state(self):
        owner_id = self.insert_user('constraint-owner')
        invalid_products = [
            ('', '설명', '1000', owner_id, None, 'selling', 0),
            ('상품', '', '1000', owner_id, None, 'selling', 0),
            ('상품', '설명', '-1', owner_id, None, 'selling', 0),
            ('상품', '설명', '01', owner_id, None, 'selling', 0),
            ('상품', '설명', '1000000001', owner_id, None, 'selling', 0),
            ('상품', '설명', '1000', str(uuid.uuid4()), None, 'selling', 0),
            ('상품', '설명', '1000', owner_id, '../../attack.svg', 'selling', 0),
            ('상품', '설명', '1000', owner_id, None, 'completed', 0),
            ('상품', '설명', '1000', owner_id, None, 'selling', -1),
        ]

        for (
            title,
            description,
            price,
            seller_id,
            image_filename,
            status,
            version,
        ) in invalid_products:
            with self.subTest(
                title=title,
                price=price,
                seller_id=seller_id,
                image_filename=image_filename,
                status=status,
                version=version,
            ):
                with self.assertRaises(sqlite3.IntegrityError):
                    with self.database_connection() as connection:
                        connection.execute(
                            """
                            INSERT INTO product
                                (id, title, description, price, seller_id,
                                 image_filename, status, version)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                str(uuid.uuid4()),
                                title,
                                description,
                                price,
                                seller_id,
                                image_filename,
                                status,
                                version,
                            ),
                        )

        with self.database_connection() as connection:
            product_count = connection.execute('SELECT COUNT(*) FROM product').fetchone()[0]
        self.assertEqual(product_count, 0)

    def test_init_db_migrates_existing_product_table(self):
        owner_id = self.insert_user('migration-owner')
        legacy_product_id = str(uuid.uuid4())
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
            connection.execute(
                """
                INSERT INTO product (id, title, description, price, seller_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (legacy_product_id, '기존 상품', '설명', '1000', owner_id),
            )

        market_app.init_db()

        with self.database_connection() as connection:
            columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(product)').fetchall()
            }
        self.assertIn('image_filename', columns)
        self.assertIn('status', columns)
        self.assertIn('version', columns)
        with self.database_connection() as connection:
            default_status = connection.execute(
                "SELECT dflt_value FROM pragma_table_info('product') "
                "WHERE name = 'status'"
            ).fetchone()['dflt_value']
            migrated_status = connection.execute(
                'SELECT status FROM product WHERE id = ?',
                (legacy_product_id,),
            ).fetchone()['status']
        self.assertEqual(default_status, "'selling'")
        self.assertEqual(migrated_status, 'selling')

    def test_init_db_rejects_invalid_legacy_products(self):
        owner_id = self.insert_user('legacy-product-owner')
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
            connection.execute(
                """
                INSERT INTO product (id, title, description, price, seller_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), '기존 상품', '설명', '-1', owner_id),
            )

        with self.assertRaises(RuntimeError):
            market_app.init_db()


if __name__ == '__main__':
    unittest.main()
