import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import patch

from werkzeug.datastructures import MultiDict
from werkzeug.security import generate_password_hash

os.environ['APP_ENV'] = 'test'
os.environ['SECRET_KEY'] = 'test-secret-key-for-user-management'

import app as market_app


VALID_PASSWORD = 'Fjord9!K'
NEW_PASSWORD = 'Cobalt7@Q'


class UserManagementTestCase(unittest.TestCase):
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
            SECRET_KEY='test-secret-key-for-user-management',
            SESSION_COOKIE_SECURE=False,
            WTF_CSRF_ENABLED=True,
        )
        market_app.init_db()
        self.client = market_app.app.test_client()

    def tearDown(self):
        market_app.DATABASE = self.original_database
        self.temporary_directory.cleanup()

    @contextmanager
    def database_connection(self, database_path=None):
        connection = sqlite3.connect(database_path or market_app.DATABASE, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def insert_user(self, username, password=VALID_PASSWORD, bio=None, session_version=0):
        user_id = str(uuid.uuid4())
        with self.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO user (id, username, password, bio, session_version)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, username, password, bio, session_version),
            )
        return user_id

    def csrf_token(self, client, path):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        self.assertIsNotNone(match, f'CSRF token not found at {path}')
        return match.group(1).decode('utf-8')

    def post_with_csrf(
        self,
        client,
        path,
        data,
        token_path=None,
        follow_redirects=False,
        headers=None,
        environ_overrides=None,
    ):
        form_data = dict(data)
        form_data['csrf_token'] = self.csrf_token(client, token_path or path)
        return client.post(
            path,
            data=form_data,
            follow_redirects=follow_redirects,
            headers=headers,
            environ_overrides=environ_overrides,
        )

    def register(self, client, username, password=VALID_PASSWORD, **kwargs):
        return self.post_with_csrf(
            client,
            '/register',
            {'username': username, 'password': password},
            **kwargs,
        )

    def login(self, client, username, password=VALID_PASSWORD, **kwargs):
        return self.post_with_csrf(
            client,
            '/login',
            {'username': username, 'password': password},
            **kwargs,
        )

    def login_session_token(self, client):
        with client.session_transaction() as current_session:
            return current_session.get('session_token')

    def test_registration_validates_username_before_database_write(self):
        invalid_usernames = ['', 'ab', 'a' * 31, 'user name', '사용자', 'user%name']
        for username in invalid_usernames:
            with self.subTest(username=username):
                response = self.register(self.client, username)
                self.assertEqual(response.status_code, 400)

        with self.database_connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM user').fetchone()[0], 0)

        response = self.register(self.client, '  Valid_User-1  ')
        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            username = connection.execute('SELECT username FROM user').fetchone()['username']
        self.assertEqual(username, 'Valid_User-1')

    def test_registration_rejects_duplicate_fields_and_ignores_security_fields(self):
        token = self.csrf_token(self.client, '/register')
        response = self.client.post(
            '/register',
            data=MultiDict([
                ('csrf_token', token),
                ('username', 'first-user'),
                ('username', 'second-user'),
                ('password', VALID_PASSWORD),
            ]),
        )
        self.assertEqual(response.status_code, 400)

        response = self.post_with_csrf(
            self.client,
            '/register',
            {
                'username': 'normal-user',
                'password': VALID_PASSWORD,
                'role': 'admin',
                'is_active': 'true',
            },
        )
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as current_session:
            self.assertNotIn('role', current_session)
            self.assertNotIn('is_active', current_session)

    def test_case_insensitive_duplicate_and_login(self):
        self.register(self.client, 'CaseUser')
        duplicate = self.register(self.client, 'caseuser')
        self.assertEqual(duplicate.status_code, 409)
        page = duplicate.get_data(as_text=True)
        self.assertIn('가입 요청을 처리할 수 없습니다.', page)
        self.assertNotIn('이미 존재', page)

        login_response = self.login(self.client, 'CASEUSER')
        self.assertEqual(login_response.status_code, 302)
        self.assertTrue(login_response.location.endswith('/dashboard'))

    def test_bio_limit_and_xss_output_escaping(self):
        self.register(self.client, 'profile-user')
        self.login(self.client, 'profile-user')

        too_long = self.post_with_csrf(
            self.client,
            '/profile',
            {'bio': 'a' * 501},
        )
        self.assertEqual(too_long.status_code, 400)
        with self.database_connection() as connection:
            bio = connection.execute(
                'SELECT bio FROM user WHERE username = ?',
                ('profile-user',),
            ).fetchone()['bio']
        self.assertIsNone(bio)

        script = '<script>alert("xss")</script>'
        response = self.post_with_csrf(self.client, '/profile', {'bio': script})
        self.assertEqual(response.status_code, 302)
        users_page = self.client.get('/users').get_data(as_text=True)
        self.assertNotIn(script, users_page)
        self.assertIn('&lt;script&gt;', users_page)

    def test_invalid_search_query_is_rejected(self):
        self.register(self.client, 'search-user')
        self.login(self.client, 'search-user')
        for query in ('%', 'bad query', '가나다', 'a' * 31):
            with self.subTest(query=query):
                response = self.client.get('/users', query_string={'q': query})
                self.assertEqual(response.status_code, 400)

    def test_password_policy_rejects_common_username_and_bad_composition(self):
        invalid_passwords = (
            'short',
            'NoSpecial1',
            'NoNumber!!',
            '1234567!',
            'password1!',
            'user123!',
            'TooLongPass123!',
        )
        for index, password in enumerate(invalid_passwords):
            username = 'user123' if password == 'user123!' else f'policy-{index}'
            with self.subTest(password=password):
                response = self.register(self.client, username, password)
                self.assertEqual(response.status_code, 400)

        with self.database_connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM user').fetchone()[0], 0)

    def test_init_db_hashes_plaintext_and_preserves_existing_user(self):
        legacy_database = os.path.join(self.temporary_directory.name, 'legacy.db')
        with self.database_connection(legacy_database) as connection:
            connection.execute(
                """
                CREATE TABLE user (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    bio TEXT
                )
                """,
            )
            connection.execute(
                'INSERT INTO user (id, username, password, bio) VALUES (?, ?, ?, ?)',
                ('legacy-id', 'legacy-user', 'legacy', '소개'),
            )

        market_app.DATABASE = legacy_database
        market_app.init_db()

        with self.database_connection() as connection:
            columns = {row['name'] for row in connection.execute('PRAGMA table_info(user)')}
            user = connection.execute(
                'SELECT username, password, bio, session_version FROM user',
            ).fetchone()
            tables = {
                row['name']
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        self.assertIn('session_version', columns)
        self.assertIn('user_session', tables)
        self.assertIn('login_attempt', tables)
        self.assertEqual(user['username'], 'legacy-user')
        self.assertEqual(user['bio'], '소개')
        self.assertTrue(market_app.is_password_hash(user['password']))
        self.assertTrue(market_app.verify_password(user['password'], 'legacy'))

    def test_old_password_hash_is_rehashed_after_login(self):
        old_hash = generate_password_hash(VALID_PASSWORD, method='pbkdf2:sha256:1000')
        self.insert_user('old-hash-user', old_hash)

        response = self.login(self.client, 'old-hash-user')
        self.assertEqual(response.status_code, 302)
        with self.database_connection() as connection:
            stored = connection.execute(
                'SELECT password FROM user WHERE username = ?',
                ('old-hash-user',),
            ).fetchone()['password']
        self.assertTrue(stored.startswith(f'{market_app.PASSWORD_HASH_METHOD}$'))
        self.assertTrue(market_app.verify_password(stored, VALID_PASSWORD))

    def test_session_token_is_hashed_at_rest_and_rotated(self):
        self.register(self.client, 'session-user')
        self.login(self.client, 'session-user')
        first_token = self.login_session_token(self.client)
        with self.client.session_transaction() as current_session:
            self.assertNotIn('user_id', current_session)
            self.assertNotIn('session_version', current_session)

        with self.database_connection() as connection:
            stored = connection.execute('SELECT token_hash FROM user_session').fetchone()['token_hash']
        self.assertNotEqual(stored, first_token)
        self.assertEqual(stored, market_app.hash_session_token(first_token))

        self.post_with_csrf(self.client, '/logout', {}, token_path='/dashboard')
        self.login(self.client, 'session-user')
        second_token = self.login_session_token(self.client)
        self.assertNotEqual(first_token, second_token)

    def test_logout_invalidates_only_current_server_session(self):
        self.register(self.client, 'multi-session-user')
        first_client = self.client
        second_client = market_app.app.test_client()
        self.login(first_client, 'multi-session-user')
        self.login(second_client, 'multi-session-user')

        with self.database_connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM user_session').fetchone()[0], 2)

        response = self.post_with_csrf(first_client, '/logout', {}, token_path='/dashboard')
        self.assertTrue(response.location.endswith('/'))
        with self.database_connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM user_session').fetchone()[0], 1)
        self.assertEqual(second_client.get('/dashboard').status_code, 200)

    def test_idle_and_absolute_session_expiration(self):
        self.register(self.client, 'expiry-user')
        self.login(self.client, 'expiry-user')
        token_hash = market_app.hash_session_token(self.login_session_token(self.client))
        now = int(market_app.time.time())

        with self.database_connection() as connection:
            connection.execute(
                'UPDATE user_session SET last_activity_at = ? WHERE token_hash = ?',
                (now - market_app.SESSION_IDLE_TIMEOUT_SECONDS, token_hash),
            )
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login'))

        self.login(self.client, 'expiry-user')
        token_hash = market_app.hash_session_token(self.login_session_token(self.client))
        with self.database_connection() as connection:
            connection.execute(
                'UPDATE user_session SET created_at = ?, last_activity_at = ? WHERE token_hash = ?',
                (now - market_app.SESSION_ABSOLUTE_TIMEOUT_SECONDS, now, token_hash),
            )
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login'))

    def test_password_change_invalidates_all_http_and_socket_sessions(self):
        self.register(self.client, 'password-user')
        self.login(self.client, 'password-user')
        other_client = market_app.app.test_client()
        self.login(other_client, 'password-user')
        socket_client = market_app.socketio.test_client(
            market_app.app,
            flask_test_client=other_client,
        )
        self.assertTrue(socket_client.is_connected())

        response = self.post_with_csrf(
            self.client,
            '/profile/password',
            {
                'current_password': VALID_PASSWORD,
                'new_password': NEW_PASSWORD,
                'new_password_confirm': NEW_PASSWORD,
            },
            token_path='/profile',
        )
        self.assertTrue(response.location.endswith('/login'))
        with self.database_connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM user_session').fetchone()[0], 0)
            user = connection.execute(
                'SELECT password, session_version FROM user WHERE username = ?',
                ('password-user',),
            ).fetchone()
        self.assertEqual(user['session_version'], 1)
        self.assertTrue(market_app.verify_password(user['password'], NEW_PASSWORD))
        self.assertTrue(other_client.get('/dashboard').location.endswith('/login'))
        socket_client.emit('send_private_message', {'message': 'hello'})
        self.assertFalse(socket_client.is_connected())

    def test_csrf_rejects_missing_tampered_cross_session_and_cross_origin(self):
        missing = self.client.post(
            '/register',
            data={'username': 'csrf-user', 'password': VALID_PASSWORD},
        )
        self.assertEqual(missing.status_code, 400)

        token = self.csrf_token(self.client, '/register')
        tampered = self.client.post(
            '/register',
            data={
                'csrf_token': f'{token}tampered',
                'username': 'csrf-user',
                'password': VALID_PASSWORD,
            },
        )
        self.assertEqual(tampered.status_code, 400)

        other_client = market_app.app.test_client()
        cross_session = other_client.post(
            '/register',
            data={
                'csrf_token': token,
                'username': 'csrf-user',
                'password': VALID_PASSWORD,
            },
        )
        self.assertEqual(cross_session.status_code, 400)

        cross_origin = self.client.post(
            '/register',
            data={
                'csrf_token': token,
                'username': 'csrf-user',
                'password': VALID_PASSWORD,
            },
            headers={'Origin': 'https://evil.example'},
        )
        self.assertEqual(cross_origin.status_code, 403)

        same_origin = self.client.post(
            '/register',
            data={
                'csrf_token': token,
                'username': 'csrf-user',
                'password': VALID_PASSWORD,
            },
            headers={'Origin': 'http://localhost:80'},
        )
        self.assertEqual(same_origin.status_code, 302)

    def test_trusted_proxy_host_and_port_are_used_for_origin_validation(self):
        original_wsgi_app = market_app.app.wsgi_app
        market_app.app.wsgi_app = market_app.ProxyFix(
            original_wsgi_app,
            x_for=0,
            x_proto=1,
            x_host=1,
            x_port=1,
        )
        try:
            response = market_app.app.test_client().post(
                '/register',
                data={'username': 'proxy-origin-user', 'password': VALID_PASSWORD},
                base_url='http://internal-app:5000',
                headers={
                    'Origin': 'https://market.example',
                    'X-Forwarded-Proto': 'https',
                    'X-Forwarded-Host': 'market.example',
                    'X-Forwarded-Port': '443',
                },
            )
        finally:
            market_app.app.wsgi_app = original_wsgi_app

        # Origin validation passed; the missing CSRF token is rejected next.
        self.assertEqual(response.status_code, 400)
        self.assertIn('페이지를 새로고침', response.get_data(as_text=True))

    def test_all_state_changing_routes_reject_missing_csrf(self):
        protected_posts = [
            ('/register', {'username': 'csrf-user', 'password': VALID_PASSWORD}),
            ('/login', {'username': 'csrf-user', 'password': VALID_PASSWORD}),
            ('/logout', {}),
            ('/profile', {'bio': '소개'}),
            ('/profile/password', {
                'current_password': VALID_PASSWORD,
                'new_password': NEW_PASSWORD,
                'new_password_confirm': NEW_PASSWORD,
            }),
            ('/product/new', {'title': 't', 'description': 'd', 'price': '1'}),
            ('/report', {'target_id': 'id', 'reason': 'reason'}),
        ]
        for path, data in protected_posts:
            with self.subTest(path=path):
                response = self.client.post(path, data=data)
                self.assertEqual(response.status_code, 400)

    def test_authentication_failure_message_does_not_reveal_account_existence(self):
        self.insert_user('known-user', market_app.hash_password(VALID_PASSWORD))
        known_response = self.login(self.client, 'known-user', 'Wrong7!K')
        unknown_client = market_app.app.test_client()
        unknown_response = self.login(unknown_client, 'unknown-user', 'Wrong7!K')
        self.assertEqual(known_response.status_code, 401)
        self.assertEqual(unknown_response.status_code, 401)
        for response in (known_response, unknown_response):
            page = response.get_data(as_text=True)
            self.assertIn('아이디 또는 비밀번호를 확인하거나 잠시 후 다시 시도해 주세요.', page)
            self.assertNotIn('known-user', page)
            self.assertNotIn('unknown-user', page)

    def test_account_rate_limit_works_across_distributed_ips(self):
        self.insert_user('rate-user', market_app.hash_password(VALID_PASSWORD))
        statuses = []
        for attempt in range(market_app.LOGIN_ACCOUNT_LIMIT):
            response = self.login(
                self.client,
                'rate-user',
                'Wrong7!K',
                environ_overrides={'REMOTE_ADDR': f'192.0.2.{attempt + 1}'},
            )
            statuses.append(response.status_code)
        self.assertEqual(statuses[:-1], [401] * (market_app.LOGIN_ACCOUNT_LIMIT - 1))
        self.assertEqual(statuses[-1], 429)
        self.assertIn('Retry-After', response.headers)

    def test_ip_rate_limit_works_across_multiple_accounts(self):
        statuses = []
        for attempt in range(market_app.LOGIN_IP_LIMIT):
            response = self.login(
                self.client,
                f'unknown-{attempt:02d}',
                'Wrong7!K',
                environ_overrides={'REMOTE_ADDR': '198.51.100.10'},
            )
            statuses.append(response.status_code)
        self.assertEqual(statuses[-1], 429)
        self.assertTrue(all(status == 401 for status in statuses[:-1]))

    def test_parallel_login_failures_are_serialized(self):
        self.insert_user('parallel-user', market_app.hash_password(VALID_PASSWORD))

        def fail_login(attempt):
            client = market_app.app.test_client()
            return self.login(
                client,
                'parallel-user',
                'Wrong7!K',
                environ_overrides={'REMOTE_ADDR': f'203.0.113.{attempt + 1}'},
            ).status_code

        with ThreadPoolExecutor(max_workers=market_app.LOGIN_ACCOUNT_LIMIT) as executor:
            statuses = list(executor.map(fail_login, range(market_app.LOGIN_ACCOUNT_LIMIT)))
        self.assertEqual(statuses.count(401), market_app.LOGIN_ACCOUNT_LIMIT - 1)
        self.assertEqual(statuses.count(429), 1)

    def test_rate_limit_expires_after_window(self):
        self.insert_user('window-user', market_app.hash_password(VALID_PASSWORD))
        with patch.object(market_app.time, 'time', return_value=1000):
            for _ in range(market_app.LOGIN_ACCOUNT_LIMIT):
                response = self.login(self.client, 'window-user', 'Wrong7!K')
            self.assertEqual(response.status_code, 429)
        with patch.object(
            market_app.time,
            'time',
            return_value=1001 + market_app.LOGIN_ATTEMPT_WINDOW_SECONDS,
        ):
            response = self.login(self.client, 'window-user', 'Wrong7!K')
        self.assertEqual(response.status_code, 401)

    def test_login_security_logs_do_not_contain_password_or_token(self):
        self.insert_user('log-user', market_app.hash_password(VALID_PASSWORD))
        with self.assertLogs(market_app.app.logger, level='WARNING') as captured:
            response = self.login(self.client, 'log-user', 'Secret7!')
        self.assertEqual(response.status_code, 401)
        log_output = '\n'.join(captured.output)
        self.assertIn('security_event=login_failure', log_output)
        self.assertIn('request_id=', log_output)
        self.assertNotIn('Secret7!', log_output)
        self.assertNotIn('session_token', log_output)

    def test_unknown_account_still_runs_password_hash_verification(self):
        with patch.object(
            market_app,
            'verify_password',
            wraps=market_app.verify_password,
        ) as verifier:
            response = self.login(self.client, 'unknown-user', 'Secret7!')
        self.assertEqual(response.status_code, 401)
        verifier.assert_called_once_with(market_app.DUMMY_PASSWORD_HASH, 'Secret7!')

    def test_error_responses_hide_internal_details_and_include_request_id(self):
        response = self.client.get('/does-not-exist')
        self.assertEqual(response.status_code, 404)
        self.assertIn('X-Request-ID', response.headers)
        self.assertNotIn('does-not-exist', response.get_data(as_text=True))

        self.register(self.client, 'error-user')
        self.login(self.client, 'error-user')
        original_setting = market_app.app.config['PROPAGATE_EXCEPTIONS']
        market_app.app.config['PROPAGATE_EXCEPTIONS'] = False
        try:
            with patch.object(market_app, 'get_profile_user', side_effect=RuntimeError('secret SQL path')):
                response = self.client.get('/profile')
        finally:
            market_app.app.config['PROPAGATE_EXCEPTIONS'] = original_setting
        self.assertEqual(response.status_code, 500)
        page = response.get_data(as_text=True)
        self.assertNotIn('secret SQL path', page)
        self.assertNotIn(market_app.DATABASE, page)
        self.assertIn('X-Request-ID', response.headers)

        market_app.app.config['PROPAGATE_EXCEPTIONS'] = False
        try:
            with patch.object(
                market_app,
                'get_profile_user',
                side_effect=sqlite3.OperationalError('database is locked: private path'),
            ):
                response = self.client.get('/profile')
        finally:
            market_app.app.config['PROPAGATE_EXCEPTIONS'] = original_setting
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private path', response.get_data(as_text=True))

    def test_production_config_requires_secret_and_enables_secure_cookie(self):
        environment = os.environ.copy()
        environment['APP_ENV'] = 'production'
        environment['SECRET_KEY'] = 'production-test-secret'
        command = (
            'import json, app; '
            'print(json.dumps({'
            '"secure": app.app.config["SESSION_COOKIE_SECURE"], '
            '"httponly": app.app.config["SESSION_COOKIE_HTTPONLY"], '
            '"samesite": app.app.config["SESSION_COOKIE_SAMESITE"], '
            '"debug": app.app.config["DEBUG"]}))'
        )
        completed = subprocess.run(
            [sys.executable, '-c', command],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        config = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(config, {
            'secure': True,
            'httponly': True,
            'samesite': 'Lax',
            'debug': False,
        })

        environment.pop('SECRET_KEY', None)
        missing_secret = subprocess.run(
            [sys.executable, '-c', 'import app'],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(missing_secret.returncode, 0)
        self.assertIn('SECRET_KEY is required', missing_secret.stderr)


if __name__ == '__main__':
    unittest.main()
