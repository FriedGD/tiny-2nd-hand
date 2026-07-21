import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import string
import time
import uuid
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_socketio import SocketIO, disconnect, send
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


APP_ENV = os.environ.get('APP_ENV', 'production').strip().lower()
if APP_ENV not in {'production', 'development', 'test'}:
    raise RuntimeError('APP_ENV must be production, development, or test.')

secret_key = os.environ.get('SECRET_KEY')
if APP_ENV == 'production' and not secret_key:
    raise RuntimeError('SECRET_KEY is required when APP_ENV=production.')
if not secret_key:
    secret_key = secrets.token_hex(32)

app = Flask(__name__)
app.config.update(
    APP_ENV=APP_ENV,
    SECRET_KEY=secret_key,
    DEBUG=(
        APP_ENV == 'development'
        and os.environ.get('FLASK_DEBUG', '0').strip().lower() in {'1', 'true', 'yes'}
    ),
    SESSION_COOKIE_SECURE=(APP_ENV == 'production'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    PRODUCT_IMAGE_UPLOAD_FOLDER=os.path.join(app.instance_path, 'product_images'),
)
app.logger.setLevel(logging.INFO)

DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect()

USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_-]{3,30}$')
SEARCH_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,30}$')
PASSWORD_HASH_PATTERN = re.compile(
    r'^(?:scrypt:\d+:\d+:\d+|pbkdf2:[^$]+)\$[^$]+\$[^$]+$'
)
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 12
LOGIN_PASSWORD_MAX_LENGTH = 128
PASSWORD_HASH_METHOD = 'scrypt:32768:8:1'
BIO_MAX_LENGTH = 500
PRODUCT_TITLE_MAX_LENGTH = 100
PRODUCT_DESCRIPTION_MAX_LENGTH = 2000
PRODUCT_PRICE_MAX = 1_000_000_000
PRODUCT_IMAGE_MAX_BYTES = 5 * 1024 * 1024
PRODUCT_IMAGE_EXTENSIONS = {
    '.gif': 'gif',
    '.jpeg': 'jpeg',
    '.jpg': 'jpeg',
    '.png': 'png',
    '.webp': 'webp',
}
PRODUCT_IMAGE_CANONICAL_EXTENSIONS = {
    'gif': '.gif',
    'jpeg': '.jpg',
    'png': '.png',
    'webp': '.webp',
}
PRODUCT_IMAGE_FILENAME_PATTERN = re.compile(
    r'^[0-9a-f]{32}\.(?:gif|jpg|png|webp)$'
)
COMMON_PASSWORDS = {
    'password1!',
    'qwerty123!',
    'admin123!',
    'welcome1!',
    'letmein1!',
    'market123!',
}
SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60
SESSION_ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
LOGIN_ACCOUNT_LIMIT = 5
LOGIN_IP_LIMIT = 20
UNSAFE_HTTP_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}


def normalize_origin(value):
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        return None
    return f'{parsed.scheme.lower()}://{parsed.netloc.lower()}'


configured_origins = {
    normalized
    for value in os.environ.get('ALLOWED_ORIGINS', '').split(',')
    if value.strip()
    for normalized in [normalize_origin(value.strip())]
    if normalized is not None
}


@app.before_request
def assign_request_id():
    g.request_id = secrets.token_hex(16)


@app.before_request
def validate_request_origin():
    if request.method not in UNSAFE_HTTP_METHODS:
        return
    origin = request.headers.get('Origin')
    if not origin:
        return
    normalized = normalize_origin(origin)
    same_origin = normalize_origin(request.host_url)
    if normalized is None or (
        normalized != same_origin and normalized not in configured_origins
    ):
        abort(403)


csrf.init_app(app)


@app.after_request
def add_security_response_headers(response):
    response.headers['X-Request-ID'] = getattr(g, 'request_id', secrets.token_hex(16))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response


def render_error_page(status_code, message):
    return render_template(
        'error.html',
        status_code=status_code,
        message=message,
        request_id=getattr(g, 'request_id', None),
    ), status_code


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    app.logger.warning(
        'security_event=csrf_rejected request_id=%s',
        getattr(g, 'request_id', 'unavailable'),
    )
    return render_error_page(400, '요청을 확인할 수 없습니다. 페이지를 새로고침해 주세요.')


@app.errorhandler(400)
def handle_bad_request(error):
    return render_error_page(400, '입력값을 확인해 주세요.')


@app.errorhandler(403)
def handle_forbidden(error):
    return render_error_page(403, '요청을 수행할 권한이 없습니다.')


@app.errorhandler(404)
def handle_not_found(error):
    return render_error_page(404, '요청한 페이지를 찾을 수 없습니다.')


@app.errorhandler(409)
def handle_conflict(error):
    return render_error_page(409, '요청을 현재 상태에서 처리할 수 없습니다.')


@app.errorhandler(413)
def handle_request_entity_too_large(error):
    return render_error_page(413, '업로드 파일이 너무 큽니다. 이미지는 5MB 이하여야 합니다.')


@app.errorhandler(429)
def handle_too_many_requests(error):
    response, status_code = render_error_page(
        429,
        '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',
    )
    response.headers['Retry-After'] = str(LOGIN_ATTEMPT_WINDOW_SECONDS)
    return response, status_code


@app.errorhandler(500)
def handle_internal_error(error):
    app.logger.error(
        'security_event=internal_error request_id=%s',
        getattr(g, 'request_id', 'unavailable'),
        exc_info=error,
    )
    return render_error_page(500, '요청 처리 중 오류가 발생했습니다.')


@app.errorhandler(sqlite3.OperationalError)
def handle_database_operational_error(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.rollback()
    app.logger.error(
        'security_event=database_unavailable request_id=%s',
        getattr(g, 'request_id', 'unavailable'),
    )
    return render_error_page(503, '서비스를 일시적으로 사용할 수 없습니다.')


def validate_username(value):
    if not isinstance(value, str):
        return None, '사용자명 형식이 올바르지 않습니다.'
    normalized = value.strip()
    if not USERNAME_PATTERN.fullmatch(normalized):
        return None, '사용자명은 3~30자의 영문자, 숫자, 밑줄, 하이픈만 사용할 수 있습니다.'
    return normalized, None


def validate_search_query(value):
    if not isinstance(value, str):
        return None, '검색어 형식이 올바르지 않습니다.'
    normalized = value.strip()
    if normalized and not SEARCH_PATTERN.fullmatch(normalized):
        return None, '검색어는 30자 이하의 영문자, 숫자, 밑줄, 하이픈만 사용할 수 있습니다.'
    return normalized, None


def validate_bio(value):
    if not isinstance(value, str):
        return '소개글 형식이 올바르지 않습니다.'
    if len(value) > BIO_MAX_LENGTH:
        return f'소개글은 {BIO_MAX_LENGTH}자 이하여야 합니다.'
    return None


def validate_product_form():
    title = get_single_form_value('title')
    description = get_single_form_value('description')
    price = get_single_form_value('price')

    if not all(isinstance(value, str) for value in (title, description, price)):
        return None, '상품 입력값을 확인해 주세요.'

    title = title.strip()
    description = description.strip()
    price = price.strip()
    if not title or len(title) > PRODUCT_TITLE_MAX_LENGTH:
        return None, f'상품명은 1~{PRODUCT_TITLE_MAX_LENGTH}자로 입력해 주세요.'
    if not description or len(description) > PRODUCT_DESCRIPTION_MAX_LENGTH:
        return None, f'상품 설명은 1~{PRODUCT_DESCRIPTION_MAX_LENGTH}자로 입력해 주세요.'
    if not price.isascii() or not price.isdecimal():
        return None, '가격은 숫자로 입력해 주세요.'
    normalized_price = price.lstrip('0') or '0'
    maximum_price = str(PRODUCT_PRICE_MAX)
    if (
        len(normalized_price) > len(maximum_price)
        or (
            len(normalized_price) == len(maximum_price)
            and normalized_price > maximum_price
        )
    ):
        return None, f'가격은 {PRODUCT_PRICE_MAX:,}원 이하로 입력해 주세요.'

    return {
        'title': title,
        'description': description,
        'price': normalized_price,
    }, None


def detect_product_image_type(content):
    if content.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if content.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if content.startswith((b'GIF87a', b'GIF89a')):
        return 'gif'
    if (
        len(content) >= 12
        and content.startswith(b'RIFF')
        and content[8:12] == b'WEBP'
    ):
        return 'webp'
    return None


def validate_product_image():
    uploaded_images = request.files.getlist('image')
    if not uploaded_images:
        return None, None
    if len(uploaded_images) != 1:
        return None, '상품 이미지는 한 장만 업로드할 수 있습니다.'

    uploaded_image = uploaded_images[0]
    if not uploaded_image.filename:
        return None, None
    extension = os.path.splitext(uploaded_image.filename)[1].lower()
    expected_type = PRODUCT_IMAGE_EXTENSIONS.get(extension)
    if expected_type is None:
        return None, 'PNG, JPEG, GIF, WebP 이미지 파일만 업로드할 수 있습니다.'

    try:
        content = uploaded_image.stream.read(PRODUCT_IMAGE_MAX_BYTES + 1)
    finally:
        uploaded_image.close()
    if not content:
        return None, '비어 있는 파일은 상품 이미지로 업로드할 수 없습니다.'
    if len(content) > PRODUCT_IMAGE_MAX_BYTES:
        return None, '상품 이미지는 5MB 이하여야 합니다.'

    detected_type = detect_product_image_type(content)
    if detected_type != expected_type:
        return None, '파일 확장자와 실제 이미지 형식이 일치하지 않습니다.'
    return {
        'content': content,
        'extension': PRODUCT_IMAGE_CANONICAL_EXTENSIONS[detected_type],
    }, None


def save_product_image(image_data):
    upload_folder = app.config['PRODUCT_IMAGE_UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    for _ in range(3):
        filename = f'{uuid.uuid4().hex}{image_data["extension"]}'
        image_path = os.path.join(upload_folder, filename)
        try:
            with open(image_path, 'xb') as image_file:
                image_file.write(image_data['content'])
            return filename
        except FileExistsError:
            continue
    raise RuntimeError('Could not allocate a unique product image filename.')


def remove_product_image(filename):
    if not filename:
        return
    if not PRODUCT_IMAGE_FILENAME_PATTERN.fullmatch(filename):
        app.logger.warning(
            'security_event=invalid_product_image_filename request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        return
    image_path = os.path.join(app.config['PRODUCT_IMAGE_UPLOAD_FOLDER'], filename)
    try:
        os.remove(image_path)
    except FileNotFoundError:
        return
    except OSError:
        app.logger.warning(
            'security_event=product_image_cleanup_failed request_id=%s filename=%s',
            getattr(g, 'request_id', 'unavailable'),
            filename,
        )


def validate_password(password, username=None):
    if not isinstance(password, str):
        return '비밀번호 형식이 올바르지 않습니다.'
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        return '비밀번호는 8자 이상 12자 이하여야 합니다.'
    if not any(character in string.ascii_letters for character in password):
        return '비밀번호에는 영문자가 하나 이상 포함되어야 합니다.'
    if not any(character in string.digits for character in password):
        return '비밀번호에는 숫자가 하나 이상 포함되어야 합니다.'
    if not any(character in string.punctuation for character in password):
        return '비밀번호에는 특수문자가 하나 이상 포함되어야 합니다.'
    if password.casefold() in COMMON_PASSWORDS:
        return '추측하기 어려운 비밀번호를 사용해 주세요.'
    if username and username.casefold() in password.casefold():
        return '비밀번호에 사용자명을 포함할 수 없습니다.'
    return None


def is_password_hash(password):
    return isinstance(password, str) and PASSWORD_HASH_PATTERN.fullmatch(password) is not None


def password_needs_rehash(password):
    return not is_password_hash(password) or password.split('$', 1)[0] != PASSWORD_HASH_METHOD


def hash_password(password):
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def verify_password(stored_password, candidate_password):
    if not isinstance(stored_password, str) or not isinstance(candidate_password, str):
        return False
    if is_password_hash(stored_password):
        try:
            return check_password_hash(stored_password, candidate_password)
        except (TypeError, ValueError):
            return False
    return hmac.compare_digest(stored_password, candidate_password)


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(24))


def escape_like(value):
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def get_single_form_value(name):
    values = request.form.getlist(name)
    if len(values) != 1:
        return None
    return values[0]


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
        db.execute('PRAGMA busy_timeout = 5000')
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                session_version INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute('PRAGMA table_info(user)')
        user_columns = {column['name'] for column in cursor.fetchall()}
        if 'session_version' not in user_columns:
            cursor.execute(
                'ALTER TABLE user ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0'
            )

        duplicate = cursor.execute(
            """
            SELECT username
            FROM user
            GROUP BY username COLLATE NOCASE
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        ).fetchone()
        if duplicate is not None:
            raise RuntimeError('Case-insensitive duplicate usernames must be resolved.')
        cursor.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS user_username_nocase_idx '
            'ON user(username COLLATE NOCASE)'
        )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_session (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_version INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_activity_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS user_session_user_idx ON user_session(user_id)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_key TEXT NOT NULL,
                ip_key TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS login_attempt_username_idx '
            'ON login_attempt(username_key, attempted_at)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS login_attempt_ip_idx '
            'ON login_attempt(ip_key, attempted_at)'
        )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image_filename TEXT
            )
        """)
        cursor.execute('PRAGMA table_info(product)')
        product_columns = {column['name'] for column in cursor.fetchall()}
        if 'image_filename' not in product_columns:
            cursor.execute('ALTER TABLE product ADD COLUMN image_filename TEXT')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS product_seller_idx ON product(seller_id)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        plaintext_users = cursor.execute('SELECT id, password FROM user').fetchall()
        for user in plaintext_users:
            if not is_password_hash(user['password']):
                cursor.execute(
                    'UPDATE user SET password = ? WHERE id = ?',
                    (hash_password(user['password']), user['id']),
                )
        db.commit()


def hash_session_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_user_session(user):
    token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(token)
    now = int(time.time())
    db = get_db()
    db.execute(
        """
        INSERT INTO user_session
            (token_hash, user_id, session_version, created_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (token_hash, user['id'], user['session_version'], now, now),
    )
    db.commit()
    session.clear()
    session['session_token'] = token


def revoke_current_session():
    token = session.get('session_token')
    if token:
        db = get_db()
        db.execute(
            'DELETE FROM user_session WHERE token_hash = ?',
            (hash_session_token(token),),
        )
        db.commit()


def get_authenticated_user():
    token = session.get('session_token')
    if not isinstance(token, str):
        return None

    token_hash = hash_session_token(token)
    db = get_db()
    user = db.execute(
        """
        SELECT u.id, u.username, u.session_version,
               s.session_version AS stored_session_version,
               s.created_at, s.last_activity_at
        FROM user_session AS s
        JOIN user AS u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if user is None or user['session_version'] != user['stored_session_version']:
        db.execute('DELETE FROM user_session WHERE token_hash = ?', (token_hash,))
        db.commit()
        return None

    now = int(time.time())
    if (
        now - user['last_activity_at'] >= SESSION_IDLE_TIMEOUT_SECONDS
        or now - user['created_at'] >= SESSION_ABSOLUTE_TIMEOUT_SECONDS
    ):
        db.execute('DELETE FROM user_session WHERE token_hash = ?', (token_hash,))
        db.commit()
        return None

    db.execute(
        'UPDATE user_session SET last_activity_at = ? WHERE token_hash = ?',
        (now, token_hash),
    )
    db.commit()
    return user


@app.before_request
def load_authenticated_user():
    g.current_user = None
    if 'session_token' not in session:
        session.pop('user_id', None)
        session.pop('session_version', None)
        return
    g.current_user = get_authenticated_user()
    if g.current_user is None:
        session.clear()


def security_key(namespace, value):
    message = f'{namespace}:{value}'.encode('utf-8')
    secret = app.config['SECRET_KEY'].encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def login_rate_keys(username):
    ip_address = request.remote_addr or 'unknown'
    return (
        security_key('username', username.casefold()),
        security_key('ip', ip_address),
    )


def get_login_rate_state(username_key, ip_key, now=None):
    current_time = int(time.time()) if now is None else now
    cutoff = current_time - LOGIN_ATTEMPT_WINDOW_SECONDS
    db = get_db()
    account_row = db.execute(
        """
        SELECT COUNT(*) AS count, MIN(attempted_at) AS first_attempt
        FROM login_attempt
        WHERE username_key = ? AND attempted_at > ?
        """,
        (username_key, cutoff),
    ).fetchone()
    ip_row = db.execute(
        """
        SELECT COUNT(*) AS count, MIN(attempted_at) AS first_attempt
        FROM login_attempt
        WHERE ip_key = ? AND attempted_at > ?
        """,
        (ip_key, cutoff),
    ).fetchone()
    blocked_rows = []
    if account_row['count'] >= LOGIN_ACCOUNT_LIMIT:
        blocked_rows.append(account_row)
    if ip_row['count'] >= LOGIN_IP_LIMIT:
        blocked_rows.append(ip_row)
    if not blocked_rows:
        return False, 0
    retry_after = max(
        1,
        max(
            LOGIN_ATTEMPT_WINDOW_SECONDS - (current_time - row['first_attempt'])
            for row in blocked_rows
        ),
    )
    return True, retry_after


def record_login_failure(username_key, ip_key):
    now = int(time.time())
    cutoff = now - LOGIN_ATTEMPT_WINDOW_SECONDS
    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM login_attempt WHERE attempted_at <= ?', (cutoff,))
        db.execute(
            """
            INSERT INTO login_attempt (username_key, ip_key, attempted_at)
            VALUES (?, ?, ?)
            """,
            (username_key, ip_key, now),
        )
        db.commit()
    except sqlite3.OperationalError:
        db.rollback()
        app.logger.error(
            'security_event=login_rate_store_error request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        return True, LOGIN_ATTEMPT_WINDOW_SECONDS
    return get_login_rate_state(username_key, ip_key, now)


def clear_login_failures(username_key):
    db = get_db()
    db.execute('DELETE FROM login_attempt WHERE username_key = ?', (username_key,))
    db.commit()


def log_login_event(event, username_key, ip_key, user_id=None):
    log_method = app.logger.info if event == 'success' else app.logger.warning
    log_method(
        'security_event=login_%s request_id=%s user_id=%s account_key=%s ip_key=%s',
        event,
        getattr(g, 'request_id', 'unavailable'),
        user_id or '-',
        username_key,
        ip_key,
    )


def render_register_error(message, status_code):
    flash(message)
    return render_template('register.html'), status_code


def render_login_error(status_code, retry_after=None):
    flash('아이디 또는 비밀번호를 확인하거나 잠시 후 다시 시도해 주세요.')
    response = app.make_response((render_template('login.html'), status_code))
    if retry_after is not None:
        response.headers['Retry-After'] = str(retry_after)
    return response


def get_profile_user():
    return get_db().execute(
        'SELECT id, username, bio FROM user WHERE id = ?',
        (g.current_user['id'],),
    ).fetchone()


def render_profile_error(message, status_code):
    flash(message)
    return render_template('profile.html', user=get_profile_user()), status_code


@app.route('/')
def index():
    if g.current_user is not None:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        raw_username = get_single_form_value('username')
        password = get_single_form_value('password')
        username, username_error = validate_username(raw_username)
        if username_error:
            return render_register_error(username_error, 400)
        password_error = validate_password(password, username)
        if password_error:
            return render_register_error(password_error, 400)

        db = get_db()
        existing = db.execute(
            'SELECT id FROM user WHERE username = ? COLLATE NOCASE',
            (username,),
        ).fetchone()
        if existing is not None:
            return render_register_error('가입 요청을 처리할 수 없습니다.', 409)
        try:
            db.execute(
                'INSERT INTO user (id, username, password) VALUES (?, ?, ?)',
                (str(uuid.uuid4()), username, hash_password(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return render_register_error('가입 요청을 처리할 수 없습니다.', 409)
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        raw_username = get_single_form_value('username')
        password = get_single_form_value('password')
        username, username_error = validate_username(raw_username)
        if username_error or not isinstance(password, str) or not password or len(password) > LOGIN_PASSWORD_MAX_LENGTH:
            return render_login_error(400)

        username_key, ip_key = login_rate_keys(username)
        blocked, retry_after = get_login_rate_state(username_key, ip_key)
        if blocked:
            log_login_event('blocked', username_key, ip_key)
            return render_login_error(429, retry_after)

        db = get_db()
        user = db.execute(
            'SELECT * FROM user WHERE username = ? COLLATE NOCASE',
            (username,),
        ).fetchone()
        stored_password = user['password'] if user is not None else DUMMY_PASSWORD_HASH
        password_matches = verify_password(stored_password, password)
        if user is None or not password_matches:
            blocked, retry_after = record_login_failure(username_key, ip_key)
            log_login_event('blocked' if blocked else 'failure', username_key, ip_key)
            return render_login_error(429 if blocked else 401, retry_after if blocked else None)

        if password_needs_rehash(user['password']):
            db.execute(
                'UPDATE user SET password = ? WHERE id = ?',
                (hash_password(password), user['id']),
            )
            db.commit()
            user = db.execute('SELECT * FROM user WHERE id = ?', (user['id'],)).fetchone()
        clear_login_failures(username_key)
        create_user_session(user)
        log_login_event('success', username_key, ip_key, user['id'])
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    revoke_current_session()
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if g.current_user is None:
        return redirect(url_for('login'))
    db = get_db()
    current_user = db.execute(
        'SELECT id, username, bio FROM user WHERE id = ?',
        (g.current_user['id'],),
    ).fetchone()
    all_products = db.execute('SELECT * FROM product').fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if g.current_user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        bio = get_single_form_value('bio')
        bio_error = validate_bio(bio)
        if bio_error:
            return render_profile_error(bio_error, 400)
        db = get_db()
        db.execute('UPDATE user SET bio = ? WHERE id = ?', (bio, g.current_user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=get_profile_user())


@app.route('/profile/password', methods=['POST'])
def update_password():
    if g.current_user is None:
        return redirect(url_for('login'))

    current_password = get_single_form_value('current_password')
    new_password = get_single_form_value('new_password')
    new_password_confirm = get_single_form_value('new_password_confirm')
    if any(value is None for value in (current_password, new_password, new_password_confirm)):
        return render_profile_error('비밀번호 입력값을 확인해 주세요.', 400)

    db = get_db()
    user = db.execute(
        'SELECT username, password FROM user WHERE id = ?',
        (g.current_user['id'],),
    ).fetchone()
    if user is None or not verify_password(user['password'], current_password):
        return render_profile_error('현재 비밀번호가 올바르지 않습니다.', 403)
    if new_password != new_password_confirm:
        return render_profile_error('새 비밀번호와 비밀번호 확인이 일치하지 않습니다.', 400)
    if hmac.compare_digest(current_password, new_password):
        return render_profile_error('새 비밀번호는 현재 비밀번호와 달라야 합니다.', 400)
    password_error = validate_password(new_password, user['username'])
    if password_error:
        return render_profile_error(password_error, 400)

    db.execute(
        """
        UPDATE user
        SET password = ?, session_version = session_version + 1
        WHERE id = ?
        """,
        (hash_password(new_password), g.current_user['id']),
    )
    db.execute('DELETE FROM user_session WHERE user_id = ?', (g.current_user['id'],))
    db.commit()
    session.clear()
    flash('비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.')
    return redirect(url_for('login'))


@app.route('/users')
def users():
    if g.current_user is None:
        return redirect(url_for('login'))
    query, query_error = validate_search_query(request.args.get('q', ''))
    if query_error:
        abort(400)
    db = get_db()
    if query:
        search_pattern = f'%{escape_like(query)}%'
        found_users = db.execute(
            """
            SELECT username, bio
            FROM user
            WHERE username LIKE ? ESCAPE '\\' COLLATE NOCASE
            ORDER BY username COLLATE NOCASE
            """,
            (search_pattern,),
        ).fetchall()
    else:
        found_users = db.execute(
            'SELECT username, bio FROM user ORDER BY username COLLATE NOCASE'
        ).fetchall()
    return render_template('users.html', users=found_users, query=query)


@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if g.current_user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        product_data, product_error = validate_product_form()
        if product_error:
            flash(product_error)
            return render_template('new_product.html'), 400
        image_data, image_error = validate_product_image()
        if image_error:
            flash(image_error)
            return render_template('new_product.html'), 400

        image_filename = save_product_image(image_data) if image_data else None
        product_id = str(uuid.uuid4())
        db = get_db()
        try:
            db.execute(
                'INSERT INTO product '
                '(id, title, description, price, seller_id, image_filename) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (
                    product_id,
                    product_data['title'],
                    product_data['description'],
                    product_data['price'],
                    g.current_user['id'],
                    image_filename,
                ),
            )
            db.commit()
        except Exception:
            db.rollback()
            remove_product_image(image_filename)
            raise
        flash('상품이 등록되었습니다.')
        return redirect(url_for('manage_products'))
    return render_template('new_product.html')


def get_owned_product(product_id):
    product = get_db().execute(
        'SELECT id, title, description, price, seller_id, image_filename '
        'FROM product WHERE id = ?',
        (product_id,),
    ).fetchone()
    if product is None:
        abort(404)
    if product['seller_id'] != g.current_user['id']:
        abort(403)
    return product


@app.route('/product/manage')
def manage_products():
    if g.current_user is None:
        return redirect(url_for('login'))
    products = get_db().execute(
        """
        SELECT id, title, description, price, image_filename
        FROM product
        WHERE seller_id = ?
        ORDER BY title COLLATE NOCASE, id
        """,
        (g.current_user['id'],),
    ).fetchall()
    return render_template('manage_products.html', products=products)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    product = get_owned_product(product_id)
    if request.method == 'POST':
        product_data, product_error = validate_product_form()
        if product_error:
            flash(product_error)
            return render_template('edit_product.html', product=product), 400

        image_data, image_error = validate_product_image()
        if image_error:
            flash(image_error)
            return render_template('edit_product.html', product=product), 400
        remove_image_values = request.form.getlist('remove_image')
        if len(remove_image_values) > 1 or (
            remove_image_values and remove_image_values[0] != '1'
        ):
            flash('이미지 삭제 요청을 확인해 주세요.')
            return render_template('edit_product.html', product=product), 400
        remove_image = remove_image_values == ['1']
        if image_data is not None and remove_image:
            flash('이미지 교체와 삭제를 동시에 선택할 수 없습니다.')
            return render_template('edit_product.html', product=product), 400

        new_image_filename = (
            save_product_image(image_data) if image_data is not None else None
        )
        resulting_image_filename = product['image_filename']
        if new_image_filename is not None:
            resulting_image_filename = new_image_filename
        elif remove_image:
            resulting_image_filename = None

        db = get_db()
        try:
            cursor = db.execute(
                """
                UPDATE product
                SET title = ?, description = ?, price = ?, image_filename = ?
                WHERE id = ? AND seller_id = ?
                """,
                (
                    product_data['title'],
                    product_data['description'],
                    product_data['price'],
                    resulting_image_filename,
                    product_id,
                    g.current_user['id'],
                ),
            )
            if cursor.rowcount != 1:
                abort(409)
            db.commit()
        except Exception:
            db.rollback()
            remove_product_image(new_image_filename)
            raise

        if resulting_image_filename != product['image_filename']:
            remove_product_image(product['image_filename'])
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('manage_products'))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    product = get_owned_product(product_id)
    db = get_db()
    cursor = db.execute(
        'DELETE FROM product WHERE id = ? AND seller_id = ?',
        (product_id, g.current_user['id']),
    )
    if cursor.rowcount != 1:
        db.rollback()
        abort(409)
    db.commit()
    remove_product_image(product['image_filename'])
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('manage_products'))


@app.route('/product/<product_id>/image')
def product_image(product_id):
    product = get_db().execute(
        'SELECT image_filename FROM product WHERE id = ?',
        (product_id,),
    ).fetchone()
    if (
        product is None
        or not product['image_filename']
        or not PRODUCT_IMAGE_FILENAME_PATTERN.fullmatch(product['image_filename'])
    ):
        abort(404)

    extension = os.path.splitext(product['image_filename'])[1]
    mime_types = {
        '.gif': 'image/gif',
        '.jpg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp',
    }
    return send_from_directory(
        app.config['PRODUCT_IMAGE_UPLOAD_FOLDER'],
        product['image_filename'],
        mimetype=mime_types[extension],
        conditional=True,
    )


@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    product = db.execute('SELECT * FROM product WHERE id = ?', (product_id,)).fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    seller = db.execute(
        'SELECT id, username, bio FROM user WHERE id = ?',
        (product['seller_id'],),
    ).fetchone()
    return render_template('view_product.html', product=product, seller=seller)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if g.current_user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        db.execute(
            'INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)',
            (str(uuid.uuid4()), g.current_user['id'], target_id, reason),
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


@socketio.on('connect')
def handle_connect():
    if get_authenticated_user() is None:
        return False


@socketio.on('send_message')
def handle_send_message_event(data):
    user = get_authenticated_user()
    if user is None:
        disconnect()
        return
    message = data.get('message', '') if isinstance(data, dict) else ''
    payload = {
        'message_id': str(uuid.uuid4()),
        'username': user['username'],
        'message': message,
    }
    send(payload, broadcast=True)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=app.config['DEBUG'])
