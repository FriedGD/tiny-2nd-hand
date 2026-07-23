import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import string
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    has_request_context,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_socketio import SocketIO, disconnect, join_room
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


APP_ENV = os.environ.get('APP_ENV', 'production').strip().lower()
if APP_ENV not in {'production', 'development', 'test'}:
    raise RuntimeError('APP_ENV must be production, development, or test.')

secret_key = os.environ.get('SECRET_KEY')
if APP_ENV == 'production' and not secret_key:
    raise RuntimeError('SECRET_KEY is required when APP_ENV=production.')
if not secret_key:
    secret_key = secrets.token_hex(32)

raw_trusted_proxy_count = os.environ.get('TRUSTED_PROXY_COUNT', '0').strip()
if (
    not raw_trusted_proxy_count.isascii()
    or not raw_trusted_proxy_count.isdecimal()
    or int(raw_trusted_proxy_count) > 10
):
    raise RuntimeError('TRUSTED_PROXY_COUNT must be an integer between 0 and 10.')
trusted_proxy_count = int(raw_trusted_proxy_count)

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
    ENFORCE_HTTPS=(APP_ENV == 'production'),
    TRUSTED_PROXY_COUNT=trusted_proxy_count,
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    PRODUCT_IMAGE_UPLOAD_FOLDER=os.path.join(app.instance_path, 'product_images'),
)
if trusted_proxy_count:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=trusted_proxy_count,
        x_proto=trusted_proxy_count,
        x_host=trusted_proxy_count,
        x_port=trusted_proxy_count,
    )
app.logger.setLevel(logging.INFO)

DATABASE = 'market.db'
socketio = SocketIO(
    app,
    max_http_buffer_size=16 * 1024,
    async_handlers=False,
)
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
PRODUCT_SEARCH_QUERY_MAX_LENGTH = 100
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
PRODUCT_IMAGE_MIME_TYPES = {
    'gif': {'image/gif'},
    'jpeg': {'image/jpeg'},
    'png': {'image/png'},
    'webp': {'image/webp'},
}
PRODUCT_IMAGE_FILENAME_PATTERN = re.compile(
    r'^[0-9a-f]{32}\.(?:gif|jpg|png|webp)$'
)
PRODUCT_STATUS_LABELS = {
    'selling': '판매 중',
    'reserved': '예약됨',
    'sold': '판매 완료',
}
PRODUCT_VERSION_MAX = 9_223_372_036_854_775_806
INITIAL_POINT_BALANCE = 1_000_000
SYSTEM_ISSUANCE_ACCOUNT_ID = 'system:issuance'
SYSTEM_ESCROW_ACCOUNT_ID = 'system:escrow'
ORDER_STATUS_LABELS = {
    'paid': '결제 완료·예치 중',
    'settled': '구매 확정·정산 완료',
    'cancelled': '취소·환불 완료',
}
PAYMENT_STATUS_LABELS = {
    'held': '예치 중',
    'settled': '정산 완료',
    'refunded': '환불 완료',
}
USER_ROLES = {'user', 'admin'}
SANCTION_DURATION_SECONDS = {
    '1d': 24 * 60 * 60,
    '7d': 7 * 24 * 60 * 60,
    '30d': 30 * 24 * 60 * 60,
    'permanent': None,
}
SANCTION_DURATION_LABELS = {
    '1d': '1일',
    '7d': '7일',
    '30d': '30일',
    'permanent': '무기한',
}
ADMIN_REASON_MAX_LENGTH = 500
REPORT_REASON_MAX_LENGTH = 500
REPORT_RATE_WINDOW_SECONDS = 60 * 60
REPORT_RATE_LIMIT = 10
REPORT_IP_RATE_LIMIT = 30
REPORT_TARGET_RATE_LIMIT = 50
REPORT_PAGE_SIZE = 50
REPORT_TARGET_LABELS = {
    'user': '사용자',
    'product': '상품',
}
REPORT_REASON_LABELS = {
    'fraud': '사기 또는 금전 탈취',
    'spam': '스팸·반복 도배',
    'abuse': '욕설·협박·괴롭힘',
    'prohibited': '금지된 상품 또는 내용',
    'other': '기타 운영 정책 위반',
}
REPORT_STATUS_LABELS = {
    'pending': '검토 대기',
    'resolved': '처리 완료',
    'dismissed': '반려',
    'cancelled': '신고 취소',
}
AUDIT_PAGE_SIZE = 50
AUDIT_ACTIONS = {
    'user.role_promoted',
    'user.sanction_created',
    'user.sanction_revoked',
    'product.hidden',
    'product.restored',
    'product.deleted',
    'report.created',
    'report.cancelled',
    'report.resolved',
    'report.dismissed',
    'payment.created',
    'payment.settled',
    'payment.refunded',
    'admin.users_viewed',
    'admin.sanctions_viewed',
    'admin.products_viewed',
    'admin.reports_viewed',
    'admin.audit_logs_viewed',
}
PRIVATE_PAYMENT_ENDPOINTS = {
    'purchase_product',
    'orders',
    'view_order',
    'confirm_order',
    'cancel_order',
}
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
CHAT_MESSAGE_MAX_LENGTH = 1000
CHAT_MESSAGE_MAX_BYTES = 4096
CHAT_HISTORY_PAGE_SIZE = 50
CHAT_SHORT_RATE_WINDOW_MS = 10 * 1000
CHAT_SHORT_RATE_LIMIT = 10
CHAT_LONG_RATE_WINDOW_MS = 5 * 60 * 1000
CHAT_LONG_RATE_LIMIT = 100
CHAT_IP_SHORT_RATE_LIMIT = 30
CHAT_IP_LONG_RATE_LIMIT = 300
CHAT_SHORT_BYTE_LIMIT = 48 * 1024
CHAT_LONG_BYTE_LIMIT = 400 * 1024
CHAT_IP_SHORT_BYTE_LIMIT = 144 * 1024
CHAT_IP_LONG_BYTE_LIMIT = 1200 * 1024
CHAT_CONNECTION_ATTEMPT_WINDOW_MS = 60 * 1000
CHAT_USER_CONNECTION_ATTEMPT_LIMIT = 20
CHAT_IP_CONNECTION_ATTEMPT_LIMIT = 60
CHAT_MAX_CONNECTIONS_PER_USER = 10
CHAT_MAX_CONNECTIONS_PER_IP = 40
CHAT_CONNECTION_STALE_MS = SESSION_ABSOLUTE_TIMEOUT_SECONDS * 1000
CHAT_CONVERSATION_LIST_LIMIT = 100
CHAT_USER_SEARCH_LIMIT = 50
CHAT_READ_SHORT_RATE_LIMIT = 30
CHAT_READ_LONG_RATE_LIMIT = 300
CHAT_READ_IP_SHORT_RATE_LIMIT = 90
CHAT_READ_IP_LONG_RATE_LIMIT = 900


def normalize_origin(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if (
        scheme not in {'http', 'https'}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or '\\' in parsed.netloc
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        return None
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname:
        return None
    hostname = hostname.rstrip('.').lower()
    if not hostname:
        return None
    if ':' in hostname:
        authority = f'[{hostname}]'
    else:
        try:
            authority = hostname.encode('idna').decode('ascii')
        except UnicodeError:
            return None
    default_port = 80 if scheme == 'http' else 443
    if port is not None and port != default_port:
        authority = f'{authority}:{port}'
    return f'{scheme}://{authority}'


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
    g.csp_nonce = secrets.token_urlsafe(24)


@app.before_request
def mark_private_payment_response():
    if request.endpoint in PRIVATE_PAYMENT_ENDPOINTS:
        g.private_no_store = True


@app.before_request
def validate_request_origin():
    if request.method not in UNSAFE_HTTP_METHODS:
        return
    origin = request.headers.get('Origin')
    if not origin:
        return
    normalized = normalize_origin(origin)
    same_origin = normalize_origin(request.host_url)
    origin_is_allowed = (
        normalized is not None
        and (normalized == same_origin or normalized in configured_origins)
    )
    if origin_is_allowed:
        return

    fetch_site = request.headers.get('Sec-Fetch-Site', '').strip().lower()

    # A browser derives Sec-Fetch-Site before a reverse proxy rewrites the
    # request host. It therefore remains a reliable same-origin signal when
    # the public Origin and the WSGI host differ. Flask-WTF still validates the
    # session-bound CSRF token after this hook.
    browser_confirms_same_origin = (
        normalized is not None
        and fetch_site == 'same-origin'
    )
    if browser_confirms_same_origin:
        app.logger.info(
            'security_event=origin_proxy_mismatch_accepted '
            'request_id=%s endpoint=%s reason=fetch_metadata_same_origin',
            getattr(g, 'request_id', 'unavailable'),
            request.endpoint or 'unmatched',
        )
        return

    # The report form is authenticated and independently protected by
    # Flask-WTF's session-bound CSRF token. Some browser shells omit Fetch
    # Metadata or expose an opaque Origin while proxying a relative form POST.
    # In that case, let CSRFProtect make the final decision instead of
    # rejecting a legitimate report based only on the rewritten WSGI host.
    # An explicit cross-site browser request is still rejected here.
    report_uses_csrf_fallback = (
        request.endpoint == 'report'
        and 'session_token' in session
        and fetch_site != 'cross-site'
    )
    if report_uses_csrf_fallback:
        app.logger.info(
            'security_event=report_origin_fallback_accepted '
            'request_id=%s endpoint=report reason=csrf_protected',
            getattr(g, 'request_id', 'unavailable'),
        )
        return

    app.logger.warning(
        'security_event=origin_rejected request_id=%s endpoint=%s reason=%s',
        getattr(g, 'request_id', 'unavailable'),
        request.endpoint or 'unmatched',
        'invalid_origin' if normalized is None else 'origin_mismatch',
    )
    return render_error_page(
        403,
        '요청 출처를 확인할 수 없습니다. '
        '현재 접속한 주소에서 페이지를 새로고침한 뒤 다시 시도해 주세요.',
    )


@app.before_request
def enforce_https_transport():
    if app.config['ENFORCE_HTTPS'] and not request.is_secure:
        app.logger.warning(
            'security_event=insecure_transport_rejected request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        abort(400)


csrf.init_app(app)


@app.context_processor
def inject_product_status_labels():
    point_balance = None
    has_unread_chat_messages = False
    if getattr(g, 'current_user', None) is not None:
        db = get_db()
        account = db.execute(
            "SELECT balance FROM virtual_account WHERE user_id = ? AND kind = 'user'",
            (g.current_user['id'],),
        ).fetchone()
        if account is not None:
            point_balance = account['balance']
        has_unread_chat_messages = user_has_unread_messages(
            db,
            g.current_user['id'],
        )
    return {
        'product_status_labels': PRODUCT_STATUS_LABELS,
        'order_status_labels': ORDER_STATUS_LABELS,
        'payment_status_labels': PAYMENT_STATUS_LABELS,
        'current_point_balance': point_balance,
        'sanction_duration_labels': SANCTION_DURATION_LABELS,
        'report_target_labels': REPORT_TARGET_LABELS,
        'report_reason_labels': REPORT_REASON_LABELS,
        'report_status_labels': REPORT_STATUS_LABELS,
        'has_unread_chat_messages': has_unread_chat_messages,
    }


@app.template_filter('utc_datetime')
def format_utc_datetime(value):
    if value is None:
        return '-'
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S UTC'
    )


@app.template_filter('chat_datetime')
def format_chat_datetime(value):
    if value is None:
        return '-'
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S UTC'
    )


@app.after_request
def add_security_response_headers(response):
    response.headers['X-Request-ID'] = getattr(g, 'request_id', secrets.token_hex(16))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=()'
    )
    response.headers['Referrer-Policy'] = 'same-origin'
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = '; '.join((
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        f"style-src 'nonce-{nonce}'",
        f"script-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com",
    ))
    if app.config['ENFORCE_HTTPS']:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )
    if request.path.startswith('/admin/') or getattr(g, 'private_no_store', False):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
    if getattr(g, 'private_no_store', False):
        response.headers['Referrer-Policy'] = 'no-referrer'
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
    response = app.make_response(
        render_error_page(
            429,
            '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',
        )
    )
    retry_after = getattr(error, 'retry_after', None)
    response.headers['Retry-After'] = str(
        retry_after if retry_after is not None else LOGIN_ATTEMPT_WINDOW_SECONDS
    )
    return response


@app.errorhandler(500)
def handle_internal_error(error):
    app.logger.error(
        'security_event=internal_error request_id=%s',
        getattr(g, 'request_id', 'unavailable'),
        exc_info=error,
    )
    return render_error_page(500, '요청 처리 중 오류가 발생했습니다.')


@app.errorhandler(503)
def handle_service_unavailable(error):
    return render_error_page(503, '서비스를 일시적으로 사용할 수 없습니다.')


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


def validate_uuid_string(value):
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    normalized = str(parsed)
    if value != normalized:
        return None
    return normalized


def validate_safe_next_url(values):
    if not isinstance(values, list) or len(values) != 1:
        return None
    value = values[0]
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or '\\' in value
        or any(unicodedata.category(character).startswith('C') for character in value)
    ):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith('/')
        or parsed.path.startswith('//')
    ):
        return None
    return value


def validate_private_message_payload(data):
    direct_fields = {'recipient_id', 'message', 'client_message_id'}
    product_fields = direct_fields | {'product_id'}
    if not isinstance(data, dict) or set(data) not in (direct_fields, product_fields):
        return None, 'invalid_payload'

    recipient_id = validate_uuid_string(data['recipient_id'])
    client_message_id = validate_uuid_string(data['client_message_id'])
    raw_message = data['message']
    product_id = None
    context_type = 'direct'
    context_id = ''
    if set(data) == product_fields:
        product_id = validate_uuid_string(data['product_id'])
        if product_id is None:
            return None, 'invalid_payload'
        context_type = 'product'
        context_id = product_id
    if recipient_id is None or client_message_id is None or not isinstance(raw_message, str):
        return None, 'invalid_payload'

    message = unicodedata.normalize('NFC', raw_message).strip()
    if not 1 <= len(message) <= CHAT_MESSAGE_MAX_LENGTH:
        return None, 'invalid_message'
    if '\r' in message or any(
        character not in {'\n', '\t'}
        and unicodedata.category(character).startswith('C')
        for character in message
    ):
        return None, 'invalid_message'
    try:
        encoded_message = message.encode('utf-8')
    except UnicodeEncodeError:
        return None, 'invalid_message'
    if len(encoded_message) > CHAT_MESSAGE_MAX_BYTES:
        return None, 'invalid_message'

    return {
        'recipient_id': recipient_id,
        'message': message,
        'client_message_id': client_message_id,
        'context_type': context_type,
        'context_id': context_id,
        'product_id': product_id,
    }, None


def validate_private_message_read_payload(data):
    if not isinstance(data, dict) or set(data) != {'conversation_id'}:
        return None
    return validate_uuid_string(data['conversation_id'])


def encode_chat_cursor(created_at, message_id):
    raw_cursor = f'{created_at}:{message_id}'.encode('ascii')
    return base64.urlsafe_b64encode(raw_cursor).decode('ascii').rstrip('=')


def decode_chat_cursor(value):
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    try:
        padding = '=' * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding,
            altchars=b'-_',
            validate=True,
        ).decode('ascii')
        created_at_text, message_id = decoded.split(':', 1)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if (
        not created_at_text.isascii()
        or not created_at_text.isdecimal()
        or len(created_at_text) > 16
        or validate_uuid_string(message_id) is None
    ):
        return None
    return int(created_at_text), message_id


def chat_user_room(user_id):
    return f'user:{user_id}'


def canonical_chat_participants(first_user_id, second_user_id):
    return tuple(sorted((first_user_id, second_user_id)))


def serialize_private_message(message):
    recipient_last_read_created_at = message['recipient_last_read_created_at']
    recipient_last_read_message_id = message['recipient_last_read_message_id']
    is_read = bool(
        recipient_last_read_created_at is not None
        and (
            message['created_at'] < recipient_last_read_created_at
            or (
                message['created_at'] == recipient_last_read_created_at
                and message['id'] <= recipient_last_read_message_id
            )
        )
    )
    return {
        'message_id': message['id'],
        'conversation_id': message['conversation_id'],
        'sender_id': message['sender_id'],
        'sender_username': message['sender_username'],
        'recipient_id': message['recipient_id'],
        'message': message['body'],
        'created_at': message['created_at'],
        'client_message_id': message['client_message_id'],
        'context_type': message['context_type'],
        'product_id': (
            message['context_id'] if message['context_type'] == 'product' else None
        ),
        'is_read': is_read,
    }


def validate_product_search_query(value):
    if not isinstance(value, str) or len(value) > PRODUCT_SEARCH_QUERY_MAX_LENGTH:
        return None, '상품 검색어 형식이 올바르지 않습니다.'
    normalized = unicodedata.normalize('NFC', value).strip()
    if len(normalized) > PRODUCT_SEARCH_QUERY_MAX_LENGTH or any(
        unicodedata.category(character).startswith('C') for character in normalized
    ):
        return None, '상품 검색어 형식이 올바르지 않습니다.'
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


def validate_product_version():
    raw_version = get_single_form_value('version')
    if (
        not isinstance(raw_version, str)
        or not raw_version.isascii()
        or not raw_version.isdecimal()
    ):
        return None, '상품 버전 정보를 확인해 주세요.'
    normalized_version = raw_version.lstrip('0') or '0'
    maximum_version = str(PRODUCT_VERSION_MAX)
    if (
        len(normalized_version) > len(maximum_version)
        or (
            len(normalized_version) == len(maximum_version)
            and normalized_version > maximum_version
        )
    ):
        return None, '상품 버전 정보를 확인해 주세요.'
    return int(normalized_version), None


def validate_product_status():
    status = get_single_form_value('status')
    if not isinstance(status, str) or status not in PRODUCT_STATUS_LABELS:
        return None, '상품 상태를 확인해 주세요.'
    return status, None


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
    if uploaded_image.mimetype not in PRODUCT_IMAGE_MIME_TYPES[expected_type]:
        uploaded_image.close()
        return None, '이미지 파일의 MIME 형식을 확인해 주세요.'

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
    try:
        os.makedirs(upload_folder, exist_ok=True)
    except OSError:
        app.logger.error(
            'security_event=product_image_storage_unavailable request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        abort(503)
    for _ in range(3):
        filename = f'{uuid.uuid4().hex}{image_data["extension"]}'
        image_path = os.path.join(upload_folder, filename)
        try:
            with open(image_path, 'xb') as image_file:
                image_file.write(image_data['content'])
            return filename
        except FileExistsError:
            continue
        except OSError:
            remove_product_image(filename)
            app.logger.error(
                'security_event=product_image_write_failed request_id=%s',
                getattr(g, 'request_id', 'unavailable'),
            )
            abort(503)
    app.logger.error(
        'security_event=product_image_name_collision request_id=%s',
        getattr(g, 'request_id', 'unavailable'),
    )
    abort(503)


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


def validate_admin_reason(field_name='reason'):
    reason = get_single_form_value(field_name)
    if not isinstance(reason, str):
        return None, '처리 사유를 확인해 주세요.'
    reason = reason.strip()
    if not 1 <= len(reason) <= ADMIN_REASON_MAX_LENGTH:
        return None, f'처리 사유는 1~{ADMIN_REASON_MAX_LENGTH}자로 입력해 주세요.'
    return reason, None


def validate_sanction_duration():
    duration = get_single_form_value('duration')
    if duration not in SANCTION_DURATION_SECONDS:
        return None, '제재 기간을 확인해 주세요.'
    return duration, None


def validate_visibility():
    visibility = get_single_form_value('visibility')
    if visibility not in {'visible', 'hidden'}:
        return None, '상품 노출 상태를 확인해 주세요.'
    return visibility, None


def validate_report_form():
    target_type = get_single_form_value('target_type')
    target_id = validate_uuid_string(get_single_form_value('target_id'))
    reason_code = get_single_form_value('reason_code')
    raw_reason = get_single_form_value('reason')
    if (
        target_type not in REPORT_TARGET_LABELS
        or target_id is None
        or reason_code not in REPORT_REASON_LABELS
    ):
        return None, '신고 대상을 확인해 주세요.'
    if not isinstance(raw_reason, str):
        return None, '신고 사유를 확인해 주세요.'
    reason = unicodedata.normalize('NFC', raw_reason).strip()
    if not 1 <= len(reason) <= REPORT_REASON_MAX_LENGTH:
        return None, f'신고 사유는 1~{REPORT_REASON_MAX_LENGTH}자로 입력해 주세요.'
    if '\r' in reason or any(
        character not in {'\n', '\t'}
        and unicodedata.category(character).startswith('C')
        for character in reason
    ):
        return None, '신고 사유에 허용되지 않는 문자가 포함되어 있습니다.'
    return {
        'target_type': target_type,
        'target_id': target_id,
        'reason_code': reason_code,
        'reason': reason,
    }, None


def validate_report_resolution():
    status = get_single_form_value('status')
    reason, reason_error = validate_admin_reason('resolution')
    if status not in {'resolved', 'dismissed'}:
        return None, '신고 처리 상태를 확인해 주세요.'
    if reason_error:
        return None, reason_error
    return {'status': status, 'resolution': reason}, None


def validate_page_number():
    raw_page = request.args.get('page', '1')
    if (
        not isinstance(raw_page, str)
        or not raw_page.isascii()
        or not raw_page.isdecimal()
    ):
        abort(400)
    normalized = raw_page.lstrip('0') or '0'
    if len(normalized) > 7:
        abort(400)
    page = int(normalized)
    if page < 1:
        abort(400)
    return page


def write_audit_log(
    db,
    action,
    target_type,
    target_id,
    details=None,
    actor=None,
    outcome='success',
):
    if action not in AUDIT_ACTIONS:
        raise ValueError('Unsupported audit action.')
    actor_user_id = actor['id'] if actor is not None else None
    actor_username = actor['username'] if actor is not None else 'system'
    request_id = getattr(g, 'request_id', None) if has_request_context() else None
    db.execute(
        """
        INSERT INTO audit_log
            (id, actor_user_id, actor_username, action, target_type, target_id,
             details_json, outcome, created_at, request_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            actor_user_id,
            actor_username,
            action,
            target_type,
            str(target_id),
            json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
            outcome,
            int(time.time()),
            request_id,
        ),
    )


class WalletError(Exception):
    pass


class InsufficientPointsError(WalletError):
    pass


class WalletConflictError(WalletError):
    pass


def user_account_id(user_id):
    return f'user:{user_id}'


def validate_idempotency_key(value):
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    normalized = str(parsed)
    return normalized if normalized == value.lower() else None


def apply_wallet_transaction(
    db,
    transaction_type,
    idempotency_key,
    postings,
    order_id=None,
    created_by=None,
    now=None,
):
    if (
        len(postings) < 2
        or any(type(amount) is not int for _, amount in postings)
        or sum(amount for _, amount in postings) != 0
    ):
        raise ValueError('Wallet postings must be balanced integers.')
    if len({account_id for account_id, _ in postings}) != len(postings):
        raise ValueError('Wallet postings must use unique accounts.')

    existing = db.execute(
        """
        SELECT id, transaction_type, order_id, created_by
        FROM wallet_transaction
        WHERE idempotency_key = ?
        """,
        (idempotency_key,),
    ).fetchone()
    if existing is not None:
        existing_postings = db.execute(
            """
            SELECT account_id, amount
            FROM wallet_entry
            WHERE transaction_id = ?
            ORDER BY account_id
            """,
            (existing['id'],),
        ).fetchall()
        requested_postings = sorted(postings)
        if (
            existing['transaction_type'] != transaction_type
            or existing['order_id'] != order_id
            or existing['created_by'] != created_by
            or [
                (entry['account_id'], entry['amount'])
                for entry in existing_postings
            ] != requested_postings
        ):
            raise WalletConflictError()
        return existing['id']

    timestamp = int(time.time()) if now is None else now
    transaction_id = str(uuid.uuid4())
    account_updates = []
    for account_id, amount in sorted(postings):
        account = db.execute(
            'SELECT id, kind, balance, version FROM virtual_account WHERE id = ?',
            (account_id,),
        ).fetchone()
        if account is None:
            raise WalletError('Wallet account does not exist.')
        resulting_balance = account['balance'] + amount
        if account['kind'] != 'issuance' and resulting_balance < 0:
            raise InsufficientPointsError()
        account_updates.append((account, amount, resulting_balance))

    db.execute(
        """
        INSERT INTO wallet_transaction
            (id, transaction_type, order_id, idempotency_key, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            transaction_id,
            transaction_type,
            order_id,
            idempotency_key,
            created_by,
            timestamp,
        ),
    )
    for account, amount, resulting_balance in account_updates:
        updated = db.execute(
            """
            UPDATE virtual_account
            SET balance = ?, version = version + 1
            WHERE id = ? AND version = ?
            """,
            (resulting_balance, account['id'], account['version']),
        )
        if updated.rowcount != 1:
            raise WalletConflictError()
        db.execute(
            """
            INSERT INTO wallet_entry
                (id, transaction_id, account_id, amount, balance_after, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                transaction_id,
                account['id'],
                amount,
                resulting_balance,
                timestamp,
            ),
        )
    return transaction_id


def ensure_user_wallet(db, user_id, now=None):
    account_id = user_account_id(user_id)
    existing_account = db.execute(
        'SELECT id, balance, version FROM virtual_account WHERE id = ?',
        (account_id,),
    ).fetchone()
    if existing_account is not None:
        return existing_account
    user = db.execute(
        "SELECT id, role FROM user WHERE id = ?",
        (user_id,),
    ).fetchone()
    if user is None or user['role'] != 'user':
        return None
    timestamp = int(time.time()) if now is None else now
    db.execute(
        """
        INSERT OR IGNORE INTO virtual_account
            (id, user_id, kind, balance, version, created_at)
        VALUES (?, ?, 'user', 0, 0, ?)
        """,
        (account_id, user_id, timestamp),
    )
    apply_wallet_transaction(
        db,
        'initial_grant',
        f'initial-grant:{user_id}',
        [
            (SYSTEM_ISSUANCE_ACCOUNT_ID, -INITIAL_POINT_BALANCE),
            (account_id, INITIAL_POINT_BALANCE),
        ],
        created_by=None,
        now=timestamp,
    )
    return db.execute(
        'SELECT id, balance, version FROM virtual_account WHERE id = ?',
        (account_id,),
    ).fetchone()


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
                session_version INTEGER NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
            )
        """)
        cursor.execute('PRAGMA table_info(user)')
        user_columns = {column['name'] for column in cursor.fetchall()}
        if 'session_version' not in user_columns:
            cursor.execute(
                'ALTER TABLE user ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0'
            )
        if 'role' not in user_columns:
            cursor.execute(
                "ALTER TABLE user ADD COLUMN role TEXT NOT NULL DEFAULT 'user' "
                "CHECK (role IN ('user', 'admin'))"
            )
        invalid_role = cursor.execute(
            "SELECT 1 FROM user WHERE role NOT IN ('user', 'admin') LIMIT 1"
        ).fetchone()
        if invalid_role is not None:
            raise RuntimeError('Invalid user roles must be resolved.')
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_role_validate_insert
            BEFORE INSERT ON user
            WHEN NEW.role IS NULL OR NEW.role NOT IN ('user', 'admin')
            BEGIN
                SELECT RAISE(ABORT, 'invalid user role');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_role_validate_update
            BEFORE UPDATE OF role ON user
            WHEN NEW.role IS NULL OR NEW.role NOT IN ('user', 'admin')
            BEGIN
                SELECT RAISE(ABORT, 'invalid user role');
            END
        """)

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
            CREATE TABLE IF NOT EXISTS user_sanction (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 500),
                duration_code TEXT NOT NULL CHECK (
                    duration_code IN ('1d', '7d', '30d', 'permanent')
                ),
                created_at INTEGER NOT NULL,
                ends_at INTEGER,
                revoked_at INTEGER,
                revoked_by TEXT,
                revoke_reason TEXT CHECK (
                    revoke_reason IS NULL
                    OR length(trim(revoke_reason)) BETWEEN 1 AND 500
                ),
                CHECK (
                    (duration_code = 'permanent' AND ends_at IS NULL)
                    OR (duration_code != 'permanent' AND ends_at > created_at)
                ),
                CHECK (
                    (revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL)
                    OR (
                        revoked_at IS NOT NULL
                        AND revoked_by IS NOT NULL
                        AND revoke_reason IS NOT NULL
                    )
                ),
                FOREIGN KEY (user_id) REFERENCES user(id),
                FOREIGN KEY (created_by) REFERENCES user(id),
                FOREIGN KEY (revoked_by) REFERENCES user(id)
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS user_sanction_user_idx '
            'ON user_sanction(user_id, created_at DESC)'
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_sanction_validate_insert
            BEFORE INSERT ON user_sanction
            WHEN
                NOT EXISTS (
                    SELECT 1 FROM user
                    WHERE id = NEW.user_id AND role = 'user'
                )
                OR NOT EXISTS (
                    SELECT 1 FROM user
                    WHERE id = NEW.created_by AND role = 'admin'
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid sanction actors');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_sanction_prevent_core_update
            BEFORE UPDATE OF id, user_id, created_by, reason, duration_code,
                             created_at, ends_at
            ON user_sanction
            BEGIN
                SELECT RAISE(ABORT, 'sanction history is immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_sanction_validate_revoke
            BEFORE UPDATE OF revoked_at, revoked_by, revoke_reason ON user_sanction
            WHEN
                NEW.revoked_at IS NULL
                OR NEW.revoked_by IS NULL
                OR NEW.revoke_reason IS NULL
                OR NOT EXISTS (
                    SELECT 1 FROM user
                    WHERE id = NEW.revoked_by AND role = 'admin'
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid sanction revocation');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS user_sanction_prevent_delete
            BEFORE DELETE ON user_sanction
            BEGIN
                SELECT RAISE(ABORT, 'sanction history is immutable');
            END
        """)
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
                title TEXT NOT NULL CHECK (
                    length(trim(title)) BETWEEN 1 AND 100
                ),
                description TEXT NOT NULL CHECK (
                    length(trim(description)) BETWEEN 1 AND 2000
                ),
                price TEXT NOT NULL CHECK (
                    length(price) BETWEEN 1 AND 10
                    AND price NOT GLOB '*[^0-9]*'
                    AND (price = '0' OR substr(price, 1, 1) != '0')
                    AND CAST(price AS INTEGER) <= 1000000000
                ),
                seller_id TEXT NOT NULL,
                image_filename TEXT CHECK (
                    image_filename IS NULL
                    OR (
                        length(image_filename) IN (36, 37)
                        AND substr(image_filename, 1, 32) NOT GLOB '*[^0-9a-f]*'
                        AND substr(image_filename, 33) IN ('.gif', '.jpg', '.png', '.webp')
                    )
                ),
                status TEXT NOT NULL DEFAULT 'selling' CHECK (
                    status IN ('selling', 'reserved', 'sold')
                ),
                version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
                is_hidden INTEGER NOT NULL DEFAULT 0 CHECK (is_hidden IN (0, 1)),
                hidden_at INTEGER,
                hidden_by TEXT,
                hidden_reason TEXT,
                FOREIGN KEY (seller_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute('PRAGMA table_info(product)')
        product_columns = {column['name'] for column in cursor.fetchall()}
        if 'image_filename' not in product_columns:
            cursor.execute('ALTER TABLE product ADD COLUMN image_filename TEXT')
        if 'status' not in product_columns:
            cursor.execute(
                "ALTER TABLE product ADD COLUMN status TEXT NOT NULL "
                "DEFAULT 'selling' CHECK (status IN ('selling', 'reserved', 'sold'))"
            )
        if 'version' not in product_columns:
            cursor.execute(
                'ALTER TABLE product ADD COLUMN version INTEGER NOT NULL DEFAULT 0'
            )
        if 'is_hidden' not in product_columns:
            cursor.execute(
                'ALTER TABLE product ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0 '
                'CHECK (is_hidden IN (0, 1))'
            )
        if 'hidden_at' not in product_columns:
            cursor.execute('ALTER TABLE product ADD COLUMN hidden_at INTEGER')
        if 'hidden_by' not in product_columns:
            cursor.execute('ALTER TABLE product ADD COLUMN hidden_by TEXT')
        if 'hidden_reason' not in product_columns:
            cursor.execute('ALTER TABLE product ADD COLUMN hidden_reason TEXT')
        invalid_product = cursor.execute("""
            SELECT 1
            FROM product
            WHERE
                length(trim(title)) NOT BETWEEN 1 AND 100
                OR length(trim(description)) NOT BETWEEN 1 AND 2000
                OR length(price) NOT BETWEEN 1 AND 10
                OR price GLOB '*[^0-9]*'
                OR (price != '0' AND substr(price, 1, 1) = '0')
                OR CAST(price AS INTEGER) > 1000000000
                OR status IS NULL
                OR status NOT IN ('selling', 'reserved', 'sold')
                OR typeof(version) != 'integer'
                OR version < 0
                OR typeof(is_hidden) != 'integer'
                OR is_hidden NOT IN (0, 1)
                OR (
                    is_hidden = 0
                    AND (
                        hidden_at IS NOT NULL
                        OR hidden_by IS NOT NULL
                        OR hidden_reason IS NOT NULL
                    )
                )
                OR (
                    is_hidden = 1
                    AND (
                        typeof(hidden_at) != 'integer'
                        OR hidden_by IS NULL
                        OR length(trim(hidden_reason)) NOT BETWEEN 1 AND 500
                        OR NOT EXISTS (
                            SELECT 1 FROM user AS hidden_admin
                            WHERE hidden_admin.id = product.hidden_by
                              AND hidden_admin.role = 'admin'
                        )
                    )
                )
                OR NOT EXISTS (SELECT 1 FROM user WHERE user.id = product.seller_id)
                OR (
                    image_filename IS NOT NULL
                    AND (
                        length(image_filename) NOT IN (36, 37)
                        OR substr(image_filename, 1, 32) GLOB '*[^0-9a-f]*'
                        OR substr(image_filename, 33)
                            NOT IN ('.gif', '.jpg', '.png', '.webp')
                    )
                )
            LIMIT 1
        """).fetchone()
        if invalid_product is not None:
            raise RuntimeError('Invalid product records must be resolved.')
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_validate_insert
            BEFORE INSERT ON product
            WHEN
                length(trim(NEW.title)) NOT BETWEEN 1 AND 100
                OR length(trim(NEW.description)) NOT BETWEEN 1 AND 2000
                OR length(NEW.price) NOT BETWEEN 1 AND 10
                OR NEW.price GLOB '*[^0-9]*'
                OR (NEW.price != '0' AND substr(NEW.price, 1, 1) = '0')
                OR CAST(NEW.price AS INTEGER) > 1000000000
                OR typeof(NEW.version) != 'integer'
                OR NEW.version < 0
                OR NOT EXISTS (SELECT 1 FROM user WHERE id = NEW.seller_id)
                OR (
                    NEW.image_filename IS NOT NULL
                    AND (
                        length(NEW.image_filename) NOT IN (36, 37)
                        OR substr(NEW.image_filename, 1, 32) GLOB '*[^0-9a-f]*'
                        OR substr(NEW.image_filename, 33)
                            NOT IN ('.gif', '.jpg', '.png', '.webp')
                    )
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid product data');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_validate_update
            BEFORE UPDATE ON product
            WHEN
                length(trim(NEW.title)) NOT BETWEEN 1 AND 100
                OR length(trim(NEW.description)) NOT BETWEEN 1 AND 2000
                OR length(NEW.price) NOT BETWEEN 1 AND 10
                OR NEW.price GLOB '*[^0-9]*'
                OR (NEW.price != '0' AND substr(NEW.price, 1, 1) = '0')
                OR CAST(NEW.price AS INTEGER) > 1000000000
                OR typeof(NEW.version) != 'integer'
                OR NEW.version < 0
                OR NOT EXISTS (SELECT 1 FROM user WHERE id = NEW.seller_id)
                OR (
                    NEW.image_filename IS NOT NULL
                    AND (
                        length(NEW.image_filename) NOT IN (36, 37)
                        OR substr(NEW.image_filename, 1, 32) GLOB '*[^0-9a-f]*'
                        OR substr(NEW.image_filename, 33)
                            NOT IN ('.gif', '.jpg', '.png', '.webp')
                    )
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid product data');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_status_validate_insert
            BEFORE INSERT ON product
            WHEN
                NEW.status IS NULL
                OR NEW.status NOT IN ('selling', 'reserved', 'sold')
            BEGIN
                SELECT RAISE(ABORT, 'invalid product status');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_status_validate_update
            BEFORE UPDATE ON product
            WHEN
                NEW.status IS NULL
                OR NEW.status NOT IN ('selling', 'reserved', 'sold')
            BEGIN
                SELECT RAISE(ABORT, 'invalid product status');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_visibility_validate_insert
            BEFORE INSERT ON product
            WHEN
                typeof(NEW.is_hidden) != 'integer'
                OR NEW.is_hidden NOT IN (0, 1)
                OR (
                    NEW.is_hidden = 0
                    AND (
                        NEW.hidden_at IS NOT NULL
                        OR NEW.hidden_by IS NOT NULL
                        OR NEW.hidden_reason IS NOT NULL
                    )
                )
                OR (
                    NEW.is_hidden = 1
                    AND (
                        typeof(NEW.hidden_at) != 'integer'
                        OR NEW.hidden_by IS NULL
                        OR length(trim(NEW.hidden_reason)) NOT BETWEEN 1 AND 500
                        OR NOT EXISTS (
                            SELECT 1 FROM user
                            WHERE id = NEW.hidden_by AND role = 'admin'
                        )
                    )
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid product visibility');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS product_visibility_validate_update
            BEFORE UPDATE ON product
            WHEN
                typeof(NEW.is_hidden) != 'integer'
                OR NEW.is_hidden NOT IN (0, 1)
                OR (
                    NEW.is_hidden = 0
                    AND (
                        NEW.hidden_at IS NOT NULL
                        OR NEW.hidden_by IS NOT NULL
                        OR NEW.hidden_reason IS NOT NULL
                    )
                )
                OR (
                    NEW.is_hidden = 1
                    AND (
                        typeof(NEW.hidden_at) != 'integer'
                        OR NEW.hidden_by IS NULL
                        OR length(trim(NEW.hidden_reason)) NOT BETWEEN 1 AND 500
                        OR NOT EXISTS (
                            SELECT 1 FROM user
                            WHERE id = NEW.hidden_by AND role = 'admin'
                        )
                    )
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid product visibility');
            END
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS product_seller_idx ON product(seller_id)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS virtual_account (
                id TEXT PRIMARY KEY,
                user_id TEXT UNIQUE,
                kind TEXT NOT NULL CHECK (kind IN ('user', 'escrow', 'issuance')),
                balance INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
                created_at INTEGER NOT NULL,
                CHECK (
                    (kind = 'user' AND user_id IS NOT NULL AND balance >= 0)
                    OR (kind = 'escrow' AND user_id IS NULL AND balance >= 0)
                    OR (kind = 'issuance' AND user_id IS NULL)
                ),
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        """)
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS virtual_account_escrow_idx "
            "ON virtual_account(kind) WHERE kind = 'escrow'"
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS virtual_account_issuance_idx "
            "ON virtual_account(kind) WHERE kind = 'issuance'"
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS virtual_account_core_immutable
            BEFORE UPDATE OF id, user_id, kind, created_at ON virtual_account
            BEGIN
                SELECT RAISE(ABORT, 'wallet account core fields are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS virtual_account_prevent_delete
            BEFORE DELETE ON virtual_account
            BEGIN
                SELECT RAISE(ABORT, 'wallet accounts cannot be deleted');
            END
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS market_order (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                product_title TEXT NOT NULL CHECK (
                    length(trim(product_title)) BETWEEN 1 AND 100
                ),
                price INTEGER NOT NULL CHECK (
                    price BETWEEN 0 AND 1000000000
                ),
                status TEXT NOT NULL CHECK (
                    status IN ('paid', 'settled', 'cancelled')
                ),
                version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
                idempotency_key TEXT NOT NULL UNIQUE CHECK (
                    length(idempotency_key) = 36
                ),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                CHECK (buyer_id != seller_id),
                FOREIGN KEY (buyer_id) REFERENCES user(id),
                FOREIGN KEY (seller_id) REFERENCES user(id)
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS market_order_buyer_idx '
            'ON market_order(buyer_id, created_at DESC, id DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS market_order_seller_idx '
            'ON market_order(seller_id, created_at DESC, id DESC)'
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS market_order_active_product_idx "
            "ON market_order(product_id) WHERE status IN ('paid', 'settled')"
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS market_order_core_immutable
            BEFORE UPDATE OF id, product_id, buyer_id, seller_id, product_title,
                             price, idempotency_key, created_at
            ON market_order
            BEGIN
                SELECT RAISE(ABORT, 'order core fields are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS market_order_status_transition
            BEFORE UPDATE OF status ON market_order
            WHEN NOT (
                OLD.status = 'paid'
                AND NEW.status IN ('settled', 'cancelled')
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid order status transition');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS market_order_prevent_delete
            BEFORE DELETE ON market_order
            BEGIN
                SELECT RAISE(ABORT, 'order history is immutable');
            END
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment (
                id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL UNIQUE,
                amount INTEGER NOT NULL CHECK (
                    amount BETWEEN 0 AND 1000000000
                ),
                status TEXT NOT NULL CHECK (
                    status IN ('held', 'settled', 'refunded')
                ),
                version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
                created_at INTEGER NOT NULL,
                settled_at INTEGER,
                refunded_at INTEGER,
                CHECK (
                    (status = 'held' AND settled_at IS NULL AND refunded_at IS NULL)
                    OR (status = 'settled' AND settled_at IS NOT NULL AND refunded_at IS NULL)
                    OR (status = 'refunded' AND settled_at IS NULL AND refunded_at IS NOT NULL)
                ),
                FOREIGN KEY (order_id) REFERENCES market_order(id)
            )
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS payment_core_immutable
            BEFORE UPDATE OF id, order_id, amount, created_at ON payment
            BEGIN
                SELECT RAISE(ABORT, 'payment core fields are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS payment_status_transition
            BEFORE UPDATE OF status ON payment
            WHEN NOT (
                OLD.status = 'held'
                AND NEW.status IN ('settled', 'refunded')
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid payment status transition');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS payment_prevent_delete
            BEFORE DELETE ON payment
            BEGIN
                SELECT RAISE(ABORT, 'payment history is immutable');
            END
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet_transaction (
                id TEXT PRIMARY KEY,
                transaction_type TEXT NOT NULL CHECK (
                    transaction_type IN (
                        'initial_grant', 'purchase', 'refund', 'settlement'
                    )
                ),
                order_id TEXT,
                idempotency_key TEXT NOT NULL UNIQUE,
                created_by TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (order_id) REFERENCES market_order(id),
                FOREIGN KEY (created_by) REFERENCES user(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet_entry (
                id TEXT PRIMARY KEY,
                transaction_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE (transaction_id, account_id),
                FOREIGN KEY (transaction_id) REFERENCES wallet_transaction(id),
                FOREIGN KEY (account_id) REFERENCES virtual_account(id)
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS wallet_entry_account_idx '
            'ON wallet_entry(account_id, created_at DESC, id DESC)'
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS wallet_transaction_prevent_update
            BEFORE UPDATE ON wallet_transaction
            BEGIN
                SELECT RAISE(ABORT, 'wallet transactions are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS wallet_transaction_prevent_delete
            BEFORE DELETE ON wallet_transaction
            BEGIN
                SELECT RAISE(ABORT, 'wallet transactions are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS wallet_entry_prevent_update
            BEFORE UPDATE ON wallet_entry
            BEGIN
                SELECT RAISE(ABORT, 'wallet entries are immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS wallet_entry_prevent_delete
            BEFORE DELETE ON wallet_entry
            BEGIN
                SELECT RAISE(ABORT, 'wallet entries are immutable');
            END
        """)
        cursor.execute('PRAGMA table_info(private_conversation)')
        conversation_columns = {column['name'] for column in cursor.fetchall()}
        if conversation_columns and 'context_type' not in conversation_columns:
            cursor.execute('DROP TRIGGER IF EXISTS private_message_validate_sender')
            cursor.execute(
                'DROP TRIGGER IF EXISTS private_conversation_participants_immutable'
            )
            cursor.execute("""
                CREATE TABLE private_conversation_new (
                    id TEXT PRIMARY KEY,
                    participant_low_id TEXT NOT NULL,
                    participant_high_id TEXT NOT NULL,
                    context_type TEXT NOT NULL
                        CHECK (context_type IN ('direct', 'product')),
                    context_id TEXT NOT NULL,
                    product_id TEXT,
                    created_at INTEGER NOT NULL,
                    last_message_at INTEGER NOT NULL,
                    CHECK (participant_low_id < participant_high_id),
                    CHECK (
                        (context_type = 'direct' AND context_id = ''
                         AND product_id IS NULL)
                        OR
                        (context_type = 'product' AND length(context_id) = 36
                         AND (product_id IS NULL OR product_id = context_id))
                    ),
                    UNIQUE (
                        participant_low_id, participant_high_id,
                        context_type, context_id
                    ),
                    FOREIGN KEY (participant_low_id)
                        REFERENCES user(id) ON DELETE CASCADE,
                    FOREIGN KEY (participant_high_id)
                        REFERENCES user(id) ON DELETE CASCADE,
                    FOREIGN KEY (product_id)
                        REFERENCES product(id) ON DELETE SET NULL
                )
            """)
            cursor.execute("""
                INSERT INTO private_conversation_new
                    (id, participant_low_id, participant_high_id,
                     context_type, context_id, product_id,
                     created_at, last_message_at)
                SELECT id, participant_low_id, participant_high_id,
                       'direct', '', NULL, created_at, last_message_at
                FROM private_conversation
            """)
            cursor.execute("""
                CREATE TABLE private_message_new (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    client_message_id TEXT NOT NULL,
                    body TEXT NOT NULL
                        CHECK (length(trim(body)) BETWEEN 1 AND 1000),
                    created_at INTEGER NOT NULL,
                    UNIQUE (sender_id, client_message_id),
                    FOREIGN KEY (conversation_id)
                        REFERENCES private_conversation_new(id) ON DELETE CASCADE,
                    FOREIGN KEY (sender_id) REFERENCES user(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO private_message_new
                    (id, conversation_id, sender_id, client_message_id,
                     body, created_at)
                SELECT id, conversation_id, sender_id, client_message_id,
                       body, created_at
                FROM private_message
            """)
            cursor.execute('DROP TABLE private_message')
            cursor.execute('DROP TABLE private_conversation')
            cursor.execute(
                'ALTER TABLE private_conversation_new RENAME TO private_conversation'
            )
            cursor.execute('ALTER TABLE private_message_new RENAME TO private_message')

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_conversation (
                id TEXT PRIMARY KEY,
                participant_low_id TEXT NOT NULL,
                participant_high_id TEXT NOT NULL,
                context_type TEXT NOT NULL DEFAULT 'direct'
                    CHECK (context_type IN ('direct', 'product')),
                context_id TEXT NOT NULL DEFAULT '',
                product_id TEXT,
                created_at INTEGER NOT NULL,
                last_message_at INTEGER NOT NULL,
                CHECK (participant_low_id < participant_high_id),
                CHECK (
                    (context_type = 'direct' AND context_id = ''
                     AND product_id IS NULL)
                    OR
                    (context_type = 'product' AND length(context_id) = 36
                     AND (product_id IS NULL OR product_id = context_id))
                ),
                UNIQUE (
                    participant_low_id, participant_high_id,
                    context_type, context_id
                ),
                FOREIGN KEY (participant_low_id) REFERENCES user(id) ON DELETE CASCADE,
                FOREIGN KEY (participant_high_id) REFERENCES user(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES product(id) ON DELETE SET NULL
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS private_conversation_low_idx '
            'ON private_conversation(participant_low_id, last_message_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS private_conversation_high_idx '
            'ON private_conversation(participant_high_id, last_message_at DESC)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_message (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                client_message_id TEXT NOT NULL,
                body TEXT NOT NULL CHECK (length(trim(body)) BETWEEN 1 AND 1000),
                created_at INTEGER NOT NULL,
                UNIQUE (sender_id, client_message_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES private_conversation(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS private_message_history_idx '
            'ON private_message(conversation_id, created_at DESC, id DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS private_message_sender_rate_idx '
            'ON private_message(sender_id, created_at DESC)'
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS private_message_validate_sender
            BEFORE INSERT ON private_message
            WHEN NOT EXISTS (
                SELECT 1
                FROM private_conversation AS conversation
                WHERE conversation.id = NEW.conversation_id
                  AND NEW.sender_id IN (
                      conversation.participant_low_id,
                      conversation.participant_high_id
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'message sender is not a conversation participant');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS private_conversation_participants_immutable
            BEFORE UPDATE OF participant_low_id, participant_high_id,
                             context_type, context_id
            ON private_conversation
            BEGIN
                SELECT RAISE(ABORT, 'conversation identity is immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS private_conversation_validate_product
            BEFORE INSERT ON private_conversation
            WHEN NEW.context_type = 'product' AND NOT EXISTS (
                SELECT 1
                FROM product
                WHERE product.id = NEW.product_id
                  AND product.seller_id IN (
                      NEW.participant_low_id,
                      NEW.participant_high_id
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'product conversation requires the seller');
            END
        """)
        read_state_exists = cursor.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'private_conversation_read_state'
            """
        ).fetchone() is not None
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_conversation_read_state (
                conversation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_read_created_at INTEGER NOT NULL,
                last_read_message_id TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, user_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES private_conversation(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
                FOREIGN KEY (last_read_message_id)
                    REFERENCES private_message(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS private_read_state_user_idx '
            'ON private_conversation_read_state(user_id, conversation_id)'
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS private_read_state_validate_insert
            BEFORE INSERT ON private_conversation_read_state
            WHEN NOT EXISTS (
                SELECT 1
                FROM private_conversation AS conversation
                WHERE conversation.id = NEW.conversation_id
                  AND NEW.user_id IN (
                      conversation.participant_low_id,
                      conversation.participant_high_id
                  )
            ) OR NOT EXISTS (
                SELECT 1
                FROM private_message AS message
                WHERE message.id = NEW.last_read_message_id
                  AND message.conversation_id = NEW.conversation_id
                  AND message.created_at = NEW.last_read_created_at
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid conversation read state');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS private_read_state_validate_update
            BEFORE UPDATE ON private_conversation_read_state
            WHEN NEW.conversation_id != OLD.conversation_id
              OR NEW.user_id != OLD.user_id
              OR NEW.updated_at < OLD.updated_at
              OR NEW.last_read_created_at < OLD.last_read_created_at
              OR (
                  NEW.last_read_created_at = OLD.last_read_created_at
                  AND NEW.last_read_message_id < OLD.last_read_message_id
              )
              OR NOT EXISTS (
                  SELECT 1
                  FROM private_message AS message
                  WHERE message.id = NEW.last_read_message_id
                    AND message.conversation_id = NEW.conversation_id
                    AND message.created_at = NEW.last_read_created_at
              )
            BEGIN
                SELECT RAISE(ABORT, 'invalid conversation read-state update');
            END
        """)
        if not read_state_exists:
            migration_now_ms = time.time_ns() // 1_000_000
            cursor.execute(
                """
                INSERT INTO private_conversation_read_state
                    (conversation_id, user_id, last_read_created_at,
                     last_read_message_id, updated_at)
                SELECT conversation.id, participant.user_id,
                       latest.created_at, latest.id, ?
                FROM private_conversation AS conversation
                JOIN (
                    SELECT id, conversation_id, created_at
                    FROM private_message AS candidate
                    WHERE candidate.id = (
                        SELECT newest.id
                        FROM private_message AS newest
                        WHERE newest.conversation_id = candidate.conversation_id
                        ORDER BY newest.created_at DESC, newest.id DESC
                        LIMIT 1
                    )
                ) AS latest ON latest.conversation_id = conversation.id
                JOIN (
                    SELECT id AS conversation_id,
                           participant_low_id AS user_id
                    FROM private_conversation
                    UNION ALL
                    SELECT id AS conversation_id,
                           participant_high_id AS user_id
                    FROM private_conversation
                ) AS participant
                  ON participant.conversation_id = conversation.id
                """,
                (migration_now_ms,),
            )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_connection_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                ip_key TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_connection_attempt_user_idx '
            'ON chat_connection_attempt(user_id, attempted_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_connection_attempt_ip_idx '
            'ON chat_connection_attempt(ip_key, attempted_at DESC)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_connection (
                sid_key TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                ip_key TEXT NOT NULL,
                connected_at INTEGER NOT NULL,
                last_activity_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_connection_user_idx '
            'ON chat_connection(user_id, last_activity_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_connection_ip_idx '
            'ON chat_connection(ip_key, last_activity_at DESC)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                ip_key TEXT NOT NULL,
                conversation_key TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_message_attempt_user_idx '
            'ON chat_message_attempt(user_id, attempted_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_message_attempt_ip_idx '
            'ON chat_message_attempt(ip_key, attempted_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_message_attempt_conversation_idx '
            'ON chat_message_attempt(conversation_key, attempted_at DESC)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_read_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                ip_key TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_read_attempt_user_idx '
            'ON chat_read_attempt(user_id, attempted_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS chat_read_attempt_ip_idx '
            'ON chat_read_attempt(ip_key, attempted_at DESC)'
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
                target_id TEXT NOT NULL,
                reason_code TEXT NOT NULL CHECK (
                    reason_code IN ('fraud', 'spam', 'abuse', 'prohibited', 'other')
                ),
                reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 500),
                ip_key TEXT NOT NULL CHECK (
                    length(ip_key) = 64 AND ip_key NOT GLOB '*[^0-9a-f]*'
                ),
                status TEXT NOT NULL DEFAULT 'pending' CHECK (
                    status IN ('pending', 'resolved', 'dismissed')
                ),
                created_at INTEGER NOT NULL,
                cancelled_at INTEGER,
                resolved_at INTEGER,
                resolved_by TEXT,
                resolution TEXT CHECK (
                    resolution IS NULL
                    OR length(trim(resolution)) BETWEEN 1 AND 500
                ),
                CHECK (
                    (status = 'pending' AND resolved_at IS NULL
                     AND resolved_by IS NULL AND resolution IS NULL)
                    OR
                    (status IN ('resolved', 'dismissed') AND resolved_at IS NOT NULL
                     AND resolved_by IS NOT NULL AND resolution IS NOT NULL)
                ),
                CHECK (
                    cancelled_at IS NULL
                    OR (status = 'pending' AND typeof(cancelled_at) = 'integer')
                ),
                FOREIGN KEY (reporter_id) REFERENCES user(id),
                FOREIGN KEY (resolved_by) REFERENCES user(id)
            )
        """)
        cursor.execute('PRAGMA table_info(report)')
        report_columns = {column['name'] for column in cursor.fetchall()}
        report_migrations = {
            'target_type': 'ALTER TABLE report ADD COLUMN target_type TEXT',
            'reason_code': 'ALTER TABLE report ADD COLUMN reason_code TEXT',
            'ip_key': 'ALTER TABLE report ADD COLUMN ip_key TEXT',
            'status': (
                "ALTER TABLE report ADD COLUMN status TEXT NOT NULL DEFAULT 'pending' "
                "CHECK (status IN ('pending', 'resolved', 'dismissed'))"
            ),
            'created_at': (
                'ALTER TABLE report ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0'
            ),
            'cancelled_at': 'ALTER TABLE report ADD COLUMN cancelled_at INTEGER',
            'resolved_at': 'ALTER TABLE report ADD COLUMN resolved_at INTEGER',
            'resolved_by': 'ALTER TABLE report ADD COLUMN resolved_by TEXT',
            'resolution': 'ALTER TABLE report ADD COLUMN resolution TEXT',
        }
        for column_name, migration in report_migrations.items():
            if column_name not in report_columns:
                cursor.execute(migration)
        cursor.execute("""
            UPDATE report
            SET target_type = CASE
                WHEN EXISTS (SELECT 1 FROM user WHERE user.id = report.target_id)
                    THEN 'user'
                WHEN EXISTS (SELECT 1 FROM product WHERE product.id = report.target_id)
                    THEN 'product'
                ELSE NULL
            END
            WHERE target_type IS NULL
        """)
        cursor.execute(
            "UPDATE report SET reason_code = 'other' WHERE reason_code IS NULL"
        )
        cursor.execute(
            "UPDATE report SET ip_key = ? WHERE ip_key IS NULL",
            ('0' * 64,),
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS report_reporter_created_idx '
            'ON report(reporter_id, created_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS report_ip_created_idx '
            'ON report(ip_key, created_at DESC)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS report_target_status_idx '
            'ON report(target_type, target_id, status)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS report_target_created_idx '
            'ON report(target_type, target_id, created_at DESC)'
        )
        cursor.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS report_pending_unique_idx '
            'ON report(reporter_id, target_type, target_id, reason_code) '
            "WHERE status = 'pending' AND cancelled_at IS NULL"
        )
        cursor.execute('DROP TRIGGER IF EXISTS report_validate_insert')
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS report_validate_insert
            BEFORE INSERT ON report
            WHEN
                NEW.target_type NOT IN ('user', 'product')
                OR NEW.reason_code NOT IN (
                    'fraud', 'spam', 'abuse', 'prohibited', 'other'
                )
                OR length(trim(NEW.reason)) NOT BETWEEN 1 AND 500
                OR length(NEW.ip_key) != 64
                OR NEW.ip_key GLOB '*[^0-9a-f]*'
                OR NEW.status != 'pending'
                OR typeof(NEW.created_at) != 'integer'
                OR NEW.cancelled_at IS NOT NULL
                OR NEW.resolved_at IS NOT NULL
                OR NEW.resolved_by IS NOT NULL
                OR NEW.resolution IS NOT NULL
                OR NOT EXISTS (SELECT 1 FROM user WHERE id = NEW.reporter_id)
                OR (
                    NEW.target_type = 'user'
                    AND NOT EXISTS (SELECT 1 FROM user WHERE id = NEW.target_id)
                )
                OR (
                    NEW.target_type = 'product'
                    AND NOT EXISTS (SELECT 1 FROM product WHERE id = NEW.target_id)
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid report');
            END
        """)
        cursor.execute('DROP TRIGGER IF EXISTS report_validate_resolution')
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS report_validate_resolution
            BEFORE UPDATE OF status, resolved_at, resolved_by, resolution ON report
            WHEN
                OLD.status != 'pending'
                OR OLD.cancelled_at IS NOT NULL
                OR NEW.status NOT IN ('resolved', 'dismissed')
                OR typeof(NEW.resolved_at) != 'integer'
                OR NEW.resolved_by IS NULL
                OR length(trim(NEW.resolution)) NOT BETWEEN 1 AND 500
                OR NOT EXISTS (
                    SELECT 1 FROM user
                    WHERE id = NEW.resolved_by AND role = 'admin'
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid report resolution');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS report_validate_cancellation
            BEFORE UPDATE OF cancelled_at ON report
            WHEN
                OLD.status != 'pending'
                OR OLD.cancelled_at IS NOT NULL
                OR typeof(NEW.cancelled_at) != 'integer'
            BEGIN
                SELECT RAISE(ABORT, 'invalid report cancellation');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS report_prevent_core_update
            BEFORE UPDATE OF id, reporter_id, target_type, target_id,
                             reason_code, reason, ip_key, created_at
            ON report
            BEGIN
                SELECT RAISE(ABORT, 'report content is immutable');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS report_prevent_delete
            BEFORE DELETE ON report
            BEGIN
                SELECT RAISE(ABORT, 'report history is immutable');
            END
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                actor_user_id TEXT,
                actor_username TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
                created_at INTEGER NOT NULL,
                request_id TEXT
            )
        """)
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS audit_log_created_idx '
            'ON audit_log(created_at DESC, id DESC)'
        )
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_log_prevent_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit logs are append-only');
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_log_prevent_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit logs are append-only');
            END
        """)

        configured_admin = os.environ.get('ADMIN_USERNAME', '').strip()
        if configured_admin:
            normalized_admin, admin_error = validate_username(configured_admin)
            if admin_error:
                raise RuntimeError('ADMIN_USERNAME must be a valid username.')
            admin_user = cursor.execute(
                'SELECT id, username, role FROM user '
                'WHERE username = ? COLLATE NOCASE',
                (normalized_admin,),
            ).fetchone()
            if admin_user is None:
                app.logger.error(
                    'security_event=admin_bootstrap_user_missing'
                )
                raise RuntimeError(
                    'ADMIN_USERNAME must identify an existing user.'
                )
            elif admin_user['role'] != 'admin':
                cursor.execute(
                    "UPDATE user SET role = 'admin', "
                    'session_version = session_version + 1 WHERE id = ?',
                    (admin_user['id'],),
                )
                cursor.execute(
                    'DELETE FROM user_session WHERE user_id = ?',
                    (admin_user['id'],),
                )
                write_audit_log(
                    db,
                    'user.role_promoted',
                    'user',
                    admin_user['id'],
                    {'username': admin_user['username'], 'new_role': 'admin'},
                )

        plaintext_users = cursor.execute('SELECT id, password FROM user').fetchall()
        for user in plaintext_users:
            if not is_password_hash(user['password']):
                cursor.execute(
                    'UPDATE user SET password = ? WHERE id = ?',
                    (hash_password(user['password']), user['id']),
                )
        now = int(time.time())
        cursor.execute(
            """
            INSERT OR IGNORE INTO virtual_account
                (id, user_id, kind, balance, version, created_at)
            VALUES (?, NULL, 'issuance', 0, 0, ?)
            """,
            (SYSTEM_ISSUANCE_ACCOUNT_ID, now),
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO virtual_account
                (id, user_id, kind, balance, version, created_at)
            VALUES (?, NULL, 'escrow', 0, 0, ?)
            """,
            (SYSTEM_ESCROW_ACCOUNT_ID, now),
        )
        existing_users = cursor.execute(
            "SELECT id FROM user WHERE role = 'user' ORDER BY id"
        ).fetchall()
        for existing_user in existing_users:
            ensure_user_wallet(db, existing_user['id'], now=now)
        foreign_key_error = cursor.execute('PRAGMA foreign_key_check').fetchone()
        if foreign_key_error is not None:
            db.rollback()
            raise RuntimeError('Database migration failed foreign-key validation.')
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


def get_active_sanction(db, user_id, now=None):
    current_time = int(time.time()) if now is None else now
    return db.execute(
        """
        SELECT id, reason, duration_code, created_at, ends_at
        FROM user_sanction
        WHERE user_id = ?
          AND revoked_at IS NULL
          AND (ends_at IS NULL OR ends_at > ?)
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (user_id, current_time),
    ).fetchone()


def get_authenticated_user():
    token = session.get('session_token')
    if not isinstance(token, str):
        return None

    token_hash = hash_session_token(token)
    db = get_db()
    user = db.execute(
        """
        SELECT u.id, u.username, u.role, u.session_version,
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
    if get_active_sanction(db, user['id'], now) is not None:
        db.execute('DELETE FROM user_session WHERE user_id = ?', (user['id'],))
        db.commit()
        return None
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


def get_private_conversation(
    db,
    first_user_id,
    second_user_id,
    context_type='direct',
    context_id='',
):
    participant_low_id, participant_high_id = canonical_chat_participants(
        first_user_id,
        second_user_id,
    )
    return db.execute(
        """
        SELECT id, participant_low_id, participant_high_id,
               context_type, context_id, product_id,
               created_at, last_message_at
        FROM private_conversation
        WHERE participant_low_id = ? AND participant_high_id = ?
          AND context_type = ? AND context_id = ?
        """,
        (participant_low_id, participant_high_id, context_type, context_id),
    ).fetchone()


def get_private_message_page(
    db,
    current_user_id,
    peer_user_id,
    before=None,
    context_type='direct',
    context_id='',
):
    conversation = get_private_conversation(
        db,
        current_user_id,
        peer_user_id,
        context_type,
        context_id,
    )
    if conversation is None:
        return [], None

    parameters = [
        current_user_id,
        peer_user_id,
        current_user_id,
        conversation['id'],
    ]
    before_clause = ''
    if before is not None:
        before_clause = (
            'AND (message.created_at < ? '
            'OR (message.created_at = ? AND message.id < ?))'
        )
        parameters.extend((before[0], before[0], before[1]))
    parameters.append(CHAT_HISTORY_PAGE_SIZE + 1)
    rows = db.execute(
        f"""
        SELECT message.id, message.conversation_id, message.sender_id,
               sender.username AS sender_username,
               CASE WHEN message.sender_id = ? THEN ? ELSE ? END AS recipient_id,
               message.client_message_id, message.body, message.created_at,
               ? AS context_type, ? AS context_id,
               recipient_read.last_read_created_at
                   AS recipient_last_read_created_at,
               recipient_read.last_read_message_id
                   AS recipient_last_read_message_id
        FROM private_message AS message
        JOIN user AS sender ON sender.id = message.sender_id
        LEFT JOIN private_conversation_read_state AS recipient_read
          ON recipient_read.conversation_id = message.conversation_id
         AND recipient_read.user_id != message.sender_id
        WHERE message.conversation_id = ?
          {before_clause}
        ORDER BY message.created_at DESC, message.id DESC
        LIMIT ?
        """,
        parameters[:3] + [context_type, context_id] + parameters[3:],
    ).fetchall()
    has_more = len(rows) > CHAT_HISTORY_PAGE_SIZE
    page_rows = rows[:CHAT_HISTORY_PAGE_SIZE]
    next_cursor = None
    if has_more and page_rows:
        oldest = page_rows[-1]
        next_cursor = encode_chat_cursor(oldest['created_at'], oldest['id'])
    return [serialize_private_message(row) for row in reversed(page_rows)], next_cursor


def get_chat_conversations(db, current_user_id, current_user_role):
    rows = db.execute(
        """
        SELECT conversation.id, conversation.last_message_at,
               conversation.context_type, conversation.context_id,
               peer.id AS peer_id, peer.username AS peer_username,
               last_message.body AS last_message_body,
               last_message.sender_id AS last_message_sender_id,
               product.title AS product_title,
               product.is_hidden AS product_is_hidden,
               product.seller_id AS product_seller_id,
               EXISTS (
                   SELECT 1
                   FROM private_message AS unread_message
                   LEFT JOIN private_conversation_read_state AS reader
                     ON reader.conversation_id = conversation.id
                    AND reader.user_id = ?
                   WHERE unread_message.conversation_id = conversation.id
                     AND unread_message.sender_id != ?
                     AND (
                         reader.user_id IS NULL
                         OR unread_message.created_at > reader.last_read_created_at
                         OR (
                             unread_message.created_at = reader.last_read_created_at
                             AND unread_message.id > reader.last_read_message_id
                         )
                     )
               ) AS has_unread
        FROM private_conversation AS conversation
        JOIN user AS peer ON peer.id = CASE
            WHEN conversation.participant_low_id = ?
            THEN conversation.participant_high_id
            ELSE conversation.participant_low_id
        END
        JOIN private_message AS last_message ON last_message.id = (
            SELECT candidate.id
            FROM private_message AS candidate
            WHERE candidate.conversation_id = conversation.id
            ORDER BY candidate.created_at DESC, candidate.id DESC
            LIMIT 1
        )
        LEFT JOIN product ON product.id = conversation.product_id
        WHERE conversation.participant_low_id = ?
           OR conversation.participant_high_id = ?
        ORDER BY conversation.last_message_at DESC, conversation.id DESC
        LIMIT ?
        """,
        (
            current_user_id,
            current_user_id,
            current_user_id,
            current_user_id,
            current_user_id,
            CHAT_CONVERSATION_LIST_LIMIT,
        ),
    ).fetchall()
    conversations = []
    for row in rows:
        conversation = dict(row)
        if conversation['context_type'] == 'product':
            can_show_product = (
                conversation['product_title'] is not None
                and (
                    not conversation['product_is_hidden']
                    or conversation['product_seller_id'] == current_user_id
                    or current_user_role == 'admin'
                )
            )
            conversation['context_label'] = (
                conversation['product_title']
                if can_show_product
                else '숨김/삭제된 상품 문의'
            )
        else:
            conversation['context_label'] = None
        conversations.append(conversation)
    return conversations


def user_has_unread_messages(db, user_id):
    return db.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM private_conversation AS conversation
            JOIN private_message AS unread_message
              ON unread_message.conversation_id = conversation.id
            LEFT JOIN private_conversation_read_state AS reader
              ON reader.conversation_id = conversation.id
             AND reader.user_id = ?
            WHERE (
                    conversation.participant_low_id = ?
                 OR conversation.participant_high_id = ?
            )
              AND unread_message.sender_id != ?
              AND (
                  reader.user_id IS NULL
                  OR unread_message.created_at > reader.last_read_created_at
                  OR (
                      unread_message.created_at = reader.last_read_created_at
                      AND unread_message.id > reader.last_read_message_id
                  )
              )
        )
        """,
        (user_id, user_id, user_id, user_id),
    ).fetchone()[0] == 1


def serialize_chat_conversation_state(conversation):
    if conversation['context_type'] == 'product':
        conversation_url = url_for(
            'product_chat',
            product_id=conversation['context_id'],
            peer_id=conversation['peer_id'],
        )
        product_id = conversation['context_id']
    else:
        conversation_url = url_for(
            'chats',
            user_id=conversation['peer_id'],
        )
        product_id = None
    return {
        'conversation_id': conversation['id'],
        'peer_id': conversation['peer_id'],
        'peer_username': conversation['peer_username'],
        'context_type': conversation['context_type'],
        'product_id': product_id,
        'context_label': conversation['context_label'],
        'last_message_preview': conversation['last_message_body'],
        'has_unread': bool(conversation['has_unread']),
        'url': conversation_url,
    }


def can_view_product(product, user):
    return bool(
        product is not None
        and (
            not product['is_hidden']
            or (
                user is not None
                and (
                    user['id'] == product['seller_id']
                    or user['role'] == 'admin'
                )
            )
        )
    )


def get_chat_search_results(db, current_user_id, query):
    if not query:
        return []
    now = int(time.time())
    search_pattern = f'%{escape_like(query)}%'
    return db.execute(
        """
        SELECT candidate.id, candidate.username, candidate.role
        FROM user AS candidate
        WHERE candidate.id != ?
          AND candidate.username LIKE ? ESCAPE '\\' COLLATE NOCASE
          AND NOT EXISTS (
              SELECT 1
              FROM user_sanction AS sanction
              WHERE sanction.user_id = candidate.id
                AND sanction.revoked_at IS NULL
                AND (sanction.ends_at IS NULL OR sanction.ends_at > ?)
        )
        ORDER BY candidate.username COLLATE NOCASE, candidate.id
        LIMIT ?
        """,
        (current_user_id, search_pattern, now, CHAT_USER_SEARCH_LIMIT),
    ).fetchall()


def get_chat_peer(db, current_user_id, peer_user_id):
    normalized_peer_id = validate_uuid_string(peer_user_id)
    if normalized_peer_id is None or normalized_peer_id == current_user_id:
        return None
    return db.execute(
        'SELECT id, username, role FROM user WHERE id = ?',
        (normalized_peer_id,),
    ).fetchone()


def resolve_product_chat(db, current_user, product_id, peer_user_id=None):
    normalized_product_id = validate_uuid_string(product_id)
    if normalized_product_id is None:
        return None
    normalized_peer_id = None
    if peer_user_id is not None:
        normalized_peer_id = validate_uuid_string(peer_user_id)
        if normalized_peer_id is None or normalized_peer_id == current_user['id']:
            return None

    product = db.execute(
        'SELECT id, title, seller_id, is_hidden FROM product WHERE id = ?',
        (normalized_product_id,),
    ).fetchone()
    if product is not None:
        if current_user['id'] == product['seller_id']:
            if normalized_peer_id is None:
                return None
            resolved_peer_id = normalized_peer_id
        else:
            resolved_peer_id = product['seller_id']
            if normalized_peer_id is not None and normalized_peer_id != resolved_peer_id:
                return None
    else:
        if normalized_peer_id is None:
            return None
        resolved_peer_id = normalized_peer_id

    peer = get_chat_peer(db, current_user['id'], resolved_peer_id)
    if peer is None:
        return None
    conversation = get_private_conversation(
        db,
        current_user['id'],
        peer['id'],
        'product',
        normalized_product_id,
    )
    if conversation is None:
        if (
            product is None
            or current_user['id'] == product['seller_id']
            or not can_view_product(product, current_user)
            or get_active_sanction(db, product['seller_id']) is not None
        ):
            return None

    show_product = product is not None and can_view_product(product, current_user)
    return {
        'product_id': normalized_product_id,
        'product': product,
        'product_label': (
            product['title'] if show_product else '숨김/삭제된 상품 문의'
        ),
        'show_product_link': bool(show_product),
        'peer': peer,
        'conversation': conversation,
    }


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


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.current_user is None:
            app.logger.warning(
                'security_event=admin_authentication_required request_id=%s '
                'endpoint=%s',
                getattr(g, 'request_id', 'unavailable'),
                request.endpoint,
            )
            return redirect(url_for('login'))
        if g.current_user['role'] != 'admin':
            app.logger.warning(
                'security_event=admin_authorization_denied request_id=%s '
                'user_id=%s endpoint=%s',
                getattr(g, 'request_id', 'unavailable'),
                g.current_user['id'],
                request.endpoint,
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def record_admin_read(action, target_type, target_id, details=None):
    db = get_db()
    try:
        write_audit_log(
            db,
            action,
            target_type,
            target_id,
            details,
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=admin_read_audit_failed request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        abort(503)


def abort_admin_action(
    status_code,
    action,
    target_type,
    target_id,
    failure_reason,
):
    db = get_db()
    db.rollback()
    try:
        write_audit_log(
            db,
            action,
            target_type,
            target_id,
            {'failure_reason': failure_reason, 'status_code': status_code},
            actor=g.current_user,
            outcome='failure',
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=admin_failure_audit_failed request_id=%s',
            getattr(g, 'request_id', 'unavailable'),
        )
        abort(503)
    abort(status_code)


def security_key(namespace, value):
    message = f'{namespace}:{value}'.encode('utf-8')
    secret = app.config['SECRET_KEY'].encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def get_trusted_socket_forwarded_value(header_name):
    proxy_count = app.config['TRUSTED_PROXY_COUNT']
    if proxy_count <= 0:
        return None
    raw_value = request.headers.get(header_name)
    if not raw_value:
        return None
    values = [value.strip() for value in raw_value.split(',') if value.strip()]
    if len(values) < proxy_count:
        return None
    return values[-proxy_count]


def is_secure_chat_transport():
    if request.is_secure:
        return True
    forwarded_protocol = get_trusted_socket_forwarded_value('X-Forwarded-Proto')
    return (
        isinstance(forwarded_protocol, str)
        and forwarded_protocol.lower() == 'https'
    )


def chat_ip_key():
    client_ip = get_trusted_socket_forwarded_value('X-Forwarded-For')
    if client_ip is None:
        client_ip = request.remote_addr or 'unknown'
    return security_key('chat-ip', client_ip)


def chat_sid_key():
    sid = getattr(request, 'sid', None)
    if not isinstance(sid, str) or not sid:
        return None
    return security_key('chat-sid', sid)


def estimate_chat_payload_bytes(data):
    try:
        encoded = json.dumps(
            data,
            ensure_ascii=False,
            separators=(',', ':'),
        ).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return 16 * 1024 + 1
    return len(encoded)


def chat_conversation_rate_key(user_id, data):
    recipient_id = None
    context_type = 'direct'
    context_id = ''
    if isinstance(data, dict):
        recipient_id = validate_uuid_string(data.get('recipient_id'))
        if 'product_id' in data:
            product_id = validate_uuid_string(data.get('product_id'))
            if product_id is None:
                context_type = 'invalid'
                context_id = 'invalid'
            else:
                context_type = 'product'
                context_id = product_id
    if recipient_id is None or recipient_id == user_id:
        return security_key('chat-conversation', f'{user_id}:invalid')
    participant_low_id, participant_high_id = canonical_chat_participants(
        user_id,
        recipient_id,
    )
    return security_key(
        'chat-conversation',
        f'{participant_low_id}:{participant_high_id}:{context_type}:{context_id}',
    )


def register_chat_connection(user):
    now_ms = time.time_ns() // 1_000_000
    attempt_cutoff = now_ms - CHAT_CONNECTION_ATTEMPT_WINDOW_MS
    stale_cutoff = now_ms - CHAT_CONNECTION_STALE_MS
    ip_key = chat_ip_key()
    user_id = user['id'] if user is not None else None
    sid_key = chat_sid_key()
    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute(
            'DELETE FROM chat_connection_attempt WHERE attempted_at <= ?',
            (attempt_cutoff,),
        )
        db.execute(
            'DELETE FROM chat_connection WHERE last_activity_at <= ?',
            (stale_cutoff,),
        )
        db.execute(
            """
            INSERT INTO chat_connection_attempt (user_id, ip_key, attempted_at)
            VALUES (?, ?, ?)
            """,
            (user_id, ip_key, now_ms),
        )
        ip_attempt_count = db.execute(
            """
            SELECT COUNT(*)
            FROM chat_connection_attempt
            WHERE ip_key = ? AND attempted_at > ?
            """,
            (ip_key, attempt_cutoff),
        ).fetchone()[0]
        user_attempt_count = 0
        if user_id is not None:
            user_attempt_count = db.execute(
                """
                SELECT COUNT(*)
                FROM chat_connection_attempt
                WHERE user_id = ? AND attempted_at > ?
                """,
                (user_id, attempt_cutoff),
            ).fetchone()[0]
        if (
            ip_attempt_count > CHAT_IP_CONNECTION_ATTEMPT_LIMIT
            or user_attempt_count > CHAT_USER_CONNECTION_ATTEMPT_LIMIT
        ):
            db.commit()
            return False, 'attempt_rate_limited'
        if user_id is None or sid_key is None:
            db.commit()
            return False, 'authentication_required'

        user_connection_count = db.execute(
            'SELECT COUNT(*) FROM chat_connection WHERE user_id = ?',
            (user_id,),
        ).fetchone()[0]
        ip_connection_count = db.execute(
            'SELECT COUNT(*) FROM chat_connection WHERE ip_key = ?',
            (ip_key,),
        ).fetchone()[0]
        if (
            user_connection_count >= CHAT_MAX_CONNECTIONS_PER_USER
            or ip_connection_count >= CHAT_MAX_CONNECTIONS_PER_IP
        ):
            db.commit()
            return False, 'connection_limit_reached'
        db.execute(
            """
            INSERT INTO chat_connection
                (sid_key, user_id, ip_key, connected_at, last_activity_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (sid_key, user_id, ip_key, now_ms, now_ms),
        )
        db.commit()
        return True, None
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=chat_connection_store_failed user_id=%s',
            user_id or '-',
        )
        return False, 'server_error'


def unregister_chat_connection():
    sid_key = chat_sid_key()
    if sid_key is None:
        return
    db = get_db()
    try:
        db.execute('DELETE FROM chat_connection WHERE sid_key = ?', (sid_key,))
        db.commit()
    except sqlite3.Error:
        db.rollback()
        app.logger.error('security_event=chat_disconnect_cleanup_failed')


def get_chat_message_attempt_stats(db, key_column, key, now_ms):
    if key_column not in {'user_id', 'ip_key', 'conversation_key'}:
        raise ValueError('Unsupported chat rate-limit key.')
    return db.execute(
        f"""
        SELECT
            SUM(CASE WHEN attempted_at > ? THEN 1 ELSE 0 END) AS short_count,
            SUM(CASE WHEN attempted_at > ? THEN payload_bytes ELSE 0 END)
                AS short_bytes,
            COUNT(*) AS long_count,
            COALESCE(SUM(payload_bytes), 0) AS long_bytes
        FROM chat_message_attempt
        WHERE {key_column} = ? AND attempted_at > ?
        """,
        (
            now_ms - CHAT_SHORT_RATE_WINDOW_MS,
            now_ms - CHAT_SHORT_RATE_WINDOW_MS,
            key,
            now_ms - CHAT_LONG_RATE_WINDOW_MS,
        ),
    ).fetchone()


def record_chat_message_attempt(user, data):
    now_ms = time.time_ns() // 1_000_000
    long_cutoff = now_ms - CHAT_LONG_RATE_WINDOW_MS
    ip_key = chat_ip_key()
    conversation_key = chat_conversation_rate_key(user['id'], data)
    payload_bytes = estimate_chat_payload_bytes(data)
    sid_key = chat_sid_key()
    if sid_key is None:
        return 'connection_invalid'

    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute(
            'DELETE FROM chat_message_attempt WHERE attempted_at <= ?',
            (long_cutoff,),
        )
        connection_update = db.execute(
            """
            UPDATE chat_connection
            SET last_activity_at = ?
            WHERE sid_key = ? AND user_id = ?
            """,
            (now_ms, sid_key, user['id']),
        )
        if connection_update.rowcount != 1:
            db.rollback()
            return 'connection_invalid'
        db.execute(
            """
            INSERT INTO chat_message_attempt
                (user_id, ip_key, conversation_key, attempted_at, payload_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user['id'],
                ip_key,
                conversation_key,
                now_ms,
                payload_bytes,
            ),
        )
        user_stats = get_chat_message_attempt_stats(
            db,
            'user_id',
            user['id'],
            now_ms,
        )
        ip_stats = get_chat_message_attempt_stats(
            db,
            'ip_key',
            ip_key,
            now_ms,
        )
        conversation_stats = get_chat_message_attempt_stats(
            db,
            'conversation_key',
            conversation_key,
            now_ms,
        )
        is_limited = (
            user_stats['short_count'] > CHAT_SHORT_RATE_LIMIT
            or user_stats['long_count'] > CHAT_LONG_RATE_LIMIT
            or user_stats['short_bytes'] > CHAT_SHORT_BYTE_LIMIT
            or user_stats['long_bytes'] > CHAT_LONG_BYTE_LIMIT
            or conversation_stats['short_count'] > CHAT_SHORT_RATE_LIMIT
            or conversation_stats['long_count'] > CHAT_LONG_RATE_LIMIT
            or conversation_stats['short_bytes'] > CHAT_SHORT_BYTE_LIMIT
            or conversation_stats['long_bytes'] > CHAT_LONG_BYTE_LIMIT
            or ip_stats['short_count'] > CHAT_IP_SHORT_RATE_LIMIT
            or ip_stats['long_count'] > CHAT_IP_LONG_RATE_LIMIT
            or ip_stats['short_bytes'] > CHAT_IP_SHORT_BYTE_LIMIT
            or ip_stats['long_bytes'] > CHAT_IP_LONG_BYTE_LIMIT
        )
        db.commit()
        return 'rate_limited' if is_limited else 'allowed'
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=chat_rate_store_failed user_id=%s',
            user['id'],
        )
        return 'server_error'


def record_chat_read_attempt(user):
    now_ms = time.time_ns() // 1_000_000
    long_cutoff = now_ms - CHAT_LONG_RATE_WINDOW_MS
    ip_key = chat_ip_key()
    sid_key = chat_sid_key()
    if sid_key is None:
        return 'connection_invalid'

    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute(
            'DELETE FROM chat_read_attempt WHERE attempted_at <= ?',
            (long_cutoff,),
        )
        connection_update = db.execute(
            """
            UPDATE chat_connection
            SET last_activity_at = ?
            WHERE sid_key = ? AND user_id = ?
            """,
            (now_ms, sid_key, user['id']),
        )
        if connection_update.rowcount != 1:
            db.rollback()
            return 'connection_invalid'
        db.execute(
            """
            INSERT INTO chat_read_attempt (user_id, ip_key, attempted_at)
            VALUES (?, ?, ?)
            """,
            (user['id'], ip_key, now_ms),
        )
        user_stats = db.execute(
            """
            SELECT
                SUM(CASE WHEN attempted_at > ? THEN 1 ELSE 0 END)
                    AS short_count,
                COUNT(*) AS long_count
            FROM chat_read_attempt
            WHERE user_id = ? AND attempted_at > ?
            """,
            (
                now_ms - CHAT_SHORT_RATE_WINDOW_MS,
                user['id'],
                long_cutoff,
            ),
        ).fetchone()
        ip_stats = db.execute(
            """
            SELECT
                SUM(CASE WHEN attempted_at > ? THEN 1 ELSE 0 END)
                    AS short_count,
                COUNT(*) AS long_count
            FROM chat_read_attempt
            WHERE ip_key = ? AND attempted_at > ?
            """,
            (
                now_ms - CHAT_SHORT_RATE_WINDOW_MS,
                ip_key,
                long_cutoff,
            ),
        ).fetchone()
        is_limited = (
            user_stats['short_count'] > CHAT_READ_SHORT_RATE_LIMIT
            or user_stats['long_count'] > CHAT_READ_LONG_RATE_LIMIT
            or ip_stats['short_count'] > CHAT_READ_IP_SHORT_RATE_LIMIT
            or ip_stats['long_count'] > CHAT_READ_IP_LONG_RATE_LIMIT
        )
        db.commit()
        return 'rate_limited' if is_limited else 'allowed'
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=chat_read_rate_store_failed user_id=%s',
            user['id'],
        )
        return 'server_error'


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


def render_login_error(status_code, retry_after=None, next_url=None):
    flash('아이디 또는 비밀번호를 확인하거나 잠시 후 다시 시도해 주세요.')
    response = app.make_response((
        render_template('login.html', next_url=next_url),
        status_code,
    ))
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
        user_id = str(uuid.uuid4())
        try:
            db.execute(
                "INSERT INTO user (id, username, password, role) "
                "VALUES (?, ?, ?, 'user')",
                (user_id, username, hash_password(password)),
            )
            ensure_user_wallet(db, user_id)
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return render_register_error('가입 요청을 처리할 수 없습니다.', 409)
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_values = (
        request.form.getlist('next')
        if request.method == 'POST'
        else request.args.getlist('next')
    )
    next_url = validate_safe_next_url(next_values) if next_values else None
    if request.method == 'POST':
        raw_username = get_single_form_value('username')
        password = get_single_form_value('password')
        username, username_error = validate_username(raw_username)
        if username_error or not isinstance(password, str) or not password or len(password) > LOGIN_PASSWORD_MAX_LENGTH:
            return render_login_error(400, next_url=next_url)

        username_key, ip_key = login_rate_keys(username)
        blocked, retry_after = get_login_rate_state(username_key, ip_key)
        if blocked:
            log_login_event('blocked', username_key, ip_key)
            return render_login_error(429, retry_after, next_url)

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
            return render_login_error(
                429 if blocked else 401,
                retry_after if blocked else None,
                next_url,
            )

        if get_active_sanction(db, user['id']) is not None:
            clear_login_failures(username_key)
            log_login_event('sanctioned', username_key, ip_key, user['id'])
            return render_login_error(403, next_url=next_url)

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
        return redirect(next_url or url_for('dashboard'))
    return render_template('login.html', next_url=next_url)


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
    query_values = request.args.getlist('q')
    if not query_values:
        raw_query = ''
    elif len(query_values) == 1:
        raw_query = query_values[0]
    else:
        raw_query = None
    query, query_error = validate_product_search_query(raw_query)
    if query_error:
        abort(400)
    db = get_db()
    current_user = db.execute(
        'SELECT id, username, bio FROM user WHERE id = ?',
        (g.current_user['id'],),
    ).fetchone()
    if query:
        search_pattern = f'%{escape_like(query)}%'
        products = db.execute(
            """
            SELECT *
            FROM product
            WHERE is_hidden = 0
              AND (
                  title LIKE ? ESCAPE '\\' COLLATE NOCASE
                  OR description LIKE ? ESCAPE '\\' COLLATE NOCASE
              )
            ORDER BY title COLLATE NOCASE, id
            """,
            (search_pattern, search_pattern),
        ).fetchall()
    else:
        products = db.execute(
            'SELECT * FROM product WHERE is_hidden = 0 '
            'ORDER BY title COLLATE NOCASE, id'
        ).fetchall()
    g.private_no_store = True
    return render_template(
        'dashboard.html',
        products=products,
        user=current_user,
        query=query,
    )


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
            SELECT id, username, bio
            FROM user
            WHERE username LIKE ? ESCAPE '\\' COLLATE NOCASE
            ORDER BY username COLLATE NOCASE
            """,
            (search_pattern,),
        ).fetchall()
    else:
        found_users = db.execute(
            'SELECT id, username, bio FROM user ORDER BY username COLLATE NOCASE'
        ).fetchall()
    return render_template('users.html', users=found_users, query=query)


@app.route('/chats')
@app.route('/chats/<user_id>')
def chats(user_id=None):
    g.private_no_store = True
    if g.current_user is None:
        return redirect(url_for('login'))

    query_values = request.args.getlist('q')
    if not query_values:
        raw_query = ''
    elif len(query_values) == 1:
        raw_query = query_values[0]
    else:
        raw_query = None
    query, query_error = validate_search_query(raw_query)
    if query_error:
        abort(400)

    db = get_db()
    selected_peer = None
    selected_peer_is_sanctioned = False
    messages = []
    next_cursor = None
    if user_id is not None:
        selected_peer = get_chat_peer(db, g.current_user['id'], user_id)
        if selected_peer is None:
            abort(404)
        selected_peer_is_sanctioned = (
            get_active_sanction(db, selected_peer['id']) is not None
        )
        messages, next_cursor = get_private_message_page(
            db,
            g.current_user['id'],
            selected_peer['id'],
        )

    return render_template(
        'chats.html',
        conversations=get_chat_conversations(
            db,
            g.current_user['id'],
            g.current_user['role'],
        ),
        search_results=get_chat_search_results(db, g.current_user['id'], query),
        selected_peer=selected_peer,
        selected_peer_is_sanctioned=selected_peer_is_sanctioned,
        selected_context_type='direct',
        selected_product_id=None,
        selected_product_label=None,
        selected_product_link=None,
        selected_conversation_id=(
            messages[0]['conversation_id'] if messages else None
        ),
        history_url=(
            url_for('chat_messages', user_id=selected_peer['id'])
            if selected_peer else None
        ),
        messages=messages,
        next_cursor=next_cursor,
        query=query,
    )


@app.route('/chats/<user_id>/messages')
def chat_messages(user_id):
    g.private_no_store = True
    if g.current_user is None:
        return {'error': {'code': 'authentication_required'}}, 401

    db = get_db()
    peer = get_chat_peer(db, g.current_user['id'], user_id)
    if peer is None:
        abort(404)
    before_values = request.args.getlist('before')
    if len(before_values) != 1:
        abort(400)
    before = decode_chat_cursor(before_values[0])
    if before is None:
        abort(400)

    messages, next_cursor = get_private_message_page(
        db,
        g.current_user['id'],
        peer['id'],
        before,
    )
    return {'messages': messages, 'next_cursor': next_cursor}


@app.route('/chats/unread-state')
def chat_unread_state():
    g.private_no_store = True
    if g.current_user is None:
        return {'error': {'code': 'authentication_required'}}, 401
    return {
        'has_unread_messages': user_has_unread_messages(
            get_db(),
            g.current_user['id'],
        ),
    }


@app.route('/chats/state')
def chat_state():
    g.private_no_store = True
    if g.current_user is None:
        return {'error': {'code': 'authentication_required'}}, 401
    db = get_db()
    conversations = get_chat_conversations(
        db,
        g.current_user['id'],
        g.current_user['role'],
    )
    return {
        'has_unread_messages': user_has_unread_messages(
            db,
            g.current_user['id'],
        ),
        'conversations': [
            serialize_chat_conversation_state(conversation)
            for conversation in conversations
        ],
    }


@app.route('/chats/products/<product_id>')
def product_chat(product_id):
    g.private_no_store = True
    if g.current_user is None:
        return redirect(url_for('login'))
    if set(request.args) - {'peer_id'} or len(request.args.getlist('peer_id')) > 1:
        abort(400)
    peer_id = request.args.get('peer_id')
    db = get_db()
    context = resolve_product_chat(db, g.current_user, product_id, peer_id)
    if context is None:
        abort(404)
    if peer_id is None:
        return redirect(url_for(
            'product_chat',
            product_id=context['product_id'],
            peer_id=context['peer']['id'],
        ))

    messages, next_cursor = get_private_message_page(
        db,
        g.current_user['id'],
        context['peer']['id'],
        context_type='product',
        context_id=context['product_id'],
    )
    return render_template(
        'chats.html',
        conversations=get_chat_conversations(
            db,
            g.current_user['id'],
            g.current_user['role'],
        ),
        search_results=[],
        selected_peer=context['peer'],
        selected_peer_is_sanctioned=(
            get_active_sanction(db, context['peer']['id']) is not None
        ),
        selected_context_type='product',
        selected_product_id=context['product_id'],
        selected_product_label=context['product_label'],
        selected_product_link=(
            url_for('view_product', product_id=context['product_id'])
            if context['show_product_link'] else None
        ),
        selected_conversation_id=(
            context['conversation']['id'] if context['conversation'] else None
        ),
        history_url=url_for(
            'product_chat_messages',
            product_id=context['product_id'],
            peer_id=context['peer']['id'],
        ),
        messages=messages,
        next_cursor=next_cursor,
        query='',
    )


@app.route('/chats/products/<product_id>/messages')
def product_chat_messages(product_id):
    g.private_no_store = True
    if g.current_user is None:
        return {'error': {'code': 'authentication_required'}}, 401
    if set(request.args) != {'peer_id', 'before'}:
        abort(400)
    peer_values = request.args.getlist('peer_id')
    before_values = request.args.getlist('before')
    if len(peer_values) != 1 or len(before_values) != 1:
        abort(400)
    before = decode_chat_cursor(before_values[0])
    if before is None:
        abort(400)
    db = get_db()
    context = resolve_product_chat(
        db,
        g.current_user,
        product_id,
        peer_values[0],
    )
    if context is None:
        abort(404)
    messages, next_cursor = get_private_message_page(
        db,
        g.current_user['id'],
        context['peer']['id'],
        before,
        'product',
        context['product_id'],
    )
    return {'messages': messages, 'next_cursor': next_cursor}


def product_has_active_order(db, product_id):
    return db.execute(
        """
        SELECT 1
        FROM market_order
        WHERE product_id = ? AND status IN ('paid', 'settled')
        LIMIT 1
        """,
        (product_id,),
    ).fetchone() is not None


def get_order_for_current_user(order_id):
    if g.current_user is None:
        return None
    return get_db().execute(
        """
        SELECT market_order.*, payment.id AS payment_id,
               payment.status AS payment_status,
               payment.version AS payment_version,
               payment.created_at AS payment_created_at,
               payment.settled_at, payment.refunded_at,
               buyer.username AS buyer_username,
               seller.username AS seller_username
        FROM market_order
        JOIN payment ON payment.order_id = market_order.id
        JOIN user AS buyer ON buyer.id = market_order.buyer_id
        JOIN user AS seller ON seller.id = market_order.seller_id
        WHERE market_order.id = ?
          AND (market_order.buyer_id = ? OR market_order.seller_id = ?)
        """,
        (order_id, g.current_user['id'], g.current_user['id']),
    ).fetchone()


def audit_payment_failure(db, action, target_id, reason):
    write_audit_log(
        db,
        action,
        'payment',
        target_id,
        {'reason': reason},
        actor=g.current_user,
        outcome='failure',
    )
    db.commit()


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
        except sqlite3.Error:
            db.rollback()
            remove_product_image(image_filename)
            raise
        flash('상품이 등록되었습니다.')
        return redirect(url_for('manage_products'))
    return render_template('new_product.html')


def get_owned_product(product_id):
    product = get_db().execute(
        'SELECT id, title, description, price, seller_id, image_filename, status, '
        'version, is_hidden, hidden_at, hidden_by, hidden_reason '
        'FROM product WHERE id = ? AND seller_id = ?',
        (product_id, g.current_user['id']),
    ).fetchone()
    if product is None:
        abort(404)
    return product


@app.route('/product/manage')
def manage_products():
    if g.current_user is None:
        return redirect(url_for('login'))
    products = get_db().execute(
        """
        SELECT product.id, product.title, product.description, product.price,
               product.image_filename, product.status, product.version,
               product.is_hidden, product.hidden_at, product.hidden_by,
               product.hidden_reason,
               EXISTS (
                   SELECT 1 FROM market_order
                   WHERE market_order.product_id = product.id
                     AND market_order.status IN ('paid', 'settled')
               ) AS has_active_order
        FROM product
        WHERE product.seller_id = ?
        ORDER BY title COLLATE NOCASE, id
        """,
        (g.current_user['id'],),
    ).fetchall()
    g.private_no_store = True
    return render_template('manage_products.html', products=products)


@app.route('/product/<product_id>/status', methods=['POST'])
def update_product_status(product_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    get_owned_product(product_id)
    db = get_db()
    if product_has_active_order(db, product_id):
        abort(409)
    status, status_error = validate_product_status()
    if status_error:
        abort(400)
    expected_version, version_error = validate_product_version()
    if version_error:
        abort(400)

    cursor = db.execute(
        """
        UPDATE product
        SET status = ?, version = version + 1
        WHERE id = ? AND seller_id = ? AND version = ?
        """,
        (status, product_id, g.current_user['id'], expected_version),
    )
    if cursor.rowcount != 1:
        db.rollback()
        abort(409)
    db.commit()
    flash('상품 상태가 변경되었습니다.')
    return redirect(url_for('manage_products'))


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    product = get_owned_product(product_id)
    if request.method == 'POST':
        if product_has_active_order(get_db(), product_id):
            abort(409)
        product_data, product_error = validate_product_form()
        if product_error:
            flash(product_error)
            return render_template('edit_product.html', product=product), 400
        expected_version, version_error = validate_product_version()
        if version_error:
            flash(version_error)
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
                SET title = ?, description = ?, price = ?, image_filename = ?,
                    version = version + 1
                WHERE id = ? AND seller_id = ? AND version = ?
                """,
                (
                    product_data['title'],
                    product_data['description'],
                    product_data['price'],
                    resulting_image_filename,
                    product_id,
                    g.current_user['id'],
                    expected_version,
                ),
            )
            if cursor.rowcount == 1:
                db.commit()
            else:
                db.rollback()
        except sqlite3.Error:
            db.rollback()
            remove_product_image(new_image_filename)
            raise
        if cursor.rowcount != 1:
            remove_product_image(new_image_filename)
            abort(409)

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
    if product_has_active_order(get_db(), product_id):
        abort(409)
    expected_version, version_error = validate_product_version()
    if version_error:
        abort(400)
    db = get_db()
    cursor = db.execute(
        'DELETE FROM product WHERE id = ? AND seller_id = ? AND version = ?',
        (product_id, g.current_user['id'], expected_version),
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
        'SELECT image_filename, seller_id, is_hidden FROM product WHERE id = ?',
        (product_id,),
    ).fetchone()
    if (
        product is None
        or (
            product['is_hidden']
            and (
                g.current_user is None
                or (
                    g.current_user['id'] != product['seller_id']
                    and g.current_user['role'] != 'admin'
                )
            )
        )
        or not product['image_filename']
        or not PRODUCT_IMAGE_FILENAME_PATTERN.fullmatch(product['image_filename'])
    ):
        abort(404)

    if product['is_hidden']:
        g.private_no_store = True

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
    if product['is_hidden'] and (
        g.current_user is None
        or (
            g.current_user['id'] != product['seller_id']
            and g.current_user['role'] != 'admin'
        )
    ):
        abort(404)
    if product['is_hidden']:
        g.private_no_store = True
    seller = db.execute(
        'SELECT id, username, bio FROM user WHERE id = ?',
        (product['seller_id'],),
    ).fetchone()
    seller_chat_available = bool(
        seller is not None and get_active_sanction(db, seller['id']) is None
    )
    purchase_idempotency_key = None
    if (
        g.current_user is not None
        and g.current_user['role'] == 'user'
        and g.current_user['id'] != product['seller_id']
        and not product['is_hidden']
        and product['status'] == 'selling'
    ):
        purchase_idempotency_key = str(uuid.uuid4())
    return render_template(
        'view_product.html',
        product=product,
        seller=seller,
        seller_chat_available=seller_chat_available,
        purchase_idempotency_key=purchase_idempotency_key,
    )


@app.route('/product/<product_id>/purchase', methods=['POST'])
def purchase_product(product_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    if g.current_user['role'] != 'user':
        abort(403)
    idempotency_key = validate_idempotency_key(
        get_single_form_value('idempotency_key')
    )
    if idempotency_key is None:
        abort(400)

    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        replay = db.execute(
            """
            SELECT id, product_id, buyer_id
            FROM market_order
            WHERE idempotency_key = ?
            """,
            (idempotency_key,),
        ).fetchone()
        if replay is not None:
            if (
                replay['buyer_id'] == g.current_user['id']
                and replay['product_id'] == product_id
            ):
                db.commit()
                return redirect(url_for('view_order', order_id=replay['id']))
            db.rollback()
            audit_payment_failure(db, 'payment.created', product_id, 'idempotency_conflict')
            abort(409)

        product = db.execute(
            """
            SELECT product.id, product.title, product.price, product.seller_id,
                   product.status, product.version, product.is_hidden,
                   seller.role AS seller_role
            FROM product
            JOIN user AS seller ON seller.id = product.seller_id
            WHERE product.id = ?
            """,
            (product_id,),
        ).fetchone()
        if product is None or product['is_hidden']:
            db.rollback()
            abort(404)
        if (
            product['seller_id'] == g.current_user['id']
            or product['seller_role'] != 'user'
            or product['status'] != 'selling'
            or product_has_active_order(db, product_id)
        ):
            db.rollback()
            audit_payment_failure(db, 'payment.created', product_id, 'purchase_not_allowed')
            abort(409)

        buyer_account = ensure_user_wallet(db, g.current_user['id'])
        seller_account = ensure_user_wallet(db, product['seller_id'])
        if buyer_account is None or seller_account is None:
            db.rollback()
            audit_payment_failure(db, 'payment.created', product_id, 'wallet_unavailable')
            abort(409)

        order_id = str(uuid.uuid4())
        payment_id = str(uuid.uuid4())
        amount = int(product['price'])
        now = int(time.time())
        db.execute(
            """
            INSERT INTO market_order
                (id, product_id, buyer_id, seller_id, product_title, price,
                 status, version, idempotency_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'paid', 0, ?, ?, ?)
            """,
            (
                order_id,
                product['id'],
                g.current_user['id'],
                product['seller_id'],
                product['title'],
                amount,
                idempotency_key,
                now,
                now,
            ),
        )
        reserved = db.execute(
            """
            UPDATE product
            SET status = 'reserved', version = version + 1
            WHERE id = ? AND status = 'selling' AND version = ?
            """,
            (product['id'], product['version']),
        )
        if reserved.rowcount != 1:
            raise WalletConflictError()
        apply_wallet_transaction(
            db,
            'purchase',
            f'purchase:{order_id}',
            [
                (buyer_account['id'], -amount),
                (SYSTEM_ESCROW_ACCOUNT_ID, amount),
            ],
            order_id=order_id,
            created_by=g.current_user['id'],
            now=now,
        )
        db.execute(
            """
            INSERT INTO payment
                (id, order_id, amount, status, version, created_at,
                 settled_at, refunded_at)
            VALUES (?, ?, ?, 'held', 0, ?, NULL, NULL)
            """,
            (payment_id, order_id, amount, now),
        )
        write_audit_log(
            db,
            'payment.created',
            'payment',
            payment_id,
            {'order_id': order_id},
            actor=g.current_user,
        )
        db.commit()
    except InsufficientPointsError:
        db.rollback()
        audit_payment_failure(db, 'payment.created', product_id, 'insufficient_points')
        flash('포인트가 부족합니다.')
        abort(409)
    except (WalletConflictError, sqlite3.IntegrityError):
        db.rollback()
        audit_payment_failure(db, 'payment.created', product_id, 'concurrent_conflict')
        abort(409)
    flash('결제가 완료되어 포인트가 예치되었습니다.')
    return redirect(url_for('view_order', order_id=order_id))


@app.route('/orders')
def orders():
    if g.current_user is None:
        return redirect(url_for('login'))
    rows = get_db().execute(
        """
        SELECT market_order.*, payment.status AS payment_status,
               buyer.username AS buyer_username,
               seller.username AS seller_username
        FROM market_order
        JOIN payment ON payment.order_id = market_order.id
        JOIN user AS buyer ON buyer.id = market_order.buyer_id
        JOIN user AS seller ON seller.id = market_order.seller_id
        WHERE market_order.buyer_id = ? OR market_order.seller_id = ?
        ORDER BY market_order.created_at DESC, market_order.id DESC
        """,
        (g.current_user['id'], g.current_user['id']),
    ).fetchall()
    account = get_db().execute(
        "SELECT balance FROM virtual_account WHERE user_id = ? AND kind = 'user'",
        (g.current_user['id'],),
    ).fetchone()
    return render_template(
        'orders.html',
        orders=rows,
        point_balance=account['balance'] if account is not None else 0,
    )


@app.route('/orders/<order_id>')
def view_order(order_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    order = get_order_for_current_user(order_id)
    if order is None:
        abort(404)
    return render_template('order_detail.html', order=order)


def transition_order(order_id, transition):
    if g.current_user is None:
        return redirect(url_for('login'))
    visible_order = get_order_for_current_user(order_id)
    if visible_order is None:
        abort(404)
    if transition == 'settle' and visible_order['buyer_id'] != g.current_user['id']:
        abort(404)
    if transition not in {'settle', 'cancel'}:
        raise ValueError('Unsupported order transition.')
    expected_version, version_error = validate_product_version()
    if version_error:
        abort(400)

    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE')
        order = db.execute(
            """
            SELECT market_order.*, payment.id AS payment_id,
                   payment.status AS payment_status,
                   payment.version AS payment_version,
                   product.status AS product_status,
                   product.version AS product_version
            FROM market_order
            JOIN payment ON payment.order_id = market_order.id
            JOIN product ON product.id = market_order.product_id
            WHERE market_order.id = ?
              AND (market_order.buyer_id = ? OR market_order.seller_id = ?)
            """,
            (order_id, g.current_user['id'], g.current_user['id']),
        ).fetchone()
        if order is None:
            db.rollback()
            abort(404)
        if (
            order['status'] != 'paid'
            or order['payment_status'] != 'held'
            or order['product_status'] != 'reserved'
            or order['version'] != expected_version
        ):
            db.rollback()
            abort(409)

        buyer_account = ensure_user_wallet(db, order['buyer_id'])
        seller_account = ensure_user_wallet(db, order['seller_id'])
        if buyer_account is None or seller_account is None:
            raise WalletConflictError()
        now = int(time.time())
        if transition == 'settle':
            if order['buyer_id'] != g.current_user['id']:
                db.rollback()
                abort(404)
            next_order_status = 'settled'
            next_payment_status = 'settled'
            next_product_status = 'sold'
            timestamp_column = 'settled_at'
            transaction_type = 'settlement'
            transaction_action = 'payment.settled'
            postings = [
                (SYSTEM_ESCROW_ACCOUNT_ID, -order['price']),
                (seller_account['id'], order['price']),
            ]
        else:
            next_order_status = 'cancelled'
            next_payment_status = 'refunded'
            next_product_status = 'selling'
            timestamp_column = 'refunded_at'
            transaction_type = 'refund'
            transaction_action = 'payment.refunded'
            postings = [
                (SYSTEM_ESCROW_ACCOUNT_ID, -order['price']),
                (buyer_account['id'], order['price']),
            ]

        apply_wallet_transaction(
            db,
            transaction_type,
            f'{transaction_type}:{order_id}',
            postings,
            order_id=order_id,
            created_by=g.current_user['id'],
            now=now,
        )
        order_update = db.execute(
            """
            UPDATE market_order
            SET status = ?, version = version + 1, updated_at = ?
            WHERE id = ? AND status = 'paid' AND version = ?
            """,
            (next_order_status, now, order_id, expected_version),
        )
        payment_update = db.execute(
            f"""
            UPDATE payment
            SET status = ?, version = version + 1, {timestamp_column} = ?
            WHERE id = ? AND status = 'held' AND version = ?
            """,
            (
                next_payment_status,
                now,
                order['payment_id'],
                order['payment_version'],
            ),
        )
        product_update = db.execute(
            """
            UPDATE product
            SET status = ?, version = version + 1
            WHERE id = ? AND status = 'reserved' AND version = ?
            """,
            (next_product_status, order['product_id'], order['product_version']),
        )
        if (
            order_update.rowcount != 1
            or payment_update.rowcount != 1
            or product_update.rowcount != 1
        ):
            raise WalletConflictError()
        write_audit_log(
            db,
            transaction_action,
            'payment',
            order['payment_id'],
            {'order_id': order_id},
            actor=g.current_user,
        )
        db.commit()
    except (WalletError, sqlite3.IntegrityError):
        db.rollback()
        audit_payment_failure(
            db,
            'payment.settled' if transition == 'settle' else 'payment.refunded',
            order_id,
            'transition_conflict',
        )
        abort(409)
    flash(
        '구매가 확정되어 판매자에게 포인트가 정산되었습니다.'
        if transition == 'settle'
        else '주문이 취소되고 포인트가 전액 환불되었습니다.'
    )
    return redirect(url_for('view_order', order_id=order_id))


@app.route('/orders/<order_id>/confirm', methods=['POST'])
def confirm_order(order_id):
    return transition_order(order_id, 'settle')


@app.route('/orders/<order_id>/cancel', methods=['POST'])
def cancel_order(order_id):
    return transition_order(order_id, 'cancel')


@app.route('/admin/users')
@admin_required
def admin_users():
    now = int(time.time())
    users = get_db().execute(
        """
        SELECT u.id, u.username, u.bio, u.role,
               EXISTS (
                   SELECT 1
                   FROM user_sanction AS sanction
                   WHERE sanction.user_id = u.id
                     AND sanction.revoked_at IS NULL
                     AND (sanction.ends_at IS NULL OR sanction.ends_at > ?)
               ) AS is_sanctioned
        FROM user AS u
        ORDER BY u.role DESC, u.username COLLATE NOCASE, u.id
        """,
        (now,),
    ).fetchall()
    record_admin_read('admin.users_viewed', 'admin_resource', 'users')
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<user_id>/sanctions', methods=['POST'])
@admin_required
def create_user_sanction(user_id):
    duration, duration_error = validate_sanction_duration()
    reason, reason_error = validate_admin_reason()
    if duration_error or reason_error:
        abort_admin_action(
            400,
            'user.sanction_created',
            'user',
            user_id,
            'invalid_input',
        )

    db = get_db()
    now = int(time.time())
    try:
        db.execute('BEGIN IMMEDIATE')
        target = db.execute(
            'SELECT id, username, role FROM user WHERE id = ?',
            (user_id,),
        ).fetchone()
        if target is None:
            abort_admin_action(
                404,
                'user.sanction_created',
                'user',
                user_id,
                'target_not_found',
            )
        if target['role'] == 'admin' or target['id'] == g.current_user['id']:
            abort_admin_action(
                403,
                'user.sanction_created',
                'user',
                target['id'],
                'protected_target',
            )
        if get_active_sanction(db, target['id'], now) is not None:
            abort_admin_action(
                409,
                'user.sanction_created',
                'user',
                target['id'],
                'active_sanction_exists',
            )

        duration_seconds = SANCTION_DURATION_SECONDS[duration]
        ends_at = None if duration_seconds is None else now + duration_seconds
        sanction_id = str(uuid.uuid4())
        db.execute(
            """
            INSERT INTO user_sanction
                (id, user_id, created_by, reason, duration_code, created_at, ends_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sanction_id,
                target['id'],
                g.current_user['id'],
                reason,
                duration,
                now,
                ends_at,
            ),
        )
        db.execute(
            'UPDATE user SET session_version = session_version + 1 WHERE id = ?',
            (target['id'],),
        )
        db.execute('DELETE FROM user_session WHERE user_id = ?', (target['id'],))
        write_audit_log(
            db,
            'user.sanction_created',
            'user',
            target['id'],
            {
                'sanction_id': sanction_id,
                'duration': duration,
                'ends_at': ends_at,
                'reason': reason,
            },
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    flash(f'{target["username"]} 회원을 제재했습니다.')
    return redirect(url_for('admin_user_sanctions', user_id=target['id']))


@app.route('/admin/users/<user_id>/sanctions')
@admin_required
def admin_user_sanctions(user_id):
    db = get_db()
    target = db.execute(
        'SELECT id, username, role FROM user WHERE id = ?',
        (user_id,),
    ).fetchone()
    if target is None:
        abort_admin_action(
            404,
            'admin.sanctions_viewed',
            'user',
            user_id,
            'target_not_found',
        )
    sanctions = db.execute(
        """
        SELECT sanction.*,
               creator.username AS created_by_username,
               revoker.username AS revoked_by_username
        FROM user_sanction AS sanction
        JOIN user AS creator ON creator.id = sanction.created_by
        LEFT JOIN user AS revoker ON revoker.id = sanction.revoked_by
        WHERE sanction.user_id = ?
        ORDER BY sanction.created_at DESC, sanction.id DESC
        """,
        (target['id'],),
    ).fetchall()
    record_admin_read(
        'admin.sanctions_viewed',
        'user',
        target['id'],
        {'username': target['username']},
    )
    return render_template(
        'admin_sanctions.html',
        target=target,
        sanctions=sanctions,
        now=int(time.time()),
    )


@app.route('/admin/sanctions/<sanction_id>/revoke', methods=['POST'])
@admin_required
def revoke_user_sanction(sanction_id):
    reason, reason_error = validate_admin_reason()
    if reason_error:
        abort_admin_action(
            400,
            'user.sanction_revoked',
            'sanction',
            sanction_id,
            'invalid_input',
        )

    db = get_db()
    now = int(time.time())
    try:
        db.execute('BEGIN IMMEDIATE')
        sanction = db.execute(
            """
            SELECT sanction.id, sanction.user_id, sanction.ends_at,
                   sanction.revoked_at, target.username
            FROM user_sanction AS sanction
            JOIN user AS target ON target.id = sanction.user_id
            WHERE sanction.id = ?
            """,
            (sanction_id,),
        ).fetchone()
        if sanction is None:
            abort_admin_action(
                404,
                'user.sanction_revoked',
                'sanction',
                sanction_id,
                'target_not_found',
            )
        if sanction['revoked_at'] is not None or (
            sanction['ends_at'] is not None and sanction['ends_at'] <= now
        ):
            abort_admin_action(
                409,
                'user.sanction_revoked',
                'sanction',
                sanction['id'],
                'sanction_not_active',
            )
        cursor = db.execute(
            """
            UPDATE user_sanction
            SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
            WHERE id = ? AND revoked_at IS NULL
            """,
            (now, g.current_user['id'], reason, sanction['id']),
        )
        if cursor.rowcount != 1:
            abort_admin_action(
                409,
                'user.sanction_revoked',
                'sanction',
                sanction['id'],
                'concurrent_update',
            )
        write_audit_log(
            db,
            'user.sanction_revoked',
            'user',
            sanction['user_id'],
            {'sanction_id': sanction['id'], 'reason': reason},
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    flash(f'{sanction["username"]} 회원의 제재를 해제했습니다.')
    return redirect(url_for('admin_user_sanctions', user_id=sanction['user_id']))


@app.route('/admin/products')
@admin_required
def admin_products():
    products = get_db().execute(
        """
        SELECT product.id, product.title, product.price, product.status,
               product.version, product.is_hidden, product.hidden_at,
               product.hidden_reason, product.seller_id,
               seller.username AS seller_username,
               EXISTS (
                   SELECT 1 FROM market_order
                   WHERE market_order.product_id = product.id
                     AND market_order.status IN ('paid', 'settled')
               ) AS has_active_order
        FROM product
        JOIN user AS seller ON seller.id = product.seller_id
        ORDER BY product.is_hidden DESC, product.title COLLATE NOCASE, product.id
        """
    ).fetchall()
    record_admin_read('admin.products_viewed', 'admin_resource', 'products')
    return render_template('admin_products.html', products=products)


@app.route('/admin/products/<product_id>/visibility', methods=['POST'])
@admin_required
def update_admin_product_visibility(product_id):
    visibility, visibility_error = validate_visibility()
    reason, reason_error = validate_admin_reason()
    expected_version, version_error = validate_product_version()
    if visibility_error or reason_error or version_error:
        abort_admin_action(
            400,
            'product.hidden' if visibility == 'hidden' else 'product.restored',
            'product',
            product_id,
            'invalid_input',
        )

    db = get_db()
    now = int(time.time())
    try:
        db.execute('BEGIN IMMEDIATE')
        product = db.execute(
            'SELECT id, title, is_hidden, version FROM product WHERE id = ?',
            (product_id,),
        ).fetchone()
        if product is None:
            abort_admin_action(
                404,
                'product.hidden' if visibility == 'hidden' else 'product.restored',
                'product',
                product_id,
                'target_not_found',
            )
        desired_hidden = 1 if visibility == 'hidden' else 0
        if product['is_hidden'] == desired_hidden:
            abort_admin_action(
                409,
                'product.hidden' if desired_hidden else 'product.restored',
                'product',
                product['id'],
                'visibility_unchanged',
            )

        if desired_hidden:
            cursor = db.execute(
                """
                UPDATE product
                SET is_hidden = 1, hidden_at = ?, hidden_by = ?, hidden_reason = ?,
                    version = version + 1
                WHERE id = ? AND version = ?
                """,
                (
                    now,
                    g.current_user['id'],
                    reason,
                    product['id'],
                    expected_version,
                ),
            )
            action = 'product.hidden'
        else:
            cursor = db.execute(
                """
                UPDATE product
                SET is_hidden = 0, hidden_at = NULL, hidden_by = NULL,
                    hidden_reason = NULL, version = version + 1
                WHERE id = ? AND version = ?
                """,
                (product['id'], expected_version),
            )
            action = 'product.restored'
        if cursor.rowcount != 1:
            abort_admin_action(
                409,
                action,
                'product',
                product['id'],
                'stale_version',
            )
        write_audit_log(
            db,
            action,
            'product',
            product['id'],
            {
                'title': product['title'],
                'previous_visibility': 'hidden' if product['is_hidden'] else 'visible',
                'new_visibility': visibility,
                'reason': reason,
            },
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    flash('상품 노출 상태가 변경되었습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/products/<product_id>/delete', methods=['POST'])
@admin_required
def delete_admin_product(product_id):
    reason, reason_error = validate_admin_reason()
    expected_version, version_error = validate_product_version()
    if reason_error or version_error:
        abort_admin_action(
            400,
            'product.deleted',
            'product',
            product_id,
            'invalid_input',
        )

    db = get_db()
    image_filename = None
    try:
        db.execute('BEGIN IMMEDIATE')
        product = db.execute(
            """
            SELECT product.id, product.title, product.seller_id,
                   product.image_filename, product.version,
                   seller.username AS seller_username
            FROM product
            JOIN user AS seller ON seller.id = product.seller_id
            WHERE product.id = ?
            """,
            (product_id,),
        ).fetchone()
        if product is None:
            abort_admin_action(
                404,
                'product.deleted',
                'product',
                product_id,
                'target_not_found',
            )
        if product_has_active_order(db, product['id']):
            abort_admin_action(
                409,
                'product.deleted',
                'product',
                product['id'],
                'active_order_exists',
            )
        cursor = db.execute(
            'DELETE FROM product WHERE id = ? AND version = ?',
            (product['id'], expected_version),
        )
        if cursor.rowcount != 1:
            abort_admin_action(
                409,
                'product.deleted',
                'product',
                product['id'],
                'stale_version',
            )
        write_audit_log(
            db,
            'product.deleted',
            'product',
            product['id'],
            {
                'title': product['title'],
                'seller_id': product['seller_id'],
                'seller_username': product['seller_username'],
                'reason': reason,
            },
            actor=g.current_user,
        )
        image_filename = product['image_filename']
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    remove_product_image(image_filename)
    flash('불량 상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/reports')
@admin_required
def admin_reports():
    page = validate_page_number()
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM report').fetchone()[0]
    reports = db.execute(
        """
        SELECT report.id, report.reporter_id, report.target_type,
               report.target_id, report.reason_code, report.reason, report.status,
               report.created_at, report.cancelled_at, report.resolved_at,
               report.resolution,
               reporter.username AS reporter_username,
               target_user.username AS target_username,
               product.title AS target_product_title,
               resolver.username AS resolver_username
        FROM report
        JOIN user AS reporter ON reporter.id = report.reporter_id
        LEFT JOIN user AS target_user
          ON report.target_type = 'user' AND target_user.id = report.target_id
        LEFT JOIN product
          ON report.target_type = 'product' AND product.id = report.target_id
        LEFT JOIN user AS resolver ON resolver.id = report.resolved_by
        ORDER BY (report.status = 'pending' AND report.cancelled_at IS NULL) DESC,
                 report.created_at DESC, report.id DESC
        LIMIT ? OFFSET ?
        """,
        (REPORT_PAGE_SIZE, (page - 1) * REPORT_PAGE_SIZE),
    ).fetchall()
    record_admin_read(
        'admin.reports_viewed',
        'admin_resource',
        'reports',
        {'page': page},
    )
    return render_template(
        'admin_reports.html',
        reports=reports,
        page=page,
        has_previous=page > 1,
        has_next=page * REPORT_PAGE_SIZE < total,
    )


@app.route('/admin/reports/<report_id>/resolve', methods=['POST'])
@admin_required
def resolve_report(report_id):
    resolution_data, resolution_error = validate_report_resolution()
    action = (
        f'report.{resolution_data["status"]}'
        if resolution_data is not None
        else 'report.resolved'
    )
    if resolution_error:
        abort_admin_action(
            400,
            action,
            'report',
            report_id,
            'invalid_input',
        )

    db = get_db()
    now = int(time.time())
    try:
        db.execute('BEGIN IMMEDIATE')
        report_record = db.execute(
            'SELECT id, target_type, target_id, status, cancelled_at '
            'FROM report WHERE id = ?',
            (report_id,),
        ).fetchone()
        if report_record is None:
            abort_admin_action(
                404,
                action,
                'report',
                report_id,
                'target_not_found',
            )
        if (
            report_record['status'] != 'pending'
            or report_record['cancelled_at'] is not None
        ):
            abort_admin_action(
                409,
                action,
                'report',
                report_record['id'],
                'report_already_reviewed',
            )
        cursor = db.execute(
            """
            UPDATE report
            SET status = ?, resolved_at = ?, resolved_by = ?, resolution = ?
            WHERE id = ? AND status = 'pending' AND cancelled_at IS NULL
            """,
            (
                resolution_data['status'],
                now,
                g.current_user['id'],
                resolution_data['resolution'],
                report_record['id'],
            ),
        )
        if cursor.rowcount != 1:
            abort_admin_action(
                409,
                action,
                'report',
                report_record['id'],
                'concurrent_update',
            )
        write_audit_log(
            db,
            action,
            'report',
            report_record['id'],
            {
                'reported_target_type': report_record['target_type'],
                'reported_target_id': report_record['target_id'],
                'resolution': resolution_data['resolution'],
            },
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    flash('신고 검토 결과가 저장되었습니다.')
    return redirect(url_for('admin_reports'))


@app.route('/admin/audit-logs')
@admin_required
def admin_audit_logs():
    page = validate_page_number()
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    logs = db.execute(
        """
        SELECT id, actor_user_id, actor_username, action, target_type, target_id,
               details_json, outcome, created_at, request_id
        FROM audit_log
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (AUDIT_PAGE_SIZE, (page - 1) * AUDIT_PAGE_SIZE),
    ).fetchall()
    record_admin_read(
        'admin.audit_logs_viewed',
        'admin_resource',
        'audit_logs',
        {'page': page},
    )
    return render_template(
        'admin_audit_logs.html',
        logs=logs,
        page=page,
        has_previous=page > 1,
        has_next=page * AUDIT_PAGE_SIZE < total,
    )


@app.route('/reports')
def reports():
    if g.current_user is None:
        return redirect(url_for('login'))
    page = validate_page_number()
    db = get_db()
    total = db.execute(
        'SELECT COUNT(*) FROM report WHERE reporter_id = ?',
        (g.current_user['id'],),
    ).fetchone()[0]
    user_reports = db.execute(
        """
        SELECT report.id, report.target_type, report.target_id,
               report.reason_code, report.reason, report.status,
               report.created_at, report.cancelled_at, report.resolved_at,
               target_user.username AS target_username,
               product.title AS target_product_title
        FROM report
        LEFT JOIN user AS target_user
          ON report.target_type = 'user' AND target_user.id = report.target_id
        LEFT JOIN product
          ON report.target_type = 'product' AND product.id = report.target_id
        WHERE report.reporter_id = ?
        ORDER BY report.created_at DESC, report.id DESC
        LIMIT ? OFFSET ?
        """,
        (
            g.current_user['id'],
            REPORT_PAGE_SIZE,
            (page - 1) * REPORT_PAGE_SIZE,
        ),
    ).fetchall()
    g.private_no_store = True
    return render_template(
        'reports.html',
        reports=user_reports,
        page=page,
        has_previous=page > 1,
        has_next=page * REPORT_PAGE_SIZE < total,
    )


@app.route('/reports/<report_id>/cancel', methods=['POST'])
def cancel_report(report_id):
    if g.current_user is None:
        return redirect(url_for('login'))
    normalized_report_id = validate_uuid_string(report_id)
    if normalized_report_id is None:
        abort(404)

    db = get_db()
    now = int(time.time())
    try:
        db.execute('BEGIN IMMEDIATE')
        report_record = db.execute(
            """
            SELECT id, target_type, target_id, status, cancelled_at
            FROM report
            WHERE id = ? AND reporter_id = ?
            """,
            (normalized_report_id, g.current_user['id']),
        ).fetchone()
        if report_record is None:
            db.rollback()
            abort(404)
        if (
            report_record['status'] != 'pending'
            or report_record['cancelled_at'] is not None
        ):
            db.rollback()
            abort(409)
        cursor = db.execute(
            """
            UPDATE report
            SET cancelled_at = ?
            WHERE id = ? AND reporter_id = ? AND status = 'pending'
              AND cancelled_at IS NULL
            """,
            (now, report_record['id'], g.current_user['id']),
        )
        if cursor.rowcount != 1:
            db.rollback()
            abort(409)
        write_audit_log(
            db,
            'report.cancelled',
            'report',
            report_record['id'],
            {
                'reported_target_type': report_record['target_type'],
                'reported_target_id': report_record['target_id'],
            },
            actor=g.current_user,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    flash('신고가 취소되었습니다.')
    return redirect(url_for('reports'))


@app.route('/report', methods=['GET', 'POST'])
def report():
    if g.current_user is None:
        return redirect(url_for('login'))
    g.private_no_store = True
    if request.method == 'POST':
        report_data, report_error = validate_report_form()
        if report_error:
            return render_template(
                'report.html',
                form_data={
                    'target_type': get_single_form_value('target_type') or 'user',
                    'target_id': get_single_form_value('target_id') or '',
                    'reason_code': get_single_form_value('reason_code') or 'other',
                    'reason': get_single_form_value('reason') or '',
                },
                error=report_error,
            ), 400

        db = get_db()
        now = int(time.time())
        ip_key = security_key('report_ip', request.remote_addr or 'unknown')
        try:
            db.execute('BEGIN IMMEDIATE')
            if report_data['target_type'] == 'user':
                target = db.execute(
                    'SELECT id FROM user WHERE id = ?',
                    (report_data['target_id'],),
                ).fetchone()
                is_own_target = report_data['target_id'] == g.current_user['id']
            else:
                target = db.execute(
                    'SELECT id, seller_id FROM product WHERE id = ?',
                    (report_data['target_id'],),
                ).fetchone()
                is_own_target = (
                    target is not None
                    and target['seller_id'] == g.current_user['id']
                )
            if target is None:
                db.rollback()
                abort(404)
            if is_own_target:
                db.rollback()
                return render_template(
                    'report.html',
                    form_data=report_data,
                    error='본인 계정이나 본인의 상품은 신고할 수 없습니다.',
                ), 400

            recent_count = db.execute(
                """
                SELECT COUNT(*)
                FROM report
                WHERE reporter_id = ? AND created_at >= ?
                """,
                (g.current_user['id'], now - REPORT_RATE_WINDOW_SECONDS),
            ).fetchone()[0]
            if recent_count >= REPORT_RATE_LIMIT:
                db.rollback()
                abort(429, retry_after=REPORT_RATE_WINDOW_SECONDS)
            recent_ip_count = db.execute(
                """
                SELECT COUNT(*)
                FROM report
                WHERE ip_key = ? AND created_at >= ?
                """,
                (ip_key, now - REPORT_RATE_WINDOW_SECONDS),
            ).fetchone()[0]
            if recent_ip_count >= REPORT_IP_RATE_LIMIT:
                db.rollback()
                abort(429, retry_after=REPORT_RATE_WINDOW_SECONDS)
            recent_target_count = db.execute(
                """
                SELECT COUNT(*)
                FROM report
                WHERE target_type = ? AND target_id = ? AND created_at >= ?
                """,
                (
                    report_data['target_type'],
                    report_data['target_id'],
                    now - REPORT_RATE_WINDOW_SECONDS,
                ),
            ).fetchone()[0]
            if recent_target_count >= REPORT_TARGET_RATE_LIMIT:
                db.rollback()
                abort(429, retry_after=REPORT_RATE_WINDOW_SECONDS)
            duplicate = db.execute(
                """
                SELECT 1 FROM report
                WHERE reporter_id = ? AND target_type = ? AND target_id = ?
                  AND reason_code = ? AND status = 'pending'
                  AND cancelled_at IS NULL
                LIMIT 1
                """,
                (
                    g.current_user['id'],
                    report_data['target_type'],
                    report_data['target_id'],
                    report_data['reason_code'],
                ),
            ).fetchone()
            if duplicate is not None:
                db.rollback()
                abort(409)

            report_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO report
                    (id, reporter_id, target_type, target_id, reason_code,
                     reason, ip_key, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    report_id,
                    g.current_user['id'],
                    report_data['target_type'],
                    report_data['target_id'],
                    report_data['reason_code'],
                    report_data['reason'],
                    ip_key,
                    now,
                ),
            )
            write_audit_log(
                db,
                'report.created',
                report_data['target_type'],
                report_data['target_id'],
                {'report_id': report_id},
                actor=g.current_user,
            )
            db.commit()
        except sqlite3.Error:
            db.rollback()
            raise

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    target_type = request.args.get('target_type', 'user')
    if target_type not in REPORT_TARGET_LABELS:
        target_type = 'user'
    target_id = validate_uuid_string(request.args.get('target_id', '')) or ''
    return render_template(
        'report.html',
        form_data={
            'target_type': target_type,
            'target_id': target_id,
            'reason_code': 'other',
            'reason': '',
        },
        error=None,
    )


@socketio.on('connect')
def handle_connect(auth=None):
    if app.config['ENFORCE_HTTPS'] and not is_secure_chat_transport():
        app.logger.warning(
            'security_event=chat_insecure_transport_rejected ip_key=%s',
            chat_ip_key(),
        )
        return False
    user = get_authenticated_user()
    registered, failure_reason = register_chat_connection(user)
    if not registered:
        app.logger.warning(
            'security_event=chat_connection_rejected user_id=%s reason=%s ip_key=%s',
            user['id'] if user is not None else '-',
            failure_reason,
            chat_ip_key(),
        )
        return False
    join_room(chat_user_room(user['id']))


@socketio.on('disconnect')
def handle_disconnect(reason=None):
    unregister_chat_connection()


def chat_event_error(code):
    messages = {
        'invalid_payload': '메시지 요청 형식을 확인해 주세요.',
        'invalid_message': '메시지는 1~1,000자의 올바른 텍스트로 입력해 주세요.',
        'invalid_recipient': '대화 상대를 확인해 주세요.',
        'product_unavailable': '이 상품에 대한 대화를 시작할 수 없습니다.',
        'recipient_unavailable': '현재 이 사용자에게 메시지를 보낼 수 없습니다.',
        'rate_limited': '메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도해 주세요.',
        'connection_invalid': '채팅 연결이 만료되었습니다. 페이지를 새로고침해 주세요.',
        'conversation_unavailable': '대화를 확인해 주세요.',
        'server_error': '메시지를 저장하지 못했습니다. 잠시 후 다시 시도해 주세요.',
    }
    return {
        'ok': False,
        'error': {
            'code': code,
            'message': messages[code],
        },
    }


@socketio.on('send_private_message')
def handle_send_private_message_event(data):
    user = get_authenticated_user()
    if user is None:
        disconnect()
        return chat_event_error('connection_invalid')

    rate_status = record_chat_message_attempt(user, data)
    if rate_status == 'connection_invalid':
        disconnect()
        return chat_event_error('connection_invalid')
    if rate_status == 'rate_limited':
        app.logger.warning(
            'security_event=chat_rate_limited user_id=%s ip_key=%s',
            user['id'],
            chat_ip_key(),
        )
        return chat_event_error('rate_limited')
    if rate_status == 'server_error':
        return chat_event_error('server_error')

    message_data, validation_error = validate_private_message_payload(data)
    if validation_error:
        app.logger.warning(
            'security_event=chat_message_rejected user_id=%s reason=%s',
            user['id'],
            validation_error,
        )
        return chat_event_error(validation_error)
    if message_data['recipient_id'] == user['id']:
        return chat_event_error('invalid_recipient')

    db = get_db()
    now_ms = time.time_ns() // 1_000_000
    try:
        db.execute('BEGIN IMMEDIATE')
        recipient = db.execute(
            'SELECT id, username FROM user WHERE id = ?',
            (message_data['recipient_id'],),
        ).fetchone()
        if recipient is None:
            db.rollback()
            return chat_event_error('invalid_recipient')
        if get_active_sanction(db, recipient['id']) is not None:
            db.rollback()
            return chat_event_error('recipient_unavailable')

        existing = db.execute(
            """
            SELECT message.id, message.conversation_id, message.sender_id,
                   sender.username AS sender_username,
                   message.client_message_id, message.body, message.created_at,
                   conversation.participant_low_id,
                   conversation.participant_high_id,
                   conversation.context_type, conversation.context_id,
                   recipient_read.last_read_created_at
                       AS recipient_last_read_created_at,
                   recipient_read.last_read_message_id
                       AS recipient_last_read_message_id
            FROM private_message AS message
            JOIN user AS sender ON sender.id = message.sender_id
            JOIN private_conversation AS conversation
              ON conversation.id = message.conversation_id
            LEFT JOIN private_conversation_read_state AS recipient_read
              ON recipient_read.conversation_id = message.conversation_id
             AND recipient_read.user_id != message.sender_id
            WHERE message.sender_id = ? AND message.client_message_id = ?
            """,
            (user['id'], message_data['client_message_id']),
        ).fetchone()
        if existing is not None:
            existing_recipient_id = (
                existing['participant_high_id']
                if existing['participant_low_id'] == user['id']
                else existing['participant_low_id']
            )
            db.rollback()
            if (
                existing_recipient_id != recipient['id']
                or existing['context_type'] != message_data['context_type']
                or existing['context_id'] != message_data['context_id']
            ):
                return chat_event_error('invalid_payload')
            existing_payload = dict(existing)
            existing_payload['recipient_id'] = existing_recipient_id
            return {
                'ok': True,
                'duplicate': True,
                'message': serialize_private_message(existing_payload),
            }

        conversation = get_private_conversation(
            db,
            user['id'],
            recipient['id'],
            message_data['context_type'],
            message_data['context_id'],
        )
        product = None
        if message_data['context_type'] == 'product' and conversation is None:
            product = db.execute(
                'SELECT id, seller_id, is_hidden FROM product WHERE id = ?',
                (message_data['product_id'],),
            ).fetchone()
            if (
                product is None
                or product['seller_id'] != recipient['id']
                or product['seller_id'] == user['id']
                or not can_view_product(product, user)
            ):
                db.rollback()
                return chat_event_error('product_unavailable')
        if conversation is None:
            conversation_id = str(uuid.uuid4())
            participant_low_id, participant_high_id = canonical_chat_participants(
                user['id'],
                recipient['id'],
            )
            db.execute(
                """
                INSERT INTO private_conversation
                    (id, participant_low_id, participant_high_id,
                     context_type, context_id, product_id,
                     created_at, last_message_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    participant_low_id,
                    participant_high_id,
                    message_data['context_type'],
                    message_data['context_id'],
                    product['id'] if product is not None else None,
                    now_ms,
                    now_ms,
                ),
            )
        else:
            conversation_id = conversation['id']

        message_id = str(uuid.uuid4())
        db.execute(
            """
            INSERT INTO private_message
                (id, conversation_id, sender_id, client_message_id, body, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                conversation_id,
                user['id'],
                message_data['client_message_id'],
                message_data['message'],
                now_ms,
            ),
        )
        db.execute(
            'UPDATE private_conversation SET last_message_at = ? WHERE id = ?',
            (now_ms, conversation_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=chat_message_store_failed user_id=%s',
            user['id'],
        )
        return chat_event_error('server_error')

    payload = {
        'message_id': message_id,
        'conversation_id': conversation_id,
        'sender_id': user['id'],
        'sender_username': user['username'],
        'recipient_id': recipient['id'],
        'message': message_data['message'],
        'created_at': now_ms,
        'client_message_id': message_data['client_message_id'],
        'context_type': message_data['context_type'],
        'product_id': message_data['product_id'],
        'is_read': False,
    }
    socketio.emit(
        'private_message',
        payload,
        to=chat_user_room(user['id']),
    )
    socketio.emit(
        'private_message',
        payload,
        to=chat_user_room(recipient['id']),
    )
    socketio.emit(
        'unread_state_changed',
        {
            'has_unread_messages': True,
            'conversation_id': conversation_id,
            'conversation_has_unread': True,
        },
        to=chat_user_room(recipient['id']),
    )
    return {'ok': True, 'duplicate': False, 'message': payload}


@socketio.on('mark_private_messages_read')
def handle_mark_private_messages_read_event(data):
    user = get_authenticated_user()
    if user is None:
        disconnect()
        return chat_event_error('connection_invalid')

    rate_status = record_chat_read_attempt(user)
    if rate_status == 'connection_invalid':
        disconnect()
        return chat_event_error('connection_invalid')
    if rate_status == 'rate_limited':
        app.logger.warning(
            'security_event=chat_read_rate_limited user_id=%s ip_key=%s',
            user['id'],
            chat_ip_key(),
        )
        return chat_event_error('rate_limited')
    if rate_status == 'server_error':
        return chat_event_error('server_error')

    conversation_id = validate_private_message_read_payload(data)
    if conversation_id is None:
        app.logger.warning(
            'security_event=chat_read_rejected user_id=%s reason=invalid_payload',
            user['id'],
        )
        return chat_event_error('invalid_payload')

    db = get_db()
    now_ms = time.time_ns() // 1_000_000
    try:
        db.execute('BEGIN IMMEDIATE')
        conversation = db.execute(
            """
            SELECT id, participant_low_id, participant_high_id
            FROM private_conversation
            WHERE id = ?
              AND (participant_low_id = ? OR participant_high_id = ?)
            """,
            (conversation_id, user['id'], user['id']),
        ).fetchone()
        if conversation is None:
            db.rollback()
            return chat_event_error('conversation_unavailable')
        latest_message = db.execute(
            """
            SELECT id, created_at
            FROM private_message
            WHERE conversation_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (conversation_id,),
        ).fetchone()
        if latest_message is None:
            db.rollback()
            return chat_event_error('conversation_unavailable')

        db.execute(
            """
            INSERT INTO private_conversation_read_state
                (conversation_id, user_id, last_read_created_at,
                 last_read_message_id, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(conversation_id, user_id) DO UPDATE SET
                last_read_created_at = excluded.last_read_created_at,
                last_read_message_id = excluded.last_read_message_id,
                updated_at = excluded.updated_at
            WHERE excluded.last_read_created_at
                      > private_conversation_read_state.last_read_created_at
               OR (
                   excluded.last_read_created_at
                       = private_conversation_read_state.last_read_created_at
                   AND excluded.last_read_message_id
                       > private_conversation_read_state.last_read_message_id
               )
            """,
            (
                conversation_id,
                user['id'],
                latest_message['created_at'],
                latest_message['id'],
                now_ms,
            ),
        )
        has_unread_messages = user_has_unread_messages(db, user['id'])
        peer_id = (
            conversation['participant_high_id']
            if conversation['participant_low_id'] == user['id']
            else conversation['participant_low_id']
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        app.logger.error(
            'security_event=chat_read_store_failed user_id=%s',
            user['id'],
        )
        return chat_event_error('server_error')

    read_payload = {
        'conversation_id': conversation_id,
        'reader_id': user['id'],
        'last_read_created_at': latest_message['created_at'],
        'last_read_message_id': latest_message['id'],
        'updated_at': now_ms,
    }
    socketio.emit(
        'conversation_read',
        read_payload,
        to=chat_user_room(user['id']),
    )
    socketio.emit(
        'conversation_read',
        read_payload,
        to=chat_user_room(peer_id),
    )
    socketio.emit(
        'unread_state_changed',
        {
            'has_unread_messages': has_unread_messages,
            'conversation_id': conversation_id,
            'conversation_has_unread': False,
        },
        to=chat_user_room(user['id']),
    )
    return {'ok': True, 'read_state': read_payload}


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=app.config['DEBUG'])
