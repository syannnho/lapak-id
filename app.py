# backend/app.py — lapakID Secure Backend (Flask + Python)
# Deploy ke Railway.app atau Render.com

import os
import re
import hmac
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ─── APP SETUP ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ─── ENV CONFIG ───────────────────────────────────────────────────────────────
MONGO_URI     = os.environ.get('MONGODB_URI')
JWT_SECRET    = os.environ.get('JWT_SECRET')
ENC_KEY_HEX   = os.environ.get('ENC_KEY')           # 64 hex chars = 32 bytes
INIT_SECRET   = os.environ.get('INIT_SECRET', 'lapakid_init_2026')
ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '*')  # https://lapakid.vercel.app

# Validasi wajib
if not MONGO_URI:
    raise RuntimeError('MONGODB_URI belum diset!')
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError('JWT_SECRET belum diset atau terlalu pendek (min 32 char)!')
if not ENC_KEY_HEX or len(ENC_KEY_HEX) != 64:
    raise RuntimeError('ENC_KEY harus 64 hex chars (32 bytes)!')

ENC_KEY = bytes.fromhex(ENC_KEY_HEX)

PRICE_MAP = {
    'low':    125000,
    'medium': 450000,
    'high':   850000,
    'legend': 1350000,
}

# ─── SECURITY HEADERS (Flask-Talisman) ────────────────────────────────────────
# Pasang HTTPS-only headers, CSP, HSTS, dll
Talisman(
    app,
    force_https=False,          # Railway sudah handle HTTPS
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=False,  # Frontend beda domain, nonaktifkan CSP di backend
    x_content_type_options=True,
    x_xss_protection=True,
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
CORS(
    app,
    origins=[ALLOWED_ORIGIN] if ALLOWED_ORIGIN != '*' else '*',
    methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization'],
    max_age=600,
    supports_credentials=False,
)

# ─── RATE LIMITER ─────────────────────────────────────────────────────────────
# Pakai Redis jika ada, fallback ke memory
REDIS_URL = os.environ.get('REDIS_URL')
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=['200 per hour', '60 per minute'],
    storage_uri=REDIS_URL if REDIS_URL else 'memory://',
    strategy='fixed-window-elastic-expiry',
)

# ─── DATABASE ──────────────────────────────────────────────────────────────────
_mongo_client = None

def get_db():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
            maxPoolSize=10,
            # TLS wajib untuk MongoDB Atlas
            tls=True,
        )
    return _mongo_client['lapakid']

# Buat indexes saat startup (jalankan sekali)
def create_indexes():
    try:
        db = get_db()
        db['users'].create_index('username', unique=True)
        db['users'].create_index('emailPhone', unique=True)
        db['admins'].create_index('username', unique=True)
        db['ids'].create_index([('status', 1), ('tier', 1)])
        db['transaksi'].create_index([('userId', 1), ('createdAt', -1)])
        db['sold'].create_index([('userId', 1), ('soldAt', -1)])
        db['topup'].create_index([('status', 1), ('createdAt', -1)])
        logger.info('MongoDB indexes created OK')
    except Exception as e:
        logger.warning(f'Index creation warning: {e}')

# ─── ENKRIPSI AES-256-GCM ─────────────────────────────────────────────────────
aesgcm = AESGCM(ENC_KEY)

def encrypt(text: str) -> str:
    """Enkripsi string dengan AES-256-GCM. Return hex string."""
    if not text:
        return text
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    ct    = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    # Format: nonce(24 hex) + ciphertext+tag(hex)
    return nonce.hex() + ct.hex()

def decrypt(enc_text: str) -> str:
    """Decrypt string. Return original atau enc_text jika gagal (data lama)."""
    if not enc_text or len(enc_text) < 25:
        return enc_text
    try:
        nonce = bytes.fromhex(enc_text[:24])
        ct    = bytes.fromhex(enc_text[24:])
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        return enc_text  # data lama plain text, return as-is

# ─── PASSWORD HASHING (bcrypt) ────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# ─── JWT ──────────────────────────────────────────────────────────────────────
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_DAYS = 7

def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        'id':       user_id,
        'username': username,
        'role':     role,
        'iat':      datetime.now(timezone.utc),
        'exp':      datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRY_DAYS),
        'jti':      secrets.token_hex(16),  # JWT ID unik untuk tiap token
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

# ─── AUTH DECORATORS ──────────────────────────────────────────────────────────
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Token tidak ditemukan'}), 401
        token = auth_header[7:]
        try:
            payload = decode_token(token)
            g.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Sesi habis, silakan login ulang'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @auth_required
    def decorated(*args, **kwargs):
        if g.user.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Akses ditolak: hanya admin'}), 403
        return f(*args, **kwargs)
    return decorated

# ─── VALIDASI INPUT ───────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
PRICE_RE    = re.compile(r'^\d+$')

def validate_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))

def sanitize_str(s, max_len=200) -> str:
    """Strip whitespace dan batasi panjang."""
    return str(s).strip()[:max_len] if s else ''

def gen_id(prefix='TX') -> str:
    ts  = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    rnd = secrets.token_hex(4).upper()
    return f'{prefix}_{ts}_{rnd}'

# ─── HELPER ───────────────────────────────────────────────────────────────────
def ok(data: dict = None, msg: str = None, code: int = 200):
    r = {'success': True}
    if msg:  r['message'] = msg
    if data: r.update(data)
    return jsonify(r), code

def err(msg: str, code: int = 400):
    return jsonify({'success': False, 'message': msg}), code

def to_str_id(doc):
    """Convert ObjectId ke string di dict."""
    if doc and '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc

def safe_object_id(id_str: str):
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        return None

# ════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE — request logging & body size limit
# ════════════════════════════════════════════════════════════════════════════
@app.before_request
def before_request():
    # Tolak body lebih dari 50KB
    if request.content_length and request.content_length > 50 * 1024:
        return err('Request terlalu besar (maks 50KB)', 413)
    # Log semua request (IP, method, path)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    logger.info(f'{ip} {request.method} {request.path}')

@app.after_request
def after_request(response):
    # Hapus header yang bocorkan info server
    response.headers.pop('Server', None)
    response.headers['X-Powered-By'] = 'lapakID'  # fake header
    return response

# ════════════════════════════════════════════════════════════════════════════
# HEALTH
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/health')
@limiter.limit('30 per minute')
def health():
    try:
        get_db().command('ping')
        return ok({'db': 'connected', 'time': datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        return err(f'DB error: {str(e)}', 500)

# ════════════════════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit('5 per minute; 20 per hour')
def register():
    data = request.get_json(silent=True) or {}
    username   = sanitize_str(data.get('username', ''))
    full_name  = sanitize_str(data.get('fullName', ''))
    email_ph   = sanitize_str(data.get('emailPhone', ''))
    password   = data.get('password', '')

    if not all([username, full_name, email_ph, password]):
        return err('Semua field wajib diisi')
    if not validate_username(username):
        return err('Username hanya huruf, angka, underscore (3-20 karakter)')
    if len(password) < 8:
        return err('Password minimal 8 karakter')
    if len(password) > 128:
        return err('Password terlalu panjang')

    db = get_db()
    try:
        hashed = hash_password(password)
        result = db['users'].insert_one({
            'username':       username.lower(),
            'fullName':       full_name,
            'emailPhone':     email_ph,
            'password':       hashed,
            'role':           'user',
            'coins':          0,
            'avatar':         None,
            'totalTransaksi': {'success': 0, 'pending': 0, 'gagal': 0},
            'cart':           [],
            'createdAt':      datetime.now(timezone.utc),
            'updatedAt':      datetime.now(timezone.utc),
        })
        user_id = str(result.inserted_id)
        token = create_token(user_id, username.lower(), 'user')
        return ok({
            'token': token,
            'user': {'id': user_id, 'username': username.lower(), 'fullName': full_name,
                     'emailPhone': email_ph, 'role': 'user', 'coins': 0}
        }, 'Pendaftaran berhasil', 201)
    except DuplicateKeyError as e:
        field = 'Username' if 'username' in str(e) else 'Email/WhatsApp'
        return err(f'{field} sudah terdaftar', 409)
    except Exception as e:
        logger.error(f'Register error: {e}')
        return err('Server error', 500)


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit('10 per minute; 50 per hour')
def login():
    data     = request.get_json(silent=True) or {}
    username = sanitize_str(data.get('username', '')).lower()
    password = data.get('password', '')

    if not username or not password:
        return err('Username dan password wajib diisi')

    db   = get_db()
    user = db['users'].find_one({'username': username})
    role = 'user'

    if not user:
        user = db['admins'].find_one({'username': username})
        if user:
            role = 'admin'

    # Timing-safe: tetap jalankan bcrypt meski user tidak ada (cegah timing attack)
    dummy_hash = '$2b$12$dummyhashfordummycomparisononly000000000000000000000000'
    password_hash = user['password'] if user else dummy_hash

    if not verify_password(password, password_hash) or not user:
        logger.warning(f'Failed login attempt for username: {username}')
        return err('Username atau password salah', 401)

    user_id = str(user['_id'])
    token   = create_token(user_id, user['username'], role)
    logger.info(f'Login success: {username} ({role})')

    return ok({
        'token': token,
        'user': {
            'id':             user_id,
            'username':       user['username'],
            'fullName':       user.get('fullName', ''),
            'emailPhone':     user.get('emailPhone', ''),
            'role':           role,
            'coins':          user.get('coins', 0),
            'totalTransaksi': user.get('totalTransaksi', {}),
        }
    }, 'Login berhasil')


@app.route('/api/auth/me')
@auth_required
def me():
    db  = get_db()
    col = 'admins' if g.user['role'] == 'admin' else 'users'
    oid = safe_object_id(g.user['id'])
    if not oid:
        return err('Token tidak valid', 401)
    user = db[col].find_one({'_id': oid}, {'password': 0})
    if not user:
        return err('User tidak ditemukan', 404)
    return ok({'user': to_str_id(user)})

# ════════════════════════════════════════════════════════════════════════════
# USER PROFILE & CART
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/user/profile')
@auth_required
def get_profile():
    db   = get_db()
    oid  = safe_object_id(g.user['id'])
    user = db['users'].find_one({'_id': oid}, {'password': 0})
    if not user:
        return err('User tidak ditemukan', 404)
    return ok({'user': to_str_id(user)})


@app.route('/api/user/cart')
@auth_required
def get_cart():
    db   = get_db()
    oid  = safe_object_id(g.user['id'])
    user = db['users'].find_one({'_id': oid}, {'cart': 1})
    return ok({'cart': user.get('cart', []) if user else []})


@app.route('/api/user/cart', methods=['POST'])
@auth_required
@limiter.limit('30 per minute')
def add_to_cart():
    data    = request.get_json(silent=True) or {}
    id_item = sanitize_str(data.get('idItem', ''))
    if not id_item:
        return err('idItem wajib diisi')

    oid_item = safe_object_id(id_item)
    if not oid_item:
        return err('ID tidak valid')

    db     = get_db()
    id_doc = db['ids'].find_one({'_id': oid_item, 'status': 'available'})
    if not id_doc:
        return err('ID tidak tersedia', 404)

    user_oid = safe_object_id(g.user['id'])
    user     = db['users'].find_one({'_id': user_oid}, {'cart': 1})
    cart     = user.get('cart', []) if user else []

    if any(c['idItem'] == id_item for c in cart):
        return err('ID sudah ada di keranjang', 409)

    db['users'].update_one(
        {'_id': user_oid},
        {'$push': {'cart': {
            'idItem':  id_item,
            'gameId':  id_doc['gameId'],
            'tier':    id_doc['tier'],
            'price':   id_doc['price'],
            'addedAt': datetime.now(timezone.utc),
        }}, '$set': {'updatedAt': datetime.now(timezone.utc)}}
    )
    return ok(msg='Ditambahkan ke keranjang')


@app.route('/api/user/cart/<id_item>', methods=['DELETE'])
@auth_required
def remove_from_cart(id_item):
    db      = get_db()
    user_oid = safe_object_id(g.user['id'])
    db['users'].update_one(
        {'_id': user_oid},
        {'$pull': {'cart': {'idItem': id_item}}, '$set': {'updatedAt': datetime.now(timezone.utc)}}
    )
    return ok(msg='Item dihapus dari keranjang')

# ════════════════════════════════════════════════════════════════════════════
# IDS (PUBLIC — tanpa credentials)
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/ids')
@limiter.limit('120 per minute')
def get_ids():
    tier  = sanitize_str(request.args.get('tier', ''))
    sort  = request.args.get('sort', 'newest')
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 24))))
    except ValueError:
        return err('Parameter tidak valid')

    db     = get_db()
    filt   = {'status': 'available'}
    if tier and tier in PRICE_MAP:
        filt['tier'] = tier

    sort_map = {
        'price_asc':  [('price', 1)],
        'price_desc': [('price', -1)],
        'newest':     [('addedAt', -1)],
    }
    sort_opt = sort_map.get(sort, [('addedAt', -1)])

    skip  = (page - 1) * limit
    total = db['ids'].count_documents(filt)
    ids   = list(db['ids'].find(
        filt,
        # PENTING: uid dan password TIDAK dikirim ke publik
        {'uid': 0, 'password': 0, 'addedBy': 0}
    ).sort(sort_opt).skip(skip).limit(limit))

    return ok({
        'ids':        [to_str_id(i) for i in ids],
        'total':      total,
        'page':       page,
        'totalPages': -(-total // limit),  # ceiling division
    })


@app.route('/api/ids/<id_str>')
@limiter.limit('60 per minute')
def get_id_detail(id_str):
    oid = safe_object_id(id_str)
    if not oid:
        return err('ID tidak valid', 400)
    db  = get_db()
    doc = db['ids'].find_one(
        {'_id': oid, 'status': 'available'},
        {'uid': 0, 'password': 0, 'addedBy': 0}
    )
    if not doc:
        return err('ID tidak ditemukan', 404)
    return ok({'id': to_str_id(doc)})

# ════════════════════════════════════════════════════════════════════════════
# PAYMENT
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/payment/buy', methods=['POST'])
@auth_required
@limiter.limit('20 per minute')
def buy_one():
    data    = request.get_json(silent=True) or {}
    id_item = sanitize_str(data.get('idItem', ''))
    if not id_item:
        return err('idItem wajib diisi')

    oid_item = safe_object_id(id_item)
    if not oid_item:
        return err('ID tidak valid')

    db       = get_db()
    user_oid = safe_object_id(g.user['id'])
    user     = db['users'].find_one({'_id': user_oid})
    if not user:
        return err('User tidak ditemukan', 404)

    # Atomic lock — cegah race condition
    id_doc = db['ids'].find_one_and_update(
        {'_id': oid_item, 'status': 'available'},
        {'$set': {'status': 'sold', 'soldAt': datetime.now(timezone.utc), 'soldTo': g.user['id']}},
        return_document=False,
    )
    if not id_doc:
        return err('ID tidak tersedia atau sudah terjual', 404)

    if user['coins'] < id_doc['price']:
        # Rollback
        db['ids'].update_one({'_id': oid_item}, {'$set': {'status': 'available', 'soldAt': None, 'soldTo': None}})
        return err(f'Saldo tidak cukup. Saldo: Rp{user["coins"]:,}, Harga: Rp{id_doc["price"]:,}', 402)

    new_coins = user['coins'] - id_doc['price']
    tx_id     = gen_id('TX')
    now       = datetime.now(timezone.utc)

    # Decrypt credentials untuk dikirim ke user
    uid_plain  = decrypt(id_doc['uid'])
    pass_plain = decrypt(id_doc['password'])

    db['users'].update_one(
        {'_id': user_oid},
        {'$set':  {'coins': new_coins, 'updatedAt': now},
         '$inc':  {'totalTransaksi.success': 1},
         '$pull': {'cart': {'idItem': id_item}}}
    )
    db['transaksi'].insert_one({
        'txId': tx_id, 'userId': g.user['id'], 'username': user['username'],
        'gameId': id_doc['gameId'], 'tier': id_doc['tier'],
        'price': id_doc['price'], 'status': 'success', 'createdAt': now,
    })
    # Simpan masih terenkripsi di sold
    db['sold'].insert_one({
        'txId': tx_id, 'userId': g.user['id'], 'username': user['username'],
        'gameId': id_doc['gameId'], 'uid': id_doc['uid'], 'password': id_doc['password'],
        'tier': id_doc['tier'], 'price': id_doc['price'],
        'note': id_doc.get('note', ''), 'soldAt': now,
    })

    return ok({'transaction': {
        'txId': tx_id, 'gameId': id_doc['gameId'],
        'uid': uid_plain, 'password': pass_plain,
        'tier': id_doc['tier'], 'price': id_doc['price'], 'newCoins': new_coins,
    }}, 'Pembelian berhasil!')


@app.route('/api/payment/buy-cart', methods=['POST'])
@auth_required
@limiter.limit('10 per minute')
def buy_cart():
    db       = get_db()
    user_oid = safe_object_id(g.user['id'])
    user     = db['users'].find_one({'_id': user_oid})

    if not user or not user.get('cart'):
        return err('Keranjang kosong')

    locked, failed = [], []
    for item in user['cart']:
        oid = safe_object_id(item['idItem'])
        if not oid:
            failed.append(item['idItem'])
            continue
        doc = db['ids'].find_one_and_update(
            {'_id': oid, 'status': 'available'},
            {'$set': {'status': 'sold', 'soldAt': datetime.now(timezone.utc), 'soldTo': g.user['id']}},
            return_document=False,
        )
        if doc:
            locked.append(doc)
        else:
            failed.append(item['idItem'])

    if not locked:
        return err('Semua ID di keranjang tidak tersedia', 404)

    total = sum(d['price'] for d in locked)
    if user['coins'] < total:
        for d in locked:
            db['ids'].update_one({'_id': d['_id']}, {'$set': {'status': 'available', 'soldAt': None, 'soldTo': None}})
        return err(f'Saldo tidak cukup. Total: Rp{total:,}, Saldo: Rp{user["coins"]:,}', 402)

    new_coins = user['coins'] - total
    purchases = []
    now       = datetime.now(timezone.utc)

    for d in locked:
        tx_id = gen_id('TX')
        db['transaksi'].insert_one({
            'txId': tx_id, 'userId': g.user['id'], 'username': user['username'],
            'gameId': d['gameId'], 'tier': d['tier'], 'price': d['price'],
            'status': 'success', 'createdAt': now,
        })
        db['sold'].insert_one({
            'txId': tx_id, 'userId': g.user['id'], 'username': user['username'],
            'gameId': d['gameId'], 'uid': d['uid'], 'password': d['password'],
            'tier': d['tier'], 'price': d['price'], 'note': d.get('note', ''), 'soldAt': now,
        })
        purchases.append({
            'txId': tx_id, 'gameId': d['gameId'],
            'uid': decrypt(d['uid']), 'password': decrypt(d['password']),
            'tier': d['tier'], 'price': d['price'],
        })

    db['users'].update_one(
        {'_id': user_oid},
        {'$set': {'coins': new_coins, 'cart': [], 'updatedAt': now},
         '$inc': {'totalTransaksi.success': len(locked)}}
    )

    return ok({
        'purchases': purchases,
        'newCoins': new_coins,
        'failedItems': failed if failed else None,
    }, f'{len(locked)} ID berhasil dibeli')

# ════════════════════════════════════════════════════════════════════════════
# TRANSAKSI
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/transaksi')
@auth_required
def get_transaksi():
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 20))))
    except ValueError:
        return err('Parameter tidak valid')

    db    = get_db()
    filt  = {'userId': g.user['id']}
    skip  = (page - 1) * limit
    total = db['transaksi'].count_documents(filt)
    txs   = list(db['transaksi'].find(filt).sort('createdAt', -1).skip(skip).limit(limit))
    return ok({'transaksi': [to_str_id(t) for t in txs], 'total': total, 'page': page})


@app.route('/api/transaksi/purchases')
@auth_required
def get_purchases():
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 20))))
    except ValueError:
        return err('Parameter tidak valid')

    db    = get_db()
    filt  = {'userId': g.user['id']}
    skip  = (page - 1) * limit
    total = db['sold'].count_documents(filt)
    docs  = list(db['sold'].find(filt).sort('soldAt', -1).skip(skip).limit(limit))

    # Decrypt sebelum dikirim
    for d in docs:
        d['_id']      = str(d['_id'])
        d['uid']      = decrypt(d.get('uid', ''))
        d['password'] = decrypt(d.get('password', ''))

    return ok({'purchases': docs, 'total': total})

# ════════════════════════════════════════════════════════════════════════════
# TOPUP
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/topup/request', methods=['POST'])
@auth_required
@limiter.limit('5 per minute')
def topup_request():
    data = request.get_json(silent=True) or {}
    try:
        coins  = int(data.get('coins', 0))
        amount = int(data.get('amount', 0))
    except (ValueError, TypeError):
        return err('Data topup tidak valid')
    if coins <= 0 or amount <= 0:
        return err('Jumlah coins dan amount harus lebih dari 0')

    db       = get_db()
    topup_id = gen_id('TOP')
    db['topup'].insert_one({
        'topupId':   topup_id,
        'userId':    g.user['id'],
        'username':  g.user['username'],
        'packageId': sanitize_str(data.get('packageId', '')),
        'coins':     coins,
        'amount':    amount,
        'status':    'pending',
        'createdAt': datetime.now(timezone.utc),
    })
    return ok({'topupId': topup_id}, 'Request topup dikirim. Menunggu konfirmasi admin.', 201)


@app.route('/api/topup/history')
@auth_required
def topup_history():
    db   = get_db()
    hist = list(db['topup'].find({'userId': g.user['id']}).sort('createdAt', -1).limit(30))
    return ok({'history': [to_str_id(h) for h in hist]})

# ════════════════════════════════════════════════════════════════════════════
# ADMIN
# ════════════════════════════════════════════════════════════════════════════
@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    db        = get_db()
    today     = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_id    = db['ids'].count_documents({'status': 'available'})
    total_sold  = db['sold'].count_documents({})
    total_users = db['users'].count_documents({})
    pending_top = db['topup'].count_documents({'status': 'pending'})
    recent_tx   = list(db['transaksi'].find().sort('createdAt', -1).limit(5))

    rev_all   = list(db['transaksi'].aggregate([
        {'$match': {'status': 'success'}},
        {'$group': {'_id': None, 'total': {'$sum': '$price'}}}
    ]))
    rev_today = list(db['transaksi'].aggregate([
        {'$match': {'status': 'success', 'createdAt': {'$gte': today}}},
        {'$group': {'_id': None, 'total': {'$sum': '$price'}}}
    ]))

    return ok({
        'stats': {
            'totalId':          total_id,
            'totalSold':        total_sold,
            'totalUsers':       total_users,
            'pendingTopup':     pending_top,
            'pendapatan':       rev_all[0]['total'] if rev_all else 0,
            'pendapatanHariIni': rev_today[0]['total'] if rev_today else 0,
        },
        'recentTx': [to_str_id(t) for t in recent_tx],
    })


@app.route('/api/admin/ids', methods=['POST'])
@admin_required
@limiter.limit('30 per minute')
def admin_add_id():
    data     = request.get_json(silent=True) or {}
    game_id  = sanitize_str(data.get('gameId', ''))
    uid      = sanitize_str(data.get('uid', ''))
    password = sanitize_str(data.get('password', ''))
    tier     = sanitize_str(data.get('tier', '')).lower()
    note     = sanitize_str(data.get('note', ''), 500)

    if not all([game_id, uid, password, tier]):
        return err('gameId, uid, password, tier wajib diisi')
    if tier not in PRICE_MAP:
        return err('Tier tidak valid. Pilih: low/medium/high/legend')

    db = get_db()
    if db['ids'].find_one({'gameId': game_id}):
        return err('Game ID sudah ada di database', 409)

    result = db['ids'].insert_one({
        'gameId':   game_id,
        'uid':      encrypt(uid),       # 🔐 enkripsi
        'password': encrypt(password),  # 🔐 enkripsi
        'tier':     tier,
        'price':    PRICE_MAP[tier],
        'note':     note,
        'status':   'available',
        'addedBy':  g.user['id'],
        'addedAt':  datetime.now(timezone.utc),
    })
    db['admins'].update_one({'_id': safe_object_id(g.user['id'])}, {'$inc': {'totalIdDitambah': 1}})
    return ok({'id': str(result.inserted_id)}, f'ID {game_id} berhasil ditambahkan', 201)


@app.route('/api/admin/ids')
@admin_required
def admin_get_ids():
    status = sanitize_str(request.args.get('status', ''))
    tier   = sanitize_str(request.args.get('tier', ''))
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 25))))
    except ValueError:
        return err('Parameter tidak valid')

    db   = get_db()
    filt = {}
    if status: filt['status'] = status
    if tier:   filt['tier']   = tier

    skip  = (page - 1) * limit
    total = db['ids'].count_documents(filt)
    ids   = list(db['ids'].find(filt).sort('addedAt', -1).skip(skip).limit(limit))

    # Decrypt untuk admin
    result = []
    for i in ids:
        i['_id']      = str(i['_id'])
        i['uid']      = decrypt(i.get('uid', ''))
        i['password'] = decrypt(i.get('password', ''))
        result.append(i)

    return ok({'ids': result, 'total': total, 'page': page})


@app.route('/api/admin/ids/<id_str>', methods=['DELETE'])
@admin_required
def admin_delete_id(id_str):
    oid = safe_object_id(id_str)
    if not oid:
        return err('ID tidak valid')
    db = get_db()
    r  = db['ids'].delete_one({'_id': oid, 'status': 'available'})
    if not r.deleted_count:
        return err('ID tidak ditemukan atau sudah terjual', 404)
    return ok(msg='ID dihapus')


@app.route('/api/admin/users')
@admin_required
def admin_get_users():
    search = sanitize_str(request.args.get('search', ''))
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 25))))
    except ValueError:
        return err('Parameter tidak valid')

    db   = get_db()
    filt = {}
    if search:
        filt['$or'] = [
            {'username':   {'$regex': re.escape(search), '$options': 'i'}},
            {'fullName':   {'$regex': re.escape(search), '$options': 'i'}},
            {'emailPhone': {'$regex': re.escape(search), '$options': 'i'}},
        ]

    skip  = (page - 1) * limit
    total = db['users'].count_documents(filt)
    users = list(db['users'].find(filt, {'password': 0}).sort('createdAt', -1).skip(skip).limit(limit))
    return ok({'users': [to_str_id(u) for u in users], 'total': total, 'page': page})


@app.route('/api/admin/users/<user_id>/coins', methods=['PUT'])
@admin_required
def admin_edit_coins(user_id):
    data = request.get_json(silent=True) or {}
    try:
        coins = int(data.get('coins', -1))
    except (ValueError, TypeError):
        return err('Jumlah coins tidak valid')
    if coins < 0:
        return err('Coins tidak boleh negatif')

    oid = safe_object_id(user_id)
    if not oid:
        return err('User ID tidak valid')

    db = get_db()
    db['users'].update_one({'_id': oid}, {'$set': {'coins': coins, 'updatedAt': datetime.now(timezone.utc)}})
    return ok(msg='Coins diperbarui')


@app.route('/api/admin/transaksi')
@admin_required
def admin_get_transaksi():
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 30))))
    except ValueError:
        return err('Parameter tidak valid')

    db    = get_db()
    skip  = (page - 1) * limit
    total = db['transaksi'].count_documents({})
    txs   = list(db['transaksi'].find().sort('createdAt', -1).skip(skip).limit(limit))
    return ok({'transaksi': [to_str_id(t) for t in txs], 'total': total, 'page': page})


@app.route('/api/admin/topup')
@admin_required
def admin_get_topup():
    status = sanitize_str(request.args.get('status', ''))
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 20))))
    except ValueError:
        return err('Parameter tidak valid')

    db   = get_db()
    filt = {'status': status} if status else {}
    skip = (page - 1) * limit
    total  = db['topup'].count_documents(filt)
    topups = list(db['topup'].find(filt).sort('createdAt', -1).skip(skip).limit(limit))
    return ok({'topups': [to_str_id(t) for t in topups], 'total': total})


@app.route('/api/admin/topup/<topup_id>/approve', methods=['PUT'])
@admin_required
def admin_approve_topup(topup_id):
    db    = get_db()
    topup = db['topup'].find_one({'topupId': topup_id, 'status': 'pending'})
    if not topup:
        return err('Request tidak ditemukan atau sudah diproses', 404)

    user_oid = safe_object_id(topup['userId'])
    db['users'].update_one({'_id': user_oid}, {'$inc': {'coins': topup['coins']}, '$set': {'updatedAt': datetime.now(timezone.utc)}})
    db['topup'].update_one({'topupId': topup_id}, {'$set': {
        'status': 'approved', 'approvedBy': g.user['id'],
        'approvedAt': datetime.now(timezone.utc),
    }})
    return ok(msg=f'Topup disetujui. +{topup["coins"]:,} coins ke @{topup["username"]}')


@app.route('/api/admin/topup/<topup_id>/reject', methods=['PUT'])
@admin_required
def admin_reject_topup(topup_id):
    data   = request.get_json(silent=True) or {}
    reason = sanitize_str(data.get('reason', ''), 300)
    db     = get_db()
    topup  = db['topup'].find_one({'topupId': topup_id, 'status': 'pending'})
    if not topup:
        return err('Request tidak ditemukan atau sudah diproses', 404)

    db['topup'].update_one({'topupId': topup_id}, {'$set': {
        'status': 'rejected', 'rejectedBy': g.user['id'],
        'rejectedAt': datetime.now(timezone.utc), 'reason': reason,
    }})
    return ok(msg='Topup ditolak')


# ─── INIT ADMIN — otomatis terkunci setelah admin pertama ada ────────────────
@app.route('/api/admin/init', methods=['POST'])
@limiter.limit('3 per minute; 5 per hour')
def admin_init():
    data       = request.get_json(silent=True) or {}
    init_secret = data.get('initSecret', '')

    # Constant-time comparison untuk cegah timing attack
    if not hmac.compare_digest(str(init_secret), INIT_SECRET):
        return err('Init secret salah', 403)

    db = get_db()
    if db['admins'].find_one({}):
        return err('Endpoint dinonaktifkan. Admin sudah ada.', 403)

    username = sanitize_str(data.get('username', ''))
    password = data.get('password', '')
    fullname = sanitize_str(data.get('fullName', 'Admin lapakID'))

    if not username or not password:
        return err('Username dan password wajib diisi')
    if len(password) < 8:
        return err('Password admin minimal 8 karakter')

    hashed = hash_password(password)
    db['admins'].insert_one({
        'username':       username.lower(),
        'fullName':       fullname,
        'password':       hashed,
        'role':           'admin',
        'totalIdDitambah': 0,
        'createdAt':      datetime.now(timezone.utc),
    })
    logger.info(f'Admin created: {username}')
    return ok(msg='Admin berhasil dibuat! Endpoint ini sekarang terkunci otomatis.', code=201)


# ─── 404 & ERROR HANDLER ──────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return err('Endpoint tidak ditemukan', 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return err('Method tidak diizinkan', 405)

@app.errorhandler(429)
def too_many_requests(e):
    return err('Terlalu banyak request. Coba lagi nanti.', 429)

@app.errorhandler(500)
def server_error(e):
    logger.error(f'Unhandled error: {e}')
    return err('Internal server error', 500)


if __name__ == '__main__':
    create_indexes()
    port = int(os.environ.get('PORT', 5000))
    # Jangan pakai debug=True di production!
    app.run(host='0.0.0.0', port=port, debug=False)
