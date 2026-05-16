// api/index.js — lapakID Backend — semua endpoint 1 file (Vercel Serverless)
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto'); // built-in Node.js, tidak perlu install

const app = express();

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.options('*', cors());
app.use(express.json());

// ─── CONFIG ──────────────────────────────────────────────────────────────────
// ⚠️  JANGAN hardcode credential di sini — semua harus dari env variable Vercel
const MONGO_URI    = process.env.MONGODB_URI;   // WAJIB diset di Vercel
const JWT_SECRET   = process.env.JWT_SECRET;    // WAJIB diset di Vercel
const INIT_SECRET  = process.env.INIT_SECRET  || 'lapakid_init_2026';
const ENC_KEY      = process.env.ENC_KEY;       // 32-char hex key untuk enkripsi UID/password
const JWT_EXPIRES  = '7d';
const PRICE_MAP    = { low: 125000, medium: 450000, high: 850000, legend: 1350000 };

// Validasi env variables wajib
if (!MONGO_URI)  throw new Error('MONGODB_URI environment variable tidak diset!');
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable tidak diset!');

// ─── ENKRIPSI UID & PASSWORD ID (AES-256-GCM) ────────────────────────────────
// Digunakan untuk menyimpan credentials ID game secara aman di MongoDB
// ENC_KEY harus 64 hex chars (32 bytes) — generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

function encrypt(text) {
  if (!ENC_KEY || !text) return text; // fallback jika ENC_KEY belum diset
  try {
    const key = Buffer.from(ENC_KEY, 'hex');
    const iv  = crypto.randomBytes(12); // 96-bit IV untuk GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag(); // authentication tag untuk verifikasi integritas
    // Format: iv(24) + tag(32) + encrypted — semua hex
    return iv.toString('hex') + tag.toString('hex') + encrypted.toString('hex');
  } catch (e) {
    console.error('Encrypt error:', e.message);
    return text;
  }
}

function decrypt(encText) {
  if (!ENC_KEY || !encText) return encText;
  // Kalau bukan format enkripsi (data lama plain text), return as-is
  if (encText.length < 56) return encText;
  try {
    const key       = Buffer.from(ENC_KEY, 'hex');
    const iv        = Buffer.from(encText.slice(0, 24), 'hex');
    const tag       = Buffer.from(encText.slice(24, 56), 'hex');
    const encrypted = Buffer.from(encText.slice(56), 'hex');
    const decipher  = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final('utf8');
  } catch (e) {
    // Kalau gagal decrypt (mungkin data lama), return as-is
    return encText;
  }
}

// ─── DATABASE (cached connection untuk serverless) ───────────────────────────
let _client = null;

async function getDb() {
  if (_client) {
    try {
      // ping untuk cek koneksi masih hidup
      await _client.db('admin').command({ ping: 1 });
      return _client.db('lapakid');
    } catch (_) {
      _client = null;
    }
  }
  _client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 8000,
  });
  await _client.connect();
  return _client.db('lapakid');
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer '))
    return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Token expired, silakan login ulang' });
  }
}

function adminOnly(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'admin')
      return res.status(403).json({ success: false, message: 'Hanya admin yang bisa akses ini' });
    next();
  });
}

function genId(prefix = 'TX') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2,8).toUpperCase()}`;
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, fullName, emailPhone, password } = req.body;
    if (!username || !fullName || !emailPhone || !password)
      return res.status(400).json({ success: false, message: 'Semua field wajib diisi' });
    if (password.length < 6)
      return res.status(400).json({ success: false, message: 'Password minimal 6 karakter' });

    const db = await getDb();
    const existing = await db.collection('users').findOne({
      $or: [{ username: username.toLowerCase() }, { emailPhone }]
    });
    if (existing) {
      const field = existing.username === username.toLowerCase() ? 'Username' : 'Email/WhatsApp';
      return res.status(409).json({ success: false, message: `${field} sudah terdaftar` });
    }

    const hashed = await bcrypt.hash(password, 10);
    const doc = {
      username: username.toLowerCase(),
      fullName,
      emailPhone,
      password: hashed,
      role: 'user',
      coins: 0,
      avatar: null,
      totalTransaksi: { success: 0, pending: 0, gagal: 0 },
      cart: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };
    const result = await db.collection('users').insertOne(doc);
    const token = jwt.sign({ id: result.insertedId.toString(), username: doc.username, role: 'user' }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    return res.status(201).json({
      success: true, message: 'Pendaftaran berhasil', token,
      user: { id: result.insertedId, username: doc.username, fullName, emailPhone, role: 'user', coins: 0 }
    });
  } catch (err) {
    console.error('register:', err);
    return res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });

    const db = await getDb();
    let user = await db.collection('users').findOne({ username: username.toLowerCase() });
    let role = user?.role || 'user';

    if (!user) {
      user = await db.collection('admins').findOne({ username: username.toLowerCase() });
      if (user) role = 'admin';
    }

    if (!user)
      return res.status(401).json({ success: false, message: 'Username atau password salah' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(401).json({ success: false, message: 'Username atau password salah' });

    const token = jwt.sign({ id: user._id.toString(), username: user.username, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    return res.json({
      success: true, message: 'Login berhasil', token,
      user: { id: user._id, username: user.username, fullName: user.fullName, emailPhone: user.emailPhone, role, coins: user.coins || 0, avatar: user.avatar || null, totalTransaksi: user.totalTransaksi || {} }
    });
  } catch (err) {
    console.error('login:', err);
    return res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const db = await getDb();
    const col = req.user.role === 'admin' ? 'admins' : 'users';
    const user = await db.collection(col).findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    return res.json({ success: true, user: { ...user, role: req.user.role } });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// USER
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/user/profile', auth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    return res.json({ success: true, user });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/user/profile', auth, async (req, res) => {
  try {
    const { fullName, emailPhone, avatar } = req.body;
    const db = await getDb();
    const upd = { updatedAt: new Date() };
    if (fullName) upd.fullName = fullName;
    if (emailPhone) upd.emailPhone = emailPhone;
    if (avatar !== undefined) upd.avatar = avatar;
    await db.collection('users').updateOne({ _id: new ObjectId(req.user.id) }, { $set: upd });
    return res.json({ success: true, message: 'Profil diperbarui' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ─── CART ─────────────────────────────────────────────────────────────────────
app.get('/api/user/cart', auth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) }, { projection: { cart: 1 } });
    return res.json({ success: true, cart: user?.cart || [] });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/user/cart', auth, async (req, res) => {
  try {
    const { idItem } = req.body;
    if (!idItem) return res.status(400).json({ success: false, message: 'idItem wajib diisi' });
    const db = await getDb();
    const idDoc = await db.collection('ids').findOne({ _id: new ObjectId(idItem), status: 'available' });
    if (!idDoc) return res.status(404).json({ success: false, message: 'ID tidak tersedia' });
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (user?.cart?.some(c => c.idItem === idItem))
      return res.status(409).json({ success: false, message: 'ID sudah ada di keranjang' });
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $push: { cart: { idItem, gameId: idDoc.gameId, tier: idDoc.tier, price: idDoc.price, addedAt: new Date() } }, $set: { updatedAt: new Date() } }
    );
    return res.json({ success: true, message: 'Ditambahkan ke keranjang' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/user/cart/:idItem', auth, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $pull: { cart: { idItem: req.params.idItem } }, $set: { updatedAt: new Date() } }
    );
    return res.json({ success: true, message: 'Item dihapus' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/user/cart', auth, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('users').updateOne({ _id: new ObjectId(req.user.id) }, { $set: { cart: [], updatedAt: new Date() } });
    return res.json({ success: true, message: 'Keranjang dikosongkan' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// IDS (public)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/ids', async (req, res) => {
  try {
    const { tier, sort, page = 1, limit = 24 } = req.query;
    const db = await getDb();
    const filter = { status: 'available' };
    if (tier) filter.tier = tier;
    const sortOpt = sort === 'price_asc' ? { price: 1 } : sort === 'price_desc' ? { price: -1 } : { addedAt: -1 };
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, ids] = await Promise.all([
      db.collection('ids').countDocuments(filter),
      db.collection('ids').find(filter, { projection: { uid: 0, password: 0 } }).sort(sortOpt).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    return res.json({ success: true, ids, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/ids/:id', async (req, res) => {
  try {
    const db = await getDb();
    const doc = await db.collection('ids').findOne({ _id: new ObjectId(req.params.id), status: 'available' }, { projection: { uid: 0, password: 0 } });
    if (!doc) return res.status(404).json({ success: false, message: 'ID tidak ditemukan atau sudah terjual' });
    return res.json({ success: true, id: doc });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// PAYMENT
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/payment/buy', auth, async (req, res) => {
  try {
    const { idItem } = req.body;
    if (!idItem) return res.status(400).json({ success: false, message: 'idItem wajib diisi' });
    const db = await getDb();

    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });

    // Atomic lock: set status sold sekaligus
    const r = await db.collection('ids').findOneAndUpdate(
      { _id: new ObjectId(idItem), status: 'available' },
      { $set: { status: 'sold', soldAt: new Date(), soldTo: req.user.id } },
      { returnDocument: 'before' }
    );
    const idDoc = r?.value || r; // driver v5 returns doc directly
    if (!idDoc || !idDoc._id)
      return res.status(404).json({ success: false, message: 'ID tidak tersedia atau sudah terjual' });

    if (user.coins < idDoc.price) {
      // Rollback
      await db.collection('ids').updateOne({ _id: idDoc._id }, { $set: { status: 'available', soldAt: null, soldTo: null } });
      return res.status(402).json({ success: false, message: `Saldo tidak cukup. Saldo: Rp${user.coins.toLocaleString()}, Harga: Rp${idDoc.price.toLocaleString()}` });
    }

    const newCoins = user.coins - idDoc.price;
    const txId = genId('TX');

    await Promise.all([
      db.collection('users').updateOne(
        { _id: new ObjectId(req.user.id) },
        { $set: { coins: newCoins, updatedAt: new Date() }, $inc: { 'totalTransaksi.success': 1 }, $pull: { cart: { idItem } } }
      ),
      db.collection('transaksi').insertOne({ txId, userId: req.user.id, username: user.username, idDocId: idDoc._id.toString(), gameId: idDoc.gameId, tier: idDoc.tier, price: idDoc.price, status: 'success', createdAt: new Date() }),
      // Simpan terenkripsi di collection sold juga
      db.collection('sold').insertOne({ txId, userId: req.user.id, username: user.username, gameId: idDoc.gameId, uid: idDoc.uid, password: idDoc.password, tier: idDoc.tier, price: idDoc.price, note: idDoc.note || '', soldAt: new Date() })
    ]);

    // Decrypt credentials sebelum dikirim ke pembeli
    return res.json({ success: true, message: 'Pembelian berhasil!', transaction: { txId, gameId: idDoc.gameId, uid: decrypt(idDoc.uid), password: decrypt(idDoc.password), tier: idDoc.tier, price: idDoc.price, newCoins } });
  } catch (err) {
    console.error('buy:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/payment/buy-cart', auth, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (!user?.cart?.length) return res.status(400).json({ success: false, message: 'Keranjang kosong' });

    const locked = [], failed = [];
    for (const item of user.cart) {
      const r = await db.collection('ids').findOneAndUpdate(
        { _id: new ObjectId(item.idItem), status: 'available' },
        { $set: { status: 'sold', soldAt: new Date(), soldTo: req.user.id } },
        { returnDocument: 'before' }
      );
      const doc = r?.value || r;
      if (doc?._id) locked.push(doc); else failed.push(item.idItem);
    }
    if (!locked.length) return res.status(404).json({ success: false, message: 'Semua ID di keranjang tidak tersedia' });

    const total = locked.reduce((s, d) => s + d.price, 0);
    if (user.coins < total) {
      for (const d of locked) await db.collection('ids').updateOne({ _id: d._id }, { $set: { status: 'available', soldAt: null, soldTo: null } });
      return res.status(402).json({ success: false, message: `Saldo tidak cukup. Total: Rp${total.toLocaleString()}, Saldo: Rp${user.coins.toLocaleString()}` });
    }

    const purchases = [];
    for (const d of locked) {
      const txId = genId('TX');
      await Promise.all([
        db.collection('transaksi').insertOne({ txId, userId: req.user.id, username: user.username, idDocId: d._id.toString(), gameId: d.gameId, tier: d.tier, price: d.price, status: 'success', createdAt: new Date() }),
        db.collection('sold').insertOne({ txId, userId: req.user.id, username: user.username, gameId: d.gameId, uid: d.uid, password: d.password, tier: d.tier, price: d.price, note: d.note || '', soldAt: new Date() })
      ]);
      purchases.push({ txId, gameId: d.gameId, uid: decrypt(d.uid), password: decrypt(d.password), tier: d.tier, price: d.price });
    }

    const newCoins = user.coins - total;
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { coins: newCoins, cart: [], updatedAt: new Date() }, $inc: { 'totalTransaksi.success': locked.length } }
    );

    return res.json({ success: true, message: `${locked.length} ID berhasil dibeli`, purchases, newCoins, failedItems: failed.length ? failed : undefined });
  } catch (err) {
    console.error('buy-cart:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// TRANSAKSI
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/transaksi', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const db = await getDb();
    const filter = { userId: req.user.id };
    if (status) filter.status = status;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, transaksi] = await Promise.all([
      db.collection('transaksi').countDocuments(filter),
      db.collection('transaksi').find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    return res.json({ success: true, transaksi, total, page: parseInt(page) });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/transaksi/purchases', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, purchases] = await Promise.all([
      db.collection('sold').countDocuments({ userId: req.user.id }),
      db.collection('sold').find({ userId: req.user.id }).sort({ soldAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    // Decrypt credentials sebelum dikirim ke user
    const decrypted = purchases.map(p => ({
      ...p,
      uid:      decrypt(p.uid),
      password: decrypt(p.password)
    }));
    return res.json({ success: true, purchases: decrypted, total });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// TOPUP
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/topup/request', auth, async (req, res) => {
  try {
    const { packageId, coins, amount } = req.body;
    if (!coins || !amount) return res.status(400).json({ success: false, message: 'Data topup tidak lengkap' });
    const db = await getDb();
    const topupId = genId('TOP');
    await db.collection('topup').insertOne({ topupId, userId: req.user.id, username: req.user.username, packageId: packageId || null, coins: parseInt(coins), amount: parseInt(amount), status: 'pending', createdAt: new Date() });
    return res.json({ success: true, message: 'Request topup dikirim. Menunggu konfirmasi admin.', topupId });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/topup/history', auth, async (req, res) => {
  try {
    const db = await getDb();
    const history = await db.collection('topup').find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(30).toArray();
    return res.json({ success: true, history });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// ADMIN
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', adminOnly, async (req, res) => {
  try {
    const db = await getDb();
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const [totalId, totalSold, totalUsers, pendingTopup, recentTx, revAll, revToday] = await Promise.all([
      db.collection('ids').countDocuments({ status: 'available' }),
      db.collection('sold').countDocuments(),
      db.collection('users').countDocuments(),
      db.collection('topup').countDocuments({ status: 'pending' }),
      db.collection('transaksi').find().sort({ createdAt: -1 }).limit(5).toArray(),
      db.collection('transaksi').aggregate([{ $match: { status: 'success' } }, { $group: { _id: null, t: { $sum: '$price' } } }]).toArray(),
      db.collection('transaksi').aggregate([{ $match: { status: 'success', createdAt: { $gte: todayStart } } }, { $group: { _id: null, t: { $sum: '$price' } } }]).toArray()
    ]);
    return res.json({ success: true, stats: { totalId, totalSold, totalUsers, pendingTopup, pendapatan: revAll[0]?.t || 0, pendapatanHariIni: revToday[0]?.t || 0 }, recentTx });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 25, search } = req.query;
    const db = await getDb();
    const filter = search ? { $or: [{ username: { $regex: search, $options: 'i' } }, { fullName: { $regex: search, $options: 'i' } }, { emailPhone: { $regex: search, $options: 'i' } }] } : {};
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, users] = await Promise.all([
      db.collection('users').countDocuments(filter),
      db.collection('users').find(filter, { projection: { password: 0 } }).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    return res.json({ success: true, users, total, page: parseInt(page) });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/admin/ids', adminOnly, async (req, res) => {
  try {
    const { gameId, uid, password, tier, note } = req.body;
    if (!gameId || !uid || !password || !tier)
      return res.status(400).json({ success: false, message: 'gameId, uid, password, tier wajib diisi' });
    const t = tier.toLowerCase();
    if (!PRICE_MAP[t])
      return res.status(400).json({ success: false, message: 'Tier tidak valid. Pilih: low/medium/high/legend' });
    const db = await getDb();
    const exists = await db.collection('ids').findOne({ gameId });
    if (exists) return res.status(409).json({ success: false, message: 'Game ID sudah ada di database' });

    // Enkripsi UID & password sebelum disimpan ke MongoDB
    const result = await db.collection('ids').insertOne({
      gameId,
      uid: encrypt(uid),           // 🔐 tersimpan terenkripsi
      password: encrypt(password), // 🔐 tersimpan terenkripsi
      tier: t,
      price: PRICE_MAP[t],
      note: note || '',
      status: 'available',
      addedBy: req.user.id,
      addedAt: new Date()
    });
    await db.collection('admins').updateOne({ _id: new ObjectId(req.user.id) }, { $inc: { totalIdDitambah: 1 } });
    return res.status(201).json({ success: true, message: `ID ${gameId} berhasil ditambahkan`, id: result.insertedId });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/ids', adminOnly, async (req, res) => {
  try {
    const { status, tier, page = 1, limit = 25 } = req.query;
    const db = await getDb();
    const filter = {};
    if (status) filter.status = status;
    if (tier) filter.tier = tier;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, ids] = await Promise.all([
      db.collection('ids').countDocuments(filter),
      db.collection('ids').find(filter).sort({ addedAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    // Decrypt UID & password untuk tampilan admin
    const result = ids.map(id => ({ ...id, uid: decrypt(id.uid), password: decrypt(id.password) }));
    return res.json({ success: true, ids: result, total, page: parseInt(page) });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/admin/ids/:id', adminOnly, async (req, res) => {
  try {
    const db = await getDb();
    const r = await db.collection('ids').deleteOne({ _id: new ObjectId(req.params.id), status: 'available' });
    if (!r.deletedCount) return res.status(404).json({ success: false, message: 'ID tidak ditemukan atau sudah terjual' });
    return res.json({ success: true, message: 'ID dihapus' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/transaksi', adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 30, status, userId } = req.query;
    const db = await getDb();
    const filter = {};
    if (status) filter.status = status;
    if (userId) filter.userId = userId;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, transaksi] = await Promise.all([
      db.collection('transaksi').countDocuments(filter),
      db.collection('transaksi').find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    return res.json({ success: true, transaksi, total, page: parseInt(page) });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/topup', adminOnly, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const filter = status ? { status } : {};
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const [total, topups] = await Promise.all([
      db.collection('topup').countDocuments(filter),
      db.collection('topup').find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).toArray()
    ]);
    return res.json({ success: true, topups, total });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/topup/:topupId/approve', adminOnly, async (req, res) => {
  try {
    const db = await getDb();
    const topup = await db.collection('topup').findOne({ topupId: req.params.topupId, status: 'pending' });
    if (!topup) return res.status(404).json({ success: false, message: 'Request topup tidak ditemukan atau sudah diproses' });
    await Promise.all([
      db.collection('users').updateOne({ _id: new ObjectId(topup.userId) }, { $inc: { coins: topup.coins }, $set: { updatedAt: new Date() } }),
      db.collection('topup').updateOne({ topupId: req.params.topupId }, { $set: { status: 'approved', approvedBy: req.user.id, approvedAt: new Date() } })
    ]);
    return res.json({ success: true, message: `Topup disetujui. +${topup.coins} coins ke @${topup.username}` });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/topup/:topupId/reject', adminOnly, async (req, res) => {
  try {
    const db = await getDb();
    const topup = await db.collection('topup').findOne({ topupId: req.params.topupId, status: 'pending' });
    if (!topup) return res.status(404).json({ success: false, message: 'Request tidak ditemukan atau sudah diproses' });
    await db.collection('topup').updateOne({ topupId: req.params.topupId }, { $set: { status: 'rejected', rejectedBy: req.user.id, rejectedAt: new Date(), reason: req.body.reason || '' } });
    return res.json({ success: true, message: 'Topup ditolak' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/users/:userId/coins', adminOnly, async (req, res) => {
  try {
    const { coins } = req.body;
    if (coins === undefined || isNaN(coins)) return res.status(400).json({ success: false, message: 'Jumlah coins tidak valid' });
    const db = await getDb();
    await db.collection('users').updateOne({ _id: new ObjectId(req.params.userId) }, { $set: { coins: parseInt(coins), updatedAt: new Date() } });
    return res.json({ success: true, message: 'Coins diperbarui' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ─── INIT ADMIN (jalankan sekali) ─────────────────────────────────────────────
app.post('/api/admin/init', async (req, res) => {
  try {
    const { username, password, fullName, initSecret } = req.body;
    if (initSecret !== INIT_SECRET)
      return res.status(403).json({ success: false, message: 'Init secret salah' });
    const db = await getDb();
    if (await db.collection('admins').findOne({ username: username.toLowerCase() }))
      return res.status(409).json({ success: false, message: 'Admin sudah ada' });
    const hashed = await bcrypt.hash(password, 10);
    await db.collection('admins').insertOne({ username: username.toLowerCase(), fullName: fullName || 'Admin lapakID', password: hashed, role: 'admin', totalIdDitambah: 0, createdAt: new Date() });
    return res.status(201).json({ success: true, message: 'Admin berhasil dibuat. Sekarang bisa login!' });
  } catch (err) { return res.status(500).json({ success: false, message: err.message }); }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await getDb();
    res.json({ success: true, message: 'lapakID API OK', db: 'connected', time: new Date() });
  } catch (err) {
    res.status(500).json({ success: false, message: 'DB error: ' + err.message });
  }
});

app.use('/api/*', (req, res) => res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan' }));

// ─── EXPORT untuk Vercel Serverless ──────────────────────────────────────────
module.exports = app;
