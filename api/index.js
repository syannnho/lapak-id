// api/index.js — lapakID Backend (semua endpoint dalam 1 file untuk Vercel)
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ─── CONFIG ────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGODB_URI || 'mongodb+srv://n4taza_db:N44E8WEKlOJLZIHQ@cluster0.pdfnlfb.mongodb.net/?appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'lapakid_secret_key_2026_change_in_prod';
const JWT_EXPIRES = '7d';

// Harga tier
const PRICE_MAP = { low: 125000, medium: 450000, high: 850000, legend: 1350000 };

// ─── DATABASE ──────────────────────────────────────────────────────────────
let cachedClient = null;

async function getDb() {
  if (cachedClient && cachedClient.topology && cachedClient.topology.isConnected()) {
    return cachedClient.db('lapakid');
  }
  const client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
    maxPoolSize: 10,
  });
  await client.connect();
  cachedClient = client;
  return client.db('lapakid');
}

// ─── MIDDLEWARE AUTH ────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Token tidak valid atau kadaluarsa' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Akses ditolak: bukan admin' });
    }
    next();
  });
}

// ─── HELPER ────────────────────────────────────────────────────────────────
function genId(prefix = 'TX') {
  return prefix + '_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, fullName, emailPhone, password } = req.body;
    if (!username || !fullName || !emailPhone || !password) {
      return res.status(400).json({ success: false, message: 'Semua field wajib diisi' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password minimal 6 karakter' });
    }

    const db = await getDb();
    const users = db.collection('users');

    const existing = await users.findOne({
      $or: [{ username: username.toLowerCase() }, { emailPhone }]
    });
    if (existing) {
      const field = existing.username === username.toLowerCase() ? 'Username' : 'Email/WhatsApp';
      return res.status(409).json({ success: false, message: `${field} sudah terdaftar` });
    }

    const hashedPass = await bcrypt.hash(password, 10);
    const newUser = {
      username: username.toLowerCase(),
      fullName,
      emailPhone,
      password: hashedPass,
      role: 'user',
      coins: 0,
      avatar: null,
      totalTransaksi: { success: 0, pending: 0, gagal: 0 },
      cart: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await users.insertOne(newUser);
    const token = jwt.sign(
      { id: result.insertedId.toString(), username: newUser.username, role: 'user' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    return res.status(201).json({
      success: true,
      message: 'Pendaftaran berhasil',
      token,
      user: {
        id: result.insertedId,
        username: newUser.username,
        fullName: newUser.fullName,
        emailPhone: newUser.emailPhone,
        role: 'user',
        coins: 0,
        avatar: null
      }
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
    }

    const db = await getDb();
    const users = db.collection('users');
    const admins = db.collection('admins');

    // Cek user biasa
    let user = await users.findOne({ username: username.toLowerCase() });
    let isAdmin = false;

    // Kalau tidak ketemu di users, cek admins
    if (!user) {
      user = await admins.findOne({ username: username.toLowerCase() });
      if (user) isAdmin = true;
    }

    if (!user) {
      return res.status(401).json({ success: false, message: 'Username atau password salah' });
    }

    const passMatch = await bcrypt.compare(password, user.password);
    if (!passMatch) {
      return res.status(401).json({ success: false, message: 'Username atau password salah' });
    }

    const role = isAdmin ? 'admin' : (user.role || 'user');
    const token = jwt.sign(
      { id: user._id.toString(), username: user.username, role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    return res.json({
      success: true,
      message: 'Login berhasil',
      token,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        emailPhone: user.emailPhone,
        role,
        coins: user.coins || 0,
        avatar: user.avatar || null,
        totalTransaksi: user.totalTransaksi || { success: 0, pending: 0, gagal: 0 }
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// GET /api/auth/me — ambil data user yang sedang login
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const collection = req.user.role === 'admin' ? db.collection('admins') : db.collection('users');
    const user = await collection.findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { password: 0 } }
    );
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    return res.json({ success: true, user: { ...user, role: req.user.role } });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/user/profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { password: 0 } }
    );
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    return res.json({ success: true, user });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/user/profile — update profil user
app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const { fullName, emailPhone, avatar } = req.body;
    const db = await getDb();
    const updateFields = { updatedAt: new Date() };
    if (fullName) updateFields.fullName = fullName;
    if (emailPhone) updateFields.emailPhone = emailPhone;
    if (avatar !== undefined) updateFields.avatar = avatar;

    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: updateFields }
    );
    return res.json({ success: true, message: 'Profil berhasil diperbarui' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ─── CART ──────────────────────────────────────────────────────────────────

// GET /api/user/cart
app.get('/api/user/cart', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { cart: 1 } }
    );
    return res.json({ success: true, cart: user?.cart || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/user/cart — tambah item ke cart
app.post('/api/user/cart', authMiddleware, async (req, res) => {
  try {
    const { idItem } = req.body; // idItem = _id dari collection 'ids'
    if (!idItem) return res.status(400).json({ success: false, message: 'idItem wajib diisi' });

    const db = await getDb();
    // Cek apakah ID masih tersedia
    const idDoc = await db.collection('ids').findOne({ _id: new ObjectId(idItem), status: 'available' });
    if (!idDoc) return res.status(404).json({ success: false, message: 'ID tidak tersedia' });

    // Cek duplikat di cart
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (user.cart && user.cart.some(c => c.idItem === idItem)) {
      return res.status(409).json({ success: false, message: 'ID sudah ada di keranjang' });
    }

    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $push: {
          cart: {
            idItem,
            gameId: idDoc.gameId,
            tier: idDoc.tier,
            price: idDoc.price,
            addedAt: new Date()
          }
        },
        $set: { updatedAt: new Date() }
      }
    );
    return res.json({ success: true, message: 'ID ditambahkan ke keranjang' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/user/cart/:idItem — hapus dari cart
app.delete('/api/user/cart/:idItem', authMiddleware, async (req, res) => {
  try {
    const { idItem } = req.params;
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $pull: { cart: { idItem } }, $set: { updatedAt: new Date() } }
    );
    return res.json({ success: true, message: 'Item dihapus dari keranjang' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/user/cart — kosongkan semua cart
app.delete('/api/user/cart', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { cart: [], updatedAt: new Date() } }
    );
    return res.json({ success: true, message: 'Keranjang dikosongkan' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ID ROUTES (browsing untuk user)
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/ids — ambil semua ID yang tersedia (available)
app.get('/api/ids', async (req, res) => {
  try {
    const { tier, sort, page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const filter = { status: 'available' };
    if (tier) filter.tier = tier;

    const sortOpt = sort === 'price_asc' ? { price: 1 }
      : sort === 'price_desc' ? { price: -1 }
      : sort === 'newest' ? { addedAt: -1 }
      : { addedAt: -1 };

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('ids').countDocuments(filter);
    const ids = await db.collection('ids')
      .find(filter, { projection: { uid: 0, password: 0 } }) // sembunyikan credentials
      .sort(sortOpt)
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, ids, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/ids/:id — detail satu ID (tanpa credentials)
app.get('/api/ids/:id', async (req, res) => {
  try {
    const db = await getDb();
    const doc = await db.collection('ids').findOne(
      { _id: new ObjectId(req.params.id), status: 'available' },
      { projection: { uid: 0, password: 0 } }
    );
    if (!doc) return res.status(404).json({ success: false, message: 'ID tidak ditemukan' });
    return res.json({ success: true, id: doc });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PAYMENT / TRANSAKSI ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/payment/buy — beli 1 ID langsung
app.post('/api/payment/buy', authMiddleware, async (req, res) => {
  try {
    const { idItem } = req.body;
    if (!idItem) return res.status(400).json({ success: false, message: 'idItem wajib diisi' });

    const db = await getDb();
    const users = db.collection('users');
    const ids = db.collection('ids');
    const sold = db.collection('sold');
    const transaksi = db.collection('transaksi');

    // Ambil data user
    const user = await users.findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });

    // Ambil data ID — LOCK dengan findOneAndUpdate untuk hindari race condition
    const idDoc = await ids.findOneAndUpdate(
      { _id: new ObjectId(idItem), status: 'available' },
      { $set: { status: 'sold', soldAt: new Date(), soldTo: req.user.id } },
      { returnDocument: 'before' }
    );

    if (!idDoc || !idDoc.value) {
      return res.status(404).json({ success: false, message: 'ID tidak tersedia atau sudah terjual' });
    }

    const id = idDoc.value;

    // Cek saldo
    if (user.coins < id.price) {
      // Kembalikan status ID kalau saldo kurang
      await ids.updateOne({ _id: id._id }, { $set: { status: 'available', soldAt: null, soldTo: null } });
      return res.status(402).json({
        success: false,
        message: `Saldo tidak mencukupi. Saldo: Rp${user.coins.toLocaleString()}, Harga: Rp${id.price.toLocaleString()}`
      });
    }

    // Kurangi saldo
    const newCoins = user.coins - id.price;
    await users.updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $set: { coins: newCoins, updatedAt: new Date() },
        $inc: { 'totalTransaksi.success': 1 },
        $pull: { cart: { idItem: idItem } }
      }
    );

    // Buat record transaksi
    const txId = genId('TX');
    const txRecord = {
      txId,
      userId: req.user.id,
      username: user.username,
      idDocId: id._id.toString(),
      gameId: id.gameId,
      tier: id.tier,
      price: id.price,
      status: 'success',
      createdAt: new Date()
    };
    await transaksi.insertOne(txRecord);

    // Simpan ke koleksi sold (dengan credentials — hanya bisa diakses user yang beli)
    await sold.insertOne({
      txId,
      userId: req.user.id,
      username: user.username,
      gameId: id.gameId,
      uid: id.uid,
      password: id.password,
      tier: id.tier,
      price: id.price,
      note: id.note || '',
      soldAt: new Date()
    });

    return res.json({
      success: true,
      message: 'Pembelian berhasil!',
      transaction: {
        txId,
        gameId: id.gameId,
        uid: id.uid,
        password: id.password,
        tier: id.tier,
        price: id.price,
        newCoins
      }
    });
  } catch (err) {
    console.error('Buy error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/payment/buy-cart — beli semua item di cart
app.post('/api/payment/buy-cart', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const users = db.collection('users');
    const ids = db.collection('ids');
    const sold = db.collection('sold');
    const transaksi = db.collection('transaksi');

    const user = await users.findOne({ _id: new ObjectId(req.user.id) });
    if (!user || !user.cart || user.cart.length === 0) {
      return res.status(400).json({ success: false, message: 'Keranjang kosong' });
    }

    const results = [];
    let totalHarga = 0;
    const failedItems = [];

    for (const cartItem of user.cart) {
      try {
        const idDoc = await ids.findOneAndUpdate(
          { _id: new ObjectId(cartItem.idItem), status: 'available' },
          { $set: { status: 'sold', soldAt: new Date(), soldTo: req.user.id } },
          { returnDocument: 'before' }
        );
        if (idDoc && idDoc.value) {
          totalHarga += idDoc.value.price;
          results.push({ cartItem, idDoc: idDoc.value });
        } else {
          failedItems.push(cartItem.idItem);
        }
      } catch (e) {
        failedItems.push(cartItem.idItem);
      }
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Semua ID di keranjang tidak tersedia' });
    }

    if (user.coins < totalHarga) {
      // Kembalikan semua ID
      for (const r of results) {
        await ids.updateOne({ _id: r.idDoc._id }, { $set: { status: 'available', soldAt: null, soldTo: null } });
      }
      return res.status(402).json({
        success: false,
        message: `Saldo tidak mencukupi. Total: Rp${totalHarga.toLocaleString()}, Saldo: Rp${user.coins.toLocaleString()}`
      });
    }

    const newCoins = user.coins - totalHarga;
    const purchases = [];

    for (const r of results) {
      const txId = genId('TX');
      await transaksi.insertOne({
        txId,
        userId: req.user.id,
        username: user.username,
        idDocId: r.idDoc._id.toString(),
        gameId: r.idDoc.gameId,
        tier: r.idDoc.tier,
        price: r.idDoc.price,
        status: 'success',
        createdAt: new Date()
      });
      await sold.insertOne({
        txId,
        userId: req.user.id,
        username: user.username,
        gameId: r.idDoc.gameId,
        uid: r.idDoc.uid,
        password: r.idDoc.password,
        tier: r.idDoc.tier,
        price: r.idDoc.price,
        note: r.idDoc.note || '',
        soldAt: new Date()
      });
      purchases.push({
        txId,
        gameId: r.idDoc.gameId,
        uid: r.idDoc.uid,
        password: r.idDoc.password,
        tier: r.idDoc.tier,
        price: r.idDoc.price
      });
    }

    await users.updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $set: { coins: newCoins, cart: [], updatedAt: new Date() },
        $inc: { 'totalTransaksi.success': results.length }
      }
    );

    return res.json({
      success: true,
      message: `${results.length} ID berhasil dibeli`,
      purchases,
      newCoins,
      failedItems: failedItems.length > 0 ? failedItems : undefined
    });
  } catch (err) {
    console.error('Buy cart error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// TRANSAKSI / RIWAYAT USER
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/transaksi — riwayat transaksi user yang login
app.get('/api/transaksi', authMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const db = await getDb();
    const filter = { userId: req.user.id };
    if (status) filter.status = status;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('transaksi').countDocuments(filter);
    const txList = await db.collection('transaksi')
      .find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, transaksi: txList, total, page: parseInt(page) });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/transaksi/purchases — riwayat pembelian user dengan credentials
app.get('/api/transaksi/purchases', authMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const filter = { userId: req.user.id };
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('sold').countDocuments(filter);
    const purchases = await db.collection('sold')
      .find(filter)
      .sort({ soldAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, purchases, total });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// TOPUP ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/topup/request — user request topup (admin yg approve)
app.post('/api/topup/request', authMiddleware, async (req, res) => {
  try {
    const { packageId, coins, amount } = req.body;
    if (!coins || !amount) return res.status(400).json({ success: false, message: 'Data topup tidak lengkap' });

    const db = await getDb();
    const topupId = genId('TOP');
    await db.collection('topup').insertOne({
      topupId,
      userId: req.user.id,
      username: req.user.username,
      packageId: packageId || null,
      coins: parseInt(coins),
      amount: parseInt(amount),
      status: 'pending',
      createdAt: new Date()
    });

    return res.json({ success: true, message: 'Request topup berhasil dikirim. Menunggu konfirmasi admin.', topupId });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/topup/history — riwayat topup user
app.get('/api/topup/history', authMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const history = await db.collection('topup')
      .find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(20)
      .toArray();
    return res.json({ success: true, history });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/admin/stats — dashboard stats
app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const [totalId, totalSold, totalUsers, pendingTopup, recentTx] = await Promise.all([
      db.collection('ids').countDocuments({ status: 'available' }),
      db.collection('sold').countDocuments(),
      db.collection('users').countDocuments(),
      db.collection('topup').countDocuments({ status: 'pending' }),
      db.collection('transaksi').find().sort({ createdAt: -1 }).limit(5).toArray()
    ]);

    const pendapatanAgg = await db.collection('transaksi').aggregate([
      { $match: { status: 'success' } },
      { $group: { _id: null, total: { $sum: '$price' } } }
    ]).toArray();

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const pendapatanHariIniAgg = await db.collection('transaksi').aggregate([
      { $match: { status: 'success', createdAt: { $gte: todayStart } } },
      { $group: { _id: null, total: { $sum: '$price' } } }
    ]).toArray();

    return res.json({
      success: true,
      stats: {
        totalId,
        totalSold,
        totalUsers,
        pendingTopup,
        pendapatan: pendapatanAgg[0]?.total || 0,
        pendapatanHariIni: pendapatanHariIniAgg[0]?.total || 0
      },
      recentTx
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/users — list semua user
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const db = await getDb();
    const filter = {};
    if (search) filter.$or = [
      { username: { $regex: search, $options: 'i' } },
      { fullName: { $regex: search, $options: 'i' } },
      { emailPhone: { $regex: search, $options: 'i' } }
    ];

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('users').countDocuments(filter);
    const users = await db.collection('users')
      .find(filter, { projection: { password: 0 } })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, users, total, page: parseInt(page) });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/admin/ids — tambah ID baru
app.post('/api/admin/ids', adminMiddleware, async (req, res) => {
  try {
    const { gameId, uid, password, tier, note } = req.body;
    if (!gameId || !uid || !password || !tier) {
      return res.status(400).json({ success: false, message: 'gameId, uid, password, dan tier wajib diisi' });
    }
    const tierLow = tier.toLowerCase();
    if (!PRICE_MAP[tierLow]) {
      return res.status(400).json({ success: false, message: 'Tier tidak valid (low/medium/high/legend)' });
    }

    const db = await getDb();
    const existing = await db.collection('ids').findOne({ gameId });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Game ID sudah ada' });
    }

    const result = await db.collection('ids').insertOne({
      gameId,
      uid,
      password,
      tier: tierLow,
      price: PRICE_MAP[tierLow],
      note: note || '',
      status: 'available',
      addedBy: req.user.id,
      addedAt: new Date()
    });

    // Update counter admin
    await db.collection('admins').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $inc: { totalIdDitambah: 1 } }
    );

    return res.status(201).json({
      success: true,
      message: 'ID berhasil ditambahkan',
      id: result.insertedId
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/ids — list semua ID (admin bisa lihat status + credentials)
app.get('/api/admin/ids', adminMiddleware, async (req, res) => {
  try {
    const { status, tier, page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const filter = {};
    if (status) filter.status = status;
    if (tier) filter.tier = tier;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('ids').countDocuments(filter);
    const ids = await db.collection('ids')
      .find(filter)
      .sort({ addedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, ids, total, page: parseInt(page) });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/ids/:id — hapus ID
app.delete('/api/admin/ids/:id', adminMiddleware, async (req, res) => {
  try {
    const db = await getDb();
    const result = await db.collection('ids').deleteOne({ _id: new ObjectId(req.params.id), status: 'available' });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: 'ID tidak ditemukan atau sudah terjual' });
    }
    return res.json({ success: true, message: 'ID berhasil dihapus' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/transaksi — semua transaksi
app.get('/api/admin/transaksi', adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, userId } = req.query;
    const db = await getDb();
    const filter = {};
    if (status) filter.status = status;
    if (userId) filter.userId = userId;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('transaksi').countDocuments(filter);
    const txList = await db.collection('transaksi')
      .find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, transaksi: txList, total, page: parseInt(page) });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/topup — list semua request topup
app.get('/api/admin/topup', adminMiddleware, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const db = await getDb();
    const filter = status ? { status } : {};
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await db.collection('topup').countDocuments(filter);
    const topups = await db.collection('topup')
      .find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    return res.json({ success: true, topups, total });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/admin/topup/:topupId/approve — approve topup
app.put('/api/admin/topup/:topupId/approve', adminMiddleware, async (req, res) => {
  try {
    const { topupId } = req.params;
    const db = await getDb();

    const topup = await db.collection('topup').findOne({ topupId, status: 'pending' });
    if (!topup) return res.status(404).json({ success: false, message: 'Request topup tidak ditemukan' });

    // Tambah coins ke user
    await db.collection('users').updateOne(
      { _id: new ObjectId(topup.userId) },
      { $inc: { coins: topup.coins }, $set: { updatedAt: new Date() } }
    );

    await db.collection('topup').updateOne(
      { topupId },
      { $set: { status: 'approved', approvedBy: req.user.id, approvedAt: new Date() } }
    );

    return res.json({ success: true, message: `Topup ${topupId} disetujui. +${topup.coins} coins ke ${topup.username}` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/admin/topup/:topupId/reject — reject topup
app.put('/api/admin/topup/:topupId/reject', adminMiddleware, async (req, res) => {
  try {
    const { topupId } = req.params;
    const { reason } = req.body;
    const db = await getDb();

    const topup = await db.collection('topup').findOne({ topupId, status: 'pending' });
    if (!topup) return res.status(404).json({ success: false, message: 'Request topup tidak ditemukan' });

    await db.collection('topup').updateOne(
      { topupId },
      { $set: { status: 'rejected', rejectedBy: req.user.id, rejectedAt: new Date(), reason: reason || '' } }
    );

    return res.json({ success: true, message: `Topup ${topupId} ditolak` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/admin/users/:userId/coins — edit coins user secara manual
app.put('/api/admin/users/:userId/coins', adminMiddleware, async (req, res) => {
  try {
    const { coins } = req.body;
    if (coins === undefined || isNaN(coins)) {
      return res.status(400).json({ success: false, message: 'Jumlah coins tidak valid' });
    }
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.params.userId) },
      { $set: { coins: parseInt(coins), updatedAt: new Date() } }
    );
    return res.json({ success: true, message: 'Coins user berhasil diubah' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ─── ADMIN: Inisialisasi akun admin pertama (jalankan sekali) ───────────────
// POST /api/admin/init — buat akun admin pertama (butuh secret key)
app.post('/api/admin/init', async (req, res) => {
  try {
    const { username, password, fullName, initSecret } = req.body;
    if (initSecret !== (process.env.INIT_SECRET || 'lapakid_init_2026')) {
      return res.status(403).json({ success: false, message: 'Secret tidak valid' });
    }

    const db = await getDb();
    const admins = db.collection('admins');
    const existing = await admins.findOne({ username: username.toLowerCase() });
    if (existing) return res.status(409).json({ success: false, message: 'Admin sudah ada' });

    const hashedPass = await bcrypt.hash(password, 10);
    await admins.insertOne({
      username: username.toLowerCase(),
      fullName: fullName || 'Admin lapakID',
      password: hashedPass,
      role: 'admin',
      totalIdDitambah: 0,
      createdAt: new Date()
    });

    return res.status(201).json({ success: true, message: 'Admin berhasil dibuat' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'lapakID API running', timestamp: new Date() });
});

// ─── 404 ──────────────────────────────────────────────────────────────────
app.use('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan' });
});

module.exports = app;

