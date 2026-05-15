# lapakID — Web Pembelian ID Game Premium

## 📁 Struktur Folder
```
lapakid/
├── api/
│   └── index.js          ← Semua API endpoint (1 file untuk Vercel)
├── public/
│   ├── js/
│   │   └── api.js        ← Shared helper + Auth untuk semua halaman
│   ├── user/
│   │   ├── dashboard.html
│   │   ├── id.html
│   │   ├── cart.html
│   │   ├── payment.html
│   │   ├── topup.html
│   │   └── transaksi.html
│   ├── admin/
│   │   ├── dashboard.html
│   │   ├── addid.html
│   │   ├── ids.html
│   │   ├── topup.html
│   │   ├── users.html
│   │   └── transaksi.html
│   ├── index.html
│   ├── signin.html
│   └── signup.html
├── vercel.json
├── package.json
└── .env.example
```

## 🗄️ Collections MongoDB
| Collection | Isi |
|---|---|
| `users` | username, fullName, emailPhone, password(hash), role, coins, totalTransaksi, cart |
| `admins` | username, fullName, password(hash), role:admin, totalIdDitambah |
| `ids` | gameId, uid, password, tier, price, status, addedBy, addedAt |
| `sold` | txId, userId, gameId, uid, password, tier, price, soldAt |
| `transaksi` | txId, userId, username, gameId, tier, price, status, createdAt |
| `topup` | topupId, userId, username, coins, amount, status, createdAt |

## 🚀 Deploy ke Vercel

### 1. Push ke GitHub
```bash
git init
git add .
git commit -m "init lapakID"
git remote add origin https://github.com/USERNAME/lapakid.git
git push -u origin main
```

### 2. Deploy di Vercel
1. Buka vercel.com → New Project → Import GitHub repo
2. Tambahkan Environment Variables:
   - `MONGODB_URI` = connection string MongoDB
   - `JWT_SECRET` = secret key acak panjang
   - `INIT_SECRET` = secret untuk buat akun admin pertama

### 3. Buat Admin Pertama
Setelah deploy, jalankan sekali via Postman/curl:
```bash
curl -X POST https://your-app.vercel.app/api/admin/init \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123","fullName":"Admin lapakID","initSecret":"lapakid_init_2026"}'
```

## 🔑 API Endpoints
| Method | Path | Auth |
|---|---|---|
| POST | /api/auth/register | — |
| POST | /api/auth/login | — |
| GET | /api/auth/me | User/Admin |
| GET | /api/ids | — |
| GET | /api/user/cart | User |
| POST | /api/user/cart | User |
| DELETE | /api/user/cart/:id | User |
| POST | /api/payment/buy | User |
| POST | /api/payment/buy-cart | User |
| GET | /api/transaksi | User |
| GET | /api/transaksi/purchases | User |
| POST | /api/topup/request | User |
| GET | /api/admin/stats | Admin |
| POST | /api/admin/ids | Admin |
| GET | /api/admin/ids | Admin |
| DELETE | /api/admin/ids/:id | Admin |
| GET | /api/admin/users | Admin |
| GET | /api/admin/topup | Admin |
| PUT | /api/admin/topup/:id/approve | Admin |
| PUT | /api/admin/topup/:id/reject | Admin |
| PUT | /api/admin/users/:id/coins | Admin |

## 💰 Harga Tier
| Tier | Harga |
|---|---|
| Low | Rp 125.000 |
| Medium | Rp 450.000 |
| High | Rp 850.000 |
| Legend | Rp 1.350.000 |
