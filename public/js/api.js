// public/js/api.js — Shared helper untuk semua halaman lapakID
// API_BASE otomatis menyesuaikan: local dev atau production Vercel
const API_BASE = '';  // kosong = relative URL, jadi /api/... → same origin

// ─── AUTH (localStorage) ──────────────────────────────────────────────────
const Auth = {
  getToken:   () => localStorage.getItem('lapakid_token'),
  getUser:    () => { try { return JSON.parse(localStorage.getItem('lapakid_user')); } catch { return null; } },
  setSession: (token, user) => {
    localStorage.setItem('lapakid_token', token);
    localStorage.setItem('lapakid_user', JSON.stringify(user));
  },
  clear: () => {
    localStorage.removeItem('lapakid_token');
    localStorage.removeItem('lapakid_user');
  },
  isLoggedIn: () => !!localStorage.getItem('lapakid_token'),
  isAdmin:    () => { const u = Auth.getUser(); return u && u.role === 'admin'; },
  requireLogin: (redirect = '/signin.html') => {
    if (!Auth.isLoggedIn()) { window.location.href = redirect; return false; }
    return true;
  },
  requireAdmin: (redirect = '/signin.html') => {
    if (!Auth.isLoggedIn() || !Auth.isAdmin()) { window.location.href = redirect; return false; }
    return true;
  }
};

// ─── HTTP HELPER ──────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (options.headers) Object.assign(headers, options.headers);

  let res;
  try {
    res = await fetch('/api' + path, { ...options, headers });
  } catch (e) {
    console.error('Network error:', e);
    return { success: false, message: 'Tidak bisa terhubung ke server. Cek koneksi internet.' };
  }

  // Token expired
  if (res.status === 401) {
    Auth.clear();
    window.location.href = '/signin.html';
    return null;
  }

  try {
    return await res.json();
  } catch {
    return { success: false, message: 'Response tidak valid dari server (status ' + res.status + ')' };
  }
}

// ─── AUTH API ─────────────────────────────────────────────────────────────
const AuthAPI = {
  register: (body) => apiFetch('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login:    (body) => apiFetch('/auth/login',    { method: 'POST', body: JSON.stringify(body) }),
  me:       ()     => apiFetch('/auth/me'),
};

// ─── USER API ─────────────────────────────────────────────────────────────
const UserAPI = {
  profile:       ()     => apiFetch('/user/profile'),
  updateProfile: (body) => apiFetch('/user/profile', { method: 'PUT', body: JSON.stringify(body) }),
  getCart:       ()     => apiFetch('/user/cart'),
  addToCart:     (idItem) => apiFetch('/user/cart', { method: 'POST', body: JSON.stringify({ idItem }) }),
  removeFromCart:(idItem) => apiFetch('/user/cart/' + idItem, { method: 'DELETE' }),
  clearCart:     ()     => apiFetch('/user/cart', { method: 'DELETE' }),
};

// ─── IDS API ──────────────────────────────────────────────────────────────
const IdsAPI = {
  getAll: (params = {}) => apiFetch('/ids?' + new URLSearchParams(params).toString()),
  getOne: (id)          => apiFetch('/ids/' + id),
};

// ─── PAYMENT API ──────────────────────────────────────────────────────────
const PaymentAPI = {
  buy:     (idItem) => apiFetch('/payment/buy',      { method: 'POST', body: JSON.stringify({ idItem }) }),
  buyCart: ()       => apiFetch('/payment/buy-cart', { method: 'POST' }),
};

// ─── TRANSAKSI API ────────────────────────────────────────────────────────
const TransaksiAPI = {
  list:      (p = {}) => apiFetch('/transaksi?' + new URLSearchParams(p).toString()),
  purchases: (p = {}) => apiFetch('/transaksi/purchases?' + new URLSearchParams(p).toString()),
};

// ─── TOPUP API ────────────────────────────────────────────────────────────
const TopupAPI = {
  request: (body) => apiFetch('/topup/request', { method: 'POST', body: JSON.stringify(body) }),
  history: ()     => apiFetch('/topup/history'),
};

// ─── ADMIN API ────────────────────────────────────────────────────────────
const AdminAPI = {
  stats:         ()              => apiFetch('/admin/stats'),
  users:         (p = {})       => apiFetch('/admin/users?' + new URLSearchParams(p).toString()),
  addId:         (body)         => apiFetch('/admin/ids', { method: 'POST', body: JSON.stringify(body) }),
  getIds:        (p = {})       => apiFetch('/admin/ids?' + new URLSearchParams(p).toString()),
  deleteId:      (id)           => apiFetch('/admin/ids/' + id, { method: 'DELETE' }),
  transaksi:     (p = {})       => apiFetch('/admin/transaksi?' + new URLSearchParams(p).toString()),
  getTopup:      (p = {})       => apiFetch('/admin/topup?' + new URLSearchParams(p).toString()),
  approveTopup:  (topupId)      => apiFetch('/admin/topup/' + topupId + '/approve', { method: 'PUT' }),
  rejectTopup:   (topupId, reason) => apiFetch('/admin/topup/' + topupId + '/reject', { method: 'PUT', body: JSON.stringify({ reason }) }),
  editCoins:     (userId, coins) => apiFetch('/admin/users/' + userId + '/coins', { method: 'PUT', body: JSON.stringify({ coins }) }),
};

// ─── TOAST ────────────────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const colors = { success: '#12b76a', warning: '#f79009', error: '#f04438', info: '#465fff' };
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = [
    'position:fixed','bottom:84px','right:16px','padding:10px 18px',
    'border-radius:40px','z-index:9999','font-size:.75rem','color:#fff',
    'font-family:Outfit,sans-serif','font-weight:600',
    'background:' + (colors[type] || colors.info),
    'box-shadow:0 4px 16px rgba(0,0,0,.18)',
    'transition:opacity .3s','pointer-events:none'
  ].join(';');
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 320); }, 2600);
}

// ─── FORMAT ───────────────────────────────────────────────────────────────
const formatRp   = (n) => 'Rp' + Number(n || 0).toLocaleString('id-ID');
const formatDate = (d) => new Date(d).toLocaleString('id-ID');

// ─── DARK MODE HELPER (reusable) ──────────────────────────────────────────
function initDarkMode(btnId = 'darkModeToggle') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  let dark = localStorage.getItem('darkMode') === 'true';
  const apply = (d) => {
    document.body.classList.toggle('dark-mode', d);
    btn.textContent = d ? '☀️' : '🌙';
    localStorage.setItem('darkMode', d);
  };
  apply(dark);
  btn.onclick = () => { dark = !dark; apply(dark); };
}

// ─── DROPDOWN HELPER ──────────────────────────────────────────────────────
function initDropdown(dropId = 'userDropdown', logoutId = 'logoutBtn') {
  const drop = document.getElementById(dropId);
  if (drop) {
    drop.addEventListener('click', e => { e.stopPropagation(); drop.classList.toggle('active'); });
    document.addEventListener('click', () => drop.classList.remove('active'));
  }
  const logoutBtn = document.getElementById(logoutId);
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => { Auth.clear(); window.location.href = '/signin.html'; });
  }
}

// ─── NAV USER INFO ────────────────────────────────────────────────────────
function fillNavUser(user) {
  if (!user) return;
  const avatarEl  = document.getElementById('navAvatar');
  const nameEl    = document.getElementById('navUsername');
  const coinsEl   = document.getElementById('navCoins');
  if (avatarEl) avatarEl.textContent = (user.fullName || user.username || 'U').charAt(0).toUpperCase();
  if (nameEl)   nameEl.textContent   = user.username || '';
  if (coinsEl)  coinsEl.textContent  = 'C.' + Number(user.coins || 0).toLocaleString('id-ID');
}
