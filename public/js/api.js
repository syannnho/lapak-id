// public/js/api.js — Shared API helper untuk semua halaman lapakID

const API_BASE = '/api';

// ─── TOKEN ────────────────────────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('lapakid_token'),
  setToken: (t) => localStorage.setItem('lapakid_token', t),
  removeToken: () => localStorage.removeItem('lapakid_token'),

  getUser: () => {
    try { return JSON.parse(localStorage.getItem('lapakid_current_user') || 'null'); }
    catch { return null; }
  },
  setUser: (u) => localStorage.setItem('lapakid_current_user', JSON.stringify(u)),
  removeUser: () => localStorage.removeItem('lapakid_current_user'),

  isLoggedIn: () => !!localStorage.getItem('lapakid_token'),
  isAdmin: () => {
    const u = Auth.getUser();
    return u && u.role === 'admin';
  },

  logout: () => {
    localStorage.removeItem('lapakid_token');
    localStorage.removeItem('lapakid_current_user');
    window.location.href = '/signin.html';
  }
};

// ─── FETCH WRAPPER ────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(API_BASE + path, { ...options, headers });
  const data = await res.json();

  // Token expired → logout otomatis
  if (res.status === 401) {
    Auth.logout();
    return;
  }
  return { ok: res.ok, status: res.status, data };
}

// ─── AUTH API ─────────────────────────────────────────────────────────────
const AuthAPI = {
  register: (body) => apiFetch('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login: (body) => apiFetch('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  me: () => apiFetch('/auth/me'),
};

// ─── USER API ─────────────────────────────────────────────────────────────
const UserAPI = {
  getProfile: () => apiFetch('/user/profile'),
  updateProfile: (body) => apiFetch('/user/profile', { method: 'PUT', body: JSON.stringify(body) }),

  getCart: () => apiFetch('/user/cart'),
  addToCart: (idItem) => apiFetch('/user/cart', { method: 'POST', body: JSON.stringify({ idItem }) }),
  removeFromCart: (idItem) => apiFetch(`/user/cart/${idItem}`, { method: 'DELETE' }),
  clearCart: () => apiFetch('/user/cart', { method: 'DELETE' }),
};

// ─── IDs API ──────────────────────────────────────────────────────────────
const IdsAPI = {
  getAll: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/ids' + (q ? '?' + q : ''));
  },
  getOne: (id) => apiFetch(`/ids/${id}`),
};

// ─── PAYMENT API ──────────────────────────────────────────────────────────
const PaymentAPI = {
  buyOne: (idItem) => apiFetch('/payment/buy', { method: 'POST', body: JSON.stringify({ idItem }) }),
  buyCart: () => apiFetch('/payment/buy-cart', { method: 'POST' }),
};

// ─── TRANSAKSI API ────────────────────────────────────────────────────────
const TransaksiAPI = {
  getAll: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/transaksi' + (q ? '?' + q : ''));
  },
  getPurchases: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/transaksi/purchases' + (q ? '?' + q : ''));
  },
};

// ─── TOPUP API ────────────────────────────────────────────────────────────
const TopupAPI = {
  request: (body) => apiFetch('/topup/request', { method: 'POST', body: JSON.stringify(body) }),
  history: () => apiFetch('/topup/history'),
};

// ─── ADMIN API ────────────────────────────────────────────────────────────
const AdminAPI = {
  getStats: () => apiFetch('/admin/stats'),
  getUsers: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/admin/users' + (q ? '?' + q : ''));
  },
  setUserCoins: (userId, coins) => apiFetch(`/admin/users/${userId}/coins`, { method: 'PUT', body: JSON.stringify({ coins }) }),

  addId: (body) => apiFetch('/admin/ids', { method: 'POST', body: JSON.stringify(body) }),
  getAllIds: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/admin/ids' + (q ? '?' + q : ''));
  },
  deleteId: (id) => apiFetch(`/admin/ids/${id}`, { method: 'DELETE' }),

  getTransaksi: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/admin/transaksi' + (q ? '?' + q : ''));
  },

  getTopup: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiFetch('/admin/topup' + (q ? '?' + q : ''));
  },
  approveTopup: (topupId) => apiFetch(`/admin/topup/${topupId}/approve`, { method: 'PUT' }),
  rejectTopup: (topupId, reason) => apiFetch(`/admin/topup/${topupId}/reject`, { method: 'PUT', body: JSON.stringify({ reason }) }),
};

// ─── GUARD: redirect kalau belum login ────────────────────────────────────
function requireLogin(redirectTo = '/signin.html') {
  if (!Auth.isLoggedIn()) window.location.href = redirectTo;
}

function requireAdmin(redirectTo = '/signin.html') {
  if (!Auth.isLoggedIn() || !Auth.isAdmin()) window.location.href = redirectTo;
}

// ─── TOAST HELPER ─────────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const colors = { success: '#12b76a', warning: '#f79009', error: '#f04438', info: '#667085' };
  const toast = document.createElement('div');
  toast.textContent = msg;
  toast.style.cssText = `position:fixed;bottom:90px;right:24px;padding:10px 22px;border-radius:40px;
    z-index:9999;font-size:.78rem;color:#fff;font-family:Outfit,sans-serif;font-weight:600;
    background:${colors[type] || colors.info};box-shadow:0 4px 16px rgba(0,0,0,.2);
    animation:fadeIn .2s ease;`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}
