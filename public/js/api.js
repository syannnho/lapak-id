// frontend/public/js/api.js
// Ganti BACKEND_URL dengan URL Railway/Render kamu setelah deploy
const BACKEND_URL = 'https://backend-production-c1faa.up.railway.app'; // ← GANTI INI

// ─── AUTH ────────────────────────────────────────────────────────────────────
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
  isAdmin:    () => { const u = Auth.getUser(); return u?.role === 'admin'; },
  requireLogin: (redirect = '/signin.html') => {
    if (!Auth.isLoggedIn()) { window.location.href = redirect; return false; }
    return true;
  },
  requireAdmin: (redirect = '/signin.html') => {
    if (!Auth.isLoggedIn() || !Auth.isAdmin()) { window.location.href = redirect; return false; }
    return true;
  }
};

// ─── FETCH HELPER ─────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (options.headers) Object.assign(headers, options.headers);

  let res;
  try {
    res = await fetch(BACKEND_URL + '/api' + path, {
      ...options,
      headers,
      // Tidak pakai credentials: 'include' karena backend beda domain
    });
  } catch (e) {
    console.error('Network error:', e);
    showToast('❌ Tidak bisa terhubung ke server', 'error');
    return { success: false, message: 'Tidak bisa terhubung ke server. Cek koneksi internet.' };
  }

  // Sesi habis
  if (res.status === 401) {
    Auth.clear();
    window.location.href = '/signin.html';
    return null;
  }

  // Rate limited
  if (res.status === 429) {
    const retryAfter = res.headers.get('Retry-After') || '60';
    showToast(`⚠️ Terlalu banyak request. Tunggu ${retryAfter} detik.`, 'warning');
    return { success: false, message: 'Rate limited' };
  }

  try {
    return await res.json();
  } catch {
    return { success: false, message: 'Response tidak valid (status ' + res.status + ')' };
  }
}

// ─── API MODULES ──────────────────────────────────────────────────────────────
const AuthAPI = {
  register: b  => apiFetch('/auth/register', { method: 'POST', body: JSON.stringify(b) }),
  login:    b  => apiFetch('/auth/login',    { method: 'POST', body: JSON.stringify(b) }),
  me:       () => apiFetch('/auth/me'),
};

const UserAPI = {
  profile:        ()   => apiFetch('/user/profile'),
  updateProfile:  b    => apiFetch('/user/profile',    { method: 'PUT',    body: JSON.stringify(b) }),
  getCart:        ()   => apiFetch('/user/cart'),
  addToCart:      id   => apiFetch('/user/cart',       { method: 'POST',   body: JSON.stringify({ idItem: id }) }),
  removeFromCart: id   => apiFetch('/user/cart/' + id, { method: 'DELETE' }),
  clearCart:      ()   => apiFetch('/user/cart',       { method: 'DELETE' }),
};

const IdsAPI = {
  getAll: (p = {}) => apiFetch('/ids?' + new URLSearchParams(p)),
  getOne: id       => apiFetch('/ids/' + id),
};

const PaymentAPI = {
  buy:     id => apiFetch('/payment/buy',      { method: 'POST', body: JSON.stringify({ idItem: id }) }),
  buyCart: () => apiFetch('/payment/buy-cart', { method: 'POST' }),
};

const TransaksiAPI = {
  list:      (p = {}) => apiFetch('/transaksi?' + new URLSearchParams(p)),
  purchases: (p = {}) => apiFetch('/transaksi/purchases?' + new URLSearchParams(p)),
};

const TopupAPI = {
  request: b  => apiFetch('/topup/request', { method: 'POST', body: JSON.stringify(b) }),
  history: () => apiFetch('/topup/history'),
};

const AdminAPI = {
  stats:        ()          => apiFetch('/admin/stats'),
  users:        (p = {})   => apiFetch('/admin/users?' + new URLSearchParams(p)),
  addId:        b           => apiFetch('/admin/ids',                  { method: 'POST',   body: JSON.stringify(b) }),
  getIds:       (p = {})   => apiFetch('/admin/ids?' + new URLSearchParams(p)),
  deleteId:     id          => apiFetch('/admin/ids/' + id,            { method: 'DELETE' }),
  transaksi:    (p = {})   => apiFetch('/admin/transaksi?' + new URLSearchParams(p)),
  getTopup:     (p = {})   => apiFetch('/admin/topup?' + new URLSearchParams(p)),
  approveTopup: id          => apiFetch('/admin/topup/' + id + '/approve', { method: 'PUT' }),
  rejectTopup:  (id, reason) => apiFetch('/admin/topup/' + id + '/reject', { method: 'PUT', body: JSON.stringify({ reason }) }),
  editCoins:    (uid, coins) => apiFetch('/admin/users/' + uid + '/coins',  { method: 'PUT', body: JSON.stringify({ coins }) }),
};

// ─── UI HELPERS ───────────────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const colors = { success: '#12b76a', warning: '#f79009', error: '#f04438', info: '#465fff' };
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = `position:fixed;bottom:84px;right:16px;padding:10px 18px;border-radius:40px;
    z-index:9999;font-size:.75rem;color:#fff;font-family:Outfit,sans-serif;font-weight:600;
    background:${colors[type]||colors.info};box-shadow:0 4px 16px rgba(0,0,0,.2);
    transition:opacity .3s;pointer-events:none;max-width:280px`;
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 320); }, 2800);
}

function initDarkMode(btnId = 'darkModeToggle') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  let dark = localStorage.getItem('darkMode') === 'true';
  const apply = d => {
    document.body.classList.toggle('dark-mode', d);
    btn.textContent = d ? '☀️' : '🌙';
    localStorage.setItem('darkMode', d);
  };
  apply(dark);
  btn.onclick = () => { dark = !dark; apply(dark); };
}

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

function fillNavUser(user) {
  if (!user) return;
  const el = id => document.getElementById(id);
  if (el('navAvatar'))   el('navAvatar').textContent  = (user.fullName || user.username || 'U').charAt(0).toUpperCase();
  if (el('navUsername')) el('navUsername').textContent = user.username || '';
  if (el('navCoins'))    el('navCoins').textContent    = 'C.' + Number(user.coins || 0).toLocaleString('id-ID');
}

const formatRp   = n => 'Rp' + Number(n || 0).toLocaleString('id-ID');
const formatDate = d => new Date(d).toLocaleString('id-ID');
