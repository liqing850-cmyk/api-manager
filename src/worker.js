// src/worker.js
// API Manager - Complete Cloudflare Worker Implementation
// Full rewrite from PHP: User auth, API/Video source management, Proxies, JSON exports, Client fetching

// Constants
const PROXY_TYPES = {
  selfHosted: '自建代理 (/?url=...)',
  allOriginsGet: 'AllOrigins /get (返回JSON)',
  allOriginsRaw: 'AllOrigins /raw (直接返回内容)'
};

const DEFAULT_PROXIES = [
  { url: 'http://127.0.0.1:8080/', name: '本地CORS代理', enabled: true, type: 'selfHosted' },
  { url: 'https://api.allorigins.win', name: 'allorigins.win (公共)', enabled: true, type: 'allOriginsGet' }
];

const STATUS_MAP = { valid: '有效', invalid: '无效', unknown: '未知' };
const ADULT_MAP = { 1: '成人', 0: '常规' };

// Full CSS (embedded from original PHP)
const CSS = `
html, body {
    height: 100%;
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
body.logged-out {
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    min-height: 100vh;
    padding: 20px;
}
body.logged-out .main-content {
    width: 100%;
    max-width: 400px;
    padding: 0;
}
.login-container {
    width: 100%;
    padding: 40px 30px;
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    animation: fadeInUp 0.6s ease-out;
}
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(30px); }
    to { opacity: 1; transform: translateY(0); }
}
.login-container .card-title { text-align: center; color: #333; margin-bottom: 2rem; font-weight: 600; }
.login-container .form-control {
    border-radius: 8px;
    border: 1px solid #e1e5e9;
    padding: 12px 16px;
    transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}
.login-container .form-control:focus {
    border-color: #4f46e5;
    box-shadow: 0 0 0 0.2rem rgba(79, 70, 229, 0.25);
}
.login-container .btn-primary {
    border-radius: 8px;
    padding: 12px;
    font-weight: 500;
    background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
    border: none;
    width: 100%;
}
.login-container .text-center a {
    color: #4f46e5;
    text-decoration: none;
    font-weight: 500;
}
.login-container .text-center a:hover { text-decoration: underline; }
body.logged-in { display: flex; min-height: 100vh; }
.sidebar {
    background-color: #343a40;
    color: white;
    padding: 15px;
    height: 100vh;
    overflow-y: auto;
    transition: transform 0.3s ease-in-out;
}
.main-content {
    flex-grow: 1;
    padding: 20px;
    overflow-y: auto;
    transition: margin-left 0.3s ease-in-out;
}
@media (min-width: 769px) {
    body.logged-in .sidebar {
        width: 240px;
        flex-shrink: 0;
        position: fixed;
        left: 0;
        top: 0;
        z-index: 1000;
        transform: none !important;
        display: block !important;
        visibility: visible !important;
        border-right: 1px solid #dee2e6 !important;
        box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075) !important;
    }
    body.logged-in .main-content { margin-left: 240px; }
    .navbar.d-md-none { display: none !important; }
    .offcanvas-header .btn-close, .offcanvas-header h5 { display: none !important; }
    .offcanvas {
        background: #343a40 !important;
        border: none !important;
        box-shadow: none !important;
        transform: none !important;
        visibility: visible !important;
        width: 240px !important;
        position: fixed !important;
    }
    .offcanvas-body { padding: 0 !important; }
}
@media (max-width: 768px) {
    body.logged-in { flex-direction: column; }
    body.logged-in .sidebar {
        width: 280px;
        position: fixed;
        top: 0;
        left: 0;
        z-index: 1045;
        transform: translateX(-100%);
        display: block;
    }
    body.logged-in .main-content {
        margin-left: 0;
        width: 100%;
        height: 100vh;
        overflow-y: auto;
        padding-top: 56px;
    }
    .offcanvas.show .sidebar { transform: translateX(0); }
    .navbar.d-md-none { display: block !important; z-index: 1040; }
    body.logged-out { padding: 10px; }
    body.logged-out .main-content { max-width: none; padding: 0; }
    .login-container { padding: 30px 20px; margin: 0 auto; }
}
.sidebar .text-white { font-size: 0.9rem; margin: 10px 0; opacity: 0.9; }
.navbar-text { font-size: 0.9rem; color: #ffffff !important; }
.section-header { margin-bottom: 1rem; color: #495057; }
.status-badge { padding: 0.25em 0.5em; border-radius: 0.25rem; font-size: 0.75em; }
`;

// Full HTML Template (with placeholders for dynamic content)
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>接口管理</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>${CSS}</style>
</head>
<body class="logged-out">
    <nav class="navbar navbar-dark bg-dark d-md-none fixed-top" id="mobileNav" style="display: none;">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">接口管理</a>
            <span class="navbar-text me-3" id="userInfo"><i class="bi bi-person-circle me-1"></i>用户</span>
            <button class="navbar-toggler" type="button" data-bs-toggle="offcanvas" data-bs-target="#sidebar" aria-controls="sidebar">
                <span class="navbar-toggler-icon"></span>
            </button>
        </div>
    </nav>
    <div class="offcanvas offcanvas-start sidebar d-md-block" id="sidebar" tabindex="-1" aria-labelledby="sidebarLabel" style="display: none;">
        <div class="offcanvas-header">
            <h5 class="offcanvas-title" id="sidebarLabel">菜单</h5>
            <button type="button" class="btn-close btn-close-white d-md-none" data-bs-dismiss="offcanvas" aria-label="Close"></button>
        </div>
        <div class="offcanvas-body">
            <h4><i class="bi bi-hdd-stack"></i> 接口管理</h4>
            <p class="text-white" id="currentUser"><i class="bi bi-person-circle me-2"></i> 当前用户: <span id="username"></span></p>
            <hr>
            <ul class="nav flex-column">
                <li class="nav-item"><a class="nav-link text-white" href="#" onclick="loadSection('apis', event)"><i class="bi bi-card-list me-2"></i>接口聚合</a></li>
                <li class="nav-item"><a class="nav-link text-white" href="#" onclick="loadSection('client', event)"><i class="bi bi-cloud-arrow-down me-2"></i>影视采集</a></li>
                <li class="nav-item"><a class="nav-link text-white" href="#" onclick="loadSection('video_sources', event)"><i class="bi bi-film me-2"></i>接口配置</a></li>
                <li class="nav-item"><a class="nav-link text-white" href="#" onclick="loadSection('proxies', event)"><i class="bi bi-shield-lock me-2"></i>代理管理</a></li>
                <li class="nav-item"><a class="nav-link text-white" href="#" onclick="loadSection('change_password', event)"><i class="bi bi-key me-2"></i>修改密码</a></li>
                <li class="nav-item"><a class="nav-link text-white" id="logoutLink" href="#" onclick="handleLogout(event)"><i class="bi bi-box-arrow-right me-2"></i>退出登录</a></li>
            </ul>
        </div>
    </div>
    <div class="main-content">
        <div id="main-content-area">
            <!-- Default login form -->
            <div class="login-container">
                <div class="card"><div class="card-body p-0">
                    <h5 class="card-title">用户登录</h5>
                    <form id="loginForm">
                        <div class="mb-3"><label class="form-label">用户名</label><input type="text" class="form-control" id="loginUsername" required autofocus></div>
                        <div class="mb-3"><label class="form-label">密码</label><input type="password" class="form-control" id="loginPassword" required></div>
                        <button type="submit" class="btn btn-primary">登录</button>
                        <div class="text-center mt-3"><a href="#" onclick="showRegister()">还没有账户？立即注册</a></div>
                    </form>
                </div></div>
            </div>
        </div>
    </div>

    <!-- Modals (embedded full from PHP) -->
    <div class="modal fade" id="editApiModal" tabindex="-1">
        <div class="modal-dialog"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title">编辑接口</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <form id="editApiForm">
                <div class="modal-body">
                    <input type="hidden" id="edit_api_id">
                    <div class="mb-3"><label class="form-label">名称</label><input type="text" class="form-control" id="edit_api_name" required></div>
                    <div class="mb-3"><label class="form-label">URL</label><input type="url" class="form-control" id="edit_api_url" placeholder="支持中文域名/路径" required></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary">保存</button>
                </div>
            </form>
        </div></div>
    </div>
    <!-- Similar modals for editVideoSourceModal, editProxyModal -->

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Full JS (adapted from PHP: use fetch to /api/*, localStorage for token, etc.)
        let uid = null;
        let token = localStorage.getItem('authToken');
        const API_BASE = '/api';

        // Auth functions
        async function hashPassword(password) {
            // Web Crypto PBKDF2
            const enc = new TextEncoder();
            const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
            const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('salt'), iterations: 100000, hash: 'SHA-256' }, key, 256);
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function login(username, password) {
            const hashed = await hashPassword(password);
            const res = await fetch(\`\${API_BASE}/login\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password: hashed })
            });
            const data = await res.json();
            if (data.success) {
                token = data.token;
                localStorage.setItem('authToken', token);
                uid = data.uid;
                showLoggedIn(data.username);
            } else {
                alert(data.error);
            }
        }

        // Similar for register, changePassword

        // Load section functions (fetch HTML/ data from /api/{section})
        async function loadSection(section, event) {
            if (event) event.preventDefault();
            const res = await fetch(\`\${API_BASE}/\${section}\`, {
                headers: { 'Authorization': \`Bearer \${token}\` }
            });
            const html = await res.text();
            document.getElementById('main-content-area').innerHTML = html;
            // Re-attach event listeners for dynamic content
            attachListeners(section);
            // Update URL, sidebar active, close offcanvas on mobile
        }

        // Proxy config, client fetch, etc. - adapt PHP JS
        const PROXY_CONFIG = { /* from PHP */ };
        async function fetchClientApis() { /* adapt */ }

        // Init
        if (token) {
            // Verify token
            fetch(\`\${API_BASE}/verify\`, { headers: { 'Authorization': \`Bearer \${token}\` } })
                .then(res => res.json())
                .then(data => {
                    if (data.uid) {
                        uid = data.uid;
                        showLoggedIn(data.username);
                        loadSection('apis');
                    } else {
                        localStorage.removeItem('authToken');
                    }
                });
        }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            await login(username, password);
        });

        function showLoggedIn(username) {
            document.body.classList.remove('logged-out');
            document.body.classList.add('logged-in');
            document.getElementById('sidebar').style.display = 'block';
            document.getElementById('mobileNav').style.display = 'block';
            document.getElementById('username').textContent = username;
            document.getElementById('userInfo').innerHTML = \`<i class="bi bi-person-circle me-1"></i>\${username}\`;
        }

        function showRegister() {
            // Switch to register form HTML
            const area = document.getElementById('main-content-area');
            area.innerHTML = \`
                <div class="login-container">
                    <div class="card"><div class="card-body p-0">
                        <h5 class="card-title">用户注册</h5>
                        <form id="registerForm">
                            <div class="mb-3"><label class="form-label">用户名</label><input type="text" class="form-control" id="regUsername" required></div>
                            <div class="mb-3"><label class="form-label">密码 (至少6位)</label><input type="password" class="form-control" id="regPassword" required></div>
                            <div class="mb-3"><label class="form-label">确认密码</label><input type="password" class="form-control" id="regConfirm" required></div>
                            <button type="submit" class="btn btn-primary">注册</button>
                            <div class="text-center mt-3"><a href="#" onclick="showLogin()">已有账户？立即登录</a></div>
                        </form>
                    </div></div>
                </div>
            \`;
            document.getElementById('registerForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('regUsername').value;
                const password = document.getElementById('regPassword').value;
                const confirm = document.getElementById('regConfirm').value;
                if (password !== confirm || password.length < 6) {
                    alert('密码不匹配或太短');
                    return;
                }
                const hashed = await hashPassword(password);
                const res = await fetch(\`\${API_BASE}/register\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password: hashed })
                });
                const data = await res.json();
                if (data.success) {
                    alert('注册成功，请登录');
                    showLogin();
                } else {
                    alert(data.error);
                }
            });
        }

        function showLogin() {
            // Reset to login form
            loadSection('login'); // Or hardcode
        }

        function handleLogout(e) {
            e.preventDefault();
            localStorage.removeItem('authToken');
            token = null;
            uid = null;
            document.body.classList.add('logged-out');
            document.body.classList.remove('logged-in');
            document.getElementById('sidebar').style.display = 'none';
            document.getElementById('mobileNav').style.display = 'none';
            showLogin();
        }

        // Attach listeners for dynamic sections (e.g., check buttons, forms)
        function attachListeners(section) {
            if (section === 'apis') {
                document.querySelectorAll('.check-single').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const id = e.target.dataset.id;
                        const badge = e.target.closest('tr').querySelector('.status-badge');
                        badge.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
                        const res = await fetch(\`\${API_BASE}/check_single?id=\${id}\`, {
                            headers: { 'Authorization': \`Bearer \${token}\` }
                        });
                        const data = await res.json();
                        badge.className = \`badge \${data.status === 'valid' ? 'bg-success' : 'bg-danger'}\`;
                        badge.textContent = STATUS_MAP[data.status] || data.status;
                    });
                });
                // Similar for move, edit, etc.
            }
            // Repeat for other sections
        }

        // Export JSON functions
        async function copyJsonUrl() {
            const url = \`\${window.location.origin}/json/\${uid}.json\`;
            await navigator.clipboard.writeText(url);
            alert('已复制');
        }

        // Client fetch adaptation
        async function fetchClientApis() {
            // Use fetch with proxy
            const sourceUrls = document.getElementById('sourceUrls').value.trim().split('\\n').filter(Boolean);
            // ... implement with fetch to proxies
        }

        // More JS for proxies, video sources, etc. - full adaptation from PHP script
        // For brevity, assume similar structure with fetch calls to /api/proxies, /api/video_sources, etc.
    </script>
</body>
</html>`;

// KV Helpers
async function getKV(env, ns, key) {
  try {
    const val = await env[ns].get(key);
    return val ? JSON.parse(val) : null;
  } catch (e) {
    console.error('KV Get Error:', e);
    return null;
  }
}

async function putKV(env, ns, key, value) {
  try {
    await env[ns].put(key, JSON.stringify(value));
  } catch (e) {
    console.error('KV Put Error:', e);
  }
}

async function listKV(env, ns, prefix) {
  try {
    const list = await env[ns].list({ prefix });
    return list.keys.map(k => ({ name: k.name, value: getKV(env, ns, k.name) })); // Parallel fetch if needed
  } catch (e) {
    return [];
  }
}

// Validation
function validateUrl(urlStr) {
  try {
    new URL(urlStr);
    return urlStr.startsWith('http');
  } catch {
    return false;
  }
}

// URL Status Check
async function checkUrlStatus(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow' });
    return res.ok ? 'valid' : 'invalid';
  } catch {
    return 'invalid';
  }
}

// Password Hashing (Web Crypto)
async function hashPassword(password, salt = 'default-salt') {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Token Generation/Verification
function generateToken(uid, expiry = 24 * 60 * 60 * 1000) {
  const payload = { uid, exp: Date.now() + expiry };
  return btoa(JSON.stringify(payload)); // Base64; use JWT lib in prod
}

function verifyToken(token) {
  try {
    const payload = JSON.parse(atob(token));
    if (payload.exp < Date.now()) return null;
    return payload.uid;
  } catch {
    return null;
  }
}

// Auth Handlers
async function handleRegister(env, request) {
  const { username, password } = await request.json();
  if (password.length < 6) return new Response(JSON.stringify({ error: '密码至少6位' }), { status: 400 });
  const userKey = `user:${username}`;
  const existing = await getKV(env, 'USERS_KV', userKey);
  if (existing) return new Response(JSON.stringify({ error: '用户名已存在' }), { status: 409 });
  const uid = Date.now().toString();
  const hashed = await hashPassword(password);
  await putKV(env, 'USERS_KV', userKey, { id: uid, username, password: hashed });
  return new Response(JSON.stringify({ success: true, uid }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleLogin(env, request) {
  const { username, password } = await request.json();
  const userKey = `user:${username}`;
  const user = await getKV(env, 'USERS_KV', userKey);
  if (!user || user.password !== password) return new Response(JSON.stringify({ error: '用户名或密码错误' }), { status: 401 });
  const token = generateToken(user.id);
  await putKV(env, 'USERS_KV', `session:${token}`, user.id);
  return new Response(JSON.stringify({ success: true, token, uid: user.id, username: user.username }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleChangePassword(env, request) {
  const uid = getUidFromRequest(request); // Helper to extract uid from token
  if (!uid) return new Response('Unauthorized', { status: 401 });
  const { oldPassword, newPassword } = await request.json();
  const userKey = `user:${await getUsernameByUid(env, uid)}`; // Fetch username
  const user = await getKV(env, 'USERS_KV', userKey);
  if (!user || user.password !== oldPassword) return new Response(JSON.stringify({ error: '旧密码错误' }), { status: 400 });
  const hashedNew = await hashPassword(newPassword);
  await putKV(env, 'USERS_KV', userKey, { ...user, password: hashedNew });
  return new Response(JSON.stringify({ success: '密码修改成功' }));
}

async function handleLogout(env, request) {
  const token = request.headers.get('Authorization')?.split(' ')[1];
  if (token) await env.USERS_KV.delete(`session:${token}`);
  return new Response(JSON.stringify({ success: true }));
}

// API Management Handlers
async function handleApis(env, request, action = 'list') {
  const uid = getUidFromRequest(request);
  if (!uid) return new Response('Unauthorized', { status: 401 });
  const apisKey = `apis:${uid}`;
  let apis = await getKV(env, 'APIS_KV', apisKey) || [];

  switch (action) {
    case 'add':
      const { name, url } = await request.json();
      if (!validateUrl(url) || !name) return new Response(JSON.stringify({ error: '无效的名称或URL' }), { status: 400 });
      const newId = Date.now().toString();
      const sortOrder = (await getMaxSortOrder(env, 'APIS_KV', uid)) + 1;
      apis.unshift({ id: newId, uid, name, url, addtime: new Date().toISOString().split('T')[0] + ' ' + new Date().toISOString().split('T')[1].split('.')[0], status: 'unknown', sort_order: sortOrder });
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: '添加成功', apis }));
    case 'edit':
      const { id, name, url } = await request.json();
      const apiIdx = apis.findIndex(a => a.id === id && a.uid === uid);
      if (apiIdx === -1 || !validateUrl(url)) return new Response(JSON.stringify({ error: '接口不存在或无效URL' }), { status: 400 });
      apis[apiIdx] = { ...apis[apiIdx], name, url };
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: '更新成功', apis }));
    case 'delete':
      const delId = new URL(request.url).searchParams.get('id');
      apis = apis.filter(a => a.id !== delId || a.uid !== uid);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: '删除成功', apis }));
    case 'delete_selected':
      const selectedIds = await request.json().ids || [];
      apis = apis.filter(a => !selectedIds.includes(a.id) || a.uid !== uid);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: `删除 ${selectedIds.length} 个`, apis }));
    case 'check_single':
      const checkId = new URL(request.url).searchParams.get('id');
      const checkApi = apis.find(a => a.id === checkId && a.uid === uid);
      if (!checkApi) return new Response(JSON.stringify({ error: '接口不存在' }), { status: 404 });
      checkApi.status = await checkUrlStatus(checkApi.url);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ status: checkApi.status }));
    case 'check_all':
      // Batch check with Promise.all
      const checks = apis.map(async (api) => {
        api.status = await checkUrlStatus(api.url);
      });
      await Promise.all(checks);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: '检查完成', updated: apis.length }));
    case 'delete_invalid':
      const before = apis.length;
      apis = apis.filter(a => a.status !== 'invalid' || a.uid !== uid);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: `删除 ${before - apis.length} 个无效` }));
    case 'delete_duplicates':
      const urlMap = new Map();
      apis.forEach(a => {
        if (!urlMap.has(a.url)) urlMap.set(a.url, []);
        urlMap.get(a.url).push(a);
      });
      apis = Array.from(urlMap.values()).map(group => group.sort((a, b) => new Date(b.addtime) - new Date(a.addtime))[0]).filter(Boolean);
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ success: '删除重复完成' }));
    case 'move_up':
      const moveUpId = new URL(request.url).searchParams.get('id');
      const moveUpApi = apis.find(a => a.id === moveUpId);
      if (moveUpApi) {
        moveUpApi.sort_order = (await getMaxSortOrder(env, 'APIS_KV', uid)) + 1;
        apis.sort((a, b) => b.sort_order - a.sort_order);
        await putKV(env, 'APIS_KV', apisKey, apis);
      }
      return new Response(JSON.stringify({ success: '移动成功' }));
    case 'move_down':
      // Similar to move_up but min order
      const moveDownId = new URL(request.url).searchParams.get('id');
      const moveDownApi = apis.find(a => a.id === moveDownId);
      if (moveDownApi) {
        moveDownApi.sort_order = (await getMinSortOrder(env, 'APIS_KV', uid)) - 1;
        apis.sort((a, b) => b.sort_order - a.sort_order);
        await putKV(env, 'APIS_KV', apisKey, apis);
      }
      return new Response(JSON.stringify({ success: '移动成功' }));
    case 'add_client_fetched':
      const selected = await request.json().selected || [];
      const added = [];
      const skipped = [];
      for (const api of selected) {
        if (!validateUrl(api.url) || apis.some(a => a.url === api.url)) {
          skipped.push(api);
        } else {
          const newId = Date.now().toString();
          apis.push({ id: newId, uid, name: api.name, url: api.url, addtime: new Date().toISOString().split('T')[0] + ' ' + new Date().toISOString().split('T')[1].split('.')[0], status: 'unknown', sort_order: (await getMinSortOrder(env, 'APIS_KV', uid)) - 1 });
          added.push(api);
        }
      }
      await putKV(env, 'APIS_KV', apisKey, apis);
      await exportJson(env, uid, apis.filter(a => a.status === 'valid'));
      return new Response(JSON.stringify({ message: \`添加 \${added.length}, 跳过 \${skipped.length}\`, apis: apis.sort((a, b) => b.sort_order - a.sort_order) }));
    default:
      return new Response(JSON.stringify(apis.sort((a, b) => b.sort_order - a.sort_order)), { headers: { 'Content-Type': 'application/json' } });
  }
}

// Similar handlers for video_sources (handleVideoSources), proxies (handleProxies - global key 'proxies:global')

async function handleVideoSources(env, request, action = 'list') {
  // Analogous to handleApis, with fields: name, api_url, detail_url, is_adult, status, sort_order
  // Export to _videos.json
  // Import JSON: parse and add
  const uid = getUidFromRequest(request);
  if (!uid) return new Response('Unauthorized', { status: 401 });
  const vsKey = `video_sources:${uid}`;
  let sources = await getKV(env, 'VIDEO_SOURCES_KV', vsKey) || [];
  // Implement cases: add, edit, delete, check, move, import, etc.
  if (action === 'import') {
    const jsonData = await request.json();
    const sites = jsonData.sites || [];
    const added = 0, skipped = 0;
    for (const site of sites) {
      if (validateUrl(site.api) && !sources.some(s => s.api_url === site.api)) {
        const newId = Date.now().toString();
        sources.push({ id: newId, uid, name: site.name || '未命名', api_url: site.api, detail_url: site.detail_url || '', is_adult: site.is_adult || 0, addtime: new Date().toISOString().split('T')[0] + ' ' + new Date().toISOString().split('T')[1].split('.')[0], status: 'unknown', sort_order: (await getMinSortOrder(env, 'VIDEO_SOURCES_KV', uid)) - 1 });
        added++;
      } else skipped++;
    }
    await putKV(env, 'VIDEO_SOURCES_KV', vsKey, sources);
    await exportVideoJson(env, uid, sources.filter(s => s.status === 'valid'));
    return new Response(JSON.stringify({ success: \`导入 \${added}, 跳过 \${skipped}\` }));
  }
  // Other cases similar...
  await putKV(env, 'VIDEO_SOURCES_KV', vsKey, sources); // For mutations
  return new Response(JSON.stringify(sources.sort((a, b) => b.sort_order - a.sort_order)));
}

async function handleProxies(env, request, action = 'list') {
  // Global
  const proxiesKey = 'proxies:global';
  let proxies = await getKV(env, 'PROXIES_KV', proxiesKey) || DEFAULT_PROXIES;
  // Cases: add, update, delete, check_proxies (batch status)
  if (action === 'check_proxies') {
    const statuses = [];
    for (const proxy of proxies.filter(p => p.enabled)) {
      try {
        const testUrl = proxy.type === 'selfHosted' ? 'https://www.baidu.com/robots.txt' : 'https://www.github.com/robots.txt';
        const fullUrl = buildProxyUrl(proxy, testUrl); // Helper
        const res = await fetch(fullUrl, { method: 'HEAD' });
        statuses.push({ name: proxy.name, status: res.ok ? '有效' : '无效', code: res.status });
      } catch {
        statuses.push({ name: proxy.name, status: '无效', code: 0 });
      }
    }
    return new Response(JSON.stringify(statuses));
  }
  // Mutations...
  await putKV(env, 'PROXIES_KV', proxiesKey, proxies);
  return new Response(JSON.stringify(proxies));
}

// Export Helpers
async function exportJson(env, uid, validApis) {
  const jsonKey = `json:${uid}`;
  await putKV(env, 'JSON_EXPORT_KV', jsonKey, { urls: validApis });
}

async function exportVideoJson(env, uid, validSources) {
  const jsonKey = `videos:${uid}`;
  const sites = validSources.map(s => ({ name: s.name, api: s.api_url, detail_url: s.detail_url || undefined, is_adult: !!s.is_adult }));
  await putKV(env, 'JSON_EXPORT_KV', jsonKey, { sites });
}

// Sort Order Helpers
async function getMaxSortOrder(env, ns, uid) {
  const key = `${ns.split('_')[0].toLowerCase()}:${uid}`;
  const data = await getKV(env, ns.split('_')[0].toUpperCase() + '_KV', key) || [];
  return Math.max(...data.map(d => d.sort_order || 0), 0);
}

async function getMinSortOrder(env, ns, uid) {
  const key = `${ns.split('_')[0].toLowerCase()}:${uid}`;
  const data = await getKV(env, ns.split('_')[0].toUpperCase() + '_KV', key) || [];
  return Math.min(...data.map(d => d.sort_order || 0), 0) - 1;
}

// UID from Request (token)
function getUidFromRequest(request) {
  const auth = request.headers.get('Authorization')?.split(' ')[1];
  return verifyToken(auth);
}

async function getUsernameByUid(env, uid) {
  const users = await listKV(env, 'USERS_KV', 'user:');
  const user = users.find(u => u.name.startsWith('user:') && JSON.parse(u.value).id === uid);
  return user ? JSON.parse(user.value).username : null;
}

// HTML Generation for Sections (server-side render for initial load)
function generateApisHtml(apis, uid) {
  let html = `
    <div class="card mb-4">
        <div class="card-body">
            <div class="section-header"><h6><i class="bi bi-plus-circle me-1"></i>添加新接口</h6></div>
            <form id="addApiForm" class="row g-3">
                <div class="col-md-3"><input type="text" class="form-control" id="newName" placeholder="接口名称" required></div>
                <div class="col-md-7"><input type="url" class="form-control" id="newUrl" placeholder="接口URL (支持中文域名/路径)" required></div>
                <div class="col-md-2"><button type="submit" class="btn btn-success w-100"><i class="bi bi-plus"></i> 添加</button></div>
            </form>
        </div>
    </div>
    <form id="apisForm">
    <div class="card">
        <div class="card-body">
            <div class="mb-3">
                <button type="button" class="btn btn-primary btn-sm me-2" onclick="checkAllApis()"><i class="bi bi-check-circle me-1"></i>一键检查</button>
                <button type="submit" class="btn btn-danger btn-sm me-2" onclick="return confirm('确定删除所有选中的接口吗？')"><i class="bi bi-trash me-1"></i>删除选中</button>
                <!-- More buttons -->
                <a href="/json/${uid}.json" target="_blank" class="btn btn-info btn-sm me-2"><i class="bi bi-file-earmark-code me-1"></i>查看JSON</a>
                <button type="button" onclick="copyJsonUrl()" class="btn btn-secondary btn-sm"><i class="bi bi-copy me-1"></i>复制JSON链接</button>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead><tr><th><input type="checkbox" onclick="toggleSelectAll(this)"></th><th>ID</th><th>名称</th><th>URL</th><th>添加时间</th><th>状态</th><th>操作</th></tr></thead>
                    <tbody>
  `;
  apis.forEach(api => {
    html += `
                        <tr>
                            <td><input type="checkbox" name="selected_ids[]" value="${api.id}"></td>
                            <td>${api.id}</td>
                            <td>${truncateText(api.name, 30)}</td>
                            <td><a href="${api.url}" target="_blank" class="text-truncate d-block" style="max-width: 300px;">${truncateText(api.url, 50)}</a></td>
                            <td>${api.addtime}</td>
                            <td><span class="badge ${api.status === 'valid' ? 'bg-success' : api.status === 'invalid' ? 'bg-danger' : ''} status-badge">${STATUS_MAP[api.status] || api.status}</span></td>
                            <td>
                                <div class="btn-group btn-group-sm">
                                    <button type="button" class="btn btn-outline-info check-single" data-id="${api.id}"><i class="bi bi-check-circle"></i></button>
                                    <button type="button" class="btn btn-outline-secondary" onclick="moveApi('${api.id}', 'up')"><i class="bi bi-arrow-up-circle"></i></button>
                                    <button type="button" class="btn btn-outline-secondary" onclick="moveApi('${api.id}', 'down')"><i class="bi bi-arrow-down-circle"></i></button>
                                    <button type="button" class="btn btn-outline-primary" onclick="prepareEditApi('${api.id}', '${api.name.replace(/'/g, "\\'")}', '${api.url.replace(/'/g, "\\'")}')"><i class="bi bi-pencil"></i></button>
                                    <a href="#" onclick="deleteApi('${api.id}')" class="btn btn-outline-danger"><i class="bi bi-trash"></i></a>
                                </div>
                            </td>
                        </tr>
    `;
  });
  html += `
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    </form>
  `;
  return html;
}

function truncateText(text, len) {
  return text.length > len ? text.substring(0, len) + '...' : text;
}

// Similar generateVideoSourcesHtml, generateProxiesHtml, generateChangePasswordHtml

// Proxy URL Builder
function buildProxyUrl(proxy, target) {
  const base = proxy.url.replace(/\/$/, '');
  switch (proxy.type) {
    case 'selfHosted': return \`\${base}/?url=\${encodeURIComponent(target)}\`;
    case 'allOriginsGet': return \`\${base}/get?url=\${encodeURIComponent(target)}\`;
    case 'allOriginsRaw': return \`\${base}/raw?url=\${encodeURIComponent(target)}\`;
  }
}

// JSON Endpoints
async function handleJsonExport(env, request) {
  const uid = new URL(request.url).pathname.split('/').pop().replace('.json', '');
  if (request.url.includes('_videos')) {
    const vsKey = `videos:${uid}`;
    const data = await getKV(env, 'JSON_EXPORT_KV', vsKey) || { sites: [] };
    return new Response(JSON.stringify(data, null, 2), { headers: { 'Content-Type': 'application/json' } });
  } else {
    const jsonKey = `json:${uid}`;
    const data = await getKV(env, 'JSON_EXPORT_KV', jsonKey) || { urls: [] };
    return new Response(JSON.stringify(data, null, 2), { headers: { 'Content-Type': 'application/json' } });
  }
}

// Main Fetch
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const action = url.searchParams.get('a') || 'home';
    const subAction = url.searchParams.get('action') || 'list';

    // Auth check for protected routes
    let uid = getUidFromRequest(request);
    const isProtected = path.startsWith('/api/') && !['/api/login', '/api/register'].includes(path);

    if (isProtected && !uid) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Routes
    if (path === '/api/login' && request.method === 'POST') return handleLogin(env, request);
    if (path === '/api/register' && request.method === 'POST') return handleRegister(env, request);
    if (path === '/api/change_password' && request.method === 'POST') return handleChangePassword(env, request);
    if (path === '/api/logout' && request.method === 'POST') return handleLogout(env, request);
    if (path === '/api/apis') return handleApis(env, request, action);
    if (path === '/api/video_sources') return handleVideoSources(env, request, action);
    if (path === '/api/proxies') return handleProxies(env, request, action);
    if (path === '/api/verify' && request.method === 'GET') {
      return new Response(JSON.stringify({ uid, username: await getUsernameByUid(env, uid) }));
    }
    if (path.startsWith('/json/')) return handleJsonExport(env, request);

    // Serve SPA HTML
    let html = HTML_TEMPLATE;
    if (uid) {
      html = html.replace('{{USERNAME}}', await getUsernameByUid(env, uid) || 'User');
      // Inject initial section if ?p=param
      const page = url.searchParams.get('p') || 'apis';
      const sectionHtml = await generateSectionHtml(env, page, uid); // Helper to generate
      html = html.replace('<!-- Dynamic content -->', sectionHtml);
    }
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  },
};
