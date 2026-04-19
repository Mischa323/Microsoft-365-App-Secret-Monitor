require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const bcrypt     = require('bcryptjs');
const speakeasy  = require('speakeasy');
const QRCode     = require('qrcode');
const nodemailer = require('nodemailer');

const app          = express();
const PORT         = process.env.PORT || 3000;
const DATA_DIR     = process.env.DATA_DIR || __dirname;
const ENV_PATH     = path.join(DATA_DIR, '.env');
const TENANTS_PATH = path.join(DATA_DIR, 'tenants.json');
const USERS_PATH   = path.join(DATA_DIR, 'users.json');
const GROUPS_PATH  = path.join(DATA_DIR, 'groups.json');

// ── Write threshold defaults to .env if not already set ───────────────────────
(function applyThresholdDefaults() {
  const defaults = { THRESHOLD_CRITICAL: 14, THRESHOLD_WARNING: 30, THRESHOLD_NOTICE: 60 };
  let changed = false;
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  function patchEnv(content, key, value) {
    const line = `${key}=${value}`;
    const re = new RegExp(`^${key}=.*$`, 'm');
    return re.test(content) ? content.replace(re, line) : content + `\n${line}`;
  }
  for (const [key, val] of Object.entries(defaults)) {
    if (!process.env[key]) {
      process.env[key] = String(val);
      env = patchEnv(env, key, val);
      changed = true;
    }
  }
  if (changed) fs.writeFileSync(ENV_PATH, env);
})();

// ── Tenant storage ────────────────────────────────────────────────────────────
function loadTenants() {
  if (!fs.existsSync(TENANTS_PATH)) return [];
  try { return JSON.parse(fs.readFileSync(TENANTS_PATH, 'utf8')); }
  catch { return []; }
}

function saveTenants(tenants) {
  fs.writeFileSync(TENANTS_PATH, JSON.stringify(tenants, null, 2));
}

function sanitizeTenant(t) {
  return {
    id: t.id, name: t.name,
    tenantId: t.tenantId, clientId: t.clientId,
    clientSecretSet: !!t.clientSecret,
    enabled: t.enabled,
  };
}

// ── User / Group storage ──────────────────────────────────────────────────────
function loadUsers() {
  if (!fs.existsSync(USERS_PATH)) return [];
  try { return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8')); }
  catch { return []; }
}

function saveUsers(u) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(u, null, 2));
}

function loadGroups() {
  if (!fs.existsSync(GROUPS_PATH)) return [];
  try { return JSON.parse(fs.readFileSync(GROUPS_PATH, 'utf8')); }
  catch { return []; }
}

function saveGroups(g) {
  fs.writeFileSync(GROUPS_PATH, JSON.stringify(g, null, 2));
}

function sanitizeUser(u) {
  const { passwordHash, totpSecret, ...safe } = u;
  return safe;
}

// ── Migration: create users.json from .env if it doesn't exist ────────────────
(function migrateUsersFromEnv() {
  if (fs.existsSync(USERS_PATH)) return;
  if (!process.env.APP_USERNAME || !process.env.SETUP_COMPLETE === 'true') return;
  if (!process.env.APP_USERNAME) return;

  const adminUser = {
    id: crypto.randomUUID(),
    username: process.env.APP_USERNAME,
    email: (process.env.APP_EMAIL || '').toLowerCase(),
    passwordHash: process.env.APP_PASSWORD_HASH || '',
    role: 'admin',
    groupIds: [],
    totpEnabled: process.env.TWO_FA_ENABLED === 'true',
    totpSecret: process.env.TOTP_SECRET || '',
    receiveNotifications: true,
    enabled: true,
  };
  saveUsers([adminUser]);
  console.log('[migration] Created users.json from .env admin user.');
})();

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '5mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Guards ────────────────────────────────────────────────────────────────────
const isSetupComplete = () => process.env.SETUP_COMPLETE === 'true';

function requireSetup(req, res, next) {
  if (!isSetupComplete()) return res.redirect('/setup');
  next();
}

function requireLogin(req, res, next) {
  if (!isSetupComplete()) return res.redirect('/setup');

  // Support legacy session format (authenticated = true) alongside new userId
  const userId = req.session.userId || req.session.authenticatedUserId;

  if (userId) {
    const users = loadUsers();
    const user = users.find(u => u.id === userId);
    if (!user || user.enabled === false) {
      req.session.destroy(() => {});
      return res.redirect('/login');
    }
    req.user = user;
    return next();
  }

  // Legacy: authenticated flag (before users.json existed)
  if (req.session.authenticated) {
    // Try to find the env admin user in users.json
    const users = loadUsers();
    const envUsername = (process.env.APP_USERNAME || '').toLowerCase();
    const adminUser = users.find(u => u.username.toLowerCase() === envUsername && u.role === 'admin');
    if (adminUser && adminUser.enabled !== false) {
      req.session.userId = adminUser.id;
      req.session.authenticated = undefined;
      req.user = adminUser;
      return next();
    }
  }

  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  requireLogin(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
  });
}

// ── Tenant access helper ──────────────────────────────────────────────────────
function getUserTenantIds(user) {
  if (user.role === 'admin') return null; // null = all tenants
  const groups = loadGroups().filter(g => (user.groupIds || []).includes(g.id));
  const ids = new Set();
  for (const g of groups) {
    if (!g.tenantIds || g.tenantIds.includes('all')) return null;
    g.tenantIds.forEach(id => ids.add(id));
  }
  return [...ids];
}

// ── Root ──────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (!isSetupComplete()) return res.redirect('/setup');
  const isAuth = req.session.userId || req.session.authenticated;
  res.redirect(isAuth ? '/dashboard' : '/login');
});

// ── Setup ─────────────────────────────────────────────────────────────────────
app.get('/setup', (req, res) => {
  if (isSetupComplete()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

app.get('/api/setup/totp', async (req, res) => {
  if (isSetupComplete()) return res.status(403).json({ error: 'Setup already completed.' });
  try {
    const secret = speakeasy.generateSecret({ name: 'M365 Secret Monitor', length: 20 });
    req.session.setupTotpSecret = secret.base32;
    req.session.setupTotpVerified = false;
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrDataUrl });
  } catch (e) {
    console.error('TOTP setup error:', e);
    res.status(500).json({ error: 'Failed to generate 2FA secret: ' + e.message });
  }
});

app.post('/api/setup/totp/verify', (req, res) => {
  if (isSetupComplete()) return res.status(403).json({ error: 'Setup already completed.' });
  const secret = req.session.setupTotpSecret;
  if (!secret) return res.status(400).json({ error: 'No TOTP secret in session. Reload step 2.' });
  const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token: req.body.token, window: 1 });
  if (!valid) return res.status(400).json({ error: 'Invalid code — check your authenticator and try again.' });
  req.session.setupTotpVerified = true;
  res.json({ ok: true });
});

app.post('/api/setup', async (req, res) => {
  if (isSetupComplete()) return res.status(403).json({ error: 'Setup already completed.' });

  const { username, email, password, confirmPassword, timezone,
          enable2fa, tenantName, tenantId, clientId, clientSecret } = req.body;

  if (!username || username.length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRe.test(email))
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (password !== confirmPassword)
    return res.status(400).json({ error: 'Passwords do not match.' });
  if (enable2fa === 'true' && !req.session.setupTotpVerified)
    return res.status(400).json({ error: '2FA code not verified. Complete step 2 first.' });

  const guidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (tenantId && !guidRe.test(tenantId))
    return res.status(400).json({ error: 'Invalid Tenant ID format.' });
  if (clientId && !guidRe.test(clientId))
    return res.status(400).json({ error: 'Invalid Client ID format.' });

  try {
    const hash = await bcrypt.hash(password, 12);
    const totpEnabled = enable2fa === 'true';
    const totpSecret  = totpEnabled ? req.session.setupTotpSecret : '';

    process.env.APP_USERNAME      = username;
    process.env.APP_EMAIL         = email.toLowerCase();
    process.env.APP_PASSWORD_HASH = hash;
    process.env.TIMEZONE          = timezone || 'UTC';
    process.env.TWO_FA_ENABLED    = totpEnabled ? 'true' : 'false';
    process.env.SETUP_COMPLETE    = 'true';
    if (totpEnabled) process.env.TOTP_SECRET = totpSecret;

    let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    env = setEnvVar(env, 'APP_USERNAME',      username);
    env = setEnvVar(env, 'APP_EMAIL',         email.toLowerCase());
    env = setEnvVar(env, 'APP_PASSWORD_HASH', hash);
    env = setEnvVar(env, 'TIMEZONE',          timezone || 'UTC');
    env = setEnvVar(env, 'TWO_FA_ENABLED',    totpEnabled ? 'true' : 'false');
    env = setEnvVar(env, 'SETUP_COMPLETE',    'true');
    if (totpEnabled) env = setEnvVar(env, 'TOTP_SECRET', totpSecret);
    fs.writeFileSync(ENV_PATH, env);

    // Save first admin user to users.json
    const adminUser = {
      id: crypto.randomUUID(),
      username,
      email: email.toLowerCase(),
      passwordHash: hash,
      role: 'admin',
      groupIds: [],
      totpEnabled,
      totpSecret,
      receiveNotifications: true,
      enabled: true,
    };
    saveUsers([adminUser]);

    // Save first tenant to tenants.json if provided
    if (tenantId && clientId && clientSecret) {
      saveTenants([{
        id: crypto.randomUUID(),
        name: (tenantName || '').trim() || 'Default Tenant',
        tenantId, clientId, clientSecret,
        enabled: true,
      }]);
    }

    delete req.session.setupTotpSecret;
    delete req.session.setupTotpVerified;
    res.json({ ok: true });
  } catch (e) {
    console.error('Setup error:', e.message);
    res.status(500).json({ error: 'Setup failed: ' + e.message });
  }
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.get('/login', requireSetup, (req, res) => {
  const isAuth = req.session.userId || req.session.authenticated;
  if (isAuth) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', requireSetup, async (req, res) => {
  const { username, password } = req.body;
  const id = (username || '').trim().toLowerCase();

  const users = loadUsers();
  const user = users.find(u =>
    u.username.toLowerCase() === id || u.email.toLowerCase() === id
  );

  if (!user || user.enabled === false) return res.redirect('/login?error=1');

  const ok = user.passwordHash && await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.redirect('/login?error=1');

  if (user.totpEnabled) {
    req.session.pendingUserId = user.id;
    req.session.pendingAuth = true; // legacy compat
    return res.redirect('/login/2fa');
  }

  req.session.userId = user.id;
  req.session.authenticated = undefined;
  res.redirect('/dashboard');
});

app.get('/login/2fa', requireSetup, (req, res) => {
  if (!req.session.pendingAuth && !req.session.pendingUserId) return res.redirect('/login');
  const isAuth = req.session.userId || req.session.authenticated;
  if (isAuth) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login-2fa.html'));
});

app.post('/login/2fa', requireSetup, (req, res) => {
  const pendingUserId = req.session.pendingUserId;
  if (!pendingUserId && !req.session.pendingAuth) return res.redirect('/login');

  let totpSecret;
  let userId;

  if (pendingUserId) {
    const users = loadUsers();
    const user = users.find(u => u.id === pendingUserId);
    if (!user) return res.redirect('/login');
    totpSecret = user.totpSecret;
    userId = user.id;
  } else {
    // Legacy fallback
    totpSecret = process.env.TOTP_SECRET;
    const users = loadUsers();
    const envAdmin = users.find(u =>
      u.username.toLowerCase() === (process.env.APP_USERNAME || '').toLowerCase() && u.role === 'admin'
    );
    userId = envAdmin ? envAdmin.id : null;
  }

  const valid = speakeasy.totp.verify({
    secret: totpSecret, encoding: 'base32',
    token: req.body.token, window: 1,
  });
  if (!valid) return res.redirect('/login/2fa?error=1');

  delete req.session.pendingAuth;
  delete req.session.pendingUserId;
  req.session.userId = userId;
  req.session.authenticated = undefined;
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── Pages ─────────────────────────────────────────────────────────────────────
app.get('/dashboard', requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/settings', requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'settings.html')));

// ── API: current user ─────────────────────────────────────────────────────────
app.get('/api/me', requireLogin, (req, res) => {
  const { id, username, email, role, groupIds, receiveNotifications } = req.user;
  res.json({ id, username, email, role, groupIds: groupIds || [], receiveNotifications: !!receiveNotifications });
});

// ── API: users (admin only) ───────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => {
  res.json(loadUsers().map(sanitizeUser));
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, email, password, role, groupIds, receiveNotifications, enabled } = req.body;
  if (!username || username.trim().length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRe.test(email))
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!['admin', 'viewer'].includes(role))
    return res.status(400).json({ error: 'Role must be admin or viewer.' });

  const users = loadUsers();
  const lname = username.trim().toLowerCase();
  const lemail = email.trim().toLowerCase();
  if (users.find(u => u.username.toLowerCase() === lname))
    return res.status(400).json({ error: 'Username already exists.' });
  if (users.find(u => u.email.toLowerCase() === lemail))
    return res.status(400).json({ error: 'Email already in use.' });

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: crypto.randomUUID(),
      username: username.trim(),
      email: lemail,
      passwordHash,
      role,
      groupIds: Array.isArray(groupIds) ? groupIds : [],
      totpEnabled: false,
      totpSecret: '',
      receiveNotifications: receiveNotifications === true || receiveNotifications === 'true',
      enabled: enabled !== false && enabled !== 'false',
    };
    users.push(user);
    saveUsers(users);
    res.json(sanitizeUser(user));
  } catch (e) {
    res.status(500).json({ error: 'Failed to create user: ' + e.message });
  }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found.' });

  const { username, email, password, role, groupIds, receiveNotifications, enabled } = req.body;

  // Prevent demoting the last admin
  if (role && role !== 'admin' && users[idx].role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin' && u.enabled !== false).length;
    if (adminCount <= 1)
      return res.status(400).json({ error: 'Cannot demote the last admin.' });
  }

  // Prevent disabling the last admin
  if ((enabled === false || enabled === 'false') && users[idx].role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin' && u.enabled !== false).length;
    if (adminCount <= 1)
      return res.status(400).json({ error: 'Cannot disable the last admin.' });
  }

  if (username !== undefined) {
    if (!username.trim() || username.trim().length < 3)
      return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    const lname = username.trim().toLowerCase();
    if (users.find((u, i) => i !== idx && u.username.toLowerCase() === lname))
      return res.status(400).json({ error: 'Username already exists.' });
    users[idx].username = username.trim();
  }

  if (email !== undefined) {
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email))
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    const lemail = email.trim().toLowerCase();
    if (users.find((u, i) => i !== idx && u.email.toLowerCase() === lemail))
      return res.status(400).json({ error: 'Email already in use.' });
    users[idx].email = lemail;
  }

  if (password) {
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    users[idx].passwordHash = await bcrypt.hash(password, 12);
  }

  if (role !== undefined) users[idx].role = role;
  if (groupIds !== undefined) users[idx].groupIds = Array.isArray(groupIds) ? groupIds : [];
  if (receiveNotifications !== undefined)
    users[idx].receiveNotifications = receiveNotifications === true || receiveNotifications === 'true';
  if (enabled !== undefined)
    users[idx].enabled = enabled !== false && enabled !== 'false';

  saveUsers(users);
  res.json(sanitizeUser(users[idx]));
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // Prevent deleting self
  if (req.user.id === user.id)
    return res.status(400).json({ error: 'You cannot delete your own account.' });

  // Prevent deleting last admin
  if (user.role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin' && u.enabled !== false).length;
    if (adminCount <= 1)
      return res.status(400).json({ error: 'Cannot delete the last admin.' });
  }

  saveUsers(users.filter(u => u.id !== req.params.id));
  res.json({ ok: true });
});

// ── API: groups (admin only) ──────────────────────────────────────────────────
app.get('/api/groups', requireAdmin, (req, res) => {
  res.json(loadGroups());
});

app.post('/api/groups', requireAdmin, (req, res) => {
  const { name, tenantIds } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Group name is required.' });

  const groups = loadGroups();
  const group = {
    id: crypto.randomUUID(),
    name: name.trim(),
    tenantIds: Array.isArray(tenantIds) ? tenantIds : ['all'],
  };
  groups.push(group);
  saveGroups(groups);
  res.json(group);
});

app.put('/api/groups/:id', requireAdmin, (req, res) => {
  const groups = loadGroups();
  const idx = groups.findIndex(g => g.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Group not found.' });

  const { name, tenantIds } = req.body;
  if (name !== undefined) {
    if (!name.trim()) return res.status(400).json({ error: 'Group name is required.' });
    groups[idx].name = name.trim();
  }
  if (tenantIds !== undefined)
    groups[idx].tenantIds = Array.isArray(tenantIds) ? tenantIds : ['all'];

  saveGroups(groups);
  res.json(groups[idx]);
});

app.delete('/api/groups/:id', requireAdmin, (req, res) => {
  const groups = loadGroups();
  if (!groups.find(g => g.id === req.params.id))
    return res.status(404).json({ error: 'Group not found.' });
  saveGroups(groups.filter(g => g.id !== req.params.id));
  res.json({ ok: true });
});

// ── API: logo ─────────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');

app.get('/api/logo', (req, res) => {
  const file = process.env.LOGO_FILE;
  if (!file) return res.status(404).end();
  const filePath = path.join(UPLOADS_DIR, file);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.post('/api/logo', requireLogin, (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No image data provided.' });

  const match = data.match(/^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,(.+)$/s);
  if (!match) return res.status(400).json({ error: 'Unsupported format. Use PNG, JPG, GIF, WebP, or SVG.' });

  const rawExt = match[1];
  const base64 = match[2];
  const ext      = rawExt === 'svg+xml' ? 'svg' : rawExt;
  const filename = `logo.${ext}`;

  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

  // Remove any previous logo files
  fs.readdirSync(UPLOADS_DIR)
    .filter(f => f.startsWith('logo.'))
    .forEach(f => fs.unlinkSync(path.join(UPLOADS_DIR, f)));

  fs.writeFileSync(path.join(UPLOADS_DIR, filename), Buffer.from(base64, 'base64'));

  process.env.LOGO_FILE = filename;
  try {
    let env = fs.readFileSync(ENV_PATH, 'utf8');
    env = setEnvVar(env, 'LOGO_FILE', filename);
    fs.writeFileSync(ENV_PATH, env);
  } catch (e) { console.error('Could not update .env:', e.message); }

  res.json({ url: `/uploads/${filename}` });
});

app.delete('/api/logo', requireLogin, (req, res) => {
  if (fs.existsSync(UPLOADS_DIR)) {
    fs.readdirSync(UPLOADS_DIR)
      .filter(f => f.startsWith('logo.'))
      .forEach(f => fs.unlinkSync(path.join(UPLOADS_DIR, f)));
  }
  process.env.LOGO_FILE = '';
  try {
    let env = fs.readFileSync(ENV_PATH, 'utf8');
    env = setEnvVar(env, 'LOGO_FILE', '');
    fs.writeFileSync(ENV_PATH, env);
  } catch (e) { console.error('Could not update .env:', e.message); }
  res.json({ ok: true });
});

// ── API: general settings (timezone only) ────────────────────────────────────
app.get('/api/settings', requireLogin, (req, res) => {
  res.json({ timezone: process.env.TIMEZONE || 'UTC', thresholds: getThresholds() });
});

app.post('/api/thresholds', requireLogin, (req, res) => {
  const critical = parseInt(req.body.critical);
  const warning  = parseInt(req.body.warning);
  const notice   = parseInt(req.body.notice);
  if (isNaN(critical) || isNaN(warning) || isNaN(notice) || critical < 1 || warning <= critical || notice <= warning)
    return res.status(400).json({ error: 'Invalid thresholds. Must be positive integers with critical < warning < notice.' });
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  env = setEnvVar(env, 'THRESHOLD_CRITICAL', critical);
  env = setEnvVar(env, 'THRESHOLD_WARNING',  warning);
  env = setEnvVar(env, 'THRESHOLD_NOTICE',   notice);
  fs.writeFileSync(ENV_PATH, env);
  process.env.THRESHOLD_CRITICAL = critical;
  process.env.THRESHOLD_WARNING  = warning;
  process.env.THRESHOLD_NOTICE   = notice;
  res.json({ ok: true });
});

// ── API: email ────────────────────────────────────────────────────────────────
function getMailConfig() {
  return {
    enabled:        process.env.MAIL_ENABLED === 'true',
    method:         process.env.MAIL_METHOD || 'smtp',
    to:             process.env.MAIL_TO || '',
    notifyExpired:  process.env.MAIL_NOTIFY_EXPIRED  !== 'false',
    notifyCritical: process.env.MAIL_NOTIFY_CRITICAL !== 'false',
    notifyWarning:  process.env.MAIL_NOTIFY_WARNING  === 'true',
    notifyNotice:   process.env.MAIL_NOTIFY_NOTICE   === 'true',
    tenantIds:      process.env.MAIL_TENANT_IDS || 'all',
    smtp: {
      host:   process.env.SMTP_HOST   || '',
      port:   parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      user:   process.env.SMTP_USER   || '',
      from:   process.env.SMTP_FROM   || '',
    },
    graph: {
      tenantRecordId: process.env.MAIL_GRAPH_TENANT_ID || '',
      sender:         process.env.MAIL_GRAPH_SENDER    || '',
    },
  };
}

function saveMailConfig(cfg, smtpPass) {
  const vars = {
    MAIL_ENABLED:        cfg.enabled  ? 'true' : 'false',
    MAIL_METHOD:         cfg.method,
    MAIL_TO:             cfg.to,
    MAIL_NOTIFY_EXPIRED:  cfg.notifyExpired  ? 'true' : 'false',
    MAIL_NOTIFY_CRITICAL: cfg.notifyCritical ? 'true' : 'false',
    MAIL_NOTIFY_WARNING:  cfg.notifyWarning  ? 'true' : 'false',
    MAIL_NOTIFY_NOTICE:   cfg.notifyNotice   ? 'true' : 'false',
    MAIL_TENANT_IDS:      cfg.tenantIds || 'all',
    SMTP_HOST:   cfg.smtp.host,
    SMTP_PORT:   String(cfg.smtp.port || 587),
    SMTP_SECURE: cfg.smtp.secure ? 'true' : 'false',
    SMTP_USER:   cfg.smtp.user,
    SMTP_FROM:   cfg.smtp.from,
    MAIL_GRAPH_TENANT_ID: cfg.graph.tenantRecordId,
    MAIL_GRAPH_SENDER:    cfg.graph.sender,
  };
  if (smtpPass !== undefined && smtpPass !== '••••••••') vars.SMTP_PASS = smtpPass;
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  for (const [k, v] of Object.entries(vars)) {
    env = setEnvVar(env, k, v);
    process.env[k] = v;
  }
  if (smtpPass !== undefined && smtpPass !== '••••••••') process.env.SMTP_PASS = smtpPass;
  fs.writeFileSync(ENV_PATH, env);
}

function statusColor(status) {
  return { expired: '#d13438', critical: '#d13438', warning: '#ca5010', notice: '#986f0b', ok: '#107c10' }[status] || '#605e5c';
}

function buildReportHtml(rows) {
  const groups = { expired: [], critical: [], warning: [], notice: [] };
  for (const r of rows) if (groups[r.status]) groups[r.status].push(r);
  const sections = Object.entries(groups)
    .filter(([, list]) => list.length)
    .map(([status, list]) => {
      const label = status.charAt(0).toUpperCase() + status.slice(1);
      const color = statusColor(status);
      const trs = list.map(r => `<tr>
        <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">${r.tenantName}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px"><strong>${r.appName}</strong></td>
        <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">${r.secretName}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">${r.expires ? new Date(r.expires).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }) : '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px;color:${color};font-weight:600">${r.daysLeft < 0 ? Math.abs(r.daysLeft) + 'd ago' : (r.daysLeft === null ? '—' : r.daysLeft + 'd')}</td>
      </tr>`).join('');
      return `<h3 style="color:${color};margin:24px 0 8px">${label} (${list.length})</h3>
      <table style="width:100%;border-collapse:collapse;background:white;border-radius:6px;overflow:hidden;border:1px solid #edebe9">
        <thead><tr style="background:#f8f7f6">
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Tenant</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Application</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Secret</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Expires</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Days left</th>
        </tr></thead>
        <tbody>${trs}</tbody>
      </table>`;
    }).join('');
  return `<!DOCTYPE html><html><body style="font-family:'Segoe UI',system-ui,sans-serif;background:#f3f2f1;margin:0;padding:32px 24px">
  <div style="max-width:700px;margin:0 auto">
    <div style="background:#0078d4;color:white;border-radius:8px 8px 0 0;padding:24px 28px">
      <h2 style="margin:0;font-size:20px">🔐 App Secret Monitor — Expiry Report</h2>
      <p style="margin:6px 0 0;opacity:.85;font-size:13px">Generated ${new Date().toLocaleString('en-GB')}</p>
    </div>
    <div style="background:white;border-radius:0 0 8px 8px;padding:24px 28px;border:1px solid #edebe9;border-top:none">
      ${sections || '<p style="color:#605e5c">No secrets require attention at this time.</p>'}
    </div>
  </div></body></html>`;
}

async function sendMailTo(to, subject, html) {
  const cfg = getMailConfig();
  if (!cfg.enabled) throw new Error('Email notifications are disabled.');
  if (!to) throw new Error('No recipients configured.');
  if (cfg.method === 'smtp') {
    const transport = nodemailer.createTransport({
      host: cfg.smtp.host, port: cfg.smtp.port, secure: cfg.smtp.secure,
      auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: process.env.SMTP_PASS || '' } : undefined,
    });
    await transport.sendMail({ from: cfg.smtp.from || cfg.smtp.user, to, subject, html });
  } else {
    const tenant = loadTenants().find(t => t.id === cfg.graph.tenantRecordId);
    if (!tenant) throw new Error('Graph mail tenant not found.');
    const token = await getGraphToken(tenant.tenantId, tenant.clientId, tenant.clientSecret);
    const resp = await fetch(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(cfg.graph.sender)}/sendMail`,
      { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { subject, body: { contentType: 'HTML', content: html },
          toRecipients: to.split(',').map(e => ({ emailAddress: { address: e.trim() } })) }, saveToSentItems: false }) }
    );
    if (!resp.ok) { const d = await resp.json().catch(() => ({})); throw new Error(d.error?.message || `Graph ${resp.status}`); }
  }
}

async function sendMail(subject, html) {
  const cfg = getMailConfig();
  await sendMailTo(cfg.to, subject, html);
}

async function fetchReportRows() {
  const cfg = getMailConfig();
  const all = loadTenants().filter(t => t.enabled !== false);
  const selectedIds = cfg.tenantIds === 'all' ? null : cfg.tenantIds.split(',').map(s => s.trim()).filter(Boolean);
  const tenants = selectedIds ? all.filter(t => selectedIds.includes(t.id)) : all;
  const results = await Promise.allSettled(
    tenants.map(async t => {
      const token = await getGraphToken(t.tenantId, t.clientId, t.clientSecret);
      return buildRows(await fetchAllApps(token), t.name, t.id);
    })
  );
  return results.flatMap(r => r.status === 'fulfilled' ? r.value : []);
}

async function sendReportToUsers(allRows, statusFilter) {
  const cfg = getMailConfig();
  const subject = 'App Secret Expiry Report – M365 Secret Monitor';

  // Find users with receiveNotifications enabled
  const notifyUsers = loadUsers().filter(u => u.receiveNotifications && u.enabled !== false && u.email);

  if (notifyUsers.length === 0) {
    // Fall back to global MAIL_TO
    const rows = allRows.filter(r => statusFilter.includes(r.status));
    await sendMail(subject, buildReportHtml(rows));
    return rows.length;
  }

  let totalCount = 0;
  await Promise.allSettled(notifyUsers.map(async user => {
    const accessibleTenantIds = getUserTenantIds(user);
    let userRows = allRows;
    if (accessibleTenantIds !== null) {
      userRows = allRows.filter(r => accessibleTenantIds.includes(r.tenantRecordId));
    }
    userRows = userRows.filter(r => statusFilter.includes(r.status));
    if (userRows.length === 0) return;
    await sendMailTo(user.email, subject, buildReportHtml(userRows));
    totalCount += userRows.length;
  }));

  return totalCount;
}

app.get('/api/email', requireLogin, (req, res) => {
  const cfg = getMailConfig();
  cfg.smtp.pass = process.env.SMTP_PASS ? '••••••••' : '';
  res.json(cfg);
});

app.post('/api/email', requireLogin, (req, res) => {
  const b = req.body;
  saveMailConfig({
    enabled: b.enabled === true || b.enabled === 'true',
    method:  b.method || 'smtp',
    to:      b.to || '',
    notifyExpired:  b.notifyExpired  !== false && b.notifyExpired  !== 'false',
    notifyCritical: b.notifyCritical !== false && b.notifyCritical !== 'false',
    notifyWarning:  b.notifyWarning  === true  || b.notifyWarning  === 'true',
    notifyNotice:   b.notifyNotice   === true  || b.notifyNotice   === 'true',
    tenantIds:      Array.isArray(b.tenantIds) ? (b.tenantIds.length ? b.tenantIds.join(',') : 'all') : (b.tenantIds || 'all'),
    smtp:  { host: b.smtpHost || '', port: parseInt(b.smtpPort) || 587, secure: b.smtpSecure === true || b.smtpSecure === 'true', user: b.smtpUser || '', from: b.smtpFrom || '' },
    graph: { tenantRecordId: b.graphTenantId || '', sender: b.graphSender || '' },
  }, b.smtpPass);
  res.json({ ok: true });
});

function getScheduleConfig() {
  return {
    freq:      process.env.MAIL_SCHEDULE_FREQ     || 'disabled',
    time:      process.env.MAIL_SCHEDULE_TIME     || '09:00',
    dow:       parseInt(process.env.MAIL_SCHEDULE_DOW)      || 1,
    dom:       parseInt(process.env.MAIL_SCHEDULE_DOM)      || 1,
    yearMonth: parseInt(process.env.MAIL_SCHEDULE_MONTH)    || 1,
    yearDay:   parseInt(process.env.MAIL_SCHEDULE_YEAR_DAY) || 1,
    lastSent:  process.env.MAIL_SCHEDULE_LAST_SENT || '',
  };
}

function nowInTz() {
  const tz = process.env.TIMEZONE || 'UTC';
  const now = new Date();
  const p = {};
  for (const part of new Intl.DateTimeFormat('en-US', {
    timeZone: tz, year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', hour12: false,
  }).formatToParts(now)) if (part.type !== 'literal') p[part.type] = parseInt(part.value);
  // hour12:false can return 24 for midnight in some runtimes
  if (p.hour === 24) p.hour = 0;
  const dateStr = `${p.year}-${String(p.month).padStart(2,'0')}-${String(p.day).padStart(2,'0')}`;
  // Day of week: build a Date string in the TZ and get .getDay()
  const dow = new Date(new Date().toLocaleString('en-US', { timeZone: tz })).getDay();
  return { ...p, dateStr, dow };
}

function shouldSendNow() {
  const sc = getScheduleConfig();
  if (sc.freq === 'disabled') return false;
  const t = nowInTz();
  const [sh, sm] = sc.time.split(':').map(Number);
  if (t.hour !== sh || t.minute !== sm) return false;
  if (sc.lastSent === t.dateStr) return false; // already sent this calendar day
  switch (sc.freq) {
    case 'daily':   return true;
    case 'weekly':  return t.dow === sc.dow;
    case 'monthly': return t.day === sc.dom;
    case 'yearly':  return t.month === sc.yearMonth && t.day === sc.yearDay;
    default:        return false;
  }
}

async function runScheduledReport() {
  if (!shouldSendNow()) return;
  const cfg = getMailConfig();
  if (!cfg.enabled) return;
  try {
    const statuses = [];
    if (cfg.notifyExpired)  statuses.push('expired');
    if (cfg.notifyCritical) statuses.push('critical');
    if (cfg.notifyWarning)  statuses.push('warning');
    if (cfg.notifyNotice)   statuses.push('notice');
    const allRows = await fetchReportRows();
    const count = await sendReportToUsers(allRows, statuses);
    const dateStr = nowInTz().dateStr;
    let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    env = setEnvVar(env, 'MAIL_SCHEDULE_LAST_SENT', dateStr);
    fs.writeFileSync(ENV_PATH, env);
    process.env.MAIL_SCHEDULE_LAST_SENT = dateStr;
    console.log(`[scheduler] Report sent (${count} items)`);
  } catch (e) { console.error('[scheduler] Failed to send report:', e.message); }
}

setInterval(runScheduledReport, 60_000); // check every minute

app.get('/api/email/schedule', requireLogin, (req, res) => res.json(getScheduleConfig()));

app.post('/api/email/schedule', requireLogin, (req, res) => {
  const { freq, time, dow, dom, yearMonth, yearDay } = req.body;
  const keys = {
    MAIL_SCHEDULE_FREQ:     freq      || 'disabled',
    MAIL_SCHEDULE_TIME:     time      || '09:00',
    MAIL_SCHEDULE_DOW:      String(dow      ?? 1),
    MAIL_SCHEDULE_DOM:      String(dom      ?? 1),
    MAIL_SCHEDULE_MONTH:    String(yearMonth ?? 1),
    MAIL_SCHEDULE_YEAR_DAY: String(yearDay  ?? 1),
  };
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  for (const [k, v] of Object.entries(keys)) { env = setEnvVar(env, k, v); process.env[k] = v; }
  fs.writeFileSync(ENV_PATH, env);
  res.json({ ok: true });
});

app.post('/api/email/test', requireLogin, async (req, res) => {
  try {
    await sendMail('Test email – M365 Secret Monitor', '<p>This is a test email from your M365 App Secret Monitor. If you can read this, email is configured correctly.</p>');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/email/send-report', requireLogin, async (req, res) => {
  try {
    const cfg  = getMailConfig();
    const statuses = [];
    if (cfg.notifyExpired)  statuses.push('expired');
    if (cfg.notifyCritical) statuses.push('critical');
    if (cfg.notifyWarning)  statuses.push('warning');
    if (cfg.notifyNotice)   statuses.push('notice');
    const allRows = await fetchReportRows();
    const count = await sendReportToUsers(allRows, statuses);
    res.json({ ok: true, count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: tenants ──────────────────────────────────────────────────────────────
app.get('/api/tenants', requireLogin, (req, res) => {
  const allTenants = loadTenants();
  const accessibleIds = getUserTenantIds(req.user);
  const tenants = accessibleIds === null ? allTenants : allTenants.filter(t => accessibleIds.includes(t.id));
  res.json(tenants.map(sanitizeTenant));
});

app.post('/api/tenants', requireAdmin, (req, res) => {
  const { name, tenantId, clientId, clientSecret } = req.body;
  const guidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Tenant name is required.' });
  if (!guidRe.test(tenantId))
    return res.status(400).json({ error: 'Invalid Tenant ID format.' });
  if (!guidRe.test(clientId))
    return res.status(400).json({ error: 'Invalid Client ID format.' });
  if (!clientSecret)
    return res.status(400).json({ error: 'Client secret is required.' });

  const tenants = loadTenants();
  const entry = {
    id: crypto.randomUUID(),
    name: name.trim(), tenantId, clientId, clientSecret,
    enabled: true,
  };
  tenants.push(entry);
  saveTenants(tenants);
  res.json(sanitizeTenant(entry));
});

app.put('/api/tenants/:id', requireAdmin, (req, res) => {
  const tenants = loadTenants();
  const idx = tenants.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Tenant not found.' });

  const { name, tenantId, clientId, clientSecret } = req.body;
  const guidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Tenant name is required.' });
  if (!guidRe.test(tenantId))
    return res.status(400).json({ error: 'Invalid Tenant ID format.' });
  if (!guidRe.test(clientId))
    return res.status(400).json({ error: 'Invalid Client ID format.' });

  tenants[idx].name     = name.trim();
  tenants[idx].tenantId = tenantId;
  tenants[idx].clientId = clientId;
  if (clientSecret) tenants[idx].clientSecret = clientSecret;
  saveTenants(tenants);
  res.json(sanitizeTenant(tenants[idx]));
});

app.patch('/api/tenants/:id/toggle', requireAdmin, (req, res) => {
  const tenants = loadTenants();
  const t = tenants.find(t => t.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'Tenant not found.' });
  t.enabled = !t.enabled;
  saveTenants(tenants);
  res.json({ enabled: t.enabled });
});

app.delete('/api/tenants/:id', requireAdmin, (req, res) => {
  const tenants = loadTenants();
  if (!tenants.find(t => t.id === req.params.id))
    return res.status(404).json({ error: 'Tenant not found.' });
  saveTenants(tenants.filter(t => t.id !== req.params.id));
  res.json({ ok: true });
});

app.post('/api/tenants/:id/test', requireLogin, async (req, res) => {
  const t = loadTenants().find(t => t.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'Tenant not found.' });
  try {
    const token  = await getGraphToken(t.tenantId, t.clientId, t.clientSecret);
    const roles  = getTokenRoles(token);
    const resp   = await fetch('https://graph.microsoft.com/v1.0/applications?$top=1', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) throw new Error(`Graph returned ${resp.status}`);
    res.json({
      ok: true,
      canRead:  roles.includes('Application.Read.All') || roles.includes('Application.ReadWrite.All'),
      canWrite: roles.includes('Application.ReadWrite.All'),
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: secrets from all enabled tenants ─────────────────────────────────────
app.get('/api/secrets', requireLogin, async (req, res) => {
  const allTenants = loadTenants().filter(t => t.enabled);
  const accessibleIds = getUserTenantIds(req.user);
  const tenants = accessibleIds === null ? allTenants : allTenants.filter(t => accessibleIds.includes(t.id));

  if (tenants.length === 0)
    return res.status(400).json({ error: 'No tenants configured. Go to Settings → Tenants to add one.' });

  const results = await Promise.allSettled(
    tenants.map(async t => {
      const token    = await getGraphToken(t.tenantId, t.clientId, t.clientSecret);
      const roles    = getTokenRoles(token);
      const canWrite = roles.includes('Application.ReadWrite.All');
      const apps     = await fetchAllApps(token);
      return { rows: buildRows(apps, t.name, t.id), canWrite, tenantName: t.name };
    })
  );

  const rows        = [];
  const errors      = [];
  const permissions = {};
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      rows.push(...r.value.rows);
      permissions[r.value.tenantName] = r.value.canWrite;
    } else {
      errors.push({ tenant: tenants[i].name, error: r.reason.message });
    }
  });

  rows.sort((a, b) => a.daysLeft - b.daysLeft);
  res.json({ rows, errors, permissions });
});

// ── API: remove a secret from an app registration ────────────────────────────
app.post('/api/secrets/remove', requireLogin, async (req, res) => {
  const { tenantRecordId, objectId, keyId } = req.body;
  if (!tenantRecordId || !objectId || !keyId)
    return res.status(400).json({ error: 'Missing required fields.' });

  const tenant = loadTenants().find(t => t.id === tenantRecordId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });

  try {
    const token  = await getGraphToken(tenant.tenantId, tenant.clientId, tenant.clientSecret);
    const roles  = getTokenRoles(token);
    if (!roles.includes('Application.ReadWrite.All'))
      return res.status(403).json({
        error: 'Permission denied. Grant Application.ReadWrite.All to this app registration in Azure Portal, then test the connection again.',
      });

    const resp = await fetch(
      `https://graph.microsoft.com/v1.0/applications/${objectId}/removePassword`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId }),
      },
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error?.message || `Graph ${resp.status}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Remove secret error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/apps/:objectId', requireLogin, async (req, res) => {
  const { objectId } = req.params;
  const { tenantRecordId } = req.body;
  if (!tenantRecordId || !objectId) return res.status(400).json({ error: 'Missing required fields.' });
  const tenant = loadTenants().find(t => t.id === tenantRecordId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });
  try {
    const token = await getGraphToken(tenant.tenantId, tenant.clientId, tenant.clientSecret);
    const roles = getTokenRoles(token);
    if (!roles.includes('Application.ReadWrite.All'))
      return res.status(403).json({ error: 'Permission denied. Grant Application.ReadWrite.All to delete app registrations.' });
    const resp = await fetch(`https://graph.microsoft.com/v1.0/applications/${objectId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok && resp.status !== 204) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error?.message || `Graph ${resp.status}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete app error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function setEnvVar(content, key, value) {
  const line = `${key}=${value}`;
  const re   = new RegExp(`^${key}=.*$`, 'm');
  return re.test(content) ? content.replace(re, line) : content + `\n${line}`;
}

async function getGraphToken(tenantId, clientId, clientSecret) {
  const resp = await fetch(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    { method: 'POST', body: new URLSearchParams({
        grant_type: 'client_credentials', client_id: clientId,
        client_secret: clientSecret, scope: 'https://graph.microsoft.com/.default',
    })},
  );
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error_description || data.error || 'Token request failed');
  return data.access_token;
}

function getTokenRoles(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    return Array.isArray(payload.roles) ? payload.roles : [];
  } catch { return []; }
}

async function fetchAllApps(token) {
  const apps = [];
  let url = 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials&$top=999';
  while (url) {
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message || `Graph ${resp.status}`);
    apps.push(...data.value);
    url = data['@odata.nextLink'] || null;
  }
  return apps;
}

function buildRows(apps, tenantName, tenantRecordId) {
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const rows = [];
  for (const app of apps) {
    const secrets = app.passwordCredentials || [];
    const certs   = app.keyCredentials || [];
    if (secrets.length === 0 && certs.length === 0) {
      rows.push({ tenantName, tenantRecordId, objectId: app.id, appName: app.displayName || '(no name)', appId: app.appId, type: 'none', keyId: null, secretName: '', hint: '', expires: null, daysLeft: null, status: 'none' });
    } else {
      for (const cred of secrets) rows.push(makeRow(app, cred, 'Secret', now, tenantName, tenantRecordId));
      for (const cert of certs)   rows.push(makeRow(app, cert, 'Certificate', now, tenantName, tenantRecordId));
    }
  }
  return rows;
}

function makeRow(app, cred, type, now, tenantName, tenantRecordId) {
  const hasExpiry = !!cred.endDateTime;
  const exp = hasExpiry ? new Date(cred.endDateTime) : null;
  if (exp) exp.setHours(0, 0, 0, 0);
  const daysLeft = hasExpiry ? Math.ceil((exp - now) / 86400000) : null;
  return {
    tenantName, tenantRecordId,
    objectId: app.id,
    appName: app.displayName || '(no name)', appId: app.appId, type,
    keyId: cred.keyId,
    secretName: cred.displayName || `(unnamed ${type.toLowerCase()})`,
    hint: cred.hint ? cred.hint + '…' : '',
    expires: cred.endDateTime || null, daysLeft, status: hasExpiry ? classify(daysLeft) : 'ok',
  };
}

function getThresholds() {
  return {
    critical: parseInt(process.env.THRESHOLD_CRITICAL) || 14,
    warning:  parseInt(process.env.THRESHOLD_WARNING)  || 30,
    notice:   parseInt(process.env.THRESHOLD_NOTICE)   || 60,
  };
}

function classify(days) {
  if (days === null) return 'ok';
  const t = getThresholds();
  if (days < 0)          return 'expired';
  if (days < t.critical) return 'critical';
  if (days < t.warning)  return 'warning';
  if (days < t.notice)   return 'notice';
  return 'ok';
}

app.listen(PORT, () => {
  console.log(`M365 App Secret Monitor → http://localhost:${PORT}`);
  if (!isSetupComplete()) console.log('  First run — open the URL to complete setup.');
});
