require('dotenv').config({ path: require('path').join(process.env.DATA_DIR || __dirname, '.env') });
const express    = require('express');
const session    = require('express-session');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const bcrypt     = require('bcryptjs');
const speakeasy  = require('speakeasy');
const QRCode     = require('qrcode');
const nodemailer = require('nodemailer');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app          = express();
const PORT         = process.env.PORT || 3000;
const DATA_DIR      = process.env.DATA_DIR || __dirname;
const ENV_PATH      = path.join(DATA_DIR, '.env');
const TENANTS_PATH  = path.join(DATA_DIR, 'tenants.json');
const USERS_PATH    = path.join(DATA_DIR, 'users.json');
const GROUPS_PATH   = path.join(DATA_DIR, 'groups.json');
const STATES_PATH   = path.join(DATA_DIR, 'secret-states.json');
const AUDIT_PATH    = path.join(DATA_DIR, 'audit.log');

// ── Write threshold defaults to .env if not already set ───────────────────────
(function applyThresholdDefaults() {
  try {
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
    if (changed) {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(ENV_PATH, env);
    }
  } catch (e) {
    console.warn('[startup] Could not write threshold defaults to .env:', e.message);
  }
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

// Session secret — auto-generate and persist to DATA_DIR/.env on first run
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.SESSION_SECRET = SESSION_SECRET;
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    if (!env.includes('SESSION_SECRET=')) {
      env = `SESSION_SECRET=${SESSION_SECRET}\n` + env;
      fs.writeFileSync(ENV_PATH, env);
      console.log('[startup] Generated and saved SESSION_SECRET to', ENV_PATH);
    }
  } catch (e) {
    console.warn('[startup] Could not persist SESSION_SECRET:', e.message);
  }
}

app.use((req, res, next) => {
  console.log(`[http] ${req.method} ${req.path} | host:${req.get('host')} | ip:${req.ip}`);
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", 'data:'],
      connectSrc:     ["'self'"],
      fontSrc:        ["'self'"],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '5mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   8 * 60 * 60 * 1000, // default 8 h; overridden to 30 d on "remember me"
    httpOnly: true,
    sameSite: 'lax',
  },
}));
app.use(express.static(path.join(__dirname, 'public')));

// CSRF: reject cross-origin state-changing requests by checking Origin/Referer
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return next();
  // Exempt unauthenticated endpoints — setup, login, logout
  const exempt = ['/login', '/login/2fa', '/logout', '/api/setup', '/api/setup/totp/verify'];
  if (exempt.some(p => req.path === p || req.path.startsWith('/api/setup'))) return next();
  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    try {
      if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'CSRF check failed.' });
    } catch { return res.status(403).json({ error: 'CSRF check failed.' }); }
  }
  next();
});

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again in 15 minutes.' },
  skipSuccessfulRequests: true,
});
const twoFaLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many 2FA attempts, please try again later.' },
  skipSuccessfulRequests: true,
});
const passkeyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many passkey attempts, please try again later.' },
});

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

// ── SSO helpers ───────────────────────────────────────────────────────────────
function getSsoConfig() {
  return {
    enabled:       process.env.SSO_ENABLED       === 'true',
    clientId:      process.env.SSO_CLIENT_ID      || '',
    clientSecret:  process.env.SSO_CLIENT_SECRET  || '',
    tenantId:      process.env.SSO_TENANT_ID      || 'common',
    autoProvision: process.env.SSO_AUTO_PROVISION !== 'false',
    defaultRole:   process.env.SSO_DEFAULT_ROLE   || 'viewer',
  };
}

function saveSsoConfig(cfg, clientSecret) {
  const vars = {
    SSO_ENABLED:        cfg.enabled        ? 'true' : 'false',
    SSO_CLIENT_ID:      cfg.clientId       || '',
    SSO_TENANT_ID:      cfg.tenantId       || 'common',
    SSO_AUTO_PROVISION: cfg.autoProvision  ? 'true' : 'false',
    SSO_DEFAULT_ROLE:   cfg.defaultRole    || 'viewer',
  };
  if (clientSecret !== undefined && clientSecret !== '••••••••')
    vars.SSO_CLIENT_SECRET = clientSecret;
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  for (const [k, v] of Object.entries(vars)) {
    env = setEnvVar(env, k, v);
    process.env[k] = v;
  }
  if (clientSecret !== undefined && clientSecret !== '••••••••') {
    process.env.SSO_CLIENT_SECRET = clientSecret;
  }
  fs.writeFileSync(ENV_PATH, env);
}

// JWKS cache to avoid fetching on every login
const _jwksCache = new Map();

async function getJwksKey(tenantId, kid) {
  const cacheKey = `${tenantId}:${kid}`;
  if (_jwksCache.has(cacheKey)) return _jwksCache.get(cacheKey);
  const jwksUri = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
  const res = await fetch(jwksUri, { signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  const { keys } = await res.json();
  const key = keys.find(k => k.kid === kid);
  if (!key) throw new Error('Signing key not found in JWKS');
  const pem = jwkToPem(key);
  _jwksCache.set(cacheKey, pem);
  setTimeout(() => _jwksCache.delete(cacheKey), 3600 * 1000); // expire after 1 h
  return pem;
}

function jwkToPem(jwk) {
  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  const pubKey = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
  return pubKey.export({ type: 'spki', format: 'pem' });
}

async function verifySsoIdToken(token, cfg) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid ID token format');
  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

  if (payload.exp && Date.now() / 1000 > payload.exp) throw new Error('ID token expired');
  if (payload.nbf && Date.now() / 1000 < payload.nbf) throw new Error('ID token not yet valid');
  if (payload.aud !== cfg.clientId) throw new Error('Audience mismatch');

  if (header.alg !== 'RS256') throw new Error(`Unexpected algorithm: ${header.alg}`);
  const pem = await getJwksKey(cfg.tenantId === 'common' ? payload.tid : cfg.tenantId, header.kid);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const signature = Buffer.from(parts[2], 'base64url');
  const valid = crypto.createVerify('SHA256').update(signingInput).verify(pem, signature);
  if (!valid) throw new Error('ID token signature invalid');
  return payload;
}

// ── Root ──────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (!isSetupComplete()) return res.redirect('/setup');
  const isAuth = req.session.userId || req.session.authenticated;
  res.redirect(isAuth ? '/dashboard' : '/login');
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, setup: isSetupComplete(), version: process.env.APP_VERSION || 'dev' });
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
    // express-session auto-saves modified sessions on response end
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrDataUrl });
  } catch (e) {
    console.error('[setup] TOTP error:', e);
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
  console.log('[setup] POST /api/setup received');
  if (isSetupComplete()) return res.status(403).json({ error: 'Setup already completed.' });

  const { username, email, password, confirmPassword, timezone,
          enable2fa, tenantName, tenantId, clientId, clientSecret } = req.body || {};

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
    console.log('[setup] hashing password...');
    const hash = await new Promise((resolve, reject) =>
      bcrypt.hash(password, 12, (err, h) => err ? reject(err) : resolve(h))
    );
    console.log('[setup] hash done, writing env...');
    const totpEnabled = enable2fa === 'true';
    const totpSecret  = totpEnabled ? req.session.setupTotpSecret : '';

    process.env.APP_USERNAME      = username;
    process.env.APP_EMAIL         = email.toLowerCase();
    process.env.APP_PASSWORD_HASH = hash;
    process.env.TIMEZONE          = timezone || 'UTC';
    process.env.TWO_FA_ENABLED    = totpEnabled ? 'true' : 'false';
    process.env.SETUP_COMPLETE    = 'true';
    if (totpEnabled) process.env.TOTP_SECRET = totpSecret;

    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    env = setEnvVar(env, 'APP_USERNAME',      username);
    env = setEnvVar(env, 'APP_EMAIL',         email.toLowerCase());
    env = setEnvVar(env, 'APP_PASSWORD_HASH', hash);
    env = setEnvVar(env, 'TIMEZONE',          timezone || 'UTC');
    env = setEnvVar(env, 'TWO_FA_ENABLED',    totpEnabled ? 'true' : 'false');
    env = setEnvVar(env, 'SETUP_COMPLETE',    'true');
    if (totpEnabled) env = setEnvVar(env, 'TOTP_SECRET', totpSecret);
    fs.writeFileSync(ENV_PATH, env);
    console.log('[setup] env written, saving users...');

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
    console.log('[setup] users saved');

    // Save first tenant to tenants.json if provided
    if (tenantId && clientId && clientSecret) {
      saveTenants([{
        id: crypto.randomUUID(),
        name: (tenantName || '').trim() || 'Default Tenant',
        tenantId, clientId, clientSecret,
        enabled: true,
      }]);
      console.log('[setup] tenant saved');
    }

    // Do not touch the session here. If the user used TOTP during setup,
    // those session keys are harmless once SETUP_COMPLETE=true (the TOTP
    // endpoint returns 403 from that point on). Calling session.destroy()
    // on an uninitialized MemoryStore session can hang the callback in some
    // Docker/Alpine environments, dropping the connection before res.json fires.
    console.log('[setup] sending ok response');
    // Redirect to success page — works for both form POST and fetch()
    res.redirect('/setup?done=1');
  } catch (e) {
    console.error('[setup] ERROR:', e);
    const msg = encodeURIComponent('Setup failed: ' + e.message);
    res.redirect(`/setup?error=${msg}`);
  }
});

// ── Factory reset (admin only) ────────────────────────────────────────────────
app.post('/api/reset', requireLogin, requireAdmin, async (req, res) => {
  try {
    const keysToRemove = [
      'SETUP_COMPLETE', 'APP_USERNAME', 'APP_EMAIL', 'APP_PASSWORD_HASH',
      'TWO_FA_ENABLED', 'TOTP_SECRET',
    ];
    let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    for (const key of keysToRemove) {
      env = env.replace(new RegExp(`^${key}=.*$\\n?`, 'm'), '');
      delete process.env[key];
    }
    fs.writeFileSync(ENV_PATH, env);

    if (fs.existsSync(USERS_PATH))   fs.unlinkSync(USERS_PATH);
    if (fs.existsSync(TENANTS_PATH)) fs.unlinkSync(TENANTS_PATH);

    await new Promise(resolve => req.session.destroy(resolve));
    res.json({ ok: true });
  } catch (e) {
    console.error('[reset] ERROR:', e);
    res.status(500).json({ error: 'Reset failed: ' + e.message });
  }
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.get('/login', requireSetup, (req, res) => {
  const isAuth = req.session.userId || req.session.authenticated;
  if (isAuth) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const REMEMBER_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days

app.post('/login', loginLimiter, requireSetup, async (req, res) => {
  const { username, password, remember } = req.body;
  const id = (username || '').trim().toLowerCase();

  const users = loadUsers();
  const user = users.find(u =>
    u.username.toLowerCase() === id || u.email.toLowerCase() === id
  );

  if (!user || user.enabled === false) {
    audit(req, 'login.fail', 'invalid credentials');
    return res.redirect('/login?error=1');
  }

  const ok = user.passwordHash && await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    audit(req, 'login.fail', 'invalid credentials');
    return res.redirect('/login?error=1');
  }

  if (user.totpEnabled) {
    req.session.pendingUserId = user.id;
    req.session.pendingAuth   = true; // legacy compat
    req.session.pendingRemember = (remember === 'on' || remember === 'true' || remember === '1');
    return res.redirect('/login/2fa');
  }

  if (remember === 'on' || remember === 'true' || remember === '1')
    req.session.cookie.maxAge = REMEMBER_MAX_AGE;
  req.session.userId = user.id;
  req.session.authenticated = undefined;
  req.user = user;
  audit(req, 'login.success', 'password');
  res.redirect('/dashboard');
});

app.get('/login/2fa', requireSetup, (req, res) => {
  if (!req.session.pendingAuth && !req.session.pendingUserId) return res.redirect('/login');
  const isAuth = req.session.userId || req.session.authenticated;
  if (isAuth) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login-2fa.html'));
});

app.post('/login/2fa', twoFaLimiter, requireSetup, (req, res) => {
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
  if (!valid) {
    audit(req, 'login.2fa.fail', '');
    return res.redirect('/login/2fa?error=1');
  }

  const remember = req.session.pendingRemember;
  delete req.session.pendingAuth;
  delete req.session.pendingUserId;
  delete req.session.pendingRemember;
  if (remember) req.session.cookie.maxAge = REMEMBER_MAX_AGE;
  req.session.userId = userId;
  req.session.authenticated = undefined;
  const u2fa = loadUsers().find(u => u.id === userId);
  req.user = u2fa;
  audit(req, 'login.success', 'password + 2FA');
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  audit(req, 'logout', '');
  req.session.destroy(() => res.redirect('/login'));
});

// ── SSO: Microsoft OAuth2 ─────────────────────────────────────────────────────
app.get('/api/sso/status', (req, res) => {
  const { enabled, tenantId } = getSsoConfig();
  res.json({ enabled, tenantId });
});

app.get('/api/sso', requireAdmin, (req, res) => {
  const cfg = getSsoConfig();
  res.json({ ...cfg, clientSecret: cfg.clientSecret ? '••••••••' : '' });
});

app.post('/api/sso', requireAdmin, (req, res) => {
  const { enabled, clientId, clientSecret, tenantId, autoProvision, defaultRole } = req.body;
  if (!['admin', 'viewer'].includes(defaultRole))
    return res.status(400).json({ error: 'Default role must be admin or viewer.' });
  saveSsoConfig({ enabled, clientId: (clientId || '').trim(), tenantId: (tenantId || 'common').trim(), autoProvision, defaultRole }, clientSecret);
  audit(req, 'settings.sso', `enabled=${enabled}`);
  res.json({ ok: true });
});

app.get('/auth/microsoft', requireSetup, (req, res) => {
  const cfg = getSsoConfig();
  if (!cfg.enabled || !cfg.clientId)
    return res.redirect('/login?error=sso_disabled');

  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  req.session.ssoState = state;
  req.session.ssoNonce = nonce;

  const params = new URLSearchParams({
    client_id:     cfg.clientId,
    response_type: 'code',
    redirect_uri:  `${req.protocol}://${req.get('host')}/auth/microsoft/callback`,
    scope:         'openid profile email',
    response_mode: 'query',
    state,
    nonce,
  });
  res.redirect(`https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/authorize?${params}`);
});

app.get('/auth/microsoft/callback', requireSetup, async (req, res) => {
  const cfg = getSsoConfig();
  if (!cfg.enabled) return res.redirect('/login?error=sso_disabled');

  const { code, state, error } = req.query;
  if (error) return res.redirect('/login?error=sso_failed');
  if (!code || state !== req.session.ssoState) return res.redirect('/login?error=sso_state');

  delete req.session.ssoState;
  const expectedNonce = req.session.ssoNonce;
  delete req.session.ssoNonce;

  try {
    const tokenRes = await fetch(
      `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/token`,
      { method: 'POST', signal: AbortSignal.timeout(15000), body: new URLSearchParams({
          grant_type:    'authorization_code',
          client_id:     cfg.clientId,
          client_secret: cfg.clientSecret,
          code,
          redirect_uri:  `${req.protocol}://${req.get('host')}/auth/microsoft/callback`,
          scope:         'openid profile email',
      })},
    );
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokenData.error_description || tokenData.error || 'Token exchange failed');

    const claims = await verifySsoIdToken(tokenData.id_token, cfg);
    if (claims.nonce !== expectedNonce) throw new Error('Nonce mismatch');
    if (claims.aud !== cfg.clientId) throw new Error('Audience mismatch');

    const email = (claims.email || claims.preferred_username || '').toLowerCase();
    if (!email) throw new Error('No email in token');

    let users = loadUsers();
    let user = users.find(u => u.email.toLowerCase() === email);

    if (!user) {
      if (!cfg.autoProvision) return res.redirect('/login?error=sso_no_user');
      user = {
        id:                  crypto.randomUUID(),
        username:            email.split('@')[0],
        email,
        passwordHash:        '',
        role:                cfg.defaultRole,
        groupIds:            [],
        totpEnabled:         false,
        totpSecret:          '',
        receiveNotifications: false,
        enabled:             true,
        ssoOnly:             true,
      };
      users.push(user);
      saveUsers(users);
      audit(req, 'sso.provision', `email=${email} role=${cfg.defaultRole}`);
    }

    if (user.enabled === false) return res.redirect('/login?error=sso_disabled_user');

    req.session.userId = user.id;
    req.session.authenticated = undefined;
    req.user = user;
    audit(req, 'login.success', 'microsoft-sso');
    res.redirect('/dashboard');
  } catch (e) {
    console.error('SSO callback error:', e.message);
    res.redirect('/login?error=sso_failed');
  }
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
    audit(req, 'user.create', `username=${username} role=${role}`);
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
  audit(req, 'user.update', `userId=${req.params.id}`);
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

  const delUser = users.find(u => u.id === req.params.id);
  saveUsers(users.filter(u => u.id !== req.params.id));
  audit(req, 'user.delete', `username=${delUser?.username}`);
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
  audit(req, 'group.create', `name=${name}`);
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
  audit(req, 'group.update', `groupId=${req.params.id}`);
  res.json(groups[idx]);
});

app.delete('/api/groups/:id', requireAdmin, (req, res) => {
  const groups = loadGroups();
  if (!groups.find(g => g.id === req.params.id))
    return res.status(404).json({ error: 'Group not found.' });
  const delGroup = groups.find(g => g.id === req.params.id);
  saveGroups(groups.filter(g => g.id !== req.params.id));
  audit(req, 'group.delete', `name=${delGroup?.name}`);
  res.json({ ok: true });
});

// ── API: logo ─────────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');

const MAGIC_BYTES = {
  png:  [0x89, 0x50, 0x4e, 0x47],
  jpeg: [0xff, 0xd8, 0xff],
  gif:  [0x47, 0x49, 0x46],
  webp: null, // checked via RIFF header below
};

function validateImageMagicBytes(buf, ext) {
  if (ext === 'webp') {
    return buf.slice(0, 4).toString('ascii') === 'RIFF' &&
           buf.slice(8, 12).toString('ascii') === 'WEBP';
  }
  const magic = MAGIC_BYTES[ext];
  if (!magic) return false;
  return magic.every((b, i) => buf[i] === b);
}

app.get('/api/logo', (req, res) => {
  const file = process.env.LOGO_FILE;
  if (!file) return res.status(404).end();
  const filePath = path.resolve(UPLOADS_DIR, path.basename(file));
  if (!filePath.startsWith(path.resolve(UPLOADS_DIR) + path.sep) && filePath !== path.resolve(UPLOADS_DIR, path.basename(file))) {
    return res.status(404).end();
  }
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.set('Content-Disposition', `inline; filename="${path.basename(filePath)}"`);
  res.sendFile(filePath);
});

app.post('/api/logo', requireLogin, (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No image data provided.' });

  const match = data.match(/^data:image\/(png|jpeg|gif|webp);base64,(.+)$/s);
  if (!match) return res.status(400).json({ error: 'Unsupported format. Use PNG, JPG, GIF, or WebP.' });

  const ext    = match[1] === 'jpeg' ? 'jpeg' : match[1];
  const base64 = match[2];
  const buf    = Buffer.from(base64, 'base64');

  if (buf.length > 5 * 1024 * 1024)
    return res.status(413).json({ error: 'File too large. Maximum size is 5 MB.' });

  if (!validateImageMagicBytes(buf, ext === 'jpeg' ? 'jpeg' : ext))
    return res.status(400).json({ error: 'File content does not match declared image type.' });

  const filename = `logo.${ext}`;
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

  fs.readdirSync(UPLOADS_DIR)
    .filter(f => f.startsWith('logo.'))
    .forEach(f => fs.unlinkSync(path.join(UPLOADS_DIR, f)));

  fs.writeFileSync(path.join(UPLOADS_DIR, filename), buf);

  process.env.LOGO_FILE = filename;
  try {
    let env = fs.readFileSync(ENV_PATH, 'utf8');
    env = setEnvVar(env, 'LOGO_FILE', filename);
    fs.writeFileSync(ENV_PATH, env);
  } catch (e) { console.error('Could not update .env:', e.message); }

  audit(req, 'settings.branding', `uploaded ${filename}`);
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
  audit(req, 'settings.branding', 'logo removed');
  res.json({ ok: true });
});

// ── API: general settings ─────────────────────────────────────────────────────
app.get('/api/settings', requireLogin, (req, res) => {
  res.json({
    timezone:  process.env.TIMEZONE     || 'UTC',
    thresholds: getThresholds(),
    rpId:      process.env.WEBAUTHN_RP_ID || '',
  });
});

app.post('/api/settings', requireLogin, (req, res) => {
  const rpId = (req.body.rpId || '').trim().toLowerCase();
  // Basic hostname validation — allow empty (auto-detect) or a plain hostname/domain
  if (rpId && !/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(rpId))
    return res.status(400).json({ error: 'Invalid domain. Use a plain hostname like monitor.contoso.com' });
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  env = setEnvVar(env, 'WEBAUTHN_RP_ID', rpId);
  fs.writeFileSync(ENV_PATH, env);
  process.env.WEBAUTHN_RP_ID = rpId;
  audit(req, 'settings.rp-id', `rpId=${rpId || '(auto)'}`);
  res.json({ ok: true });
});

// ── Audit log ─────────────────────────────────────────────────────────────────
function audit(req, event, detail = '') {
  const entry = {
    ts:       new Date().toISOString(),
    event,
    detail,
    username: req.user ? req.user.username : (req.session?.pendingUserId ? '(pending 2fa)' : '(unauthenticated)'),
    userId:   req.user ? req.user.id : null,
    ip:       req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '',
  };
  try { fs.appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n'); } catch {}
}

app.get('/api/audit', requireAdmin, (req, res) => {
  if (!fs.existsSync(AUDIT_PATH)) return res.json([]);
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').split('\n').filter(Boolean);
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(500, Math.max(1, parseInt(req.query.limit) || 100));
  const filter = (req.query.filter || '').toLowerCase();
  let entries = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
  if (filter) entries = entries.filter(e => e.event.includes(filter) || e.username.includes(filter) || (e.detail || '').toLowerCase().includes(filter));
  const total = entries.length;
  entries = entries.slice((page - 1) * limit, page * limit);
  res.json({ total, page, limit, entries });
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
  audit(req, 'settings.thresholds', `critical=${critical} warning=${warning} notice=${notice}`);
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
    stateAlerts:    process.env.MAIL_STATE_ALERTS    === 'true',
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
    MAIL_STATE_ALERTS:    cfg.stateAlerts    ? 'true' : 'false',
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
      return buildRows(await fetchAllApps(token), t.name, t.id, t.tenantId);
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
    stateAlerts:    b.stateAlerts    === true  || b.stateAlerts    === 'true',
    tenantIds:      Array.isArray(b.tenantIds) ? (b.tenantIds.length ? b.tenantIds.join(',') : 'all') : (b.tenantIds || 'all'),
    smtp:  { host: b.smtpHost || '', port: parseInt(b.smtpPort) || 587, secure: b.smtpSecure === true || b.smtpSecure === 'true', user: b.smtpUser || '', from: b.smtpFrom || '' },
    graph: { tenantRecordId: b.graphTenantId || '', sender: b.graphSender || '' },
  }, b.smtpPass);
  audit(req, 'settings.email', `enabled=${b.enabled} method=${b.method || 'smtp'}`);
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

// ── State-change alerts ───────────────────────────────────────────────────────
const STATUS_SEVERITY = { none: 0, ok: 1, notice: 2, warning: 3, critical: 4, expired: 5 };

function loadSecretStates() {
  if (!fs.existsSync(STATES_PATH)) return {};
  try { return JSON.parse(fs.readFileSync(STATES_PATH, 'utf8')); } catch { return {}; }
}
function saveSecretStates(states) {
  fs.writeFileSync(STATES_PATH, JSON.stringify(states));
}

function buildStateChangeHtml(changes) {
  const rows = changes.map(c => {
    const fromColor = statusColor(c.from);
    const toColor   = statusColor(c.to);
    return `<tr>
      <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">${c.tenantName}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px"><strong>${c.appName}</strong></td>
      <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">${c.secretName}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px">
        <span style="color:${fromColor};font-weight:600">${c.from}</span>
        &nbsp;→&nbsp;
        <span style="color:${toColor};font-weight:600">${c.to}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #edebe9;font-size:13px;color:${toColor};font-weight:600">${c.daysLeft < 0 ? Math.abs(c.daysLeft) + 'd ago' : (c.daysLeft === null ? '—' : c.daysLeft + 'd')}</td>
    </tr>`;
  }).join('');
  return `<!DOCTYPE html><html><body style="font-family:'Segoe UI',system-ui,sans-serif;background:#f3f2f1;margin:0;padding:32px 24px">
  <div style="max-width:700px;margin:0 auto">
    <div style="background:#0078d4;color:white;border-radius:8px 8px 0 0;padding:24px 28px">
      <h2 style="margin:0;font-size:20px">🔐 App Secret Monitor — Status Change Alert</h2>
      <p style="margin:6px 0 0;opacity:.85;font-size:13px">Detected ${new Date().toLocaleString('en-GB')}</p>
    </div>
    <div style="background:white;border-radius:0 0 8px 8px;padding:24px 28px;border:1px solid #edebe9;border-top:none">
      <p style="margin:0 0 16px;font-size:14px;color:#605e5c">The following app secrets changed to a more critical status:</p>
      <table style="width:100%;border-collapse:collapse;background:white;border-radius:6px;overflow:hidden;border:1px solid #edebe9">
        <thead><tr style="background:#f8f7f6">
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Tenant</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Application</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Secret</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Status change</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;color:#605e5c;text-transform:uppercase">Days left</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div></body></html>`;
}

async function checkStateChanges() {
  const cfg = getMailConfig();
  if (!cfg.enabled || !cfg.stateAlerts) return;
  try {
    const allRows    = await fetchReportRows();
    const prevStates = loadSecretStates();
    const newStates  = {};
    const changes    = [];

    for (const r of allRows) {
      const key = `${r.tenantRecordId}::${r.appId}::${r.keyId || 'none'}`;
      newStates[key] = r.status;
      const prev = prevStates[key];
      if (prev && prev !== r.status &&
          (STATUS_SEVERITY[r.status] || 0) > (STATUS_SEVERITY[prev] || 0)) {
        changes.push({ ...r, from: prev, to: r.status });
      }
    }
    saveSecretStates(newStates);

    if (changes.length === 0) return;

    const subject = `App Secret Status Change Alert – ${changes.length} secret${changes.length > 1 ? 's' : ''} worsened`;
    const notifyUsers = loadUsers().filter(u => u.receiveNotifications && u.enabled !== false && u.email);

    if (notifyUsers.length === 0) {
      await sendMail(subject, buildStateChangeHtml(changes));
      return;
    }
    await Promise.allSettled(notifyUsers.map(async user => {
      const accessibleTenantIds = getUserTenantIds(user);
      let userChanges = accessibleTenantIds
        ? changes.filter(c => accessibleTenantIds.includes(c.tenantRecordId))
        : changes;
      if (userChanges.length === 0) return;
      await sendMailTo(user.email, subject, buildStateChangeHtml(userChanges));
    }));
    console.log(`[state-alerts] Sent alerts for ${changes.length} status change(s).`);
  } catch (e) { console.error('[state-alerts] Failed:', e.message); }
}

setInterval(checkStateChanges, 15 * 60 * 1000); // check every 15 minutes

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
  audit(req, 'settings.email.schedule', `freq=${freq} time=${time}`);
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
  audit(req, 'tenant.create', `name=${name}`);
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
  audit(req, 'tenant.update', `name=${tenants[idx].name}`);
  res.json(sanitizeTenant(tenants[idx]));
});

app.patch('/api/tenants/:id/toggle', requireAdmin, (req, res) => {
  const tenants = loadTenants();
  const t = tenants.find(t => t.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'Tenant not found.' });
  t.enabled = !t.enabled;
  saveTenants(tenants);
  audit(req, 'tenant.toggle', `name=${t.name} enabled=${t.enabled}`);
  res.json({ enabled: t.enabled });
});

app.delete('/api/tenants/:id', requireAdmin, (req, res) => {
  const tenants = loadTenants();
  if (!tenants.find(t => t.id === req.params.id))
    return res.status(404).json({ error: 'Tenant not found.' });
  const delTenant = tenants.find(t => t.id === req.params.id);
  saveTenants(tenants.filter(t => t.id !== req.params.id));
  audit(req, 'tenant.delete', `name=${delTenant?.name}`);
  res.json({ ok: true });
});

app.post('/api/tenants/:id/test', requireLogin, async (req, res) => {
  const t = loadTenants().find(t => t.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'Tenant not found.' });
  try {
    const token  = await getGraphToken(t.tenantId, t.clientId, t.clientSecret);
    const roles  = getTokenRoles(token);
    const resp   = await fetch('https://graph.microsoft.com/v1.0/applications?$top=1', {
      signal: timeoutSignal(), headers: { Authorization: `Bearer ${token}` },
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
      return { rows: buildRows(apps, t.name, t.id, t.tenantId), canWrite, tenantName: t.name, tenantRecordId: t.id };
    })
  );

  const rows            = [];
  const errors          = [];
  const permissions     = {};
  const tenantRecordIds = {};
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      rows.push(...r.value.rows);
      permissions[r.value.tenantName]     = r.value.canWrite;
      tenantRecordIds[r.value.tenantName] = r.value.tenantRecordId;
    } else {
      errors.push({ tenant: tenants[i].name, error: r.reason.message });
    }
  });

  rows.sort((a, b) => a.daysLeft - b.daysLeft);
  res.json({ rows, errors, permissions, tenantRecordIds });
});

// ── API: remove a secret from an app registration ────────────────────────────
app.post('/api/secrets/remove', requireLogin, async (req, res) => {
  const { tenantRecordId, objectId, keyId } = req.body;
  if (!tenantRecordId || !objectId || !keyId)
    return res.status(400).json({ error: 'Missing required fields.' });

  const accessibleIds = getUserTenantIds(req.user);
  if (accessibleIds !== null && !accessibleIds.includes(tenantRecordId))
    return res.status(403).json({ error: 'Access denied to this tenant.' });

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
        method: 'POST', signal: timeoutSignal(),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId }),
      },
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error?.message || `Graph ${resp.status}`);
    }
    audit(req, 'secret.remove', `objectId=${objectId} keyId=${keyId} tenant=${tenant.name}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('Remove secret error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── API: add a new secret to an app registration ─────────────────────────────
app.post('/api/secrets/add', requireLogin, async (req, res) => {
  const { tenantRecordId, objectId, displayName, endDateTime } = req.body;
  if (!tenantRecordId || !objectId || !displayName)
    return res.status(400).json({ error: 'Missing required fields.' });

  const accessibleIds = getUserTenantIds(req.user);
  if (accessibleIds !== null && !accessibleIds.includes(tenantRecordId))
    return res.status(403).json({ error: 'Access denied to this tenant.' });

  const tenant = loadTenants().find(t => t.id === tenantRecordId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });

  try {
    const token = await getGraphToken(tenant.tenantId, tenant.clientId, tenant.clientSecret);
    const roles = getTokenRoles(token);
    if (!roles.includes('Application.ReadWrite.All'))
      return res.status(403).json({
        error: 'Permission denied. Grant Application.ReadWrite.All to this app registration in Azure Portal.',
      });

    const credential = { displayName };
    if (endDateTime) credential.endDateTime = endDateTime;

    const resp = await fetch(
      `https://graph.microsoft.com/v1.0/applications/${objectId}/addPassword`,
      {
        method: 'POST', signal: timeoutSignal(),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ passwordCredential: credential }),
      },
    );
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message || `Graph ${resp.status}`);
    // secretText is only returned once — pass it back to the client now
    audit(req, 'secret.add', `objectId=${objectId} name=${displayName} tenant=${tenant.name}`);
    res.json({ ok: true, keyId: data.keyId, secretText: data.secretText, endDateTime: data.endDateTime });
  } catch (e) {
    console.error('Add secret error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── API: create a new app registration ───────────────────────────────────────
app.post('/api/apps', requireLogin, async (req, res) => {
  const { tenantRecordId, displayName, description, signInAudience } = req.body;
  if (!tenantRecordId || !displayName || !displayName.trim())
    return res.status(400).json({ error: 'Missing required fields.' });

  const tenant = loadTenants().find(t => t.id === tenantRecordId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });

  try {
    const token = await getGraphToken(tenant.tenantId, tenant.clientId, tenant.clientSecret);
    const roles = getTokenRoles(token);
    if (!roles.includes('Application.ReadWrite.All'))
      return res.status(403).json({ error: 'Permission denied. Grant Application.ReadWrite.All to create app registrations.' });

    const body = { displayName: displayName.trim() };
    if (signInAudience) body.signInAudience = signInAudience;
    if (description)    body.description    = description.trim();

    const resp = await fetch('https://graph.microsoft.com/v1.0/applications', {
      method: 'POST', signal: timeoutSignal(),
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message || `Graph ${resp.status}`);

    audit(req, 'app.create', `name=${displayName.trim()} objectId=${data.id} tenant=${tenant.name}`);
    res.json({ ok: true, objectId: data.id, appId: data.appId, displayName: data.displayName });
  } catch (e) {
    console.error('Create app error:', e.message);
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
      method: 'DELETE', signal: timeoutSignal(),
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok && resp.status !== 204) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error?.message || `Graph ${resp.status}`);
    }
    audit(req, 'app.delete', `objectId=${objectId} tenant=${tenant.name}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete app error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Passkeys (WebAuthn) ───────────────────────────────────────────────────────
const WEBAUTHN_RP_NAME = 'M365 App Secret Monitor';

function getRpId(req) {
  return process.env.WEBAUTHN_RP_ID || req.hostname || 'localhost';
}
function getOrigin(req) {
  return req.headers.origin || `${req.protocol}://${req.get('host')}`;
}

// Registration options (must be logged in)
app.get('/api/passkeys/register/options', requireLogin, async (req, res) => {
  const rpID = getRpId(req);
  const existing = (req.user.passkeys || []).map(pk => ({
    id: Buffer.from(pk.id, 'base64url'),
    type: 'public-key',
    transports: pk.transports || [],
  }));
  const options = await generateRegistrationOptions({
    rpName: WEBAUTHN_RP_NAME,
    rpID,
    userID: req.user.id,
    userName: req.user.username,
    userDisplayName: req.user.username,
    attestationType: 'none',
    excludeCredentials: existing,
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  });
  req.session.passkeyChallenge = options.challenge;
  res.json(options);
});

// Verify registration (must be logged in)
app.post('/api/passkeys/register', requireLogin, async (req, res) => {
  const { response, name } = req.body;
  const expectedChallenge = req.session.passkeyChallenge;
  if (!expectedChallenge) return res.status(400).json({ error: 'No active challenge — start registration first.' });
  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      requireUserVerification: false,
    });
    if (!verification.verified || !verification.registrationInfo)
      return res.status(400).json({ error: 'Verification failed.' });
    const { credentialID, credentialPublicKey, counter, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const passkey = {
      id:         Buffer.from(credentialID).toString('base64url'),
      publicKey:  Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      deviceType: credentialDeviceType,
      backedUp:   credentialBackedUp,
      transports: response.response?.transports || [],
      name:       (name || 'Passkey').slice(0, 64),
      createdAt:  new Date().toISOString(),
    };
    const users = loadUsers();
    const idx = users.findIndex(u => u.id === req.user.id);
    if (!users[idx].passkeys) users[idx].passkeys = [];
    users[idx].passkeys.push(passkey);
    saveUsers(users);
    delete req.session.passkeyChallenge;
    audit(req, 'passkey.register', `name=${passkey.name}`);
    res.json({ ok: true, passkey: { id: passkey.id, name: passkey.name, createdAt: passkey.createdAt } });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// List passkeys for logged-in user
app.get('/api/passkeys', requireLogin, (req, res) => {
  res.json((req.user.passkeys || []).map(pk => ({
    id: pk.id, name: pk.name, createdAt: pk.createdAt,
    backedUp: pk.backedUp, deviceType: pk.deviceType,
  })));
});

// Delete a passkey
app.delete('/api/passkeys/:id', requireLogin, (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === req.user.id);
  const before = (users[idx].passkeys || []).length;
  const delPk = (users[idx].passkeys || []).find(pk => pk.id === req.params.id);
  users[idx].passkeys = (users[idx].passkeys || []).filter(pk => pk.id !== req.params.id);
  if (users[idx].passkeys.length === before) return res.status(404).json({ error: 'Passkey not found.' });
  saveUsers(users);
  audit(req, 'passkey.delete', `name=${delPk?.name}`);
  res.json({ ok: true });
});

// Auth options (no login needed — called during the login flow)
app.get('/api/passkeys/auth/options', passkeyLimiter, async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: getRpId(req),
    userVerification: 'preferred',
    allowCredentials: [],
  });
  req.session.passkeyChallenge = options.challenge;
  res.json(options);
});

// Verify auth / log in via passkey
app.post('/api/passkeys/auth', passkeyLimiter, async (req, res) => {
  const { response, remember } = req.body;
  const expectedChallenge = req.session.passkeyChallenge;
  delete req.session.passkeyChallenge; // consume immediately to prevent replay
  if (!expectedChallenge) return res.status(400).json({ error: 'No active challenge.' });

  const credId = response.id;
  const users  = loadUsers();
  let targetUser = null, targetPasskey = null;
  for (const u of users) {
    const pk = (u.passkeys || []).find(p => p.id === credId);
    if (pk) { targetUser = u; targetPasskey = pk; break; }
  }
  if (!targetUser) return res.status(400).json({ error: 'Passkey not recognised.' });
  if (targetUser.enabled === false) return res.status(403).json({ error: 'Account is disabled.' });

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      authenticator: {
        credentialID:        Buffer.from(targetPasskey.id, 'base64url'),
        credentialPublicKey: Buffer.from(targetPasskey.publicKey, 'base64url'),
        counter:             targetPasskey.counter,
        transports:          targetPasskey.transports || [],
      },
      requireUserVerification: false,
    });
    if (!verification.verified) return res.status(400).json({ error: 'Verification failed.' });

    // Update replay counter
    const ui  = users.findIndex(u => u.id === targetUser.id);
    const pki = users[ui].passkeys.findIndex(p => p.id === credId);
    users[ui].passkeys[pki].counter = verification.authenticationInfo.newCounter;
    saveUsers(users);

    if (remember) req.session.cookie.maxAge = REMEMBER_MAX_AGE;
    req.session.userId = targetUser.id;
    req.session.authenticated = undefined;
    req.user = targetUser;
    audit(req, 'login.success', 'passkey');
    res.json({ ok: true });
  } catch (e) {
    audit(req, 'login.passkey.fail', e.message);
    res.status(400).json({ error: e.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function setEnvVar(content, key, value) {
  const line = `${key}=${value}`;
  const re   = new RegExp(`^${key}=.*$`, 'm');
  return re.test(content) ? content.replace(re, line) : content + `\n${line}`;
}

function timeoutSignal(ms = 30000) { return AbortSignal.timeout(ms); }

async function getGraphToken(tenantId, clientId, clientSecret) {
  const resp = await fetch(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    { method: 'POST', signal: timeoutSignal(), body: new URLSearchParams({
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
    const resp = await fetch(url, { signal: timeoutSignal(), headers: { Authorization: `Bearer ${token}` } });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message || `Graph ${resp.status}`);
    apps.push(...data.value);
    url = data['@odata.nextLink'] || null;
  }
  return apps;
}

function buildRows(apps, tenantName, tenantRecordId, tenantId) {
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const rows = [];
  for (const app of apps) {
    const secrets = app.passwordCredentials || [];
    const certs   = app.keyCredentials || [];
    if (secrets.length === 0 && certs.length === 0) {
      rows.push({ tenantName, tenantRecordId, tenantId, objectId: app.id, appName: app.displayName || '(no name)', appId: app.appId, type: 'none', keyId: null, secretName: '', hint: '', expires: null, daysLeft: null, status: 'none' });
    } else {
      for (const cred of secrets) rows.push(makeRow(app, cred, 'Secret', now, tenantName, tenantRecordId, tenantId));
      for (const cert of certs)   rows.push(makeRow(app, cert, 'Certificate', now, tenantName, tenantRecordId, tenantId));
    }
  }
  return rows;
}

function makeRow(app, cred, type, now, tenantName, tenantRecordId, tenantId) {
  const hasExpiry = !!cred.endDateTime;
  const exp = hasExpiry ? new Date(cred.endDateTime) : null;
  if (exp) exp.setHours(0, 0, 0, 0);
  const daysLeft = hasExpiry ? Math.ceil((exp - now) / 86400000) : null;
  return {
    tenantName, tenantRecordId, tenantId,
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

const APP_VERSION = process.env.APP_VERSION || 'dev';
const VERSION_LOG_FILE = path.join(DATA_DIR, 'version.log');

function getLogRetentionDays() {
  const v = parseInt(process.env.LOG_RETENTION_DAYS || '90', 10);
  return isNaN(v) || v < 0 ? 90 : v;
}

function pruneLogFile(filePath) {
  const days = getLogRetentionDays();
  if (days === 0) return;
  if (!fs.existsSync(filePath)) return;
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
  const kept  = lines.filter(l => {
    try { return new Date(JSON.parse(l).timestamp).getTime() >= cutoff; } catch { return true; }
  });
  if (kept.length !== lines.length) fs.writeFileSync(filePath, kept.join('\n') + (kept.length ? '\n' : ''));
}

function appendVersionLog() {
  const entry = JSON.stringify({ timestamp: new Date().toISOString(), version: APP_VERSION }) + '\n';
  try { fs.appendFileSync(VERSION_LOG_FILE, entry); } catch {}
}

function readVersionLog() {
  try {
    return fs.readFileSync(VERSION_LOG_FILE, 'utf8')
      .split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean)
      .reverse();
  } catch { return []; }
}

app.get('/api/version', requireLogin, (req, res) => {
  res.json({ version: APP_VERSION });
});

app.get('/api/log-retention', requireAdmin, (req, res) => {
  res.json({ days: getLogRetentionDays() });
});

app.post('/api/log-retention', requireAdmin, (req, res) => {
  const days = parseInt(req.body.days, 10);
  if (isNaN(days) || days < 0) return res.status(400).json({ error: 'Invalid value. Use 0 for unlimited or a positive number of days.' });
  let env = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  env = setEnvVar(env, 'LOG_RETENTION_DAYS', String(days));
  fs.writeFileSync(ENV_PATH, env);
  process.env.LOG_RETENTION_DAYS = String(days);
  pruneLogFile(AUDIT_PATH);
  pruneLogFile(VERSION_LOG_FILE);
  audit(req, 'settings.log_retention', `days=${days}`);
  res.json({ ok: true, days });
});

app.get('/api/version-log', requireLogin, (req, res) => {
  const limit   = Math.min(parseInt(req.query.limit  || '10', 10), 500);
  const filter  = (req.query.version || '').trim().toLowerCase();
  let entries = readVersionLog();
  if (filter) entries = entries.filter(e => e.version.toLowerCase().includes(filter));
  res.json({ entries: entries.slice(0, limit), total: entries.length });
});

// Global Express error handler — catches errors passed to next(err)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[express] Unhandled error:', err.message || err);
  if (!res.headersSent) {
    res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
  }
});

process.on('uncaughtException', (err) => {
  console.error('[crash] Uncaught Exception — server will continue:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[crash] Unhandled Promise Rejection — server will continue:', reason);
});

app.listen(PORT, '0.0.0.0', () => {
  pruneLogFile(AUDIT_PATH);
  pruneLogFile(VERSION_LOG_FILE);
  appendVersionLog();
  console.log(`M365 App Secret Monitor → http://localhost:${PORT}`);
  console.log(`  Version: ${APP_VERSION}`);
  if (!isSetupComplete()) console.log('  First run — open the URL to complete setup.');
});
