'use strict';
/**
 * Capotis Push 1.0.0
 * Servidor de notificaciones para Capotis Mail. Sin Firebase: habla directamente con APNs de Apple
 * usando la llave .p8 del propio usuario. Vigila las bandejas por IMAP (IDLE) y avisa al iPhone.
 */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const https = require('https');
const { ImapFlow } = require('imapflow');

const VERSION = '1.0.0';
const PORT = parseInt(process.env.PORT || '7391', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';
const P8_PATH = path.join(DATA_DIR, 'AuthKey.p8');
fs.mkdirSync(DATA_DIR, { recursive: true });

// ───────────────────────── Almacenamiento ─────────────────────────
const file = (n) => path.join(DATA_DIR, n);
function readJSON(name, fallback) { try { return JSON.parse(fs.readFileSync(file(name), 'utf8')); } catch { return fallback; } }
function writeJSON(name, data) {
  const tmp = file(name + '.tmp');
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file(name));
}
let config = readJSON('config.json', { user: null, mailcow: null, apple: null });
let devices = readJSON('devices.json', []);
const saveConfig = () => writeJSON('config.json', config);
const saveDevices = () => writeJSON('devices.json', devices);

// Clave para cifrar las contraseñas de correo guardadas (AES-256-GCM)
let secret;
if (fs.existsSync(file('secret.key'))) secret = Buffer.from(fs.readFileSync(file('secret.key'), 'utf8'), 'hex');
else { secret = crypto.randomBytes(32); fs.writeFileSync(file('secret.key'), secret.toString('hex'), { mode: 0o600 }); }
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', secret, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decrypt(b64) {
  const raw = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', secret, raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
}

// ───────────────────────── Usuarios y sesiones ─────────────────────────
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function checkPassword(user, pw) {
  if (!config.user || user !== config.user.name) return false;
  const a = Buffer.from(hashPw(pw, config.user.salt), 'hex');
  const b = Buffer.from(config.user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sessions = new Map(); // token -> expira
const authCache = new Map(); // cabecera Basic -> expira
const failures = new Map(); // ip -> [timestamps]
function tooMany(ip) {
  const now = Date.now();
  const list = (failures.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  failures.set(ip, list);
  return list.length >= 10;
}
const noteFail = (ip) => failures.set(ip, [...(failures.get(ip) || []), Date.now()]);
function cookieOf(req, name) {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
function isLoggedIn(req) {
  const t = cookieOf(req, 'capotis_session');
  return !!t && (sessions.get(t) || 0) > Date.now();
}
function startSession(res) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, Date.now() + 12 * 3600 * 1000);
  res.setHeader('Set-Cookie', `capotis_session=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}`);
}
function requireAuth(req, res, next) {
  if (isLoggedIn(req)) return next();
  const ip = req.ip;
  const h = req.headers.authorization || '';
  if (h.startsWith('Basic ')) {
    if ((authCache.get(h) || 0) > Date.now()) return next();
    if (tooMany(ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
    const [u, ...p] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
    if (checkPassword(u, p.join(':'))) { authCache.set(h, Date.now() + 5 * 60 * 1000); return next(); }
    noteFail(ip);
  }
  res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
}

// ───────────────────────── APNs (HTTP/2 + JWT ES256) ─────────────────────────
const b64url = (b) => Buffer.from(b).toString('base64url');
let jwtCache = { token: null, at: 0, key: '' };
function providerToken() {
  const a = config.apple;
  if (!a || !fs.existsSync(P8_PATH)) throw new Error('Falta la llave .p8 de Apple');
  const id = `${a.teamId}:${a.keyId}`;
  if (jwtCache.token && jwtCache.key === id && Date.now() - jwtCache.at < 40 * 60 * 1000) return jwtCache.token;
  const header = b64url(JSON.stringify({ alg: 'ES256', kid: a.keyId }));
  const claims = b64url(JSON.stringify({ iss: a.teamId, iat: Math.floor(Date.now() / 1000) }));
  const sig = crypto.sign('sha256', Buffer.from(`${header}.${claims}`), { key: fs.readFileSync(P8_PATH), dsaEncoding: 'ieee-p1363' });
  jwtCache = { token: `${header}.${claims}.${b64url(sig)}`, at: Date.now(), key: id };
  return jwtCache.token;
}
function apnsRequest({ token, env, payload, pushType = 'alert', priority = 10 }) {
  return new Promise((resolve) => {
    const host = env === 'development' ? 'api.sandbox.push.apple.com' : 'api.push.apple.com';
    let done = false;
    const finish = (r) => { if (!done) { done = true; try { client.close(); } catch {} resolve(r); } };
    const client = http2.connect(`https://${host}:443`);
    client.on('error', (e) => finish({ status: 0, networkError: e.code || e.message }));
    client.setTimeout(12000, () => finish({ status: 0, networkError: 'ETIMEDOUT' }));
    let jwt;
    try { jwt = providerToken(); } catch (e) { return finish({ status: 0, localError: e.message }); }
    const req = client.request({
      ':method': 'POST', ':path': `/3/device/${token}`,
      authorization: `bearer ${jwt}`, 'apns-topic': config.apple.bundleId,
      'apns-push-type': pushType, 'apns-priority': String(priority), 'content-type': 'application/json',
    });
    let status = 0, apnsId = '', body = '';
    req.on('response', (h) => { status = h[':status']; apnsId = h['apns-id'] || ''; });
    req.setEncoding('utf8');
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      let reason = '';
      try { reason = JSON.parse(body || '{}').reason || ''; } catch {}
      finish({ status, apnsId, reason, body, host });
    });
    req.on('error', (e) => finish({ status: 0, networkError: e.code || e.message }));
    req.end(JSON.stringify(payload));
  });
}
/** Envía a un dispositivo; si el token es del otro entorno (pruebas/App Store) lo reintenta allí. */
async function sendToDevice(device, payload, opts = {}) {
  let r = await apnsRequest({ token: device.token, env: device.env, payload, ...opts });
  if (r.status === 400 && r.reason === 'BadDeviceToken') {
    const other = device.env === 'development' ? 'production' : 'development';
    const r2 = await apnsRequest({ token: device.token, env: other, payload, ...opts });
    if (r2.status === 200) { device.env = other; saveDevices(); r = r2; }
  }
  if (r.status === 410 || (r.status === 400 && r.reason === 'BadDeviceToken' && false)) { /* se limpia en el llamador */ }
  return r;
}
function friendlyApns(r) {
  if (r.localError) return { friendly: 'Falta configurar la llave de Apple (paso 3).', technical: r.localError };
  if (r.networkError) {
    return {
      friendly: 'El servidor no puede llegar a Apple. Revisa que tenga internet y que no bloquee la salida por el puerto 443.',
      technical: `Error de red: ${r.networkError}`,
    };
  }
  const tech = `HTTP ${r.status}\nreason: ${r.reason || '(vacío)'}\napns-id: ${r.apnsId || '(ninguno)'}\nservidor: ${r.host}\ncuerpo: ${r.body || '(vacío)'}`;
  const map = {
    InvalidProviderToken: 'Apple no ha aceptado tu llave. Revisa que el Team ID y el Key ID sean los de esa llave y que el archivo .p8 sea el correcto.',
    ExpiredProviderToken: 'La firma de Apple ha caducado. Reinicia el servidor e inténtalo otra vez.',
    MissingProviderToken: 'No se ha podido firmar con tu llave de Apple. Vuelve a subir el archivo .p8.',
    BadDeviceToken: 'Apple dice que el identificador de tu iPhone no es válido. Desactiva y vuelve a activar las notificaciones en la app.',
    DeviceTokenNotForTopic: 'Este iPhone está registrado para otra app. Comprueba que el Bundle ID del paso 3 es com.capotis.apps.mail.',
    TopicDisallowed: 'Tu llave de Apple no tiene permiso para este Bundle ID. Crea la llave con «Apple Push Notifications service (APNs)» activado.',
    BadTopic: 'El Bundle ID no es válido. Debe ser el de la app (com.capotis.apps.mail).',
    Unregistered: 'El iPhone ya no está registrado (borraste la app o desactivaste los avisos). Vuelve a activar las notificaciones en la app.',
    TooManyRequests: 'Apple pide ir más despacio. Espera un minuto e inténtalo de nuevo.',
    InternalServerError: 'Apple tiene un problema temporal. Inténtalo en unos minutos.',
    ServiceUnavailable: 'Apple no está disponible ahora mismo. Inténtalo en unos minutos.',
  };
  return { friendly: map[r.reason] || 'Apple ha rechazado la notificación. Pulsa «Ver error completo» para ver el motivo exacto.', technical: tech };
}

// ───────────────────────── Vigilancia de bandejas (IMAP IDLE) ─────────────────────────
const watchers = new Map(); // clave -> { stop, sig }
const lastUids = new Map();
const acctKey = (a) => `${a.email}|${a.imapHost}|${a.imapPort}`;

function tokensFor(email) { return devices.filter((d) => d.accounts.some((a) => a.email === email)); }

async function notifyNewMail(email, msg) {
  const from = msg.envelope?.from?.[0];
  const sender = from?.name || from?.address || 'Correo nuevo';
  const subject = msg.envelope?.subject || '(Sin asunto)';
  for (const d of tokensFor(email)) {
    const alert = { title: sender, body: subject };
    if (d.accounts.length > 1) alert.subtitle = email;
    const r = await sendToDevice(d, { aps: { alert, sound: 'default', 'thread-id': email }, email, uid: msg.uid });
    if (r.status === 410 || r.reason === 'Unregistered') { devices = devices.filter((x) => x.token !== d.token); saveDevices(); syncWatchers(); }
    else if (r.status !== 200) console.log(`[push] ${email}: APNs ${r.status} ${r.reason || r.networkError || ''}`);
  }
}

function startWatcher(acct) {
  const key = acctKey(acct);
  const state = { stopped: false, client: null, sig: acct.sig };
  const allowSelfSigned = !!(config.mailcow && config.mailcow.selfSigned);
  (async () => {
    let backoff = 3000;
    while (!state.stopped) {
      const client = new ImapFlow({
        host: acct.imapHost, port: acct.imapPort, secure: acct.imapTLS,
        auth: { user: acct.imapUser, pass: acct.password }, logger: false,
        tls: { rejectUnauthorized: !allowSelfSigned },
      });
      state.client = client;
      client.on('error', () => {});
      try {
        await client.connect();
        await client.mailboxOpen('INBOX');
        if (!lastUids.has(key)) lastUids.set(key, client.mailbox.uidNext - 1);
        backoff = 3000;
        console.log(`[imap] vigilando ${acct.email}`);
        client.on('exists', async () => {
          try {
            const since = lastUids.get(key);
            const found = [];
            for await (const m of client.fetch(`${since + 1}:*`, { envelope: true, uid: true }, { uid: true })) {
              if (m.uid > since) found.push(m);
            }
            found.sort((a, b) => a.uid - b.uid);
            if (found.length) lastUids.set(key, found[found.length - 1].uid);
            for (const m of found.slice(-5)) await notifyNewMail(acct.email, m);
          } catch (e) { console.log(`[imap] ${acct.email}: ${e.message}`); }
        });
        await new Promise((resolve) => client.once('close', resolve));
      } catch (e) {
        console.log(`[imap] ${acct.email}: ${e.responseText || e.message} (reintento en ${Math.round(backoff / 1000)} s)`);
      }
      try { await client.logout(); } catch {}
      if (state.stopped) break;
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(backoff * 2, 120000);
    }
  })();
  return { stop: () => { state.stopped = true; try { state.client && state.client.close(); } catch {} }, sig: acct.sig };
}

function syncWatchers() {
  const wanted = new Map();
  for (const d of devices) for (const a of d.accounts) {
    let pw; try { pw = decrypt(a.passwordEnc); } catch { continue; }
    const acct = { ...a, password: pw, sig: crypto.createHash('sha256').update(`${a.imapUser}|${pw}|${a.imapTLS}`).digest('hex') };
    wanted.set(acctKey(a), acct);
  }
  for (const [k, w] of watchers) if (!wanted.has(k) || wanted.get(k).sig !== w.sig) { w.stop(); watchers.delete(k); if (!wanted.has(k)) lastUids.delete(k); }
  for (const [k, a] of wanted) if (!watchers.has(k)) watchers.set(k, startWatcher(a));
}

// ───────────────────────── Comprobaciones (Mailcow y Apple) ─────────────────────────
function friendlyNetError(e, host, port) {
  const code = e.code || '';
  if (code === 'ENOTFOUND') return `No encontramos «${host}». Revisa que esté bien escrito.`;
  if (code === 'ECONNREFUSED') return `El servidor «${host}» rechazó la conexión en el puerto ${port}. Revisa el puerto (993 en Mailcow) y que Mailcow esté encendido.`;
  if (code === 'ETIMEDOUT' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return `No hemos podido llegar a «${host}». Revisa la IP, tu red o Tailscale.`;
  if (/CERT|SELF_SIGNED|ALTNAME|certificate/i.test(code + e.message)) return 'El certificado de seguridad del servidor no es de confianza. Si es tu propio servidor (o usas una IP), marca «Mi servidor usa certificado propio» y vuelve a comprobar.';
  return 'No hemos podido conectar con Mailcow. Pulsa «Ver error completo» para ver el motivo.';
}
function checkImap(host, port, selfSigned) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: !selfSigned, timeout: 8000 });
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (d) => { buf += d; if (buf.includes('\n')) { sock.end(); resolve(buf.trim()); } });
    sock.on('timeout', () => { sock.destroy(); const e = new Error('Tiempo de espera agotado'); e.code = 'ETIMEDOUT'; reject(e); });
    sock.on('error', reject);
  });
}
function probeMailcowWeb(host) {
  return new Promise((resolve) => {
    const req = https.get({ host, port: 443, path: '/', rejectUnauthorized: false, timeout: 5000, servername: net.isIP(host) ? undefined : host }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { if (body.length < 30000) body += d; });
      res.on('end', () => resolve(/mailcow/i.test(body) || /mailcow/i.test(JSON.stringify(res.headers))));
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}
async function verifyApple() {
  // Mandamos un token falso: si Apple contesta «BadDeviceToken», nuestra firma y llave son correctas.
  const r = await apnsRequest({ token: 'a'.repeat(64), env: 'production', payload: { aps: { alert: 'x' } } });
  if (r.localError || r.networkError || (r.status === 403) || (r.status === 400 && r.reason !== 'BadDeviceToken' && r.reason !== 'DeviceTokenNotForTopic')) {
    const f = friendlyApns(r); return { ok: false, ...f };
  }
  return { ok: true, friendly: 'Apple ha aceptado tu llave. Todo correcto.', technical: `HTTP ${r.status} ${r.reason}` };
}

// ───────────────────────── Servidor web / API ─────────────────────────
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));

const mask = (t) => t.slice(0, 6) + '…' + t.slice(-4);
const tests = new Map(); // testId -> { acked, at }

app.get('/api/health', (req, res) => res.json({ ok: true, name: 'Capotis Push', version: VERSION }));

app.get('/api/state', (req, res) => {
  res.json({
    version: VERSION, port: PORT, hasUser: !!config.user, loggedIn: isLoggedIn(req),
    username: isLoggedIn(req) ? config.user.name : undefined,
    mailcow: isLoggedIn(req) ? config.mailcow : null,
    apple: isLoggedIn(req) && config.apple ? { teamId: config.apple.teamId, keyId: config.apple.keyId, bundleId: config.apple.bundleId, verified: !!config.apple.verified } : null,
    mailcowConfigured: !!config.mailcow, appleConfigured: !!(config.apple && fs.existsSync(P8_PATH)),
    devices: devices.length,
  });
});

app.post('/api/setup', (req, res) => {
  if (config.user) return res.status(409).json({ error: 'Ya hay un usuario creado. Inicia sesión.' });
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || username.trim().length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres.' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
  const salt = crypto.randomBytes(16).toString('hex');
  config.user = { name: username.trim(), salt, hash: hashPw(password, salt) };
  saveConfig();
  startSession(res);
  res.json({ ok: true });
});
app.post('/api/login', (req, res) => {
  if (tooMany(req.ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const { username, password } = req.body || {};
  if (!checkPassword(String(username || '').trim(), String(password || ''))) { noteFail(req.ip); return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' }); }
  startSession(res);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  const t = cookieOf(req, 'capotis_session'); if (t) sessions.delete(t);
  res.setHeader('Set-Cookie', 'capotis_session=; Max-Age=0; Path=/');
  res.json({ ok: true });
});

// Para la app del iPhone
app.get('/api/status', requireAuth, (req, res) => res.json({
  ok: true, version: VERSION, mailcowConfigured: !!config.mailcow,
  appleConfigured: !!(config.apple && fs.existsSync(P8_PATH)), devices: devices.length,
}));

app.post('/api/mailcow/check', requireAuth, async (req, res) => {
  const host = String(req.body.host || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const port = parseInt(req.body.port || '993', 10);
  const selfSigned = !!req.body.selfSigned;
  if (!host) return res.status(400).json({ ok: false, friendly: 'Escribe la dirección de tu Mailcow.', technical: 'host vacío' });
  try {
    const greeting = await checkImap(host, port, selfSigned);
    if (!/^\* (OK|PREAUTH)/i.test(greeting)) return res.json({ ok: false, friendly: 'El servidor responde, pero no parece un servidor de correo IMAP. Revisa el puerto.', technical: greeting });
    const web = await probeMailcowWeb(host);
    const dovecot = /dovecot/i.test(greeting);
    config.mailcow = { host, port, selfSigned, verifiedAt: Date.now() };
    saveConfig();
    res.json({
      ok: true, detected: web || dovecot,
      friendly: web ? '¡Mailcow encontrado! Veo tu servidor de correo y su panel.' : dovecot ? 'Veo tu servidor de correo (Dovecot, el que usa Mailcow). Todo bien.' : 'Veo un servidor de correo IMAP. Puedes continuar.',
      technical: `Saludo IMAP: ${greeting}\nPanel web de Mailcow detectado: ${web ? 'sí' : 'no'}`,
    });
  } catch (e) {
    res.json({ ok: false, friendly: friendlyNetError(e, host, port), technical: `${e.code || 'ERROR'}: ${e.message}\nhost: ${host}\npuerto: ${port}` });
  }
});

app.post('/api/apple/save', requireAuth, async (req, res) => {
  const { teamId, keyId, bundleId, p8 } = req.body || {};
  const bad = (m) => res.status(400).json({ ok: false, friendly: m, technical: m });
  if (!/^[A-Z0-9]{10}$/i.test(String(teamId || '').trim())) return bad('El Team ID tiene 10 letras/números (lo ves en developer.apple.com > Membership).');
  if (!/^[A-Z0-9]{10}$/i.test(String(keyId || '').trim())) return bad('El Key ID tiene 10 letras/números (aparece junto a tu llave en Keys).');
  const bid = String(bundleId || 'com.capotis.apps.mail').trim();
  if (p8) {
    if (!/BEGIN PRIVATE KEY/.test(p8)) return bad('Ese archivo no parece una llave .p8 de Apple (debe empezar por «BEGIN PRIVATE KEY»).');
    try { crypto.createPrivateKey(p8); } catch { return bad('No se puede leer esa llave. Descarga de nuevo el archivo .p8 desde Apple.'); }
    fs.writeFileSync(P8_PATH, p8, { mode: 0o600 });
  } else if (!fs.existsSync(P8_PATH)) return bad('Sube primero el archivo .p8.');
  config.apple = { teamId: teamId.trim().toUpperCase(), keyId: keyId.trim().toUpperCase(), bundleId: bid, verified: false };
  jwtCache = { token: null, at: 0, key: '' };
  const v = await verifyApple();
  config.apple.verified = v.ok;
  saveConfig();
  res.json(v);
});

app.get('/api/devices', requireAuth, (req, res) => res.json({
  devices: devices.map((d) => ({ id: mask(d.token), name: d.deviceName, env: d.env, accounts: d.accounts.map((a) => a.email), updatedAt: d.updatedAt })),
}));

app.post('/api/apple/test', requireAuth, async (req, res) => {
  if (!config.apple || !fs.existsSync(P8_PATH)) return res.json({ ok: false, results: [], friendly: 'Primero completa el paso 3 (llave de Apple).', technical: 'Sin configuración de Apple' });
  if (!devices.length) return res.json({ ok: false, results: [], friendly: 'Todavía no hay ningún iPhone registrado. En la app: Ajustes > Notificaciones > activar, y conecta con este servidor.', technical: 'devices.json vacío' });
  const testId = crypto.randomBytes(8).toString('hex');
  tests.set(testId, { acked: false, at: Date.now() });
  const results = [];
  for (const d of [...devices]) {
    const r = await sendToDevice(d, {
      aps: { alert: { title: 'Capotis Mail', body: '¡Funciona! Esta es una notificación de prueba.' }, sound: 'default', 'content-available': 1, 'thread-id': 'capotis-test' },
      testId,
    });
    if (r.status === 200) results.push({ device: d.deviceName || mask(d.token), ok: true, friendly: 'Apple ha aceptado la notificación.', technical: `HTTP 200\napns-id: ${r.apnsId}\nservidor: ${r.host}` });
    else {
      if (r.status === 410) { devices = devices.filter((x) => x.token !== d.token); saveDevices(); syncWatchers(); }
      results.push({ device: d.deviceName || mask(d.token), ok: false, ...friendlyApns(r) });
    }
  }
  res.json({ ok: results.some((r) => r.ok), testId, results });
});
app.get('/api/test/:id', requireAuth, (req, res) => res.json({ acked: !!(tests.get(req.params.id) || {}).acked }));

// Dispositivos (los llama la app con usuario/contraseña)
app.post('/api/device/register', requireAuth, (req, res) => {
  const b = req.body || {};
  const token = String(b.deviceToken || '').toLowerCase();
  if (!/^[0-9a-f]{64,200}$/.test(token)) return res.status(400).json({ error: 'Token de dispositivo no válido' });
  const accounts = (Array.isArray(b.accounts) ? b.accounts : []).filter((a) => a && a.email && a.imapHost && a.password).map((a) => ({
    email: String(a.email), name: String(a.name || ''), imapHost: String(a.imapHost), imapPort: parseInt(a.imapPort || 993, 10),
    imapTLS: a.imapTLS !== false, imapUser: String(a.imapUser || a.email), passwordEnc: encrypt(String(a.password)),
  }));
  let d = devices.find((x) => x.token === token);
  if (!d) { d = { token, accounts: [] }; devices.push(d); }
  d.env = b.environment === 'development' ? 'development' : 'production';
  d.deviceName = String(b.deviceName || 'iPhone').slice(0, 60);
  d.bundleId = String(b.bundleId || '');
  d.accounts = accounts;
  d.updatedAt = Date.now();
  saveDevices();
  syncWatchers();
  res.json({ ok: true, accounts: accounts.length });
});
app.post('/api/device/unregister', requireAuth, (req, res) => {
  devices = devices.filter((d) => d.token !== String((req.body || {}).deviceToken || '').toLowerCase());
  saveDevices(); syncWatchers(); res.json({ ok: true });
});
app.post('/api/device/remove-account', requireAuth, (req, res) => {
  const d = devices.find((x) => x.token === String((req.body || {}).deviceToken || '').toLowerCase());
  if (d) { d.accounts = d.accounts.filter((a) => a.email !== (req.body || {}).email); saveDevices(); syncWatchers(); }
  res.json({ ok: true });
});
app.post('/api/device/ack', requireAuth, (req, res) => {
  const t = tests.get(String((req.body || {}).testId || ''));
  if (t) t.acked = true;
  res.json({ ok: true });
});

app.use((req, res) => res.status(404).json({ error: 'No encontrado' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Error interno del servidor' }); });

// ───────────────────────── Arranque ─────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  const ips = Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address);
  const line = '═'.repeat(58);
  console.log(`\n╔${line}╗`);
  console.log(`║  Capotis Push ${VERSION}`.padEnd(59) + '║');
  console.log(`║  ✅ Servidor creado en el puerto ${PORT}`.padEnd(58) + '║');
  console.log(`║  Panel web:  http://IP-DE-TU-SERVIDOR:${PORT}`.padEnd(59) + '║');
  console.log(`╚${line}╝`);
  console.log(`Puerto del servidor: ${PORT}`);
  if (ips.length) console.log(`(Dentro de Docker la IP interna es ${ips.join(', ')}; usa la IP de tu servidor o la de Tailscale.)`);
  console.log(config.user ? 'Usuario ya creado. Entra al panel para continuar.' : 'Primer arranque: abre el panel web y crea tu usuario y contraseña.');
  syncWatchers();
});
