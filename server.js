'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan, normalize } = require('./src/scanner');
const turnstile = require('./src/turnstile');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // só atrás de proxy confiável (Caddy, Cloudflare Tunnel...)
const CLIENT_IP_HEADER = (process.env.CLIENT_IP_HEADER || 'x-forwarded-for').toLowerCase();
const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 10; // scans por minuto por IP
const TARGET_RATE_LIMIT = Number(process.env.TARGET_RATE_LIMIT) || 6; // scans por minuto para o MESMO domínio (todos os IPs)
const MAX_INFLIGHT = 20;
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOG_SALT = process.env.LOG_SALT || crypto.randomBytes(16).toString('hex');

// O próprio site usa os headers que recomenda. Com Turnstile ativo, libera só o domínio da Cloudflare.
const CF = 'https://challenges.cloudflare.com';
const CSP = [
  "default-src 'none'",
  `script-src 'self'${turnstile.enabled ? ' ' + CF : ''}`,
  "style-src 'self'",
  `connect-src 'self'${turnstile.enabled ? ' ' + CF : ''}`,
  "img-src 'self'",
  turnstile.enabled ? `frame-src ${CF}` : null,
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].filter(Boolean).join('; ');

const SEC = {
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
  '/robots.txt': ['robots.txt', 'text/plain; charset=utf-8'],
};

// Janela deslizante de 60 s, em memória (1 instância). Para várias instâncias, use Redis/Cloudflare.
function makeLimiter(max) {
  const hits = new Map();
  const check = (key) => {
    const now = Date.now();
    const arr = (hits.get(key) || []).filter((t) => now - t < 60000);
    arr.push(now);
    hits.set(key, arr);
    return arr.length > max;
  };
  setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some((t) => now - t < 60000)) hits.delete(k); }, 60000).unref();
  return check;
}
const ipLimited = makeLimiter(RATE_LIMIT);
const targetLimited = makeLimiter(TARGET_RATE_LIMIT);
let inflight = 0;

function clientIp(req) {
  if (TRUST_PROXY) {
    const v = String(req.headers[CLIENT_IP_HEADER] || '').split(',').map((s) => s.trim()).filter(Boolean);
    // Com X-Forwarded-For, o último valor é o que o nosso proxy acrescentou (o primeiro pode ser forjado).
    if (v.length) return CLIENT_IP_HEADER === 'x-forwarded-for' ? v[v.length - 1] : v[0];
  }
  return req.socket.remoteAddress;
}

// LGPD: não gravamos o IP em claro, só um hash curto que muda a cada dia.
const anon = (ip) => crypto.createHash('sha256').update(`${LOG_SALT}|${new Date().toISOString().slice(0, 10)}|${ip}`).digest('hex').slice(0, 12);
const log = (obj) => console.log(JSON.stringify({ t: new Date().toISOString(), ...obj }));

function send(res, code, body, type, extra) {
  res.writeHead(code, { ...SEC, 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
  res.end(body);
}
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);

async function handleScan(req, res, url) {
  const ip = clientIp(req);
  const who = anon(ip);
  const t0 = Date.now();
  const fail = (code, error, why) => { log({ ev: 'scan', ok: false, why, ip: who }); return json(res, code, { error }); };

  if (ipLimited(ip)) return fail(429, 'Muitas requisições. Tente novamente em 1 minuto.', 'rate_ip');
  if (inflight >= MAX_INFLIGHT) return fail(503, 'Servidor ocupado. Tente novamente.', 'busy');

  const target = url.searchParams.get('url');
  if (!target || target.length > 2048) return fail(400, 'Informe o parâmetro ?url= (máx. 2048 caracteres)', 'bad_param');

  // Impede usar o serviço para martelar um site de terceiros.
  let host = null;
  try { host = new URL(normalize(target)).hostname.toLowerCase(); } catch { /* o scan devolverá "URL inválida" */ }
  if (host && targetLimited(host)) return fail(429, 'Esse domínio foi analisado muitas vezes agora há pouco. Aguarde 1 minuto.', 'rate_target');

  if (turnstile.enabled) {
    const ok = await turnstile.verify(url.searchParams.get('cf-turnstile-response'), ip);
    if (ok === null) return fail(503, 'Não foi possível validar a verificação anti-robô. Tente novamente.', 'turnstile_unavailable');
    if (!ok) return fail(403, 'Verificação anti-robô inválida ou expirada. Refaça a verificação.', 'turnstile_failed');
  }

  inflight++;
  try {
    const result = await scan(target);
    log({ ev: 'scan', ok: true, host, grade: result.grade, score: result.score, ms: Date.now() - t0, ip: who });
    return json(res, 200, result);
  } catch (e) {
    log({ ev: 'scan', ok: false, why: 'scan_error', host, msg: e.message, ms: Date.now() - t0, ip: who });
    return json(res, 400, { error: e.message });
  } finally { inflight--; }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Método não permitido' }, { Allow: 'GET, HEAD' });

  if (url.pathname === '/healthz') return json(res, 200, { ok: true });
  if (url.pathname === '/api/config') return json(res, 200, { turnstileSiteKey: turnstile.enabled ? turnstile.siteKey : null });
  if (url.pathname === '/api/scan') return handleScan(req, res, url);

  const f = FILES[url.pathname];
  if (!f) return json(res, 404, { error: 'Não encontrado' });
  fs.readFile(path.join(PUBLIC_DIR, f[0]), (err, data) => (err ? json(res, 500, { error: 'Erro interno' }) : send(res, 200, data, f[1])));
});

server.listen(PORT, HOST, () => log({ ev: 'start', port: PORT, turnstile: turnstile.enabled, trustProxy: TRUST_PROXY }));

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => { log({ ev: 'stop', sig }); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); });
}
