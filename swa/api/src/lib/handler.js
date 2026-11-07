'use strict';
// Lógica da API, independente do framework (facilita testar). As funções do Azure só adaptam entrada/saída.
const crypto = require('node:crypto');
const { scan, normalize } = require('./scanner');
const turnstile = require('./turnstile');

const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 10;          // scans/min por IP (por instância)
const TARGET_RATE_LIMIT = Number(process.env.TARGET_RATE_LIMIT) || 6; // scans/min por domínio-alvo (por instância)
const SCAN_DEADLINE_MS = 25000;                                   // teto total de uma análise
const LOG_SALT = process.env.LOG_SALT || crypto.randomBytes(16).toString('hex');

// Janela deslizante em memória. Em serverless vale só por instância e zera em partida a frio:
// é uma proteção "de melhor esforço". A defesa principal é o Turnstile.
function makeLimiter(max) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    if (hits.size > 5000) for (const [k, a] of hits) if (!a.some((t) => now - t < 60000)) hits.delete(k);
    const arr = (hits.get(key) || []).filter((t) => now - t < 60000);
    arr.push(now);
    hits.set(key, arr);
    return arr.length > max;
  };
}
const ipLimited = makeLimiter(RATE_LIMIT);
const targetLimited = makeLimiter(TARGET_RATE_LIMIT);

// O Static Web Apps costuma enviar x-forwarded-for como "1.2.3.4:5678" (com porta).
function clientIp(xff) {
  const first = String(xff || '').split(',')[0].trim();
  if (!first) return 'unknown';
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(first);
  if (v6) return v6[1];
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(first)) return first.slice(0, first.lastIndexOf(':'));
  return first;
}

// LGPD: nos logs vai só um hash curto do IP, que muda a cada dia.
const anon = (ip) => crypto.createHash('sha256').update(`${LOG_SALT}|${new Date().toISOString().slice(0, 10)}|${ip}`).digest('hex').slice(0, 12);

const withDeadline = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('A análise demorou demais (limite de 25 s)')), ms).unref())]);

// Retorna { status, body }.
async function handleScan({ target, token, ip, log = () => {} }) {
  const who = anon(ip);
  const t0 = Date.now();
  const fail = (status, error, why) => { log({ ev: 'scan', ok: false, why, ip: who }); return { status, body: { error } }; };

  if (ipLimited(ip)) return fail(429, 'Muitas requisições. Tente novamente em 1 minuto.', 'rate_ip');
  if (!target || target.length > 2048) return fail(400, 'Informe o parâmetro ?url= (máx. 2048 caracteres)', 'bad_param');

  let host = null;
  try { host = new URL(normalize(target)).hostname.toLowerCase(); } catch { /* o scan devolverá "URL inválida" */ }
  if (host && targetLimited(host)) return fail(429, 'Esse domínio foi analisado muitas vezes agora há pouco. Aguarde 1 minuto.', 'rate_target');

  if (turnstile.enabled) {
    const ok = await turnstile.verify(token, ip);
    if (ok === null) return fail(503, 'Não foi possível validar a verificação anti-robô. Tente novamente.', 'turnstile_unavailable');
    if (!ok) return fail(403, 'Verificação anti-robô inválida ou expirada. Refaça a verificação.', 'turnstile_failed');
  }

  try {
    const result = await withDeadline(scan(target), SCAN_DEADLINE_MS);
    log({ ev: 'scan', ok: true, host, grade: result.grade, score: result.score, ms: Date.now() - t0, ip: who });
    return { status: 200, body: result };
  } catch (e) {
    log({ ev: 'scan', ok: false, why: 'scan_error', host, msg: e.message, ms: Date.now() - t0, ip: who });
    return { status: 400, body: { error: e.message } };
  }
}

const getConfig = () => ({ status: 200, body: { turnstileSiteKey: turnstile.enabled ? turnstile.siteKey : null } });

// Headers das respostas JSON da API (os do site estático ficam em staticwebapp.config.json).
const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
};

module.exports = { handleScan, getConfig, clientIp, JSON_HEADERS };
