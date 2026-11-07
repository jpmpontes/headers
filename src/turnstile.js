'use strict';
// Verificação server-side do Cloudflare Turnstile (captcha gratuito).
// Ativado quando TURNSTILE_SITE_KEY e TURNSTILE_SECRET_KEY estão definidos.
const SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const SECRET = process.env.TURNSTILE_SECRET_KEY || '';
const VERIFY_URL = process.env.TURNSTILE_VERIFY_URL || 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const enabled = Boolean(SITE_KEY && SECRET);

// Retorna true (humano), false (token inválido) ou null (não foi possível verificar).
async function verify(token, ip) {
  if (!token || typeof token !== 'string' || token.length > 2048) return false;
  const body = new URLSearchParams({ secret: SECRET, response: token });
  if (ip) body.set('remoteip', ip);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(VERIFY_URL, { method: 'POST', body, signal: ctrl.signal });
    if (!r.ok) return null;
    const d = await r.json();
    return d.success === true;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { enabled, siteKey: SITE_KEY, verify };
