'use strict';
const { fetchHeaders } = require('./fetcher');

const mk = (id, name, max, points, status, message, fix, value) => ({
  id, name, max, points: Math.max(0, Math.round(points * 10) / 10), status, message, fix, value: value || null,
});

function parseCSP(v) {
  const out = {};
  for (const part of String(v).split(';')) {
    const t = part.trim().split(/\s+/).filter(Boolean);
    if (t.length) out[t[0].toLowerCase()] = t.slice(1);
  }
  return out;
}

function checkHttps(ctx) {
  return ctx.https
    ? mk('https', 'HTTPS', 5, 5, 'pass', 'O site final é servido via HTTPS.', null, ctx.finalUrl)
    : mk('https', 'HTTPS', 5, 0, 'fail', 'O site final é servido sem criptografia (HTTP).',
      'Habilite HTTPS (ex.: Let\'s Encrypt) e redirecione todo o tráfego HTTP para HTTPS.', ctx.finalUrl);
}

function checkCSP(h) {
  const name = 'Content-Security-Policy', max = 25;
  const fix = "Comece com: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
  const enforced = h['content-security-policy'];
  const ro = h['content-security-policy-report-only'];
  if (!enforced) {
    if (ro) return mk('csp', name, max, 5, 'warn', 'Existe apenas em modo Report-Only: não bloqueia nada.', 'Após validar os relatórios, publique como Content-Security-Policy.', ro);
    return mk('csp', name, max, 0, 'fail', 'Header ausente. Principal defesa contra XSS e injeção de conteúdo.', fix);
  }
  const p = parseCSP(enforced);
  const issues = [];
  let pts = max;
  const script = p['script-src'] || p['default-src'];
  if (!script) { pts -= 8; issues.push('sem script-src nem default-src'); }
  else {
    const strict = script.some((x) => /^'(nonce-|sha(256|384|512)-)/.test(x)) || script.includes("'strict-dynamic'");
    if (script.includes("'unsafe-inline'") && !strict) { pts -= 10; issues.push("'unsafe-inline' em scripts"); }
    if (script.includes("'unsafe-eval'")) { pts -= 5; issues.push("'unsafe-eval' em scripts"); }
    if (script.some((x) => x === '*' || x === 'http:' || x === 'data:')) { pts -= 5; issues.push('origens muito amplas (*, http:, data:)'); }
  }
  if (!p['object-src'] && !p['default-src']) { pts -= 3; issues.push("falta object-src 'none'"); }
  pts = Math.max(pts, 5);
  return issues.length
    ? mk('csp', name, max, pts, 'warn', `Presente, porém fraca: ${issues.join('; ')}.`, 'Remova diretivas inseguras; prefira nonces/hashes e origens específicas.', enforced)
    : mk('csp', name, max, pts, 'pass', 'Política presente e sem problemas óbvios.', null, enforced);
}

function checkHSTS(h, ctx) {
  const name = 'Strict-Transport-Security', max = 20;
  const fix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload';
  if (!ctx.https) return mk('hsts', name, max, 0, 'fail', 'Não aplicável: o site não usa HTTPS.', 'Habilite HTTPS primeiro e depois adicione o HSTS.');
  const v = h['strict-transport-security'];
  if (!v) return mk('hsts', name, max, 0, 'fail', 'Header ausente: navegadores podem ser forçados a usar HTTP.', fix);
  const m = /max-age=(\d+)/i.exec(v);
  const age = m ? Number(m[1]) : 0;
  if (age < 15552000) return mk('hsts', name, max, 8, 'warn', `max-age muito curto (${age}s). Recomendado ≥ 15552000 (180 dias).`, fix, v);
  let pts = 14;
  const notes = [];
  if (/includeSubDomains/i.test(v)) pts += 3; else notes.push('falta includeSubDomains');
  if (/preload/i.test(v)) pts += 3; else notes.push('falta preload');
  return mk('hsts', name, max, pts, notes.length ? 'warn' : 'pass',
    notes.length ? `Boa, mas ${notes.join(' e ')}.` : 'Configuração completa.', notes.length ? fix : null, v);
}

function checkXCTO(h) {
  const v = h['x-content-type-options'];
  const ok = v && /nosniff/i.test(v);
  return ok ? mk('xcto', 'X-Content-Type-Options', 10, 10, 'pass', 'nosniff ativo.', null, v)
    : mk('xcto', 'X-Content-Type-Options', 10, 0, 'fail', 'Ausente ou inválido: o navegador pode "adivinhar" tipos MIME.', 'X-Content-Type-Options: nosniff', v);
}

function checkFraming(h) {
  const xfo = h['x-frame-options'];
  const fa = h['content-security-policy'] && parseCSP(h['content-security-policy'])['frame-ancestors'];
  if (fa) return mk('framing', 'Proteção contra clickjacking', 10, 10, 'pass', 'CSP frame-ancestors definido.', null, `frame-ancestors ${fa.join(' ')}`);
  if (xfo && /^(deny|sameorigin)$/i.test(xfo.trim())) return mk('framing', 'Proteção contra clickjacking', 10, 10, 'pass', 'X-Frame-Options definido.', null, xfo);
  return mk('framing', 'Proteção contra clickjacking', 10, 0, 'fail', 'Nem X-Frame-Options nem CSP frame-ancestors: o site pode ser embutido em iframes de terceiros.',
    "Content-Security-Policy: frame-ancestors 'self'  (ou X-Frame-Options: SAMEORIGIN)", xfo);
}

function checkReferrer(h) {
  const v = h['referrer-policy'];
  if (!v) return mk('referrer', 'Referrer-Policy', 10, 0, 'fail', 'Ausente: URLs completas podem vazar para outros sites.', 'Referrer-Policy: strict-origin-when-cross-origin');
  const last = v.split(',').pop().trim().toLowerCase();
  if (['unsafe-url', 'no-referrer-when-downgrade', ''].includes(last)) return mk('referrer', 'Referrer-Policy', 10, 4, 'warn', `Valor fraco (${last || 'vazio'}).`, 'Referrer-Policy: strict-origin-when-cross-origin', v);
  return mk('referrer', 'Referrer-Policy', 10, 10, 'pass', 'Política restritiva definida.', null, v);
}

function checkPermissions(h) {
  const v = h['permissions-policy'];
  if (v) return mk('permissions', 'Permissions-Policy', 10, 10, 'pass', 'Recursos do navegador restringidos.', null, v);
  if (h['feature-policy']) return mk('permissions', 'Permissions-Policy', 10, 5, 'warn', 'Usa o antigo Feature-Policy (descontinuado).', 'Permissions-Policy: camera=(), microphone=(), geolocation=()', h['feature-policy']);
  return mk('permissions', 'Permissions-Policy', 10, 0, 'fail', 'Ausente: sem restrição de câmera, microfone, geolocalização etc.', 'Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

function checkCrossOrigin(h) {
  const parts = [['cross-origin-opener-policy', 2, 'COOP'], ['cross-origin-resource-policy', 2, 'CORP'], ['cross-origin-embedder-policy', 1, 'COEP']];
  let pts = 0;
  const have = [], miss = [];
  for (const [k, w, n] of parts) { if (h[k]) { pts += w; have.push(`${n}: ${h[k]}`); } else miss.push(n); }
  const status = miss.length === 0 ? 'pass' : (have.length ? 'warn' : 'info');
  return mk('coop', 'Cross-Origin-* (COOP/CORP/COEP)', 5, pts, status,
    miss.length ? `Ausentes: ${miss.join(', ')}. (Isolamento entre origens: recomendado, nem sempre aplicável.)` : 'Todos presentes.',
    miss.length ? 'Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Resource-Policy: same-origin' : null, have.join(' | '));
}

function checkCookies(h, ctx) {
  const raw = h['set-cookie'];
  if (!raw || !raw.length) return mk('cookies', 'Cookies', 10, 10, 'pass', 'Nenhum cookie definido nesta resposta.', null);
  let total = 0, ok = 0;
  const problems = [];
  for (const c of raw) {
    const cname = c.split('=')[0];
    const flags = [[ctx.https ? /;\s*secure/i.test(c) : true, 'Secure'], [/;\s*httponly/i.test(c), 'HttpOnly'], [/;\s*samesite=(lax|strict|none)/i.test(c), 'SameSite']];
    for (const [pass, f] of flags) { total++; if (pass) ok++; else problems.push(`${cname}: falta ${f}`); }
  }
  const pts = 10 * (ok / total);
  return problems.length
    ? mk('cookies', 'Cookies', 10, pts, 'warn', `Flags ausentes — ${problems.join('; ')}.`, 'Set-Cookie: sessao=...; Secure; HttpOnly; SameSite=Lax', raw.map((c) => c.split(';')[0].split('=')[0]).join(', '))
    : mk('cookies', 'Cookies', 10, 10, 'pass', 'Todos os cookies com Secure, HttpOnly e SameSite.', null);
}

function checkLeak(h) {
  const leaks = [];
  if (h['x-powered-by']) leaks.push(`X-Powered-By: ${h['x-powered-by']}`);
  if (h.server && /\d/.test(h.server)) leaks.push(`Server: ${h.server}`);
  if (h['x-aspnet-version']) leaks.push(`X-AspNet-Version: ${h['x-aspnet-version']}`);
  return leaks.length
    ? mk('leak', 'Vazamento de informações', 5, 0, 'warn', `Expõe tecnologia/versão: ${leaks.join('; ')}.`, 'Remova ou genericize X-Powered-By e a versão no header Server.', leaks.join(' | '))
    : mk('leak', 'Vazamento de informações', 5, 5, 'pass', 'Sem versões de software expostas nos headers.', null, h.server || null);
}

const GRADES = [[95, 'A+'], [85, 'A'], [70, 'B'], [55, 'C'], [40, 'D'], [25, 'E'], [0, 'F']];
const ORDER = GRADES.map((g) => g[1]).reverse(); // F..A+

function gradeFor(pct, checks) {
  let g = GRADES.find(([min]) => pct >= min)[1];
  const cap = (limit) => { if (ORDER.indexOf(g) > ORDER.indexOf(limit)) g = limit; };
  if (checks.find((c) => c.id === 'csp').points === 0) cap('B'); // sem CSP: no máximo B
  if (checks.find((c) => c.id === 'https').points === 0) cap('D'); // sem HTTPS: no máximo D
  return g;
}

// Função pura: facilita testes.
function analyze(headers, finalUrl) {
  const ctx = { https: finalUrl.startsWith('https:'), finalUrl };
  const checks = [
    checkHttps(ctx), checkCSP(headers), checkHSTS(headers, ctx), checkXCTO(headers), checkFraming(headers),
    checkReferrer(headers), checkPermissions(headers), checkCrossOrigin(headers), checkCookies(headers, ctx), checkLeak(headers),
  ];
  const max = checks.reduce((s, c) => s + c.max, 0);
  const got = checks.reduce((s, c) => s + c.points, 0);
  const score = Math.min(100, Math.round((got / max) * 100));
  return { score, grade: gradeFor(score, checks), checks };
}

// Avisos que ajudam a interpretar o resultado (ex.: a resposta pode ser uma página de bloqueio de WAF).
function warningsFor(status) {
  if (status >= 500) return [`O site respondeu HTTP ${status} (erro no servidor). Os headers abaixo podem ser de uma página de erro, não do site funcionando normalmente.`];
  if (status === 401 || status === 403) return [`O site respondeu HTTP ${status} (acesso negado). Sites protegidos por WAF ou Cloudflare costumam bloquear ferramentas automáticas, então os headers abaixo podem ser de uma página de bloqueio e não do site real. A nota pode não refletir o site de verdade.`];
  if (status === 429) return ['O site respondeu HTTP 429 (muitas requisições) e limitou esta análise. Os headers abaixo podem não refletir o site real. Tente de novo mais tarde.'];
  if (status >= 400) return [`O site respondeu HTTP ${status}. Os headers abaixo podem ser de uma página de erro e não da página que você quer avaliar.`];
  return [];
}

function normalize(input) {
  const s = String(input).trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
}

async function scan(input) {
  const raw = normalize(input);
  const r = await fetchHeaders(raw);
  return {
    target: raw, finalUrl: r.finalUrl, status: r.status, redirects: r.chain, warnings: warningsFor(r.status),
    ...analyze(r.headers, r.finalUrl),
    headers: r.headers, scannedAt: new Date().toISOString(),
  };
}

module.exports = { scan, analyze, parseCSP, normalize, warningsFor };
