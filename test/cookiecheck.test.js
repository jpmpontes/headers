'use strict';
process.env.ALLOW_PRIVATE = '1';
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { checkPrivacy, fetchPage, parseSetCookie, classifyCookie, scanHtml } = require('../src/cookiecheck');

const NOW = Date.parse('2026-11-24T12:00:00Z');
const page = (o = {}) => async () => ({ finalUrl: 'https://exemplo.com.br/', status: 200, chain: [{ url: 'https://exemplo.com.br/', status: 200 }], setCookies: [], html: '<html><body>oi</body></html>', truncated: false, ...o });
const sc = (raw, https = true) => ({ raw, host: 'exemplo.com.br', https });
const run = (o) => checkPrivacy('exemplo.com.br', { fetchPage: page(o), now: NOW });
const get = (r, id) => r.checks.find((c) => c.id === id);

test('parseSetCookie: atributos, validade e sem guardar o valor', () => {
  const c = parseSetCookie('sid=SEGREDO123; Path=/; Domain=.Exemplo.com.br; Max-Age=3600; Secure; HttpOnly; SameSite=Lax', NOW);
  assert.deepStrictEqual({ n: c.name, d: c.domain, s: c.secure, h: c.httpOnly, ss: c.sameSite, l: c.lifetime }, { n: 'sid', d: 'exemplo.com.br', s: true, h: true, ss: 'lax', l: 3600 });
  assert.ok(!JSON.stringify(c).includes('SEGREDO123'));
  const e = parseSetCookie('a=b; Expires=Wed, 25 Nov 2026 12:00:00 GMT', NOW);
  assert.strictEqual(e.lifetime, 86400);
  assert.strictEqual(parseSetCookie('x=1', NOW).lifetime, null);
});

test('classifyCookie: categorias conhecidas e desconhecido', () => {
  const cat = (n) => classifyCookie(n).cat;
  assert.strictEqual(cat('_ga'), 'analitica');
  assert.strictEqual(cat('_ga_ABC123'), 'analitica');
  assert.strictEqual(cat('_hjSessionUser_123'), 'analitica');
  assert.strictEqual(cat('_fbp'), 'marketing');
  assert.strictEqual(cat('_gcl_au'), 'marketing');
  assert.strictEqual(cat('PHPSESSID'), 'necessario');
  assert.strictEqual(cat('__Host-sessao'), 'necessario');
  assert.strictEqual(cat('OptanonConsent'), 'preferencias');
  assert.strictEqual(cat('xyz_custom'), 'desconhecido');
});

test('scanHtml: rastreadores, plataformas de consentimento, banner e links', () => {
  const html = `<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script src="https://connect.facebook.net/pt_BR/fbevents.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter"><script src="https://consent.cookiebot.com/uc.js"></script>
    <a href="/politica-de-privacidade">Política</a> <a href="/cookies">Cookies</a>`;
  const s = scanHtml(html);
  assert.deepStrictEqual(s.trackers.map((t) => t.nome), ['Google Analytics', 'Meta (Facebook) Pixel/SDK', 'Google Fonts (servidores do Google)']);
  assert.deepStrictEqual(s.cmps, ['Cookiebot']);
  assert.ok(s.privacy && s.cookiePolicy);
  for (const [trecho, nome] of [['cdn.cookielaw.org/scripttemplates/otSDKStub.js', 'OneTrust'], ['cdn.iubenda.com/cs/iubenda_cs.js', 'iubenda'], ['app.termly.io/resource-blocker/x', 'Termly'], ['cdn.cookieserve.com/banner.js', 'CookieServe']]) {
    assert.ok(scanHtml(`<script src="https://${trecho}"></script>`).cmps.includes(nome), nome);
  }
  assert.ok(scanHtml('<div class="cookie-banner">Usamos cookies</div>').bannerHint);
  assert.ok(!scanHtml('<p>oi</p>').bannerHint);
});

test('site limpo: tudo ok, sem nota e com avisos de limitação', async () => {
  const r = await run({ html: '<a href="/privacidade">Privacidade</a>' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.informativa, true);
  assert.match(r.nota, /não entra na nota geral/);
  assert.strictEqual(r.score, undefined);
  assert.ok(r.checks.every((c) => c.max === 0));
  assert.strictEqual(get(r, 'ckpre').status, 'pass');
  assert.match(get(r, 'ckpre').message, /JavaScript/);
  assert.strictEqual(get(r, 'ckpolicy').status, 'pass');
});

test('cookie de marketing na primeira resposta => aviso; valor nunca aparece', async () => {
  const r = await run({ setCookies: [sc('_fbp=fb.1.123.SEGREDO; Max-Age=7776000; Secure; SameSite=Lax')] });
  const c = get(r, 'ckpre');
  assert.strictEqual(c.status, 'warn');
  assert.match(c.message, /_fbp/);
  assert.ok(!JSON.stringify(r).includes('SEGREDO'));
});

test('cookies de redirecionamentos entram na análise (via fetchPage injetado) e flags faltando falham no cookie de sessão', async () => {
  const r = await run({ setCookies: [sc('PHPSESSID=abc; Path=/'), sc('tema=escuro; Secure; SameSite=Lax')] });
  const f = get(r, 'ckflags');
  assert.strictEqual(f.status, 'fail');
  assert.match(f.message, /PHPSESSID: falta Secure, SameSite, HttpOnly/);
  assert.ok(!/tema/.test(f.message));
});

test('SameSite=None sem Secure é falha; sem cookies, flags passa', async () => {
  assert.strictEqual(get(await run({ setCookies: [sc('x=1; SameSite=None')] }), 'ckflags').status, 'fail');
  assert.strictEqual(get(await run(), 'ckflags').status, 'pass');
});

test('validade: só cookie não essencial acima de 13 meses avisa', async () => {
  const r = await run({ setCookies: [sc('_ga=1; Max-Age=63072000; Secure; SameSite=Lax'), sc('PHPSESSID=1; Max-Age=63072000; Secure; HttpOnly; SameSite=Lax')] });
  const c = get(r, 'ckexpiry');
  assert.strictEqual(c.status, 'warn');
  assert.match(c.message, /_ga/);
  assert.ok(!/PHPSESSID/.test(c.message));
});

test('rastreadores sem plataforma de consentimento => avisos em rastreadores e banner', async () => {
  const r = await run({ html: '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>' });
  assert.strictEqual(get(r, 'cktrackers').status, 'warn');
  assert.strictEqual(get(r, 'ckcmp').status, 'warn');
  assert.strictEqual(get(r, 'ckpolicy').status, 'warn');
});

test('rastreadores com plataforma de consentimento => informativo, banner ok', async () => {
  const r = await run({ html: '<script src="https://cdn.iubenda.com/cs/iubenda_cs.js"></script><script src="https://www.google-analytics.com/analytics.js"></script><a href="/privacidade">p</a> <a href="/cookies">c</a>' });
  assert.strictEqual(get(r, 'cktrackers').status, 'info');
  assert.strictEqual(get(r, 'ckcmp').status, 'pass');
  assert.match(get(r, 'ckcmp').message, /iubenda/);
  assert.strictEqual(get(r, 'ckpolicy').status, 'pass');
});

test('só Google Fonts: informativo com dica de hospedar localmente', async () => {
  const c = get(await run({ html: '<link href="https://fonts.googleapis.com/css">' }), 'cktrackers');
  assert.strictEqual(c.status, 'info');
  assert.match(c.message, /IP do visitante/);
});

test('sem HTML (erro ou não HTML): itens do HTML viram informativos e status >= 400 avisa', async () => {
  const r = await run({ html: null, status: 403 });
  for (const id of ['cktrackers', 'ckcmp', 'ckpolicy']) assert.strictEqual(get(r, id).status, 'info', id);
  assert.match(r.warnings[0], /HTTP 403/);
});

test('fetchPage real: segue redirect, junta cookies dos dois saltos, lê HTML e limita o tamanho', async () => {
  const srv = http.createServer((q, s) => {
    if (q.url === '/') { s.writeHead(302, { Location: '/home', 'Set-Cookie': 'a=1; Path=/' }); return s.end(); }
    if (q.url === '/home') { s.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'b=2; Path=/' }); return s.end('<a href="/privacidade">p</a>' + 'x'.repeat(600 * 1024)); }
    if (q.url === '/img') { s.writeHead(200, { 'Content-Type': 'image/png' }); return s.end('PNG'); }
    s.writeHead(404); s.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const p = await fetchPage(base + '/');
    assert.deepStrictEqual(p.setCookies.map((c) => c.raw.split('=')[0]), ['a', 'b']);
    assert.strictEqual(p.status, 200);
    assert.ok(p.truncated && p.html.length <= 400 * 1024 + 10 && p.html.includes('privacidade'));
    assert.strictEqual((await fetchPage(base + '/img')).html, null);
  } finally { srv.close(); }
});

test('SSRF: sem ALLOW_PRIVATE, endereços privados são recusados', async () => {
  const antes = process.env.ALLOW_PRIVATE;
  delete process.env.ALLOW_PRIVATE;
  try { await assert.rejects(() => fetchPage('http://127.0.0.1:9/'), /./); } finally { process.env.ALLOW_PRIVATE = antes; }
});
