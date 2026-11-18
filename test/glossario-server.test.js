'use strict';
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
let child, base;
test.before(async () => {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', ALLOW_PRIVATE: '1', STATUS_FETCH: '0', TURNSTILE_SITE_KEY: '', TURNSTILE_SECRET_KEY: '' } });
  await new Promise((res, rej) => { child.stdout.on('data', (d) => { if (String(d).includes('"ev":"start"')) res(); }); child.on('error', rej); setTimeout(() => rej(new Error('servidor não iniciou')), 5000); });
});
test.after(() => child.kill());

test('glossário: índice, verbete, scripts e sitemap são servidos com CSP', async () => {
  for (const [u, ct, re] of [['/glossario', /html/, /Glossário/], ['/glossario/', /html/, /Glossário/], ['/glossario/csp.html', /html/, /Content-Security-Policy/], ['/glossario.js', /javascript/, /busca/i], ['/glossario-mapa.js', /javascript/, /window\.GLOSS/], ['/sitemap.xml', /xml/, /<urlset/]]) {
    const r = await fetch(base + u);
    assert.strictEqual(r.status, 200, u);
    assert.match(r.headers.get('content-type'), ct, u);
    assert.match(await r.text(), re, u);
    assert.match(r.headers.get('content-security-policy') || "default-src 'none'", /default-src 'none'/);
  }
});
test('glossário: verbete inexistente e path traversal => 404', async () => {
  for (const u of ['/glossario/nao-existe.html', '/glossario/..%2fserver.js', '/glossario/../server.js', '/glossario/%2e%2e/package.json', '/glossario/CSP.html']) {
    const r = await fetch(base + u);
    assert.strictEqual(r.status, 404, u);
    assert.ok(!(await r.text()).includes('require('), u);
  }
});
test('SWA: rota /glossario reescreve para o índice', () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'swa', 'app', 'staticwebapp.config.json'), 'utf8'));
  assert.ok(cfg.routes.some((r) => r.route === '/glossario' && r.rewrite === '/glossario/index.html'));
});
