'use strict';
// Integração: o painel de status é independente do scanner e respeita a CSP do site.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
let child, base, target, tport;
test.before(async () => {
  target = http.createServer((_q, r) => { r.writeHead(200); r.end('ok'); });
  await new Promise((r) => target.listen(0, '127.0.0.1', r)); tport = target.address().port;
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', ALLOW_PRIVATE: '1', STATUS_FETCH: '0', TURNSTILE_SITE_KEY: '', TURNSTILE_SECRET_KEY: '' } });
  await new Promise((res, rej) => { child.stdout.on('data', (d) => { if (String(d).includes('"ev":"start"')) res(); }); child.on('error', rej); setTimeout(() => rej(new Error('servidor não iniciou')), 5000); });
});
test.after(() => { child.kill(); target.close(); });

test('/status, /status.js e /api/status são servidos com os headers de segurança', async () => {
  const page = await fetch(`${base}/status`);
  assert.strictEqual(page.status, 200);
  assert.match(page.headers.get('content-type'), /text\/html/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'none'/);
  assert.match(await page.text(), /Status/);
  const js = await fetch(`${base}/status.js`);
  assert.match(js.headers.get('content-type'), /javascript/);
  const api = await fetch(`${base}/api/status`);
  assert.strictEqual(api.status, 200);
  assert.match(api.headers.get('cache-control'), /max-age=30/);
  const body = await api.json();
  assert.ok(body.provedores.length >= 8);
  assert.ok(body.provedores.every((p) => p.estado === 'semdados')); // sem fontes alcançáveis: nada é "operacional"
  assert.strictEqual(body.brasil.length, 4);
});

test('o scanner continua funcionando com o status sem fontes', async () => {
  await fetch(`${base}/api/status`);
  const r = await fetch(`${base}/api/scan?url=http://127.0.0.1:${tport}/`);
  assert.strictEqual(r.status, 200);
  assert.ok((await r.json()).overall.grade);
});

test('frontend compatível com a CSP: sem script/estilo inline, sem innerHTML, sem atributo style', () => {
  const root = path.join(__dirname, '..', 'public');
  const html = fs.readFileSync(path.join(root, 'status.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), 'script inline');
  assert.ok(!/<style/i.test(html) && !/\sstyle=/i.test(html), 'estilo inline');
  const js = fs.readFileSync(path.join(root, 'status.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|setAttribute\(\s*['"]style/.test(js));
});
test('rota /status existe no Azure Static Web Apps e /api/status na Function', () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'swa', 'app', 'staticwebapp.config.json'), 'utf8'));
  assert.ok(cfg.routes.some((r) => r.route === '/status' && r.rewrite === '/status.html'));
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'swa', 'api', 'src', 'functions', 'status.js')));
});
