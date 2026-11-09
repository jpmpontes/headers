'use strict';
// Teste de integração: sobe o servidor de verdade com um verificador Turnstile simulado e um alvo local.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const path = require('node:path');

const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
const listen = (srv) => new Promise((res) => srv.listen(0, '127.0.0.1', () => res(srv.address().port)));

let verifier, target, child, base, vport, tport;
const logs = [];

test.before(async () => {
  // Verificador simulado: token "good" => ok, "boom" => HTTP 500, qualquer outro => falha.
  verifier = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const tok = new URLSearchParams(body).get('response');
      if (tok === 'boom') { res.writeHead(500); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: tok === 'good' }));
    });
  });
  vport = await listen(verifier);
  target = http.createServer((_q, r) => { r.writeHead(200, { 'X-Content-Type-Options': 'nosniff' }); r.end('ok'); });
  tport = await listen(target);

  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env, PORT: String(port), HOST: '127.0.0.1', ALLOW_PRIVATE: '1', TARGET_RATE_LIMIT: '3', RATE_LIMIT: '50',
      TURNSTILE_SITE_KEY: 'site-key-test', TURNSTILE_SECRET_KEY: 'secret-test', TURNSTILE_VERIFY_URL: `http://127.0.0.1:${vport}/`,
    },
  });
  await new Promise((res, rej) => {
    child.stdout.on('data', (d) => { String(d).split('\n').filter(Boolean).forEach((l) => logs.push(l)); if (logs.some((l) => l.includes('"ev":"start"'))) res(); });
    child.on('error', rej);
    setTimeout(() => rej(new Error('servidor não iniciou')), 5000);
  });
});

test.after(() => { child.kill(); verifier.close(); target.close(); });

const get = async (p) => { const r = await fetch(base + p); return { r, body: await r.json().catch(() => null) }; };
const scanUrl = (tok, host = `127.0.0.1:${tport}`) => `/api/scan?url=http://${host}/${tok ? '&cf-turnstile-response=' + tok : ''}`;

test('healthz e config', async () => {
  assert.strictEqual((await get('/healthz')).body.ok, true);
  assert.strictEqual((await get('/api/config')).body.turnstileSiteKey, 'site-key-test');
});

test('CSP libera o domínio do Turnstile quando ativo', async () => {
  const r = await fetch(base + '/');
  assert.match(r.headers.get('content-security-policy'), /script-src 'self' https:\/\/challenges\.cloudflare\.com/);
  assert.match(r.headers.get('content-security-policy'), /frame-src https:\/\/challenges\.cloudflare\.com/);
});

test('sem token ou com token inválido: 403', async () => {
  assert.strictEqual((await get(scanUrl(''))).r.status, 403);
  assert.strictEqual((await get(scanUrl('ruim'))).r.status, 403);
});

test('verificador fora do ar: falha fechada (503)', async () => {
  assert.strictEqual((await get(scanUrl('boom', 'outro-host.test'))).r.status, 503);
});

test('token válido: scan executa', async () => {
  const { r, body } = await get(scanUrl('good'));
  assert.strictEqual(r.status, 200);
  assert.ok(body.overall.grade && body.sections.headers.checks.length === 10);
});

test('limite por domínio-alvo: 4ª análise do mesmo host dá 429', async () => {
  // Já houve 1 scan de 127.0.0.1 (+ 2 bloqueios por token, que também contam). Esgota o restante.
  let last;
  for (let i = 0; i < 4; i++) last = (await get(scanUrl('good'))).r.status;
  assert.strictEqual(last, 429);
});

test('logs não contêm o IP em claro', async () => {
  const scans = logs.filter((l) => l.includes('"ev":"scan"'));
  assert.ok(scans.length > 0);
  assert.ok(scans.every((l) => /"ip":"[0-9a-f]{12}"/.test(l)));
});

test('arquivos estáticos e 404', async () => {
  assert.strictEqual((await fetch(base + '/favicon.svg')).status, 200);
  assert.strictEqual((await fetch(base + '/robots.txt')).status, 200);
  assert.strictEqual((await fetch(base + '/nao-existe')).status, 404);
  assert.strictEqual((await fetch(base + '/', { method: 'POST' })).status, 405);
});
