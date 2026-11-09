'use strict';
// Testa a lógica da API da versão Azure (swa/api) sem precisar do runtime do Azure Functions.
process.env.ALLOW_PRIVATE = '1'; // alvo de teste é local
process.env.TARGET_RATE_LIMIT = '3';
process.env.RATE_LIMIT = '100';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { handleScan, getConfig, clientIp, JSON_HEADERS } = require('../swa/api/src/lib/handler');

let target, port;
test.before(async () => {
  target = http.createServer((_q, r) => { r.writeHead(200, { 'X-Content-Type-Options': 'nosniff' }); r.end('ok'); });
  await new Promise((res) => target.listen(0, '127.0.0.1', res));
  port = target.address().port;
});
test.after(() => target.close());

test('clientIp trata porta, IPv6 e vazio', () => {
  assert.strictEqual(clientIp('1.2.3.4:5678, 10.0.0.1'), '1.2.3.4');
  assert.strictEqual(clientIp('1.2.3.4'), '1.2.3.4');
  assert.strictEqual(clientIp('[2001:db8::1]:443'), '2001:db8::1');
  assert.strictEqual(clientIp('2001:db8::1'), '2001:db8::1');
  assert.strictEqual(clientIp(''), 'unknown');
  assert.strictEqual(clientIp(null), 'unknown');
});

test('config sem Turnstile devolve siteKey nula', () => {
  assert.deepStrictEqual(getConfig(), { status: 200, body: { turnstileSiteKey: null } });
});

test('parâmetro ausente: 400', async () => {
  const r = await handleScan({ target: null, ip: '9.9.9.1' });
  assert.strictEqual(r.status, 400);
});

test('scan válido e log sem IP em claro', async () => {
  const logs = [];
  const r = await handleScan({ target: `http://127.0.0.1:${port}/`, ip: '9.9.9.2', log: (o) => logs.push(o) });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body.sections.headers.checks.length, 10);
  assert.ok(/^[0-9a-f]{12}$/.test(logs[0].ip));
});

test('limite por domínio-alvo: 429 depois de 3', async () => {
  let last;
  for (let i = 0; i < 4; i++) last = (await handleScan({ target: `http://localhost:${port}/`, ip: '9.9.9.3' })).status;
  assert.strictEqual(last, 429);
});

test('erros de SSRF viram 400 (com travas ligadas isso bloquearia)', async () => {
  const r = await handleScan({ target: 'file:///etc/passwd', ip: '9.9.9.4' });
  assert.strictEqual(r.status, 400);
});

test('headers JSON da API são restritivos', () => {
  assert.strictEqual(JSON_HEADERS['Cache-Control'], 'no-store');
  assert.strictEqual(JSON_HEADERS['X-Content-Type-Options'], 'nosniff');
});
