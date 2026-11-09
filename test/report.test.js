'use strict';
process.env.ALLOW_PRIVATE = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { fullScan, WEIGHTS } = require('../src/report');

let target, port;
test.before(async () => {
  target = http.createServer((_q, r) => { r.writeHead(200, { 'X-Content-Type-Options': 'nosniff' }); r.end('ok'); });
  await new Promise((res) => target.listen(0, '127.0.0.1', res));
  port = target.address().port;
});
test.after(() => target.close());

test('seções independentes: IP local só tem headers; TLS/DNS/e-mail viram erro sem derrubar o resto', async () => {
  const r = await fullScan(`http://127.0.0.1:${port}/`);
  assert.strictEqual(r.sections.headers.ok, true);
  assert.strictEqual(r.sections.headers.checks.length, 10);
  assert.strictEqual(r.sections.tls.ok, false);
  assert.strictEqual(r.sections.dns.ok, false);
  assert.match(r.sections.email.error, /nomes de domínio públicos/);
  assert.strictEqual(r.overall.sections, 1);
  assert.strictEqual(r.overall.score, r.sections.headers.score);
  assert.strictEqual(r.overall.grade, r.sections.headers.grade);
});

test('pesos somam 100', () => {
  assert.strictEqual(Object.values(WEIGHTS).reduce((a, b) => a + b, 0), 100);
});

test('seletor DKIM inválido é recusado', async () => {
  await assert.rejects(() => fullScan(`http://127.0.0.1:${port}/`, { dkim: 'a b;c' }), /Seletor DKIM inválido/);
});

test('se nenhuma seção funciona, devolve erro', async () => {
  const closed = await new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
  await assert.rejects(() => fullScan(`http://127.0.0.1:${closed}/`), /Falha ao conectar/);
});
