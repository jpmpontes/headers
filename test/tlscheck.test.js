'use strict';
// Testa o TLS de verdade contra servidores locais com certificados gerados pelo openssl.
process.env.ALLOW_PRIVATE = '1'; // os alvos são locais

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const { checkTls } = require('../src/tlscheck');

let hasOpenssl = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { hasOpenssl = false; }

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'coreva-tls-'));
function makeCert(name, days) {
  const key = path.join(dir, `${name}.key`);
  const crt = path.join(dir, `${name}.crt`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', String(days),
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

const servers = [];
function serve(opts) {
  return new Promise((res) => {
    const s = tls.createServer(opts, (sock) => sock.end());
    s.on('tlsClientError', () => {});
    s.listen(0, '127.0.0.1', () => { servers.push(s); res(s.address().port); });
  });
}
const byId = (r, id) => r.checks.find((c) => c.id === id);
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });

test.after(() => { servers.forEach((s) => s.close()); fs.rmSync(dir, { recursive: true, force: true }); });

test('certificado autoassinado, nome correto, TLS 1.2 e 1.3', { skip: !hasOpenssl }, async () => {
  const port = await serve(makeCert('a', 60));
  const r = await checkTls('localhost', { port });
  assert.strictEqual(byId(r, 'trust').status, 'fail');
  assert.match(byId(r, 'trust').message, /autoassinado/);
  assert.strictEqual(byId(r, 'hostname').status, 'pass');
  assert.strictEqual(byId(r, 'expiry').status, 'pass');
  assert.strictEqual(byId(r, 'tls12').status, 'pass');
  assert.strictEqual(byId(r, 'tls13').status, 'pass');
  assert.strictEqual(byId(r, 'key').status, 'pass');
  assert.match(byId(r, 'key').value, /RSA 2048/);
  assert.ok(['pass', 'info'].includes(byId(r, 'legacy').status), byId(r, 'legacy').message); // info se o cliente não suporta TLS 1.0
  assert.ok(r.details.some((d) => d.label === 'Detalhes do certificado'));
});

test('servidor só com TLS 1.2: sem TLS 1.3 gera aviso', { skip: !hasOpenssl }, async () => {
  const port = await serve({ ...makeCert('b', 60), maxVersion: 'TLSv1.2' });
  const r = await checkTls('localhost', { port });
  assert.strictEqual(byId(r, 'tls12').status, 'pass');
  assert.strictEqual(byId(r, 'tls13').status, 'warn');
});

test('nome divergente: conectar por IP não bate com o SAN', { skip: !hasOpenssl }, async () => {
  const port = await serve(makeCert('c', 60));
  const r = await checkTls('127.0.0.1', { port });
  assert.strictEqual(byId(r, 'hostname').status, 'fail');
});

test('validade: perto de expirar avisa; relógio no futuro => expirado', { skip: !hasOpenssl }, async () => {
  const port = await serve(makeCert('d', 10));
  const near = await checkTls('localhost', { port });
  assert.strictEqual(byId(near, 'expiry').status, 'warn');
  assert.match(byId(near, 'expiry').message, /Expira em \d+ dias/);
  const expired = await checkTls('localhost', { port, now: Date.now() + 400 * 86400000 });
  assert.strictEqual(byId(expired, 'expiry').status, 'fail');
  assert.match(byId(expired, 'expiry').message, /expirado há/);
});

test('servidor que aceita TLS 1.0/1.1 é reprovado (quando o cliente consegue testar)', { skip: !hasOpenssl }, async (t) => {
  const port = await serve({ ...makeCert('e', 60), minVersion: 'TLSv1', ciphers: 'DEFAULT:@SECLEVEL=0' });
  const r = await checkTls('localhost', { port });
  const legacy = byId(r, 'legacy');
  if (legacy.status === 'info') return t.skip('Este Node/OpenSSL não consegue iniciar handshakes TLS 1.0/1.1 como cliente.');
  assert.strictEqual(legacy.status, 'fail');
});

test('porta fechada: erro claro; nome local sem ALLOW_PRIVATE não é testado aqui', async () => {
  const port = await freePort();
  await assert.rejects(() => checkTls('localhost', { port }), /Não foi possível estabelecer conexão TLS/);
});
