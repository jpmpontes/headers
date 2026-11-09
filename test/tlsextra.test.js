'use strict';
process.env.ALLOW_PRIVATE = '1';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const { execFileSync } = require('node:child_process');
const { X509Certificate } = require('node:crypto');
const X = require('../src/tlsextra');
const { checkTls } = require('../src/tlscheck');

let hasOpenssl = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { hasOpenssl = false; }
const opt = { skip: !hasOpenssl };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'coreva-tlsx-'));
function cert(name, { days = 30, extra = [], hash = 'sha256' } = {}) {
  const key = path.join(dir, `${name}.key`); const crt = path.join(dir, `${name}.crt`);
  const ext = ['subjectAltName=DNS:localhost', ...extra].join('\n');
  const cnf = path.join(dir, `${name}.cnf`);
  fs.writeFileSync(cnf, `[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n[v3]\n${ext}\n`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', `-${hash}`, '-keyout', key, '-out', crt, '-days', String(days), '-config', cnf], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}
const rawOf = (pem) => new X509Certificate(pem).raw;

// ---- DER auxiliar ----
const len = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const der = (tag, ...c) => { const b = Buffer.concat(c); return Buffer.concat([Buffer.from([tag]), len(b.length), b]); };
const gt = (s) => der(0x18, Buffer.from(s));
function ocsp(state, next = '20991231000000Z') {
  const st = state === 'good' ? der(0x80) : state === 'revoked' ? der(0xa1, gt('20260101000000Z')) : der(0x82);
  const single = der(0x30, der(0x30), st, gt('20260101000000Z'), der(0xa0, gt(next)));
  const tbs = der(0x30, der(0xa2, der(0x04, Buffer.alloc(20))), gt('20260101000000Z'), der(0x30, single));
  const basic = der(0x30, tbs, der(0x30), der(0x03, Buffer.from([0])));
  return der(0x30, der(0x0a, Buffer.from([0])), der(0xa0, der(0x30, der(0x06, Buffer.from('2b0601050507010101', 'hex')), der(0x04, basic))));
}

test('OCSP: lê estado e validade da resposta', () => {
  assert.strictEqual(X.parseOcsp(ocsp('good')).state, 'good');
  assert.strictEqual(X.parseOcsp(ocsp('revoked')).state, 'revoked');
  assert.strictEqual(X.parseOcsp(ocsp('good', '20200101000000Z')).nextUpdate.getUTCFullYear(), 2020);
  assert.ok(X.parseOcsp(Buffer.from([1, 2, 3])).error);
});
test('SCTs: conta registros da extensão', () => {
  const sct = Buffer.alloc(10);
  const entry = Buffer.concat([Buffer.from([0, 10]), sct]);
  const list = Buffer.concat([Buffer.from([0, entry.length * 2]), entry, entry]);
  assert.strictEqual(X.sctCount(der(0x04, list)), 2);
  assert.strictEqual(X.sctCount(Buffer.alloc(0)), 0);
});

test('assinatura SHA-1 no certificado do site => falha e teto D', opt, () => {
  let c; try { c = cert('sha1', { hash: 'sha1' }); } catch { return; }
  const x = new X509Certificate(c.cert);
  const r = X.analyzeChain([x.raw], false, new Date(x.validFrom), new Date(x.validTo));
  assert.strictEqual(r.checks.find((k) => k.id === 'sigalg').status, 'fail');
  assert.deepStrictEqual(r.caps, ['D']);
});
test('assinatura SHA-256 passa; prazo total acima do limite gera aviso (CA pública)', opt, () => {
  const c = cert('long', { days: 500 });
  const x = new X509Certificate(c.cert);
  const r = X.analyzeChain([x.raw], true, new Date(x.validFrom), new Date(x.validTo));
  assert.strictEqual(r.checks.find((k) => k.id === 'sigalg').status, 'pass');
  assert.strictEqual(r.checks.find((k) => k.id === 'lifetime').status, 'warn');
  const ok = X.analyzeChain([x.raw], true, new Date(x.validFrom), new Date(+new Date(x.validFrom) + 90 * 86400000));
  assert.strictEqual(ok.checks.find((k) => k.id === 'lifetime').status, 'pass');
});

const REV = (c, staple, auth = true) => { const x = new X509Certificate(c.cert); return X.analyzeRevocation(x, X.parseCert(x.raw), staple, auth, Date.now()); };
test('revogação: Must-Staple sem grampo => falha e teto C; com grampo bom => passa', opt, () => {
  const c = cert('ms', { extra: ['tlsfeature=status_request', 'authorityInfoAccess=OCSP;URI:http://ocsp.exemplo.com'] });
  const a = REV(c, null);
  assert.strictEqual(a.checks[0].status, 'fail'); assert.deepStrictEqual(a.caps, ['C']);
  assert.strictEqual(REV(c, ocsp('good')).checks[0].status, 'pass');
  const rv = REV(c, ocsp('revoked'));
  assert.deepStrictEqual(rv.caps, ['F']);
  assert.strictEqual(REV(c, ocsp('good', '20200101000000Z')).checks[0].status, 'warn');
});
test('revogação: OCSP sem stapling => informativo; só CRL => passa; nenhum => aviso; autoassinado => ignora', opt, () => {
  const o = cert('ocsp', { extra: ['authorityInfoAccess=OCSP;URI:http://ocsp.exemplo.com'] });
  assert.strictEqual(REV(o, null).checks[0].status, 'info');
  const crl = cert('crl', { extra: ['crlDistributionPoints=URI:http://crl.exemplo.com/a.crl'] });
  assert.strictEqual(REV(crl, null).checks[0].status, 'pass');
  assert.strictEqual(REV(cert('none'), null).checks[0].status, 'warn');
  assert.strictEqual(REV(cert('none'), null, false).checks.length, 0);
});

const none = { s: 'rejected' };
const P = (o = {}) => ({ tls12: true, pfs: { s: 'accepted', cipher: 'ECDHE-X' }, noPfs: none, rc4: none, des3: none, exportNull: none, curves: { X25519: 'accepted', 'P-256': 'accepted', 'P-384': 'rejected' }, alpn: 'h2', ...o });
test('cifras: PFS, cifras fracas, TLS 1.3 apenas e não testável', () => {
  const g = (r, id) => r.checks.find((c) => c.id === id);
  assert.strictEqual(g(X.analyzeCiphers(P()), 'pfs').status, 'pass');
  assert.strictEqual(g(X.analyzeCiphers(P({ noPfs: { s: 'accepted' } })), 'pfs').status, 'warn');
  const np = X.analyzeCiphers(P({ pfs: none }));
  assert.strictEqual(g(np, 'pfs').status, 'fail'); assert.deepStrictEqual(np.caps, ['B']);
  const weak = X.analyzeCiphers(P({ rc4: { s: 'accepted' } }));
  assert.strictEqual(g(weak, 'weakciphers').status, 'fail'); assert.ok(weak.caps.includes('C'));
  assert.strictEqual(g(X.analyzeCiphers(P({ des3: { s: 'accepted' } })), 'weakciphers').status, 'warn');
  assert.strictEqual(g(X.analyzeCiphers(P({ tls12: false })), 'pfs').status, 'pass');
  const unt = { s: 'untestable' };
  assert.strictEqual(g(X.analyzeCiphers(P({ rc4: unt, des3: unt, exportNull: unt })), 'weakciphers').max, 0);
  assert.strictEqual(g(X.analyzeCiphers(P({ alpn: null })), 'http2').status, 'info');
});

test('redirecionamento HTTP→HTTPS: casos', () => {
  const R = (h) => X.analyzeRedirect(h, 'www.exemplo.com.br');
  assert.strictEqual(R({ status: 301, headers: { location: 'https://www.exemplo.com.br/' } }).points, 5);
  assert.strictEqual(R({ status: 302, headers: { location: 'https://exemplo.com.br/' } }).points, 4);
  assert.strictEqual(R({ status: 301, headers: { location: 'http://www.exemplo.com.br/' } }).status, 'fail');
  assert.strictEqual(R({ status: 301, headers: { location: 'https://outro.com/' } }).status, 'warn');
  assert.strictEqual(R({ status: 200, headers: {} }).status, 'fail');
  assert.strictEqual(R({ error: 'ECONNREFUSED' }).status, 'info');
});
test('HSTS: ausente, fraco, forte e elegível a preload', () => {
  const H = (v) => X.analyzeHsts({ status: 200, headers: v ? { 'strict-transport-security': v } : {} }, 'x.com');
  assert.match(H(null).message, /Sem HSTS/);
  assert.strictEqual(H('max-age=300').status, 'warn');
  assert.strictEqual(H('max-age=31536000').status, 'warn'); // sem includeSubDomains
  assert.match(H('max-age=31536000; includeSubDomains').message, /preload/);
  assert.match(H('max-age=63072000; includeSubDomains; preload').message, /elegível/);
  assert.strictEqual(X.analyzeHsts({ error: 'x' }, 'x.com'), null);
});

test('checkTls integrado: servidor local com HTTP→HTTPS e HSTS', opt, async () => {
  const c = cert('srv');
  const hs = https.createServer({ ...c, ALPNProtocols: ['http/1.1'] }, (req, res) => { res.writeHead(200, { 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload', 'alt-svc': 'h3=":443"' }); res.end('ok'); });
  await new Promise((r) => hs.listen(0, '127.0.0.1', r));
  const hp = http.createServer((req, res) => { res.writeHead(301, { location: 'https://localhost/' }); res.end(); });
  await new Promise((r) => hp.listen(0, '127.0.0.1', r));
  try {
    const r = await checkTls('localhost', { port: hs.address().port, httpPort: hp.address().port });
    const g = (id) => r.checks.find((k) => k.id === id);
    assert.strictEqual(g('redirect').status, 'pass');
    assert.match(g('hsts').message, /elegível/);
    assert.strictEqual(g('sigalg').status, 'pass');
    assert.ok(g('pfs') && g('weakciphers'));
    assert.ok(r.details[1].lines.some((l) => /HTTP\/3/.test(l)));
  } finally { hs.close(); hp.close(); }
});
test('checkTls: falha nas sondas avançadas não derruba o relatório', opt, async () => {
  const c = cert('srv2');
  const tlsMod = require('node:tls');
  const s = tlsMod.createServer(c, (k) => k.end());
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  try {
    const boom = async () => { throw new Error('x'); };
    const r = await checkTls('localhost', { port: s.address().port, probes: { ciphers: boom, ocsp: boom, http: boom } });
    assert.ok(r.ok);
    assert.ok(!r.checks.find((k) => k.id === 'pfs'));
  } finally { s.close(); }
});
