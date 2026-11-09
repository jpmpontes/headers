'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const { fakeResolver } = require('./helpers');
const { checkEmail } = require('../src/emailcheck');
const X = require('../src/mailextra');

let hasOpenssl = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { hasOpenssl = false; }

// ---- servidor SMTP falso (STARTTLS opcional) ----
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'coreva-smtp-'));
function cert() {
  const key = path.join(dir, 'k.pem'); const crt = path.join(dir, 'c.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '30', '-subj', '/CN=mx.exemplo.com.br', '-addext', 'subjectAltName=DNS:mx.exemplo.com.br'], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}
const servers = [];
function smtpServer({ starttls }) {
  const creds = starttls && hasOpenssl ? cert() : null;
  return new Promise((res) => {
    const s = net.createServer((sock) => {
      sock.write('220 mx.exemplo.com.br ESMTP pronto\r\n');
      sock.on('data', (d) => {
        const cmd = d.toString().trim().toUpperCase();
        if (cmd.startsWith('EHLO')) sock.write(`250-mx.exemplo.com.br\r\n${starttls ? '250-STARTTLS\r\n' : ''}250 8BITMIME\r\n`);
        else if (cmd === 'STARTTLS') {
          sock.write('220 vai\r\n');
          sock.removeAllListeners('data');
          new tls.TLSSocket(sock, { isServer: true, ...creds }).on('error', () => {});
        } else if (cmd === 'QUIT') sock.end('221 tchau\r\n');
      });
      sock.on('error', () => {});
    }).listen(0, '127.0.0.1', () => { servers.push(s); res(s.address().port); });
  });
}
test.after(() => servers.forEach((s) => s.close()));

test('sonda SMTP: STARTTLS com TLS 1.2+ e certificado (autoassinado => não confiável)', { skip: !hasOpenssl }, async () => {
  const port = await smtpServer({ starttls: true });
  const r = await X.smtpProbe('mx.exemplo.com.br', '127.0.0.1', port);
  assert.ok(r.reachable && r.starttls);
  assert.match(r.protocol, /TLSv1\.[23]/);
  assert.strictEqual(r.cert.hostOk, true);
  assert.strictEqual(r.cert.trusted, false);
});
test('sonda SMTP: servidor sem STARTTLS; porta fechada', async () => {
  const port = await smtpServer({ starttls: false });
  const r = await X.smtpProbe('mx.exemplo.com.br', '127.0.0.1', port);
  assert.ok(r.reachable); assert.strictEqual(r.starttls, false);
  const c = await X.smtpProbe('mx.exemplo.com.br', '127.0.0.1', 1);
  assert.strictEqual(c.reachable, false);
});

// ---- tabela DNS base: domínio com MX, SPF e DMARC ----
const base = (extra = {}) => ({
  'MX exemplo.com.br': [{ priority: 10, exchange: 'mx.exemplo.com.br' }],
  'TXT exemplo.com.br': ['v=spf1 mx -all'],
  'TXT _dmarc.exemplo.com.br': ['v=DMARC1; p=reject; rua=mailto:dmarc@exemplo.com.br'],
  'A mx.exemplo.com.br': ['8.8.4.4'],
  ...extra,
});
const probeOk = (over = {}) => async (host, ip) => ({ host, ip, reachable: true, starttls: true, protocol: 'TLSv1.3', banner: '220 x', error: null, cert: { subject: host, trusted: true, hostOk: true, daysLeft: 60, authError: null }, ...over });
const run = (t, o = {}) => checkEmail('exemplo.com.br', { resolver: fakeResolver(t), smtpProbe: probeOk(), ...o });
const get = (r, id) => r.checks.find((c) => c.id === id);

test('STARTTLS ok e certificado válido => passam; detalhes da conexão', async () => {
  const r = await run(base());
  assert.strictEqual(get(r, 'starttls').status, 'pass');
  assert.strictEqual(get(r, 'mxcert').status, 'pass');
  assert.ok(r.details.some((d) => d.label.includes('porta 25')));
});
test('MX sem STARTTLS => falha; TLS 1.0 => aviso; certificado inválido => aviso', async () => {
  assert.strictEqual(get(await run(base(), { smtpProbe: probeOk({ starttls: false, protocol: null, cert: null }) }), 'starttls').status, 'fail');
  assert.strictEqual(get(await run(base(), { smtpProbe: probeOk({ protocol: 'TLSv1' }) }), 'starttls').status, 'warn');
  const r = await run(base(), { smtpProbe: probeOk({ cert: { subject: 'x', trusted: false, hostOk: false, daysLeft: 5, authError: 'SELF_SIGNED' } }) });
  assert.strictEqual(get(r, 'mxcert').status, 'warn');
});
test('MX inacessível na porta 25 => itens de STARTTLS ficam de fora (sem penalizar)', async () => {
  const before = await run(base(), { smtpProbe: async (host, ip) => ({ host, ip, reachable: false, error: 'ETIMEDOUT' }) });
  assert.strictEqual(get(before, 'starttls'), undefined);
});
test('MX com IP privado nunca é sondado (SSRF)', async () => {
  let called = 0;
  await run(base({ 'A mx.exemplo.com.br': ['10.1.2.3'] }), { smtpProbe: async () => { called++; return {}; } });
  assert.strictEqual(called, 0);
});

const policy = (txt, over = {}) => async () => ({ status: 200, type: 'text/plain', body: txt, ...over });
const POL = 'version: STSv1\nmode: enforce\nmx: mx.exemplo.com.br\nmax_age: 604800\n';
const withSts = (extra = {}) => base({ 'TXT _mta-sts.exemplo.com.br': ['v=STSv1; id=1'], ...extra });
test('MTA-STS: política enforce cobrindo o MX => passa', async () => {
  assert.strictEqual(get(await run(withSts(), { fetchPolicy: policy(POL) }), 'mtastspol').status, 'pass');
});
test('MTA-STS: modo testing, MX não coberto, HTTP 404 e erro de rede', async () => {
  assert.strictEqual(get(await run(withSts(), { fetchPolicy: policy(POL.replace('enforce', 'testing')) }), 'mtastspol').status, 'warn');
  const unc = get(await run(withSts(), { fetchPolicy: policy(POL.replace('mx.exemplo.com.br', '*.outro.com')) }), 'mtastspol');
  assert.strictEqual(unc.status, 'fail'); assert.match(unc.message, /não estão cobertos/);
  assert.strictEqual(get(await run(withSts(), { fetchPolicy: policy('', { status: 404 }) }), 'mtastspol').status, 'warn');
  assert.match(get(await run(withSts(), { fetchPolicy: async () => ({ error: 'CERT_HAS_EXPIRED' }) }), 'mtastspol').message, /CERT_HAS_EXPIRED/);
});
test('MTA-STS: curinga *.dominio cobre subdomínio de um nível', () => {
  assert.strictEqual(X.checkMtaStsPolicy({ status: 200, body: 'version: STSv1\nmode: enforce\nmx: *.exemplo.com.br\nmax_age: 604800' }, ['mx.exemplo.com.br'], 'exemplo.com.br').status, 'pass');
});

test('DMARC: relatório para domínio externo sem autorização => aviso; com autorização => ok', async () => {
  const t = base({ 'TXT _dmarc.exemplo.com.br': ['v=DMARC1; p=reject; rua=mailto:r@terceiro.com'] });
  assert.strictEqual(get(await run(t), 'dmarcrep').status, 'warn');
  t['TXT exemplo.com.br._report._dmarc.terceiro.com'] = ['v=DMARC1'];
  assert.strictEqual(get(await run(t), 'dmarcrep').status, 'pass');
  const bad = base({ 'TXT _dmarc.exemplo.com.br': ['v=DMARC1; p=none; rua=http://x'] });
  assert.match(get(await run(bad), 'dmarcrep').message, /mailto/);
});
test('BIMI: exige DMARC enforce e SVG https', async () => {
  const ok = await run(base({ 'TXT default._bimi.exemplo.com.br': ['v=BIMI1; l=https://exemplo.com.br/logo.svg'] }));
  assert.strictEqual(get(ok, 'bimi').status, 'pass');
  const weak = await run(base({ 'TXT default._bimi.exemplo.com.br': ['v=BIMI1; l=http://x/logo.png'], 'TXT _dmarc.exemplo.com.br': ['v=DMARC1; p=none'] }));
  assert.strictEqual(get(weak, 'bimi').status, 'warn');
  assert.strictEqual(get(await run(base()), 'bimi').status, 'info');
});
test('DANE: TLSA com DNSSEC válido => passa; sem DNSSEC => aviso', async () => {
  const t = base({ 'TLSA _25._tcp.mx.exemplo.com.br': [{ usage: 3 }] });
  const doh = (ad) => async (n, type) => (type === 'DS' ? { Status: 0, Answer: [{ type: 43, data: '1 13 2 AB' }] } : { Status: 0, AD: ad });
  assert.strictEqual(get(await run(t, { dohQuery: doh(true) }), 'dane').status, 'pass');
  assert.strictEqual(get(await run(t, { dohQuery: doh(false) }), 'dane').status, 'warn');
  assert.strictEqual(get(await run(base()), 'dane').status, 'info');
});
test('DNS reverso dos MX: forward-confirmed ok; ausente => aviso', async () => {
  const ok = await run(base({ 'PTR 8.8.4.4': ['mx.exemplo.com.br'] }));
  assert.strictEqual(get(ok, 'mxrdns').status, 'pass');
  assert.strictEqual(get(await run(base()), 'mxrdns').status, 'warn');
});
test('domínio sem e-mail: nenhuma verificação avançada é feita', async () => {
  const r = await checkEmail('exemplo.com.br', { resolver: fakeResolver({ 'MX exemplo.com.br': [{ priority: 0, exchange: '' }], 'TXT exemplo.com.br': ['v=spf1 -all'] }), smtpProbe: async () => assert.fail('não deveria sondar') });
  for (const id of ['starttls', 'bimi', 'dane', 'mxrdns']) assert.strictEqual(get(r, id), undefined);
});
