'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { checkEmail, analyzeSpf } = require('../src/emailcheck');
const { fakeResolver } = require('./helpers');

const byId = (r, id) => r.checks.find((c) => c.id === id);
const pub = (bits) => crypto.generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const MX = [{ exchange: 'mx.example.net', priority: 10 }];
const DMARC_OK = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com';

test('configuração forte: SPF -all, DMARC reject, DKIM 2048 => 100', async () => {
  const r = fakeResolver({
    'MX example.com': MX,
    'TXT example.com': ['v=spf1 include:_spf.prov.example -all', 'google-site-verification=abc'],
    'TXT _spf.prov.example': ['v=spf1 ip4:203.0.113.0/24 ~all'],
    'TXT _dmarc.example.com': [DMARC_OK],
    'TXT google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${pub(2048)}`],
    'TXT _mta-sts.example.com': ['v=STSv1; id=1'],
  });
  const res = await checkEmail('example.com', { resolver: r });
  assert.strictEqual(byId(res, 'spf').status, 'pass');
  assert.strictEqual(byId(res, 'dmarc').status, 'pass');
  assert.strictEqual(byId(res, 'dkim').status, 'pass');
  assert.match(byId(res, 'dkim').value, /rsa 2048 bits/);
  assert.strictEqual(byId(res, 'mtasts').status, 'pass');
  assert.strictEqual(res.score, 100);
  assert.strictEqual(res.grade, 'A+');
});

test('sem SPF/DMARC: nota F; DKIM ausente é só informativo e fora da nota', async () => {
  const res = await checkEmail('example.com', { resolver: fakeResolver({ 'MX example.com': MX }) });
  assert.strictEqual(byId(res, 'spf').status, 'fail');
  assert.strictEqual(byId(res, 'dmarc').status, 'fail');
  assert.strictEqual(byId(res, 'dkim').status, 'info');
  assert.strictEqual(byId(res, 'dkim').max, 0);
  assert.strictEqual(res.score, 0);
  assert.strictEqual(res.grade, 'F');
});

test('SPF: +all falha, ~all avisa, múltiplos registros falham', async () => {
  const mk = (spf) => checkEmail('example.com', { resolver: fakeResolver({ 'MX example.com': MX, 'TXT example.com': spf }) });
  assert.strictEqual(byId(await mk(['v=spf1 +all']), 'spf').status, 'fail');
  assert.strictEqual(byId(await mk(['v=spf1 all']), 'spf').status, 'fail');
  const soft = byId(await mk(['v=spf1 mx ~all']), 'spf');
  assert.strictEqual(soft.status, 'warn');
  assert.strictEqual(soft.points, 22);
  assert.strictEqual(byId(await mk(['v=spf1 -all', 'v=spf1 mx -all']), 'spf').status, 'fail');
  assert.strictEqual(byId(await mk(['v=spf1 mx']), 'spf').status, 'warn');
});

test('SPF: mais de 10 consultas DNS é erro (permerror)', async () => {
  const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.prov.example`).join(' ');
  const table = { 'MX example.com': MX, 'TXT example.com': [`v=spf1 ${includes} -all`] };
  for (let i = 0; i < 11; i++) table[`TXT i${i}.prov.example`] = ['v=spf1 -all'];
  const spf = byId(await checkEmail('example.com', { resolver: fakeResolver(table) }), 'spf');
  assert.strictEqual(spf.status, 'fail');
  assert.match(spf.message, /10 consultas/);
});

test('analyzeSpf: contagem correta, proteção contra loop e limite de consultas', async () => {
  const get = (m) => async (n) => m[n] || [];
  const a = await analyzeSpf('a.example', get({ 'a.example': ['v=spf1 a mx include:b.example -all'], 'b.example': ['v=spf1 ip4:1.2.3.4 -all'] }));
  assert.strictEqual(a.lookups, 3);
  const loop = await analyzeSpf('a.example', get({ 'a.example': ['v=spf1 include:a.example -all'] }));
  assert.ok(loop.lookups <= 2);
  // cadeia profunda: o limite de profundidade (10) encerra a busca
  const m = {};
  for (let i = 0; i < 60; i++) m[`n${i}.x`] = [`v=spf1 include:n${i + 1}.x -all`];
  const deep = await analyzeSpf('n0.x', get(m));
  assert.ok(deep.queries <= 11 && deep.lookups > 10);
  // muitos include lado a lado: o teto de 25 consultas encerra a busca
  const wide = { 'w.x': [`v=spf1 ${Array.from({ length: 40 }, (_, i) => `include:c${i}.x`).join(' ')} -all`] };
  for (let i = 0; i < 40; i++) wide[`c${i}.x`] = ['v=spf1 -all'];
  const fan = await analyzeSpf('w.x', get(wide));
  assert.ok(fan.truncated && fan.queries === 25 && fan.lookups > 10);
});

test('DMARC: p=none avisa; pct<100 e sp mais fraco reduzem a nota', async () => {
  const mk = (d) => checkEmail('example.com', { resolver: fakeResolver({ 'MX example.com': MX, 'TXT example.com': ['v=spf1 -all'], 'TXT _dmarc.example.com': [d] }) });
  const none = byId(await mk('v=DMARC1; p=none; rua=mailto:a@example.com'), 'dmarc');
  assert.strictEqual(none.status, 'warn');
  assert.strictEqual(none.points, 12);
  const pct = byId(await mk('v=DMARC1; p=quarantine; pct=50; rua=mailto:a@example.com'), 'dmarc');
  assert.strictEqual(pct.status, 'warn');
  assert.ok(pct.points < 28);
  const sp = byId(await mk('v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com'), 'dmarc');
  assert.match(sp.message, /subdomínios/);
  const norua = byId(await mk('v=DMARC1; p=reject'), 'dmarc');
  assert.strictEqual(norua.points, 32);
  const dup = byId(await mk('v=DMARC1; p=reject').then(() => checkEmail('example.com', { resolver: fakeResolver({ 'MX example.com': MX, 'TXT _dmarc.example.com': [DMARC_OK, DMARC_OK] }) })), 'dmarc');
  assert.strictEqual(dup.status, 'fail');
});

test('DKIM: seletor informado pelo usuário, chave fraca (1024) e chave revogada', async () => {
  const base = { 'MX example.com': MX };
  const custom = await checkEmail('example.com', { dkim: 'meusel', resolver: fakeResolver({ ...base, 'TXT meusel._domainkey.example.com': [`v=DKIM1; p=${pub(2048)}`] }) });
  assert.strictEqual(byId(custom, 'dkim').status, 'pass');
  const weak = await checkEmail('example.com', { resolver: fakeResolver({ ...base, 'TXT selector1._domainkey.example.com': [`v=DKIM1; p=${pub(1024)}`] }) });
  assert.strictEqual(byId(weak, 'dkim').status, 'warn');
  assert.match(byId(weak, 'dkim').message, /1024 bits/);
  const revoked = await checkEmail('example.com', { resolver: fakeResolver({ ...base, 'TXT k1._domainkey.example.com': ['v=DKIM1; p='] }) });
  assert.match(byId(revoked, 'dkim').message, /revogada/);
});

test('domínio sem e-mail (null MX): orienta SPF -all e DMARC reject', async () => {
  const r = fakeResolver({ 'MX example.com': [{ exchange: '', priority: 0 }], 'TXT example.com': ['v=spf1 -all'], 'TXT _dmarc.example.com': [DMARC_OK] });
  const res = await checkEmail('example.com', { resolver: r });
  assert.match(byId(res, 'mx').message, /não recebe e-mail/);
  assert.strictEqual(res.score, 100);
});

test('usa o domínio registrável (www.x.com.br -> x.com.br) e detecta NXDOMAIN', async () => {
  const r = fakeResolver({ 'MX corevatech.com.br': MX, 'TXT corevatech.com.br': ['v=spf1 -all'] });
  const res = await checkEmail('www.corevatech.com.br', { resolver: r });
  assert.match(res.details[0].lines[0], /corevatech\.com\.br/);
  await assert.rejects(() => checkEmail('naoexiste.example', { resolver: fakeResolver({}, { nxdomain: true }) }), /NXDOMAIN/);
});
