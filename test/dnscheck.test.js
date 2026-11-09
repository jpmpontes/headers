'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { checkDns } = require('../src/dnscheck');
const { registrable, climb } = require('../src/common');
const { fakeResolver } = require('./helpers');

const byId = (r, id) => r.checks.find((c) => c.id === id);

test('registrable e climb cobrem .com.br e domínios simples', () => {
  assert.strictEqual(registrable('www.corevatech.com.br'), 'corevatech.com.br');
  assert.strictEqual(registrable('corevatech.com.br'), 'corevatech.com.br');
  assert.strictEqual(registrable('a.b.example.com'), 'example.com');
  assert.strictEqual(registrable('localhost'), 'localhost');
  assert.deepStrictEqual(climb('a.b.example.com'), ['a.b.example.com', 'b.example.com', 'example.com']);
});

test('domínio bem configurado: nota máxima', async () => {
  const r = fakeResolver({
    'NS example.com': ['ns1.dns.example', 'ns2.dns.example'],
    'A example.com': ['203.0.113.10'],
    'AAAA example.com': ['2001:db8::10'],
    'CAA example.com': [{ critical: 0, issue: 'letsencrypt.org' }],
  });
  const res = await checkDns('example.com', { resolver: r });
  assert.strictEqual(res.score, 100);
  assert.strictEqual(res.grade, 'A+');
  assert.strictEqual(byId(res, 'caa').status, 'pass');
});

test('configuração mínima: 1 NS, só IPv4, sem CAA', async () => {
  const r = fakeResolver({ 'NS example.com': ['ns1.dns.example'], 'A example.com': ['203.0.113.10'] });
  const res = await checkDns('example.com', { resolver: r });
  assert.strictEqual(byId(res, 'ns').status, 'warn');
  assert.strictEqual(byId(res, 'ipv6').status, 'warn');
  assert.strictEqual(byId(res, 'caa').status, 'warn');
  assert.strictEqual(res.score, 56);
});

test('CAA é herdado do domínio pai (subida de árvore) e NS vem da zona', async () => {
  const r = fakeResolver({
    'NS corevatech.com.br': ['a.ns', 'b.ns'],
    'A www.corevatech.com.br': ['203.0.113.1'],
    'CAA corevatech.com.br': [{ critical: 0, issue: 'digicert.com' }],
  });
  const res = await checkDns('www.corevatech.com.br', { resolver: r });
  assert.strictEqual(byId(res, 'ns').status, 'pass');
  assert.strictEqual(byId(res, 'caa').status, 'pass');
  assert.match(byId(res, 'caa').message, /corevatech\.com\.br/);
});

test('NXDOMAIN gera erro; falha de DNS gera erro; apenas IPv6 gera aviso', async () => {
  await assert.rejects(() => checkDns('naoexiste.example', { resolver: fakeResolver({}, { nxdomain: true }) }), /NXDOMAIN/);
  await assert.rejects(() => checkDns('x.example', {
    resolver: fakeResolver({ 'NS x.example': 'SERVFAIL', 'A x.example': 'SERVFAIL', 'AAAA x.example': 'SERVFAIL', 'CNAME x.example': 'SERVFAIL' }),
  }), /Falha ao consultar o DNS/);
  const res = await checkDns('v6.example', { resolver: fakeResolver({ 'NS v6.example': ['a', 'b'], 'AAAA v6.example': ['2001:db8::1'] }) });
  assert.strictEqual(byId(res, 'addr').status, 'warn');
});
