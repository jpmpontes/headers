'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { checkDns } = require('../src/dnscheck');
const { fakeResolver } = require('./helpers');

const SOA_OK = { nsname: 'ns1.dns.net', hostmaster: 'h.dns.net', serial: 100, refresh: 7200, retry: 3600, expire: 1209600, minttl: 3600 };
const base = (extra = {}) => ({
  'A exemplo.com.br': ['203.0.113.10'],
  'AAAA exemplo.com.br': ['2001:db8::1'],
  'NS exemplo.com.br': ['ns1.dns.net', 'ns2.outro.org'],
  'CAA exemplo.com.br': [{ critical: 0, issue: 'letsencrypt.org' }],
  'A ns1.dns.net': ['9.9.9.9'],
  'A ns2.outro.org': ['1.1.1.1'],
  ...extra,
});
const okQuery = (soaByIp = {}, ttl = 3600) => async (ip, name, type) => {
  if (type === 'SOA') return soaByIp[ip] || SOA_OK;
  return [{ address: '203.0.113.10', ttl }];
};
const run = (table, serverQuery, opts) => checkDns('exemplo.com.br', { resolver: fakeResolver(table, opts), serverQuery });
const get = (r, id) => r.checks.find((c) => c.id === id);

test('NS saudáveis, SOA e TTL corretos, redes diferentes => tudo passa', async () => {
  const r = await run(base(), okQuery());
  for (const id of ['nshealth', 'soa', 'ttl', 'diversity']) assert.strictEqual(get(r, id).status, 'pass', id);
  assert.strictEqual(r.score, 100);
  assert.ok(r.details.some((d) => d.label.includes('servidores de nomes')));
});

test('NS que recusa a zona => aviso com nota parcial', async () => {
  const q = async (ip, name, type) => {
    if (ip === '1.1.1.1') { const e = new Error('x'); e.code = 'EREFUSED'; throw e; }
    return okQuery()(ip, name, type);
  };
  const c = get(await run(base(), q), 'nshealth');
  assert.strictEqual(c.status, 'warn');
  assert.match(c.message, /1 de 2/);
});

test('serial diferente entre NS => dessincronizado', async () => {
  const c = get(await run(base(), okQuery({ '1.1.1.1': { ...SOA_OK, serial: 99 } })), 'nshealth');
  assert.strictEqual(c.status, 'warn');
  assert.match(c.message, /série/);
});

test('timeout em todos => aviso (não falha), sem delegação provada quebrada', async () => {
  const q = async () => { const e = new Error('t'); e.code = 'ETIMEOUT'; throw e; };
  const c = get(await run(base(), q), 'nshealth');
  assert.strictEqual(c.status, 'warn');
});

test('NS com IP privado nunca é consultado (SSRF)', async () => {
  let called = [];
  const q = async (ip, n, t) => { called.push(ip); return okQuery()(ip, n, t); };
  const t = base({ 'A ns1.dns.net': ['10.0.0.5'], 'A ns2.outro.org': ['169.254.169.254'] });
  const r = await run(t, q);
  assert.deepStrictEqual(called, []);
  assert.strictEqual(get(r, 'nshealth').status, 'fail');
});

test('NS sem IP resolvido => item informativo fora da nota', async () => {
  const t = base();
  delete t['A ns1.dns.net']; delete t['A ns2.outro.org'];
  const c = get(await run(t, okQuery()), 'nshealth');
  assert.strictEqual(c.max, 0);
  assert.strictEqual(c.status, 'info');
});

test('SOA e TTL fora do recomendado geram avisos', async () => {
  const bad = { ...SOA_OK, refresh: 300, retry: 600, expire: 1000, minttl: 172800 };
  const r = await run(base(), okQuery({ '9.9.9.9': bad, '1.1.1.1': bad }, 10));
  assert.strictEqual(get(r, 'soa').status, 'warn');
  assert.match(get(r, 'soa').message, /refresh muito curto/);
  assert.match(get(r, 'soa').message, /expire curto/);
  assert.strictEqual(get(r, 'ttl').status, 'warn');
});

test('NS na mesma rede => diversidade baixa', async () => {
  const r = await run(base({ 'A ns2.outro.org': ['9.9.9.10'] }), okQuery());
  assert.strictEqual(get(r, 'diversity').status, 'warn');
});

test('CNAME na raiz (apex) é falha', async () => {
  const r = await run(base({ 'CNAME exemplo.com.br': ['site.hospedagem.com'], 'A site.hospedagem.com': ['203.0.113.50'] }), okQuery());
  const c = get(r, 'cname');
  assert.strictEqual(c.status, 'fail');
  assert.match(c.message, /apex/);
});

test('CNAME para destino inexistente => risco de takeover', async () => {
  const t = base({ 'CNAME app.exemplo.com.br': ['velho.herokuapp.com'], 'A app.exemplo.com.br': undefined });
  delete t['A exemplo.com.br']; delete t['AAAA exemplo.com.br'];
  t['A velho.herokuapp.com'] = 'NXDOMAIN'; t['AAAA velho.herokuapp.com'] = 'NXDOMAIN';
  const r = await checkDns('app.exemplo.com.br', { resolver: fakeResolver(t), serverQuery: okQuery() });
  assert.strictEqual(get(r, 'cname').status, 'fail');
  assert.match(get(r, 'cname').message, /takeover/);
});

test('CNAME para serviço de terceiros que resolve => informativo', async () => {
  const t = base({ 'CNAME blog.exemplo.com.br': ['empresa.github.io'], 'A empresa.github.io': ['185.199.108.153'] });
  const r = await checkDns('blog.exemplo.com.br', { resolver: fakeResolver(t), serverQuery: okQuery() });
  const c = get(r, 'cname');
  assert.strictEqual(c.status, 'info');
  assert.match(c.message, /GitHub Pages/);
});

test('MX apontando para CNAME é avisado', async () => {
  const r = await run(base({ 'MX exemplo.com.br': [{ priority: 10, exchange: 'mail.exemplo.com.br' }], 'CNAME mail.exemplo.com.br': ['smtp.provedor.com'] }), okQuery());
  const c = get(r, 'cname');
  assert.strictEqual(c.status, 'warn');
  assert.match(c.message, /MX/);
});

test('DNSSEC entra na nota do DNS via dohQuery injetado', async () => {
  const dohQuery = async (n, type) => (type === 'DS' ? { Status: 0, Answer: [{ type: 43, data: '1 13 2 AB' }] } : { Status: 0, AD: true });
  const r = await checkDns('exemplo.com.br', { resolver: fakeResolver(base()), serverQuery: okQuery(), dohQuery });
  assert.strictEqual(get(r, 'dnssec').status, 'pass');
  assert.strictEqual(r.score, 100);
});
