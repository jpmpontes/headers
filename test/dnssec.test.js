'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { checkDnssec } = require('../src/dnssec');
require('./helpers');

const DS13 = { type: 43, data: '2371 13 2 ABCDEF' };
const KEY = { type: 48, data: '257 3 13 AAAA' };
// doh simulado: respostas por tipo; cd=true usa a chave "CD"
const doh = (m) => async (name, type, o = {}) => {
  const r = m[o.cd ? 'CD' : type];
  if (r === 'ERR') throw new Error('rede');
  return r || { Status: 0 };
};

test('DS + AD => passa', async () => {
  const c = await checkDnssec('www.exemplo.com.br', { dohQuery: doh({ DS: { Status: 0, Answer: [DS13] }, DNSKEY: { Status: 0, Answer: [KEY] }, A: { Status: 0, AD: true } }) });
  assert.strictEqual(c.status, 'pass');
  assert.strictEqual(c.points, 15);
});
test('sem DS e sem chave => não assinado (aviso)', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 0 } }) });
  assert.strictEqual(c.status, 'warn'); assert.strictEqual(c.points, 0); assert.match(c.message, /não está ativo/);
});
test('chave sem DS => cadeia incompleta', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 0 }, DNSKEY: { Status: 0, Answer: [KEY] } }) });
  assert.match(c.message, /incompleta/);
});
test('SERVFAIL que funciona com CD => DNSSEC quebrado (falha)', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 2 }, CD: { Status: 0 } }) });
  assert.strictEqual(c.status, 'fail'); assert.strictEqual(c.points, 0); assert.match(c.message, /quebrado/);
});
test('SERVFAIL também com CD => não testável, fora da nota', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 2 }, CD: { Status: 2 } }) });
  assert.strictEqual(c.max, 0); assert.strictEqual(c.status, 'info');
});
test('DS sem AD => não validou', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 0, Answer: [DS13] }, A: { Status: 0, AD: false } }) });
  assert.strictEqual(c.status, 'warn'); assert.match(c.message, /AD/);
});
test('algoritmo RSASHA1 => defasado; digest só SHA-1 => aviso', async () => {
  const a = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 0, Answer: [{ type: 43, data: '1 5 2 AB' }] }, A: { Status: 0, AD: true } }) });
  assert.match(a.message, /defasado/);
  const b = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: { Status: 0, Answer: [{ type: 43, data: '1 13 1 AB' }] }, A: { Status: 0, AD: true } }) });
  assert.match(b.message, /SHA-1/);
});
test('DoH indisponível => fora da nota; padrão desativado em testes', async () => {
  const c = await checkDnssec('exemplo.com.br', { dohQuery: doh({ DS: 'ERR' }) });
  assert.strictEqual(c.max, 0);
  const d = await checkDnssec('exemplo.com.br');
  assert.strictEqual(d.max, 0);
});
