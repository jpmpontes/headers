'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyze, parseCSP } = require('../src/scanner');

const GOOD = {
  'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  server: 'cloudflare',
};

test('site bem configurado recebe A+', () => {
  const r = analyze(GOOD, 'https://ok.example/');
  assert.strictEqual(r.grade, 'A+');
  assert.ok(r.score >= 95);
});

test('site sem headers recebe F', () => {
  const r = analyze({}, 'https://nada.example/');
  assert.strictEqual(r.grade, 'F');
});

test('sem CSP a nota fica limitada a B', () => {
  const { 'content-security-policy': _, ...h } = GOOD;
  const r = analyze({ ...h, 'x-frame-options': 'DENY' }, 'https://x.example/');
  assert.ok(['B', 'C', 'D', 'E', 'F'].includes(r.grade), r.grade);
});

test('HTTP puro é limitado a D e HSTS não se aplica', () => {
  const r = analyze(GOOD, 'http://inseguro.example/');
  assert.ok(['D', 'E', 'F'].includes(r.grade), r.grade);
  assert.strictEqual(r.checks.find((c) => c.id === 'hsts').points, 0);
});

test('CSP com unsafe-inline é penalizada', () => {
  const r = analyze({ ...GOOD, 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'" }, 'https://x.example/');
  const csp = r.checks.find((c) => c.id === 'csp');
  assert.strictEqual(csp.status, 'warn');
  assert.ok(csp.points < 25);
});

test('cookies sem flags e vazamento de versão', () => {
  const r = analyze({ ...GOOD, 'set-cookie': ['sid=1; Path=/'], 'x-powered-by': 'Express', server: 'nginx/1.18.0' }, 'https://x.example/');
  assert.strictEqual(r.checks.find((c) => c.id === 'cookies').status, 'warn');
  assert.strictEqual(r.checks.find((c) => c.id === 'leak').status, 'warn');
});

test('parseCSP', () => {
  assert.deepStrictEqual(parseCSP("default-src 'self'; img-src a b"), { 'default-src': ["'self'"], 'img-src': ['a', 'b'] });
});
