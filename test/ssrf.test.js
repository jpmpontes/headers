'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { isBlockedIP, validateUrl, resolvePublic } = require('../src/ssrf');

test('bloqueia IPs privados, loopback, metadata e mapped', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1',
    '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', 'lixo']) {
    assert.ok(isBlockedIP(ip), ip);
  }
});

test('permite IPs públicos', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.ok(!isBlockedIP(ip), ip);
});

test('validateUrl rejeita esquemas, credenciais e portas', () => {
  assert.throws(() => validateUrl('file:///etc/passwd'));
  assert.throws(() => validateUrl('gopher://x'));
  assert.throws(() => validateUrl('http://user:pw@example.com'));
  assert.throws(() => validateUrl('http://example.com:6379'));
  assert.doesNotThrow(() => validateUrl('https://example.com/a?b=1'));
});

test('formas alternativas de localhost são normalizadas e bloqueadas', async () => {
  for (const u of ['http://2130706433/', 'http://0x7f.1/', 'http://127.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/']) {
    await assert.rejects(() => resolvePublic(validateUrl(u).hostname), /bloqueado/i, u);
  }
});
