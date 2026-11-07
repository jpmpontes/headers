'use strict';
// Faz a requisição seguindo redirects manualmente, revalidando cada salto (SSRF).
// Não lê o corpo da resposta: só os headers, e fecha a conexão.
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { validateUrl, resolvePublic } = require('./ssrf');

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8000;
const UA = 'CorevaHeadersScanner/0.1';

function requestOnce(u, addr) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const req = lib.request({
      hostname: host,
      port: u.port || undefined,
      path: u.pathname + u.search,
      method: 'GET',
      servername: net.isIP(host) ? undefined : host, // SNI correto mesmo com IP fixado
      headers: { 'User-Agent': UA, Accept: '*/*', 'Accept-Encoding': 'identity' },
      lookup: (_h, opts, cb) => (opts && opts.all
        ? cb(null, [{ address: addr.address, family: addr.family }])
        : cb(null, addr.address, addr.family)),
    });
    const timer = setTimeout(() => req.destroy(new Error('Tempo esgotado (8s)')), TIMEOUT_MS);
    req.on('response', (res) => {
      clearTimeout(timer);
      const out = { status: res.statusCode, headers: res.headers };
      res.destroy();
      resolve(out);
    });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

async function fetchHeaders(rawUrl) {
  let u = validateUrl(rawUrl);
  const chain = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const addr = await resolvePublic(u.hostname);
    let res;
    try { res = await requestOnce(u, addr); }
    catch (e) {
      const code = e.code ? ` (${e.code})` : '';
      throw new Error(`Falha ao conectar em ${u.host}: ${e.message}${code}`);
    }
    chain.push({ url: u.href, status: res.status });
    const loc = res.headers.location;
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      if (i === MAX_REDIRECTS) throw new Error('Redirects demais (limite 5)');
      u = validateUrl(new URL(loc, u).href); // revalida o próximo destino
      continue;
    }
    return { finalUrl: u.href, status: res.status, headers: res.headers, chain };
  }
  throw new Error('Redirects demais');
}

module.exports = { fetchHeaders };
