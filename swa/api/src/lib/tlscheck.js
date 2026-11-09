'use strict';
// Verificação do certificado e da configuração TLS (porta 443).
// SSRF: os IPs são resolvidos e validados por resolveAllPublic(), e a conexão vai direto para um desses IPs.
const tls = require('node:tls');
const net = require('node:net');
const { X509Certificate } = require('node:crypto');
const { resolveAllPublic } = require('./ssrf');
const { mk, finish } = require('./common');
const X = require('./tlsextra');

const TIMEOUT_MS = 6000;
const MAX_ADDRS = 4;

function connectOnce(addr, host, port, extra = {}) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({
      host: addr.address, port,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false, // queremos inspecionar mesmo certificados inválidos
      ...extra,
    });
    const timer = setTimeout(() => sock.destroy(new Error('Tempo esgotado na conexão TLS')), TIMEOUT_MS);
    sock.once('secureConnect', () => { clearTimeout(timer); resolve(sock); });
    sock.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function collect(sock, host) {
  const info = {
    protocol: sock.getProtocol(),
    cipher: (sock.getCipher() || {}).name || null,
    authorized: sock.authorized,
    authError: sock.authorizationError ? String(sock.authorizationError.code || sock.authorizationError) : null,
    cert: null,
  };
  const peer = sock.getPeerCertificate(true);
  info.chain = [];
  for (let c = peer, seen = new Set(); c && c.raw && !seen.has(c.fingerprint256); c = c.issuerCertificate) { seen.add(c.fingerprint256); info.chain.push(c.raw); }
  if (peer && peer.raw) {
    const x = new X509Certificate(peer.raw);
    const pk = x.publicKey;
    const det = pk.asymmetricKeyDetails || {};
    const cn = /CN=([^\n]+)/.exec(x.subject);
    info.cert = {
      subjectCN: cn ? cn[1] : null,
      issuer: x.issuer.replace(/\n/g, ', '),
      validFrom: new Date(x.validFrom),
      validTo: new Date(x.validTo),
      sans: (x.subjectAltName || '').split(',').map((s) => s.trim()).filter(Boolean),
      keyType: pk.asymmetricKeyType,
      keyBits: det.modulusLength || null,
      curve: det.namedCurve || null,
      hostMatch: net.isIP(host) ? Boolean(x.checkIP(host)) : Boolean(x.checkHost(host)),
      fingerprint: x.fingerprint256,
    };
  }
  return info;
}

const AUTH_MSG = {
  DEPTH_ZERO_SELF_SIGNED_CERT: ['O certificado é autoassinado: navegadores mostram aviso de segurança.', 'Use um certificado de uma autoridade pública (ex.: Let\'s Encrypt, gratuito).'],
  SELF_SIGNED_CERT_IN_CHAIN: ['A cadeia termina em uma raiz não confiável (autoassinada).', 'Use um certificado emitido por uma autoridade pública.'],
  CERT_HAS_EXPIRED: ['O certificado está expirado.', 'Renove o certificado imediatamente e automatize a renovação.'],
  CERT_NOT_YET_VALID: ['O certificado ainda não é válido (data de início no futuro).', 'Confira a data do servidor e a emissão do certificado.'],
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: ['Cadeia incompleta: falta o certificado intermediário. Alguns navegadores e apps vão recusar a conexão.', 'Configure o servidor para enviar a cadeia completa (fullchain.pem), não só o certificado do site.'],
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: ['Cadeia incompleta ou emissor desconhecido.', 'Configure o servidor para enviar a cadeia completa (fullchain.pem).'],
};
const EC_OK = new Set(['prime256v1', 'secp384r1', 'secp521r1']);

// Tenta TLS 1.0/1.1 (obsoletos). Alguns clientes modernos não conseguem nem iniciar esse handshake: nesse caso, "untestable".
async function probeLegacy(addr, host, port) {
  try {
    const s = await connectOnce(addr, host, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' });
    s.destroy();
    return 'accepted';
  } catch (e) {
    const text = `${e.code || ''} ${e.message || ''}`;
    if (/NO_PROTOCOLS_AVAILABLE|INVALID_PROTOCOL|no protocols available|Tempo esgotado/i.test(text)) return 'untestable';
    return 'rejected';
  }
}

async function checkTls(host, { port = 443, now = Date.now(), httpPort = 80, probes = {} } = {}) {
  const addrs = (await resolveAllPublic(host)).slice(0, MAX_ADDRS); // bloqueia IPs privados/locais (SSRF)
  let sock = null;
  let used = null;
  let lastErr = null;
  for (const addr of addrs) {
    try { sock = await connectOnce(addr, host, port); used = addr; break; } catch (e) { lastErr = e; }
  }
  if (!sock) {
    throw new Error(`Não foi possível estabelecer conexão TLS com ${host}:${port} (${lastErr.code || lastErr.message}). O site pode não usar HTTPS, ou aceitar apenas protocolos antigos (TLS 1.0/1.1).`);
  }
  const info = collect(sock, host);
  sock.destroy();

  const supports = (v) => connectOnce(used, host, port, { minVersion: v, maxVersion: v }).then((s) => { s.destroy(); return true; }, () => false);
  const [tls12, tls13, legacy] = await Promise.all([supports('TLSv1.2'), supports('TLSv1.3'), probeLegacy(used, host, port)]);
  // sondas avançadas (cifras, OCSP, HTTP). Cada uma é isolada: se falhar, o item simplesmente não aparece.
  const safe = (fn) => Promise.resolve().then(fn).catch(() => null);
  const [cipherProbe, staple, httpRes, httpsRes] = await Promise.all([
    safe(() => (probes.ciphers || X.probeCiphers)(used, host, port, tls12)),
    safe(() => (probes.ocsp || X.probeOcsp)(used, host, port)),
    safe(() => (probes.http || X.httpGet)({ secure: false, addr: used, host, port: httpPort })),
    safe(() => (probes.http || X.httpGet)({ secure: true, addr: used, host, port })),
  ]);

  const c = info.cert;
  const checks = [];
  const caps = [];
  const fmt = (d) => d.toLocaleDateString('pt-BR', { timeZone: 'UTC' });

  // 1. Confiança na cadeia (erro de nome é tratado no item "hostname")
  if (info.authorized || info.authError === 'ERR_TLS_CERT_ALTNAME_INVALID') checks.push(mk('trust', 'Certificado confiável', 25, 25, 'pass', 'Cadeia válida, emitida por uma autoridade confiável.'));
  else {
    const [msg, fix] = AUTH_MSG[info.authError] || [`Falha na validação do certificado (${info.authError}).`, 'Verifique o certificado e a cadeia no servidor.'];
    checks.push(mk('trust', 'Certificado confiável', 25, 0, 'fail', msg, fix));
    caps.push('D');
  }

  if (c) {
    // 2. Nome
    if (c.hostMatch) checks.push(mk('hostname', 'Nome no certificado', 15, 15, 'pass', 'O certificado é válido para este endereço.', null, c.sans.join(', ') || c.subjectCN));
    else {
      checks.push(mk('hostname', 'Nome no certificado', 15, 0, 'fail', `O certificado não cobre "${host}". Nomes no certificado: ${c.sans.join(', ') || c.subjectCN || '-'}.`, 'Emita um certificado que inclua este nome (SAN).'));
      caps.push('D');
    }

    // 3. Validade
    const days = Math.floor((c.validTo.getTime() - now) / 86400000);
    const period = `${fmt(c.validFrom)} a ${fmt(c.validTo)}`;
    if (days < 0) { checks.push(mk('expiry', 'Validade', 20, 0, 'fail', `Certificado expirado há ${-days} dia(s) (em ${fmt(c.validTo)}).`, 'Renove o certificado imediatamente.', period)); caps.push('F'); }
    else if (days < 7) checks.push(mk('expiry', 'Validade', 20, 4, 'fail', `Expira em ${days} dias (${fmt(c.validTo)}).`, 'Renove agora e automatize a renovação (ACME/certbot).', period));
    else if (days < 15) checks.push(mk('expiry', 'Validade', 20, 10, 'warn', `Expira em ${days} dias (${fmt(c.validTo)}).`, 'Renove em breve e automatize a renovação.', period));
    else if (days < 30) checks.push(mk('expiry', 'Validade', 20, 15, 'warn', `Expira em ${days} dias (${fmt(c.validTo)}).`, 'Confirme que a renovação automática está funcionando.', period));
    else checks.push(mk('expiry', 'Validade', 20, 20, 'pass', `Válido por mais ${days} dias (até ${fmt(c.validTo)}).`, null, period));

    // 4. Chave pública
    const bits = c.keyBits;
    if (c.keyType === 'rsa') {
      checks.push(bits >= 2048
        ? mk('key', 'Chave pública', 10, 10, 'pass', 'Chave RSA com tamanho adequado.', null, `RSA ${bits} bits`)
        : mk('key', 'Chave pública', 10, 0, 'fail', `Chave RSA de ${bits} bits é fraca.`, 'Gere um novo certificado com RSA de 2048 bits ou mais (ou ECDSA P-256).', `RSA ${bits} bits`));
    } else if (c.keyType === 'ec') {
      checks.push(EC_OK.has(c.curve)
        ? mk('key', 'Chave pública', 10, 10, 'pass', 'Chave ECDSA com curva adequada.', null, `ECDSA ${c.curve}`)
        : mk('key', 'Chave pública', 10, 6, 'warn', 'Curva elíptica incomum.', null, `ECDSA ${c.curve}`));
    } else checks.push(mk('key', 'Chave pública', 10, 6, 'warn', `Tipo de chave: ${c.keyType}.`, null, c.keyType));
  }

  // 5. Protocolos
  checks.push(tls13
    ? mk('tls13', 'TLS 1.3', 10, 10, 'pass', 'Suporta TLS 1.3.')
    : mk('tls13', 'TLS 1.3', 10, 0, 'warn', 'Não suporta TLS 1.3 (mais rápido e seguro).', 'Habilite TLS 1.3 no servidor ou no CDN.'));
  if (tls12) checks.push(mk('tls12', 'TLS 1.2', 5, 5, 'pass', 'Suporta TLS 1.2 (compatível com a maioria dos clientes).'));
  else if (tls13) checks.push(mk('tls12', 'TLS 1.2', 5, 3, 'info', 'Não suporta TLS 1.2: só TLS 1.3. É seguro, mas clientes mais antigos podem não conectar.'));
  else checks.push(mk('tls12', 'TLS 1.2', 5, 0, 'fail', `Não foi possível negociar TLS 1.2 nem 1.3 (negociado: ${info.protocol}).`, 'Atualize o servidor para suportar TLS 1.2 e 1.3.'));

  if (legacy === 'accepted') checks.push(mk('legacy', 'Protocolos obsoletos (TLS 1.0/1.1)', 10, 0, 'fail', 'O servidor aceita TLS 1.0/1.1, protocolos obsoletos e vulneráveis.', 'Desative TLS 1.0 e 1.1 no servidor (mínimo TLS 1.2).'));
  else if (legacy === 'rejected') checks.push(mk('legacy', 'Protocolos obsoletos (TLS 1.0/1.1)', 10, 10, 'pass', 'O servidor recusa TLS 1.0/1.1.'));
  else checks.push(mk('legacy', 'Protocolos obsoletos (TLS 1.0/1.1)', 0, 0, 'info', 'Não foi possível testar TLS 1.0/1.1 a partir deste ambiente (fora da nota).'));

  // 6. Cifra negociada
  const good = info.protocol === 'TLSv1.3' || /GCM|CHACHA20/.test(info.cipher || '');
  checks.push(good
    ? mk('cipher', 'Suíte de cifras', 5, 5, 'pass', `Negociada: ${info.cipher}.`)
    : mk('cipher', 'Suíte de cifras', 5, 2, 'warn', `Negociada: ${info.cipher} (modo CBC, menos moderno).`, 'Priorize suítes AEAD (AES-GCM, ChaCha20-Poly1305).'));

  // ---- avançadas ----
  const extraLines = [];
  if (c && info.chain.length) {
    try {
      const ch = X.analyzeChain(info.chain, info.authorized, c.validFrom, c.validTo);
      checks.push(...ch.checks); caps.push(...ch.caps); extraLines.push(...ch.lines);
      const rv = X.analyzeRevocation(ch.leaf.x, ch.leaf.p, staple, info.authorized, now);
      checks.push(...rv.checks); caps.push(...rv.caps);
    } catch { /* certificado em formato incomum: pula as checagens avançadas */ }
  }
  if (cipherProbe) {
    const cp = X.analyzeCiphers(cipherProbe);
    checks.push(...cp.checks); caps.push(...cp.caps); extraLines.push(...cp.lines);
  }
  if (httpRes) checks.push(X.analyzeRedirect(httpRes, host));
  const hsts = httpsRes && X.analyzeHsts(httpsRes, host);
  if (hsts) checks.push(hsts);
  if (httpsRes && httpsRes.headers && /\bh3\b/.test(String(httpsRes.headers['alt-svc'] || ''))) extraLines.push('HTTP/3: anunciado via Alt-Svc');

  const lines = c ? [
    `Assunto (CN): ${c.subjectCN || '-'}`,
    `Nomes (SAN): ${c.sans.slice(0, 12).join(', ') || '-'}${c.sans.length > 12 ? ` (+${c.sans.length - 12})` : ''}`,
    `Emissor: ${c.issuer}`,
    `Válido de ${fmt(c.validFrom)} até ${fmt(c.validTo)}`,
    `Chave: ${c.keyType}${c.keyBits ? ` ${c.keyBits} bits` : ''}${c.curve ? ` ${c.curve}` : ''}`,
    `Protocolo negociado: ${info.protocol} · cifra: ${info.cipher}`,
    `Impressão digital SHA-256: ${c.fingerprint}`,
  ] : ['Nenhum certificado recebido.'];
  const details = [{ label: 'Detalhes do certificado', lines }];
  if (extraLines.length) details.push({ label: 'Cadeia, cifras e protocolos', lines: extraLines });
  return { ...finish(checks, caps), details };
}

module.exports = { checkTls };
