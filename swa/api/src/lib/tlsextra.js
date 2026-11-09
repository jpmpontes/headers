'use strict';
// Verificações avançadas de TLS: assinatura/cadeia/validade total, revogação (OCSP/CRL/Must-Staple) e Certificate Transparency,
// cifras (PFS, cifras fracas, curvas, ALPN) e HTTP→HTTPS + HSTS. Tudo recebe o endereço IP já validado (anti-SSRF).
const tls = require('node:tls');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const { X509Certificate } = require('node:crypto');
const { mk, registrable } = require('./common');

const TIMEOUT_MS = 5000;

// ---------- leitor mínimo de DER (suficiente para X.509 e OCSP) ----------
function tlv(b, o) {
  const tag = b[o];
  let len = b[o + 1];
  let h = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len * 256) + b[o + 2 + i]; h = 2 + n; }
  return { tag, start: o + h, end: o + h + len, next: o + h + len };
}
function kids(b, t) {
  const out = [];
  for (let o = t.start; o < t.end;) { const c = tlv(b, o); out.push(c); o = c.next; }
  return out;
}
function oidOf(b, t) {
  const bytes = b.subarray(t.start, t.end);
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) { v = (v * 128) + (bytes[i] & 0x7f); if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; } }
  return parts.join('.');
}
const SIG_ALGS = {
  '1.2.840.113549.1.1.4': 'md5WithRSA', '1.2.840.113549.1.1.5': 'sha1WithRSA', '1.2.840.113549.1.1.11': 'sha256WithRSA',
  '1.2.840.113549.1.1.12': 'sha384WithRSA', '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
};
const OID_SCT = '1.3.6.1.4.1.11129.2.4.2';
const OID_TLSFEATURE = '1.3.6.1.5.5.7.1.24';
const OID_CRLDP = '2.5.29.31';

// Lê algoritmo de assinatura e extensões de um certificado DER.
function parseCert(raw) {
  const top = tlv(raw, 0);
  const [tbs, sigAlg] = kids(raw, top);
  const out = { sigOid: oidOf(raw, kids(raw, sigAlg)[0]), ext: {} };
  out.sigAlg = SIG_ALGS[out.sigOid] || out.sigOid;
  const ext3 = kids(raw, tbs).find((t) => t.tag === 0xa3);
  if (ext3) {
    for (const e of kids(raw, kids(raw, ext3)[0])) {
      const k = kids(raw, e);
      out.ext[oidOf(raw, k[0])] = { critical: k.length > 2 && raw[k[1].start] !== 0, value: raw.subarray(k[k.length - 1].start, k[k.length - 1].end) };
    }
  }
  return out;
}
function sctCount(extValue) { // OCTET STRING { u16 total, (u16 len, sct)* }
  try {
    const inner = tlv(extValue, 0);
    const list = extValue.subarray(inner.start, inner.end);
    let n = 0;
    for (let o = 2; o + 2 <= list.length; o += 2 + list.readUInt16BE(o)) n++;
    return n;
  } catch { return 0; }
}

// ---------- 1. assinatura, cadeia e validade total ----------
function analyzeChain(rawChain, authorized, validFrom, validTo) {
  const checks = [];
  const caps = [];
  const certs = rawChain.map((raw) => {
    const x = new X509Certificate(raw);
    const cn = (s) => (/CN=([^\n]+)/.exec(s) || [])[1] || s.replace(/\n/g, ', ');
    return { x, p: parseCert(raw), subject: cn(x.subject), issuer: cn(x.issuer), selfSigned: x.subject === x.issuer };
  });
  const leaf = certs[0];
  const lines = certs.map((c, i) => `${i === 0 ? 'Site' : c.selfSigned ? 'Raiz' : 'Intermediário'}: ${c.subject} (emissor: ${c.issuer}) · assinatura ${c.p.sigAlg}`);

  const bad = ['md5WithRSA', 'sha1WithRSA', 'ecdsa-with-SHA1'];
  const inter = certs.filter((c, i) => i > 0 && !c.selfSigned && bad.includes(c.p.sigAlg));
  if (bad.includes(leaf.p.sigAlg)) {
    checks.push(mk('sigalg', 'Algoritmo de assinatura', 5, 0, 'fail', `O certificado é assinado com ${leaf.p.sigAlg}, algoritmo quebrado: navegadores modernos recusam.`, 'Reemita o certificado (SHA-256 ou superior).', leaf.p.sigAlg));
    caps.push('D');
  } else if (inter.length) {
    checks.push(mk('sigalg', 'Algoritmo de assinatura', 5, 2, 'warn', `Um certificado intermediário (${inter[0].subject}) usa ${inter[0].p.sigAlg}.`, 'Atualize a cadeia enviada pelo servidor.', lines.join('\n')));
  } else checks.push(mk('sigalg', 'Algoritmo de assinatura', 5, 5, 'pass', `Assinatura moderna (${leaf.p.sigAlg}).`, null, leaf.p.sigAlg));

  // Limite de validade para certificados de CAs públicas (CA/B Forum): 398 dias; 200 dias desde 15/03/2026.
  if (authorized) {
    const days = Math.round((validTo - validFrom) / 86400000);
    const limit = validFrom >= new Date('2026-03-15T00:00:00Z') ? 200 : 398;
    if (validFrom >= new Date('2020-09-01T00:00:00Z') && days > limit + 1) {
      checks.push(mk('lifetime', 'Prazo total do certificado', 0, 0, 'warn', `Validade total de ${days} dias, acima do máximo aceito para este certificado (${limit} dias). Pode ser rejeitado por navegadores.`, 'Reemita com prazo menor e automatize a renovação (ACME).', `${days} dias`));
    } else checks.push(mk('lifetime', 'Prazo total do certificado', 0, 0, 'pass', `Validade total de ${days} dias (dentro do limite).`, null, `${days} dias`));
  }
  const rootSent = certs.slice(1).some((c) => c.selfSigned);
  if (rootSent) checks.push(mk('chain', 'Cadeia enviada', 0, 0, 'info', 'A cadeia contém o certificado raiz. Não é necessário enviá-lo (clientes já o têm) e ocupa banda.', 'Envie apenas o certificado do site e os intermediários.'));
  return { checks, caps, lines, leaf };
}

// ---------- 2. revogação e Certificate Transparency ----------
function parseOcsp(buf) {
  try {
    const top = tlv(buf, 0);
    const [status, rb] = kids(buf, top);
    if (buf[status.start] !== 0 || !rb) return { error: `status ${buf[status.start]}` };
    const seq = kids(buf, kids(buf, rb)[0]); // ResponseBytes { OID, OCTET }
    const basic = tlv(buf, seq[1].start);
    const tbs = kids(buf, kids(buf, basic)[0]);
    const responses = tbs.find((t) => t.tag === 0x30 && tbs.indexOf(t) >= 2);
    const single = kids(buf, kids(buf, responses)[0]);
    const st = single[1];
    const state = st.tag === 0x80 ? 'good' : st.tag === 0xa1 ? 'revoked' : 'unknown';
    const time = (t) => { const s = buf.subarray(t.start, t.end).toString('ascii'); return new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`); };
    const next = single.find((t) => t.tag === 0xa0);
    return { state, thisUpdate: time(single[2]), nextUpdate: next ? time(tlv(buf, next.start)) : null };
  } catch (e) { return { error: 'resposta ilegível' }; }
}

function analyzeRevocation(leafX, leafP, staple, authorized, now) {
  const checks = [];
  const caps = [];
  if (!authorized) return { checks, caps };
  const info = leafX.infoAccess || '';
  const hasOcsp = /OCSP - URI:/i.test(info);
  const hasCrl = Boolean(leafP.ext[OID_CRLDP]);
  const mustStaple = Boolean(leafP.ext[OID_TLSFEATURE] && leafP.ext[OID_TLSFEATURE].value.includes(Buffer.from([0x05])));
  const how = [hasOcsp ? 'OCSP' : null, hasCrl ? 'CRL' : null, mustStaple ? 'Must-Staple' : null].filter(Boolean).join(', ') || 'nenhum';
  const parsed = staple && staple.length ? parseOcsp(staple) : null;

  if (parsed && parsed.state === 'revoked') {
    checks.push(mk('revocation', 'Revogação (OCSP/CRL)', 5, 0, 'fail', 'O servidor entregou uma resposta OCSP informando que o certificado foi REVOGADO.', 'Substitua o certificado imediatamente.', how));
    caps.push('F');
  } else if (parsed && parsed.state === 'good') {
    const stale = parsed.nextUpdate && parsed.nextUpdate.getTime() < now;
    checks.push(stale
      ? mk('revocation', 'Revogação (OCSP/CRL)', 5, 3, 'warn', 'OCSP stapling ativo, mas a resposta está vencida.', 'Verifique o cache de OCSP do servidor web.', how)
      : mk('revocation', 'Revogação (OCSP/CRL)', 5, 5, 'pass', `OCSP stapling ativo e a resposta confirma que o certificado é válido (mecanismos: ${how}).`, null, how));
  } else if (mustStaple) {
    checks.push(mk('revocation', 'Revogação (OCSP/CRL)', 5, 0, 'fail', 'O certificado exige OCSP Must-Staple, mas o servidor não entrega a resposta: navegadores como o Firefox recusam o acesso.', 'Habilite OCSP stapling no servidor ou reemita o certificado sem Must-Staple.', how));
    caps.push('C');
  } else if (hasOcsp) {
    checks.push(mk('revocation', 'Revogação (OCSP/CRL)', 5, 3, 'info', 'O certificado tem OCSP, mas o servidor não faz stapling: cada cliente precisa consultar a CA (mais lento e menos privado).', 'Habilite OCSP stapling (ssl_stapling on; no nginx).', how));
  } else if (hasCrl) {
    checks.push(mk('revocation', 'Revogação (OCSP/CRL)', 5, 5, 'pass', 'Revogação por CRL (sem OCSP), o que é comum em CAs que descontinuaram o OCSP.', null, how));
  } else {
    checks.push(mk('revocation', 'Revogação (OCSP/CRL)', 5, 2, 'warn', 'O certificado não informa nenhum meio de checar revogação (nem OCSP nem CRL).', 'Use certificados de uma CA pública.', how));
  }
  const n = leafP.ext[OID_SCT] ? sctCount(leafP.ext[OID_SCT].value) : 0;
  if (n >= 2) checks.push(mk('ct', 'Certificate Transparency', 5, 5, 'pass', `${n} registros SCT embutidos: o certificado foi publicado em logs públicos.`, null, `${n} SCTs`));
  else if (n === 1) checks.push(mk('ct', 'Certificate Transparency', 5, 3, 'warn', 'Apenas 1 SCT embutido (os navegadores costumam exigir 2 ou mais).', 'Reemita o certificado em uma CA que inclua SCTs.', '1 SCT'));
  else checks.push(mk('ct', 'Certificate Transparency', 5, 0, 'warn', 'Nenhum SCT embutido no certificado. Eles também podem ser entregues por extensão TLS ou OCSP, o que esta ferramenta não consegue ver.', 'Confirme com a CA que o certificado é registrado em logs de CT.'));
  return { checks, caps };
}

// ---------- conexões de teste ----------
function connect(addr, host, port, extra = {}) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host: addr.address, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, ...extra });
    const timer = setTimeout(() => sock.destroy(new Error('Tempo esgotado na conexão TLS')), TIMEOUT_MS);
    sock.once('secureConnect', () => { clearTimeout(timer); resolve(sock); });
    sock.once('error', (e) => { clearTimeout(timer); reject(e); });
    sock.once('OCSPResponse', () => {});
  });
}
async function probeOcsp(addr, host, port) {
  return new Promise((resolve) => {
    let resp = null;
    const sock = tls.connect({ host: addr.address, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, requestOCSP: true });
    const timer = setTimeout(() => { sock.destroy(); resolve(null); }, TIMEOUT_MS);
    sock.on('OCSPResponse', (r) => { resp = r; });
    sock.once('secureConnect', () => { clearTimeout(timer); sock.destroy(); resolve(resp); });
    sock.once('error', () => { clearTimeout(timer); resolve(null); });
  });
}
// 'accepted' | 'rejected' | 'untestable' (o cliente Node/OpenSSL não consegue nem oferecer essa suíte)
async function tryCiphers(addr, host, port, ciphers, extra = {}) {
  try {
    const s = await connect(addr, host, port, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers, ...extra });
    const r = { s: 'accepted', cipher: (s.getCipher() || {}).name, alpn: s.alpnProtocol };
    s.destroy();
    return r;
  } catch (e) {
    const text = `${e.code || ''} ${e.message || ''}`;
    if (/no cipher match|NO_CIPHER_MATCH|no ciphers available|Tempo esgotado|invalid cipher/i.test(text) && !/alert|handshake failure/i.test(text)) return { s: 'untestable' };
    return { s: 'rejected' };
  }
}

// ---------- 3. cifras, PFS, curvas, ALPN ----------
async function probeCiphers(addr, host, port, tls12) {
  const [pfs, noPfs, rc4, des3, exportNull, x25519, p256, p384, alpn] = await Promise.all([
    tryCiphers(addr, host, port, 'ECDHE:DHE'), tryCiphers(addr, host, port, 'kRSA:@SECLEVEL=0'),
    tryCiphers(addr, host, port, 'RC4:@SECLEVEL=0'), tryCiphers(addr, host, port, '3DES:@SECLEVEL=0'),
    tryCiphers(addr, host, port, 'aNULL:eNULL:EXPORT:DES:@SECLEVEL=0'),
    tryCiphers(addr, host, port, 'ECDHE', { ecdhCurve: 'X25519' }), tryCiphers(addr, host, port, 'ECDHE', { ecdhCurve: 'prime256v1' }), tryCiphers(addr, host, port, 'ECDHE', { ecdhCurve: 'secp384r1' }),
    connect(addr, host, port, { ALPNProtocols: ['h2', 'http/1.1'] }).then((s) => { const p = s.alpnProtocol; s.destroy(); return p || null; }, () => null),
  ]);
  return { tls12, pfs, noPfs, rc4, des3, exportNull, curves: { X25519: x25519.s, 'P-256': p256.s, 'P-384': p384.s }, alpn };
}

function analyzeCiphers(p) {
  const checks = [];
  const caps = [];
  if (!p.tls12) {
    checks.push(mk('pfs', 'Sigilo futuro (PFS)', 5, 5, 'pass', 'Somente TLS 1.3, que sempre usa sigilo futuro.'));
  } else if (p.pfs.s === 'accepted' && p.noPfs.s !== 'accepted') {
    checks.push(mk('pfs', 'Sigilo futuro (PFS)', 5, 5, 'pass', 'O servidor usa suítes com sigilo futuro (ECDHE/DHE) e não aceita troca de chaves RSA estática.'));
  } else if (p.pfs.s === 'accepted') {
    checks.push(mk('pfs', 'Sigilo futuro (PFS)', 5, 3, 'warn', 'Suporta PFS, mas também aceita suítes sem sigilo futuro (RSA estático): um cliente pode ser rebaixado e o tráfego gravado hoje decifrado se a chave vazar no futuro.', 'Desative as suítes de troca de chaves RSA.'));
  } else if (p.pfs.s === 'rejected') {
    checks.push(mk('pfs', 'Sigilo futuro (PFS)', 5, 0, 'fail', 'O servidor não oferece suítes com sigilo futuro (ECDHE/DHE).', 'Habilite suítes ECDHE com AES-GCM ou ChaCha20.'));
    caps.push('B');
  }
  const weakOn = [['RC4', p.rc4], ['3DES', p.des3], ['EXPORT/NULL/DES', p.exportNull]].filter(([, r]) => r.s === 'accepted').map(([n]) => n);
  const tested = [p.rc4, p.des3, p.exportNull].some((r) => r.s !== 'untestable');
  if (weakOn.length) {
    const serious = weakOn.some((n) => n !== '3DES');
    checks.push(mk('weakciphers', 'Cifras fracas', 5, serious ? 0 : 2, serious ? 'fail' : 'warn', `O servidor aceita cifras fracas: ${weakOn.join(', ')}.`, 'Desative RC4, 3DES, EXPORT, NULL e DES.'));
    if (serious) caps.push('C');
  } else if (tested) {
    checks.push(mk('weakciphers', 'Cifras fracas', 5, 5, 'pass', 'Nenhuma cifra fraca (RC4, 3DES, EXPORT, NULL) é aceita.'));
  } else checks.push(mk('weakciphers', 'Cifras fracas', 0, 0, 'info', 'Não foi possível testar cifras fracas a partir deste ambiente (fora da nota).'));

  const ok = Object.entries(p.curves).filter(([, s]) => s === 'accepted').map(([n]) => n);
  const lines = [
    `Sigilo futuro: ${!p.tls12 ? 'TLS 1.3 apenas' : p.pfs.s === 'accepted' ? `sim (${p.pfs.cipher})` : 'não'}`,
    `Curvas aceitas: ${ok.join(', ') || 'não testado'}`,
    `ALPN: ${p.alpn || 'sem ALPN (HTTP/1.1)'}`,
  ];
  checks.push(p.alpn === 'h2'
    ? mk('http2', 'HTTP/2', 0, 0, 'pass', 'O servidor negocia HTTP/2 (ALPN h2).')
    : mk('http2', 'HTTP/2', 0, 0, 'info', 'O servidor não negocia HTTP/2. Recomendado para desempenho.', 'Habilite HTTP/2 no servidor ou CDN.'));
  return { checks, caps, lines };
}

// ---------- 4. HTTP→HTTPS e HSTS ----------
function httpGet({ secure, addr, host, port }) {
  return new Promise((resolve) => {
    const mod = secure ? https : http;
    const req = mod.request({
      host: addr.address, port, method: 'GET', path: '/', timeout: TIMEOUT_MS, servername: secure && !net.isIP(host) ? host : undefined,
      rejectUnauthorized: false, headers: { host, 'user-agent': 'Verifica-CorevaTech/1.0', accept: '*/*' },
    }, (res) => { resolve({ status: res.statusCode, headers: res.headers }); res.destroy(); });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ error: e.code || e.message }));
    req.end();
  });
}

function analyzeRedirect(h, host) {
  const NAME = 'Redirecionamento HTTP → HTTPS';
  const FIX = 'Configure a porta 80 para redirecionar (301) para https:// do mesmo domínio.';
  if (h.error) return mk('redirect', NAME, 5, 3, 'info', `A porta 80 não respondeu (${h.error}). Não é um risco, mas quem digitar http:// não conseguirá acessar.`, 'Mantenha a porta 80 aberta apenas para redirecionar para HTTPS.');
  const loc = h.headers.location;
  if ([301, 302, 303, 307, 308].includes(h.status) && loc) {
    let u;
    try { u = new URL(loc, `http://${host}/`); } catch { return mk('redirect', NAME, 5, 0, 'fail', 'O cabeçalho Location do redirecionamento é inválido.', FIX); }
    if (u.protocol !== 'https:') return mk('redirect', NAME, 5, 0, 'fail', `O HTTP redireciona para ${u.protocol}//, ou seja, continua sem criptografia.`, FIX, loc);
    if (registrable(u.hostname) !== registrable(host)) return mk('redirect', NAME, 5, 3, 'warn', `O HTTP redireciona para outro domínio (${u.hostname}).`, FIX, loc);
    return [301, 308].includes(h.status)
      ? mk('redirect', NAME, 5, 5, 'pass', `HTTP redireciona permanentemente para HTTPS (${h.status}).`, null, loc)
      : mk('redirect', NAME, 5, 4, 'pass', `HTTP redireciona para HTTPS (${h.status}, temporário; prefira 301/308).`, null, loc);
  }
  return mk('redirect', NAME, 5, 0, 'fail', `A porta 80 responde (HTTP ${h.status}) sem redirecionar para HTTPS: o conteúdo pode ser lido e alterado na rede.`, FIX);
}

function analyzeHsts(h, host) {
  const NAME = 'HSTS (política de HTTPS)';
  if (h.error || !h.headers) return null;
  const v = h.headers['strict-transport-security'];
  if (!v) return mk('hsts', NAME, 0, 0, 'warn', 'Sem HSTS: o navegador não é forçado a usar HTTPS nas próximas visitas (ataques de downgrade).', 'Envie Strict-Transport-Security: max-age=31536000; includeSubDomains');
  const age = Number((/max-age=(\d+)/i.exec(v) || [])[1]);
  const sub = /includesubdomains/i.test(v);
  const pre = /preload/i.test(v);
  const issues = [];
  if (!Number.isFinite(age) || age < 15552000) issues.push(`max-age curto (${Number.isFinite(age) ? age : 'ausente'}s; recomendado ≥ 31536000)`);
  if (!sub) issues.push('sem includeSubDomains');
  if (issues.length) return mk('hsts', NAME, 0, 0, 'warn', `HSTS presente, mas ${issues.join('; ')}.`, 'Use max-age=31536000; includeSubDomains', v);
  const eligible = age >= 31536000 && sub && pre;
  return mk('hsts', NAME, 0, 0, 'pass', eligible ? 'HSTS forte e elegível à lista de pré-carregamento dos navegadores (preload).' : 'HSTS forte. Para entrar na lista de pré-carregamento, acrescente "preload" e registre em hstspreload.org.', null, v);
}

module.exports = { parseCert, sctCount, parseOcsp, analyzeChain, analyzeRevocation, analyzeCiphers, analyzeRedirect, analyzeHsts, probeOcsp, probeCiphers, httpGet, tryCiphers };
