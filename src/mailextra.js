'use strict';
// Verificações avançadas de e-mail que vão além do DNS: STARTTLS nos MX (porta 25), política MTA-STS (HTTPS),
// DMARC (autorização de relatórios externos), BIMI, DANE e DNS reverso dos MX.
// Tudo é injetável (smtpProbe, fetchPolicy) para testes sem rede. Item não testável => max 0 (fora da nota).
const net = require('node:net');
const tls = require('node:tls');
const https = require('node:https');
const { isBlockedIP, resolveAllPublic } = require('./ssrf');
const { mk, attempt, registrable } = require('./common');

const MAX_MX = 3;
const EHLO_NAME = 'verifica.corevatech.com.br';
const SMTP_TIMEOUT = 6000;

const probesEnabled = () => process.env.MAIL_PROBE !== '0' && process.env.ALLOW_PRIVATE !== '1';

// ---------- sonda SMTP (porta 25) ----------
function smtpProbe(host, ip, port = 25) {
  return new Promise((resolve) => {
    const out = { host, ip, reachable: false, starttls: false, banner: null, error: null, protocol: null, cert: null };
    let buf = '';
    let step = 'connect';
    let waiter = null;
    const sock = net.connect({ host: ip, port });
    const done = (extra = {}) => { clearTimeout(timer); sock.destroy(); resolve({ ...out, ...extra }); };
    const timer = setTimeout(() => done({ error: out.reachable ? 'timeout' : 'ETIMEDOUT' }), SMTP_TIMEOUT);
    sock.on('error', (e) => done({ error: e.code || e.message }));
    sock.on('close', () => done({ error: out.error || 'conexão encerrada' }));
    // Lê uma resposta SMTP completa (linhas "250-..." terminam em "250 ...").
    const reply = () => new Promise((res) => { waiter = res; flush(); });
    const flush = () => {
      if (!waiter) return;
      const lines = buf.split('\r\n');
      const last = lines.length > 1 ? lines[lines.length - 2] : null;
      if (last && /^\d{3} /.test(last)) { const w = waiter; waiter = null; const text = buf; buf = ''; w({ code: Number(last.slice(0, 3)), text }); }
    };
    sock.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 20000) done({ error: 'resposta grande demais' }); flush(); });
    sock.once('connect', async () => {
      out.reachable = true;
      try {
        step = 'banner'; const b = await reply();
        out.banner = b.text.split('\r\n')[0].slice(0, 120);
        if (b.code !== 220) return done({ error: `banner ${b.code}` });
        sock.write(`EHLO ${EHLO_NAME}\r\n`); step = 'ehlo'; const e = await reply();
        if (e.code !== 250) return done({ error: `EHLO ${e.code}` });
        out.starttls = /^250[- ]STARTTLS\s*$/im.test(e.text);
        if (!out.starttls) { sock.write('QUIT\r\n'); return done(); }
        sock.write('STARTTLS\r\n'); step = 'starttls'; const s = await reply();
        if (s.code !== 220) return done({ error: `STARTTLS ${s.code}`, starttls: false });
        sock.removeAllListeners('data'); sock.removeAllListeners('close');
        const t = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false, minVersion: 'TLSv1' });
        t.once('secureConnect', () => {
          const c = t.getPeerCertificate();
          const idErr = c && c.subject ? tls.checkServerIdentity(host, c) : new Error('sem certificado');
          out.protocol = t.getProtocol();
          out.cert = {
            subject: c && c.subject && c.subject.CN, validTo: c && c.valid_to, trusted: t.authorized, authError: t.authorizationError ? String(t.authorizationError.code || t.authorizationError) : null,
            hostOk: !idErr, daysLeft: c && c.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 86400000) : null,
          };
          done();
        });
        t.once('error', (er) => done({ error: `TLS: ${er.code || er.message}`, starttls: true }));
      } catch (err) { done({ error: `${step}: ${err.message}` }); }
    });
  });
}

async function mxTargets(mxList, resolver) {
  const top = [...mxList].filter((m) => m.exchange && m.exchange !== '.').sort((a, b) => a.priority - b.priority).slice(0, MAX_MX);
  return Promise.all(top.map(async (m) => {
    const host = m.exchange.replace(/\.$/, '').toLowerCase();
    const [r4, r6] = await Promise.all([attempt(() => resolver.resolve4(host)), attempt(() => resolver.resolve6(host))]);
    const ips = [...r4.data, ...r6.data].map((x) => (typeof x === 'string' ? x : x.address));
    const ip = ips.find((x) => !isBlockedIP(x)) || null; // SSRF: nunca conecta em IP privado/reservado
    return { host, ips, ip, blocked: ips.length > 0 && !ip };
  }));
}

// ---------- STARTTLS ----------
function checkStartTls(results) {
  const reach = results.filter((r) => r.reachable);
  if (!reach.length) return [];
  const noTls = reach.filter((r) => !r.starttls);
  const failed = reach.filter((r) => r.starttls && !r.protocol);
  const old = reach.filter((r) => r.protocol && /^TLSv1(\.[01])?$/.test(r.protocol));
  const value = reach.map((r) => `${r.host} [${r.ip}] ${r.starttls ? `STARTTLS ${r.protocol || 'falhou'}` : 'sem STARTTLS'}`).join('\n');
  const FIX = 'Habilite STARTTLS com TLS 1.2 ou superior no servidor de e-mail (ou no painel do provedor).';
  let c;
  if (noTls.length) c = mk('starttls', 'Criptografia no recebimento (STARTTLS)', 10, noTls.length === reach.length ? 0 : 4, 'fail', `${noTls.map((r) => r.host).join(', ')} não oferece STARTTLS: o e-mail recebido trafega sem criptografia.`, FIX, value);
  else if (failed.length) c = mk('starttls', 'Criptografia no recebimento (STARTTLS)', 10, 5, 'warn', `${failed.map((r) => r.host).join(', ')} anuncia STARTTLS, mas o handshake TLS falhou (${failed[0].error}).`, FIX, value);
  else if (old.length) c = mk('starttls', 'Criptografia no recebimento (STARTTLS)', 10, 5, 'warn', `${old[0].host} negocia ${old[0].protocol}, protocolo obsoleto.`, FIX, value);
  else c = mk('starttls', 'Criptografia no recebimento (STARTTLS)', 10, 10, 'pass', `${reach.length} servidor(es) de e-mail com STARTTLS e ${[...new Set(reach.map((r) => r.protocol))].join('/')}.`, null, value);

  const withCert = reach.filter((r) => r.cert);
  const out = [c];
  if (withCert.length) {
    const bad = withCert.filter((r) => !r.cert.trusted || !r.cert.hostOk || (r.cert.daysLeft !== null && r.cert.daysLeft < 0));
    const certValue = withCert.map((r) => `${r.host}: CN=${r.cert.subject || '?'} · ${r.cert.trusted ? 'confiável' : `não confiável (${r.cert.authError})`} · ${r.cert.hostOk ? 'nome confere' : 'nome NÃO confere'} · vence em ${r.cert.daysLeft} dia(s)`).join('\n');
    out.push(bad.length
      ? mk('mxcert', 'Certificado dos servidores de e-mail', 5, 2, 'warn', `O certificado de ${bad[0].host} é inválido para validação estrita (expirado, nome diferente ou emissor não confiável). Servidores comuns ainda entregam, mas MTA-STS em modo enforce e DANE não funcionariam.`, 'Instale um certificado válido emitido para o nome do MX.', certValue)
      : mk('mxcert', 'Certificado dos servidores de e-mail', 5, 5, 'pass', 'Certificados confiáveis, válidos e com o nome do MX.', null, certValue));
  }
  return out;
}

// ---------- MTA-STS: política em https://mta-sts.<dominio>/.well-known/mta-sts.txt ----------
async function fetchPolicy(domain) {
  const host = `mta-sts.${domain}`;
  let addrs;
  try { addrs = await resolveAllPublic(host); } catch (e) { return { error: e.message }; }
  return new Promise((resolve) => {
    const req = https.request({
      host: addrs[0].address, servername: host, port: 443, path: '/.well-known/mta-sts.txt', method: 'GET',
      headers: { host, 'user-agent': 'Verifica-CorevaTech/1.0', accept: 'text/plain' }, timeout: 5000, rejectUnauthorized: true,
    }, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (d) => { size += d.length; if (size > 65536) req.destroy(new Error('política grande demais')); else chunks.push(d); });
      res.on('end', () => resolve({ status: res.statusCode, type: String(res.headers['content-type'] || ''), body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ error: e.code || e.message }));
    req.end();
  });
}

function parsePolicy(body) {
  const p = { mx: [] };
  for (const line of body.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    if (k === 'mx') p.mx.push(v.toLowerCase()); else if (k) p[k] = v;
  }
  return p;
}
const mxMatches = (pattern, host) => (pattern.startsWith('*.') ? host.endsWith(pattern.slice(1)) && host.split('.').length === pattern.split('.').length : pattern === host);

function checkMtaStsPolicy(res, mxHosts, domain) {
  const NAME = 'MTA-STS (política)';
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const fixPub = `Publique a política em ${url} (HTTPS válido, sem redirecionamento), por exemplo:\nversion: STSv1\nmode: testing\nmx: ${mxHosts[0] || 'mail.' + domain}\nmax_age: 86400`;
  if (res.error) return mk('mtastspol', NAME, 0, 0, 'warn', `O registro MTA-STS existe, mas a política não pôde ser lida em ${url} (${res.error}). Sem ela, o MTA-STS não vale.`, fixPub);
  if (res.status !== 200) return mk('mtastspol', NAME, 0, 0, 'warn', `A política respondeu HTTP ${res.status} (esperado 200; redirecionamentos não são permitidos).`, fixPub);
  const p = parsePolicy(res.body);
  const value = res.body.trim().slice(0, 600);
  const issues = [];
  let bad = false;
  if (p.version !== 'STSv1') { bad = true; issues.push('falta "version: STSv1"'); }
  if (!['enforce', 'testing', 'none'].includes(p.mode)) { bad = true; issues.push('"mode" ausente ou inválido'); }
  if (!p.mx.length && p.mode !== 'none') { bad = true; issues.push('nenhuma linha "mx:"'); }
  const age = Number(p.max_age);
  if (!Number.isFinite(age)) { bad = true; issues.push('"max_age" ausente ou inválido'); }
  const uncovered = mxHosts.filter((h) => !p.mx.some((pat) => mxMatches(pat, h)));
  if (p.mx.length && uncovered.length) { bad = true; issues.push(`os MX ${uncovered.join(', ')} não estão cobertos pela lista mx: (com mode=enforce o e-mail seria recusado)`); }
  if (bad) return mk('mtastspol', NAME, 0, 0, 'fail', `Política MTA-STS com problemas: ${issues.join('; ')}.`, 'Corrija o arquivo da política.', value);
  if (p.mode === 'enforce') {
    return age < 86400
      ? mk('mtastspol', NAME, 0, 4, 'warn', `Política em modo enforce, mas max_age=${age}s é curto (recomendado ≥ 604800, ou 1 semana).`, 'Aumente o max_age.', value)
      : mk('mtastspol', NAME, 0, 6, 'pass', `Política MTA-STS em modo enforce, cobrindo todos os MX (max_age ${age}s).`, null, value);
  }
  if (p.mode === 'testing') return mk('mtastspol', NAME, 0, 2, 'warn', 'Política MTA-STS em modo testing: só gera relatórios, não impõe criptografia.', 'Após validar os relatórios TLS-RPT, mude para mode: enforce.', value);
  return mk('mtastspol', NAME, 0, 0, 'warn', 'Política MTA-STS em modo none: desativada.', 'Use mode: enforce quando os MX tiverem certificados válidos.', value);
}

// ---------- DMARC: relatórios para domínios externos ----------
async function checkDmarcReports(rec, domain, txtOf) {
  if (!rec) return null;
  const tags = Object.fromEntries(rec.split(';').map((s) => s.trim()).filter(Boolean).map((s) => { const i = s.indexOf('='); return i < 0 ? [s, ''] : [s.slice(0, i).trim().toLowerCase(), s.slice(i + 1).trim()]; }));
  const dests = ['rua', 'ruf'].flatMap((t) => (tags[t] ? tags[t].split(',').map((x) => ({ tag: t, uri: x.trim().replace(/!\d+[kmgt]?$/i, '') })) : []));
  if (!dests.length) return null;
  const issues = [];
  const ok = [];
  for (const d of dests.slice(0, 6)) {
    const m = /^mailto:([^@\s]+)@([^\s]+)$/i.exec(d.uri);
    if (!m) { issues.push(`${d.tag}=${d.uri} não é um endereço mailto: válido`); continue; }
    const rd = m[2].toLowerCase();
    if (registrable(rd) === domain) { ok.push(`${m[1]}@${rd}`); continue; }
    const r = await txtOf(`${domain}._report._dmarc.${rd}`);
    if (r.s === 'ok' && r.data.some((x) => /^v=DMARC1/i.test(x.trim()))) ok.push(`${m[1]}@${rd} (autorizado)`);
    else issues.push(`${m[1]}@${rd} não autorizou receber relatórios de ${domain} (falta ${domain}._report._dmarc.${rd} TXT "v=DMARC1")`);
  }
  const value = [...ok, ...issues.map((i) => `✗ ${i}`)].join('\n');
  return issues.length
    ? mk('dmarcrep', 'DMARC: destino dos relatórios', 0, 0, 'warn', `Relatórios podem não chegar: ${issues[0]}${issues.length > 1 ? ` (+${issues.length - 1})` : ''}.`, 'Peça ao responsável pelo domínio externo para publicar o registro de autorização, ou use um endereço do próprio domínio.', value)
    : mk('dmarcrep', 'DMARC: destino dos relatórios', 0, 0, 'pass', 'Os endereços de relatório são válidos e autorizados.', null, value);
}

// ---------- BIMI ----------
function checkBimi(recs, dmarcPolicy, pctOk) {
  const rec = recs.find((x) => /^v=BIMI1/i.test(x.trim()));
  if (!rec) return mk('bimi', 'BIMI (logo na caixa de entrada)', 0, 0, 'info', 'Sem BIMI: recurso opcional que exibe a logo da marca em provedores compatíveis. Exige DMARC em quarantine/reject.');
  const l = (/(?:^|;)\s*l=\s*([^;\s]*)/i.exec(rec) || [])[1] || '';
  const enforced = (dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine') && pctOk;
  const issues = [];
  if (!enforced) issues.push('exige DMARC com p=quarantine ou p=reject (pct=100)');
  if (!/^https:\/\/.+\.svg(\?.*)?$/i.test(l)) issues.push('l= deve ser uma URL https de arquivo .svg');
  return issues.length
    ? mk('bimi', 'BIMI (logo na caixa de entrada)', 0, 0, 'warn', `BIMI publicado, mas não vai funcionar: ${issues.join('; ')}.`, 'Ajuste o DMARC e o endereço da logo (SVG Tiny PS).', rec)
    : mk('bimi', 'BIMI (logo na caixa de entrada)', 0, 2, 'pass', 'BIMI publicado e com pré-requisitos atendidos.', null, rec);
}

// ---------- DANE (TLSA nos MX) ----------
async function checkDane(targets, resolver, dnssecOf) {
  if (typeof resolver.resolveTlsa !== 'function') return null;
  const found = [];
  for (const t of targets) {
    const r = await attempt(() => resolver.resolveTlsa(`_25._tcp.${t.host}`));
    if (r.s === 'ok' && r.data.length) found.push(t.host);
  }
  if (!found.length) return mk('dane', 'DANE (TLSA nos MX)', 0, 0, 'info', 'Sem DANE: recurso opcional (exige DNSSEC) que fixa o certificado esperado do servidor de e-mail.');
  const signed = dnssecOf ? await dnssecOf(found[0]) : null;
  return signed === false
    ? mk('dane', 'DANE (TLSA nos MX)', 0, 0, 'warn', `Há registro TLSA para ${found.join(', ')}, mas o DNSSEC do domínio do MX não está válido: o DANE é ignorado.`, 'Ative o DNSSEC no domínio dos servidores de e-mail.')
    : mk('dane', 'DANE (TLSA nos MX)', 0, 3, 'pass', `Registro TLSA publicado para ${found.join(', ')}.${signed ? '' : ' (DNSSEC não confirmado.)'}`, null, found.join('\n'));
}

// ---------- DNS reverso dos MX ----------
async function checkReverse(targets, resolver) {
  const rows = [];
  for (const t of targets.filter((x) => x.ip)) {
    const r = await attempt(() => resolver.reverse(t.ip));
    const names = (r.data || []).map((n) => n.replace(/\.$/, '').toLowerCase());
    let fc = false;
    for (const n of names) {
      const [a, aaaa] = await Promise.all([attempt(() => resolver.resolve4(n)), attempt(() => resolver.resolve6(n))]);
      if ([...a.data, ...aaaa.data].map((x) => (typeof x === 'string' ? x : x.address)).includes(t.ip)) { fc = true; break; }
    }
    rows.push({ t, names, fc });
  }
  if (!rows.length) return null;
  const bad = rows.filter((r) => !r.fc);
  const value = rows.map((r) => `${r.t.ip} → ${r.names.join(', ') || 'sem PTR'}${r.fc ? ' ✓' : ' ✗'}`).join('\n');
  return bad.length
    ? mk('mxrdns', 'DNS reverso dos MX', 0, 0, 'warn', `${bad[0].t.host} (${bad[0].t.ip}) ${bad[0].names.length ? 'tem PTR que não confirma o IP (forward-confirmed)' : 'não tem DNS reverso (PTR)'}. Alguns servidores rejeitam ou penalizam e-mail de IPs assim.`, 'Peça ao dono do IP (provedor) um PTR apontando para o nome do servidor, e que esse nome resolva de volta para o IP.', value)
    : mk('mxrdns', 'DNS reverso dos MX', 0, 0, 'pass', 'DNS reverso consistente (forward-confirmed) nos MX.', null, value);
}

module.exports = { smtpProbe, fetchPolicy, mxTargets, checkStartTls, checkMtaStsPolicy, checkDmarcReports, checkBimi, checkDane, checkReverse, probesEnabled, parsePolicy };
