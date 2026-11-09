'use strict';
// Verificações de e-mail: MX, SPF (com contagem de consultas DNS), DMARC, DKIM, MTA-STS e TLS-RPT.
// Só lê registros DNS públicos; não envia nenhuma mensagem. O resolvedor é injetável para testes.
const crypto = require('node:crypto');
const { mk, finish, attempt, registrable, defaultResolver } = require('./common');
const X = require('./mailextra');
const { checkDnssec } = require('./dnssec');

// DKIM não tem como ser "listado": só dá para testar seletores conhecidos (ou o que o usuário informar).
const COMMON_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'smtp', 'mandrill', 'zoho', 'mxvault', 'dk', 'email'];
const SPF_MAX_QUERIES = 25; // teto de consultas ao expandir includes (evita abuso)
const SPF_MAX_DEPTH = 10;
const SPF_BUDGET_MS = 10000;

const isSpf = (x) => /^v=spf1(\s|$)/i.test(x.trim());

const parseTags = (rec) => Object.fromEntries(rec.split(';').map((s) => s.trim()).filter(Boolean).map((s) => {
  const i = s.indexOf('=');
  return i < 0 ? [s.toLowerCase(), ''] : [s.slice(0, i).trim().toLowerCase(), s.slice(i + 1).trim()];
}));

// ---------- SPF ----------
// get(nome) => lista de strings TXT (lança erro com .code se a consulta falhar).
async function analyzeSpf(domain, get, { budgetMs = SPF_BUDGET_MS } = {}) {
  const st = { records: [], lookups: 0, queries: 0, truncated: false, ptr: false, missing: [], failed: null };
  const visited = new Set();
  const deadline = Date.now() + budgetMs;

  async function walk(name, depth) {
    visited.add(name);
    if (st.queries >= SPF_MAX_QUERIES || Date.now() > deadline) { st.truncated = true; return; }
    st.queries++;
    let txts;
    try { txts = await get(name); } catch (e) {
      if (depth === 0) st.failed = e.code || 'ERRO'; else st.missing.push(name);
      return;
    }
    const recs = txts.filter(isSpf);
    if (depth === 0) st.records = recs;
    if (recs.length !== 1) { if (depth > 0) st.missing.push(name); return; }
    for (const raw of recs[0].trim().split(/\s+/).slice(1)) {
      const t = raw.toLowerCase().replace(/^[+\-~?]/, '');
      const m = /^(include|a|mx|ptr|exists|redirect)(?=[:=/]|$)/.exec(t);
      if (!m) continue;
      st.lookups++; // cada mecanismo desses conta para o limite de 10 consultas do SPF
      if (m[1] === 'ptr') st.ptr = true;
      if (m[1] === 'include' || m[1] === 'redirect') {
        const target = (t.split(/[:=]/)[1] || '').replace(/\/\d+$/, '');
        if (!target || visited.has(target)) continue; // proteção contra loop
        if (depth >= SPF_MAX_DEPTH) { st.truncated = true; continue; }
        await walk(target, depth + 1);
      }
    }
  }
  await walk(domain, 0);
  return st;
}

function checkSpf(st, noMail) {
  const max = 30;
  if (st.failed) return mk('spf', 'SPF', max, 0, 'warn', `Não foi possível consultar o DNS (${st.failed}).`);
  if (!st.records.length) {
    return mk('spf', 'SPF', max, 0, 'fail',
      noMail ? 'Sem SPF. Este domínio não recebe e-mail, então deveria declarar que ninguém pode enviar por ele.' : 'Nenhum registro SPF: qualquer servidor pode se passar pelo seu domínio com mais facilidade.',
      noMail ? 'TXT: "v=spf1 -all"' : 'TXT: "v=spf1 include:<seu-provedor-de-email> -all"');
  }
  if (st.records.length > 1) {
    return mk('spf', 'SPF', max, 0, 'fail', 'Há mais de um registro SPF. O padrão exige exatamente um, e os receptores tratam isso como erro.', 'Una tudo em um único registro TXT que comece com v=spf1.', st.records.join('\n'));
  }
  const rec = st.records[0];
  const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(rec);
  const notes = [];
  let pts;
  let status = 'pass';
  if (all) {
    const q = all[1] || '+';
    if (q === '-') pts = 30;
    else if (q === '~') { pts = 22; status = 'warn'; notes.push('termina em ~all (softfail). Prefira -all quando todos os remetentes estiverem listados'); }
    else if (q === '?') { pts = 8; status = 'fail'; notes.push('termina em ?all (neutro) e não protege'); }
    else { pts = 0; status = 'fail'; notes.push('termina em +all e autoriza qualquer servidor a enviar em nome do domínio'); }
  } else if (/(?:^|\s)redirect=/i.test(rec)) pts = 26;
  else { pts = 8; status = 'warn'; notes.push('não termina com "all"'); }

  if (st.lookups > 10) { pts = Math.min(pts, 8); status = 'fail'; notes.push(`excede o limite de 10 consultas DNS (${st.lookups}): o SPF é inválido e a entrega pode falhar`); }
  if (st.ptr) { pts -= 3; if (status === 'pass') status = 'warn'; notes.push('usa o mecanismo ptr (desaconselhado)'); }
  if (st.missing.length) { pts -= 4; if (status === 'pass') status = 'warn'; notes.push(`include sem SPF válido: ${st.missing.join(', ')}`); }
  if (st.truncated && st.lookups <= 10) notes.push('a contagem de consultas pode estar incompleta');

  return mk('spf', 'SPF', max, pts, status,
    notes.length ? `Presente, mas ${notes.join('; ')}.` : `Política restritiva (-all), com ${st.lookups} de 10 consultas DNS.`,
    status === 'pass' ? null : 'Use um único registro, com -all no final e no máximo 10 consultas DNS (include, a, mx, exists, redirect).', rec);
}

// ---------- MX ----------
function checkMx(mx) {
  if (mx.s === 'err') return { noMail: false, check: mk('mx', 'Servidores de e-mail (MX)', 0, 0, 'info', `Não foi possível consultar os MX (${mx.code}).`) };
  const real = mx.data.filter((m) => m.exchange && m.exchange !== '.');
  if (real.length) {
    const list = [...real].sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`);
    return { noMail: false, check: mk('mx', 'Servidores de e-mail (MX)', 0, 0, 'pass', `${real.length} servidor(es) de e-mail.`, null, list.join('\n')) };
  }
  return {
    noMail: true,
    check: mk('mx', 'Servidores de e-mail (MX)', 0, 0, 'info',
      mx.data.length ? 'MX nulo: o domínio declara que não recebe e-mail.' : 'Sem MX: o domínio não recebe e-mail. Se for intencional, proteja-o contra falsificação (SPF -all e DMARC reject).'),
  };
}

// ---------- DMARC ----------
function checkDmarc(d, domain) {
  const max = 35;
  const fix = `_dmarc.${domain}  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@${domain}"  (comece com p=none, acompanhe os relatórios e evolua para quarantine e depois reject)`;
  if (d.s === 'err') return mk('dmarc', 'DMARC', max, 0, 'warn', `Não foi possível consultar o DNS (${d.code}).`);
  const recs = d.data.filter((x) => /^v=DMARC1\s*(;|$)/i.test(x.trim()));
  if (!recs.length) return mk('dmarc', 'DMARC', max, 0, 'fail', 'Sem DMARC: não há política para e-mails que falham no SPF/DKIM, e você não recebe relatórios de abuso.', fix);
  if (recs.length > 1) return mk('dmarc', 'DMARC', max, 0, 'fail', 'Há mais de um registro DMARC: os receptores ignoram a política.', 'Mantenha apenas um registro DMARC.', recs.join('\n'));
  const rec = recs[0];
  const t = parseTags(rec);
  const p = (t.p || '').toLowerCase();
  const notes = [];
  let pts;
  let status = 'pass';
  if (p === 'reject') pts = 35;
  else if (p === 'quarantine') pts = 28;
  else if (p === 'none') { pts = 12; status = 'warn'; notes.push('p=none é só monitoramento: e-mails falsificados continuam sendo entregues'); }
  else { pts = 0; status = 'fail'; notes.push('a política (p=) está ausente ou inválida'); }
  if (p === 'reject' || p === 'quarantine') {
    const pct = t.pct ? Number(t.pct) : 100;
    if (pct < 100) { pts -= 5; status = 'warn'; notes.push(`pct=${pct}: a política vale só para parte dos e-mails`); }
    if ((t.sp || '').toLowerCase() === 'none') { pts -= 5; status = 'warn'; notes.push('sp=none deixa os subdomínios sem proteção'); }
  }
  if (!t.rua) { pts -= 3; if (status === 'pass') status = 'warn'; notes.push('sem rua= (você não recebe relatórios agregados)'); }
  return mk('dmarc', 'DMARC', max, pts, status,
    notes.length ? `Presente, mas ${notes.join('; ')}.` : `Política ${p} ativa.`,
    status === 'pass' ? null : 'Evolua a política para p=quarantine e depois p=reject, com rua= definido para receber relatórios.', rec);
}

// ---------- DKIM (opcional: fora da nota base, só dá bônus) ----------
function keyInfo(rec) {
  const t = parseTags(rec);
  const p = (t.p || '').replace(/\s+/g, '');
  if (!p) return { revoked: true };
  if ((t.k || '').toLowerCase() === 'ed25519') return { type: 'ed25519', bits: null, weak: false };
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
    const bits = (key.asymmetricKeyDetails || {}).modulusLength || null;
    return { type: key.asymmetricKeyType, bits, weak: key.asymmetricKeyType === 'rsa' && bits !== null && bits < 2048 };
  } catch { return { type: (t.k || 'rsa').toLowerCase(), bits: null, weak: false, unreadable: true }; }
}

function checkDkim(found, extra, skipReason) {
  if (skipReason) return mk('dkim', 'DKIM', 0, 0, 'info', skipReason);
  if (!found.length) {
    return extra
      ? mk('dkim', 'DKIM', 0, 0, 'warn', `O seletor "${extra}" não foi encontrado em ${extra}._domainkey.`, 'Confira o nome do seletor no painel do seu provedor de e-mail.')
      : mk('dkim', 'DKIM', 0, 0, 'info', 'Nenhum seletor comum foi encontrado. Isso não prova que não há DKIM: ele pode usar um seletor próprio. Informe-o em "Opções avançadas" para testar. (Não entra na nota.)',
        'Publique <seletor>._domainkey TXT "v=DKIM1; k=rsa; p=<chave pública>" (o provedor de e-mail gera a chave).');
  }
  const keys = found.map((f) => ({ selector: f.selector, ...keyInfo(f.rec) }));
  const value = keys.map((k) => `${k.selector}: ${k.revoked ? 'revogada (p= vazio)' : `${k.type}${k.bits ? ` ${k.bits} bits` : ''}`}`).join('\n');
  const active = keys.filter((k) => !k.revoked);
  if (!active.length) return mk('dkim', 'DKIM', 0, 0, 'warn', 'As chaves DKIM encontradas estão com a chave revogada (p= vazio).', 'Publique uma chave ativa.', value);
  const weak = active.filter((k) => k.weak);
  if (weak.length) {
    return mk('dkim', 'DKIM', 0, 0, 'warn', `Chave RSA de ${weak[0].bits} bits no seletor "${weak[0].selector}": fraca (o recomendado é 2048).`, 'Gere uma chave RSA de 2048 bits (ou Ed25519) e troque.', value);
  }
  return mk('dkim', 'DKIM', 0, 8, 'pass', `${active.length} seletor(es) DKIM ativo(s).`, null, value);
}

// ---------- MTA-STS e TLS-RPT (opcionais: bônus) ----------
function checkMtaSts(recs, domain, skip, policyChecked = false) {
  if (skip) return mk('mtasts', 'MTA-STS', 0, 0, 'info', skip);
  return recs.length
    ? mk('mtasts', 'MTA-STS', 0, 4, 'pass', `Registro MTA-STS publicado.${policyChecked ? '' : ' (Verificamos só o registro DNS, não o arquivo de política.)'}`, null, recs[0])
    : mk('mtasts', 'MTA-STS', 0, 0, 'info', 'Sem MTA-STS: recurso opcional que impede o e-mail recebido de ser rebaixado para uma conexão sem criptografia.',
      `_mta-sts.${domain}  TXT  "v=STSv1; id=<data>"  e publique a política em https://mta-sts.${domain}/.well-known/mta-sts.txt`);
}

function checkTlsRpt(recs, domain, skip) {
  if (skip) return mk('tlsrpt', 'TLS-RPT', 0, 0, 'info', skip);
  return recs.length
    ? mk('tlsrpt', 'TLS-RPT', 0, 2, 'pass', 'Registro TLS-RPT publicado.', null, recs[0])
    : mk('tlsrpt', 'TLS-RPT', 0, 0, 'info', 'Sem TLS-RPT: recurso opcional para receber relatórios de falhas de criptografia no e-mail.',
      `_smtp._tls.${domain}  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@${domain}"`);
}

async function checkEmail(host, { dkim: extraSelector, resolver = defaultResolver(), smtpProbe, fetchPolicy, dohQuery } = {}) {
  const domain = registrable(host);
  const txtOf = (name) => attempt(async () => (await resolver.resolveTxt(name)).map((chunks) => chunks.join('')));
  const getTxt = async (name) => {
    const r = await txtOf(name);
    if (r.s === 'err') { const e = new Error('dns'); e.code = r.code; throw e; }
    return r.data;
  };

  const [mx, apex] = await Promise.all([attempt(() => resolver.resolveMx(domain)), txtOf(domain)]);
  if (mx.s === 'nx' && apex.s === 'nx') throw new Error(`O domínio ${domain} não existe (NXDOMAIN).`);

  const selectors = [...new Set([...(extraSelector ? [extraSelector.toLowerCase()] : []), ...COMMON_SELECTORS])];
  const [spf, dmarc, mtasts, tlsrpt, dkimFound] = await Promise.all([
    analyzeSpf(domain, getTxt),
    txtOf(`_dmarc.${domain}`),
    txtOf(`_mta-sts.${domain}`),
    txtOf(`_smtp._tls.${domain}`),
    Promise.all(selectors.map(async (selector) => {
      const r = await txtOf(`${selector}._domainkey.${domain}`);
      const rec = r.s === 'ok' ? r.data.find((x) => /(^|;)\s*p=/i.test(x)) : null;
      return rec ? { selector, rec } : null;
    })),
  ]);
  const dkimList = dkimFound.filter(Boolean);
  const mtaRecs = mtasts.data.filter((x) => /^v=STSv1/i.test(x.trim()));
  const rptRecs = tlsrpt.data.filter((x) => /^v=TLSRPTv1/i.test(x.trim()));

  const { noMail, check: mxCheck } = checkMx(mx);
  const spfCheck = checkSpf(spf, noMail);
  const onlyDenySpf = spf.records.length === 1 && /^v=spf1\s+-all\s*$/i.test(spf.records[0].trim());
  const dkimSkip = noMail && onlyDenySpf ? 'Não aplicável: o domínio não envia nem recebe e-mail (SPF -all, sem MX).' : null;
  const mailSkip = noMail ? 'Não aplicável: o domínio não recebe e-mail.' : null;

  // ---- verificações avançadas (consultas a servidores de e-mail e à política MTA-STS) ----
  const dmarcRec = dmarc.data.find((x) => /^v=DMARC1\s*(;|$)/i.test(x.trim())) || null;
  const dmarcTags = dmarcRec ? parseTags(dmarcRec) : {};
  const dmarcPolicy = (dmarcTags.p || '').toLowerCase();
  const doProbe = smtpProbe || X.probesEnabled();
  const doPolicy = fetchPolicy || X.probesEnabled();
  const targets = !noMail && mx.s === 'ok' ? await X.mxTargets(mx.data, resolver) : [];
  const probeFn = smtpProbe || X.smtpProbe;
  const results = doProbe && targets.length
    ? await Promise.all(targets.filter((t) => t.ip).map((t) => probeFn(t.host, t.ip).catch((e) => ({ host: t.host, ip: t.ip, reachable: false, error: e.message }))))
    : [];
  let policyRes = null;
  if (!mailSkip && mtaRecs.length && doPolicy) policyRes = await (fetchPolicy || X.fetchPolicy)(domain);

  const extra = [];
  if (!mailSkip) {
    extra.push(...X.checkStartTls(results));
    if (policyRes) extra.push(X.checkMtaStsPolicy(policyRes, targets.map((t) => t.host), domain));
    const rep = await X.checkDmarcReports(dmarcRec, domain, txtOf);
    if (rep) extra.push(rep);
    const bimi = await txtOf(`default._bimi.${domain}`);
    extra.push(X.checkBimi(bimi.data, dmarcPolicy, !dmarcTags.pct || Number(dmarcTags.pct) === 100));
    const dnssecOf = async (h) => { const c = await checkDnssec(h, dohQuery ? { dohQuery } : {}); return c.max === 0 ? null : c.status === 'pass'; };
    const dane = targets.length ? await X.checkDane(targets, resolver, dnssecOf) : null;
    if (dane) extra.push(dane);
    const rev = typeof resolver.reverse === 'function' ? await X.checkReverse(targets, resolver) : null;
    if (rev) extra.push(rev);
  }

  const checks = [
    mxCheck, spfCheck, checkDmarc(dmarc, domain), checkDkim(dkimList, extraSelector, dkimSkip),
    checkMtaSts(mtaRecs, domain, mailSkip, !!policyRes), checkTlsRpt(rptRecs, domain, mailSkip), ...extra,
  ];
  const lines = [
    `Domínio analisado: ${domain}`,
    `MX: ${mx.s === 'ok' ? (mx.data.map((m) => `${m.priority} ${m.exchange || '.'}`).join(', ') || '-') : '-'}`,
    `SPF: ${spf.records.join(' | ') || '-'}`,
    `DMARC: ${dmarc.data.filter((x) => /^v=DMARC1/i.test(x.trim())).join(' | ') || '-'}`,
    `DKIM: ${dkimList.map((k) => k.selector).join(', ') || 'nenhum seletor encontrado'}`,
    `MTA-STS: ${mtaRecs[0] || '-'}`,
    `TLS-RPT: ${rptRecs[0] || '-'}`,
  ];
  const details = [{ label: 'Registros encontrados', lines }];
  const probed = results.filter((r) => r.host);
  if (probed.length) {
    details.push({
      label: 'Conexão aos servidores de e-mail (porta 25)',
      lines: probed.map((r) => (r.reachable
        ? `${r.host} [${r.ip}] ${r.starttls ? `STARTTLS ${r.protocol || '(handshake falhou)'}` : 'sem STARTTLS'}${r.banner ? ` · ${r.banner}` : ''}`
        : `${r.host} [${r.ip}] inacessível (${r.error})`)),
    });
  }
  return { ...finish(checks), details };
}

module.exports = { checkEmail, analyzeSpf };
