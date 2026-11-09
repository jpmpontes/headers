'use strict';
// Verificações de DNS:
//  - básicas: resolução (A/AAAA), IPv6, servidores de nomes (NS) e CAA;
//  - avançadas: saúde dos NS (consulta direta), sanidade do SOA, TTL, diversidade de rede dos NS e riscos de CNAME.
// O resolvedor e a consulta direta a servidores são injetáveis (opções "resolver" e "serverQuery") para testes sem rede.
// Regra: o que não puder ser testado fica de fora da nota (max 0), nunca vira penalidade.
const dns = require('node:dns');
const { isBlockedIP } = require('./ssrf');
const { checkDnssec } = require('./dnssec');
const { mk, finish, attempt, climb, registrable, defaultResolver } = require('./common');

const MAX_NS_QUERIED = 6;
const SERVER_TIMEOUT_MS = 2500;

// Serviços de terceiros em que um CNAME esquecido pode permitir "subdomain takeover".
const TAKEOVER_PROVIDERS = [
  ['github.io', 'GitHub Pages'], ['herokuapp.com', 'Heroku'], ['herokudns.com', 'Heroku'], ['azurewebsites.net', 'Azure App Service'],
  ['cloudapp.net', 'Azure Cloud Services'], ['trafficmanager.net', 'Azure Traffic Manager'], ['blob.core.windows.net', 'Azure Blob Storage'],
  ['azureedge.net', 'Azure CDN'], ['s3.amazonaws.com', 'Amazon S3'], ['elasticbeanstalk.com', 'AWS Elastic Beanstalk'],
  ['cloudfront.net', 'Amazon CloudFront'], ['fastly.net', 'Fastly'], ['pantheonsite.io', 'Pantheon'], ['ghost.io', 'Ghost'],
  ['myshopify.com', 'Shopify'], ['surge.sh', 'Surge'], ['bitbucket.io', 'Bitbucket'], ['zendesk.com', 'Zendesk'],
  ['statuspage.io', 'Statuspage'], ['readme.io', 'ReadMe'], ['netlify.app', 'Netlify'], ['vercel.app', 'Vercel'],
];
const providerOf = (name) => (TAKEOVER_PROVIDERS.find(([sfx]) => name === sfx || name.endsWith(`.${sfx}`)) || [])[1] || null;

const fmtCaa = (e) => {
  const tag = ['issue', 'issuewild', 'iodef'].find((t) => e[t] !== undefined);
  return tag ? `${e.critical ? 128 : 0} ${tag} "${e[tag]}"` : JSON.stringify(e);
};

// Procura o registro no nome e depois nos pais (até o domínio registrável).
async function firstWith(names, fn) {
  let sawErr = null;
  let allNx = true;
  for (const name of names) {
    const r = await attempt(() => fn(name));
    if (r.s === 'ok' && r.data.length) return { name, data: r.data, s: 'ok' };
    if (r.s === 'err') sawErr = r.code;
    if (r.s !== 'nx') allNx = false;
  }
  return { name: null, data: [], s: sawErr ? 'err' : allNx ? 'nx' : 'none', code: sawErr };
}

// Consulta DIRETA a um servidor de nomes (sem recursão do nosso resolvedor): usada para saúde dos NS e TTL.
function defaultServerQuery(ip, name, type) {
  const r = new dns.promises.Resolver({ timeout: SERVER_TIMEOUT_MS, tries: 1 });
  r.setServers([ip]);
  if (type === 'SOA') return r.resolveSoa(name);
  if (type === 'A') return r.resolve4(name, { ttl: true });
  return r.resolve6(name, { ttl: true });
}

const addrOf = (x) => (typeof x === 'string' ? x : x.address);

// ---------- 1. Saúde dos servidores de nomes ----------
// SSRF: os IPs vêm do DNS do domínio analisado, então IPs privados/reservados NUNCA são consultados.
async function probeNameservers(nsList, zone, { resolver, serverQuery }) {
  const allowPrivate = process.env.ALLOW_PRIVATE === '1';
  return Promise.all(nsList.slice(0, MAX_NS_QUERIED).map(async (ns) => {
    const e = { ns, ips: [], ip: null, state: 'untested', serial: null, soa: null, ms: null, err: null };
    const [r4, r6] = await Promise.all([attempt(() => resolver.resolve4(ns)), attempt(() => resolver.resolve6(ns))]);
    e.ips = [...r4.data.map(addrOf), ...r6.data.map(addrOf)];
    if (!e.ips.length) {
      if (r4.s === 'nx' && r6.s === 'nx') { e.state = 'fail'; e.err = 'o nome do servidor não existe (NXDOMAIN)'; }
      return e;
    }
    e.ip = allowPrivate ? e.ips[0] : e.ips.find((ip) => !isBlockedIP(ip));
    if (!e.ip) { e.state = 'fail'; e.err = `aponta para endereço privado/reservado (${e.ips[0]}); não foi consultado`; return e; }
    const t0 = Date.now();
    try {
      const res = await serverQuery(e.ip, zone, 'SOA');
      const soa = Array.isArray(res) ? res[0] : res;
      e.state = 'ok'; e.soa = soa; e.serial = soa && soa.serial; e.ms = Date.now() - t0;
    } catch (err) { e.state = 'fail'; e.err = err.code || err.message || 'erro'; }
    return e;
  }));
}

function checkNsHealth(probes) {
  const tested = probes.filter((p) => p.state !== 'untested');
  if (!tested.length) {
    return mk('nshealth', 'Saúde dos servidores de nomes', 0, 0, 'info', 'Não foi possível testar os servidores de nomes diretamente (endereços IP não resolvidos). Fora da nota.');
  }
  const ok = tested.filter((p) => p.state === 'ok');
  const bad = tested.filter((p) => p.state === 'fail');
  const serials = [...new Set(ok.map((p) => p.serial))];
  const whyList = bad.map((p) => `${p.ns}: ${p.err}`).join('; ');
  const fix = 'Confira no provedor de DNS se todos os servidores listados na delegação estão ativos, respondem pela zona e têm o mesmo conteúdo.';
  const max = 20;

  if (!ok.length) {
    const positive = bad.some((p) => /REFUSED|SERVFAIL|NXDOMAIN|privado/.test(p.err));
    return mk('nshealth', 'Saúde dos servidores de nomes', max, 0, positive ? 'fail' : 'warn',
      positive
        ? `Nenhum servidor respondeu corretamente pela zona (${whyList}). Pode ser delegação quebrada (lame delegation).`
        : `Nenhum servidor respondeu à consulta direta (${whyList}). Pode ser bloqueio de consultas diretas ou falha real; confirme no seu provedor.`,
      fix);
  }
  if (bad.length) {
    return mk('nshealth', 'Saúde dos servidores de nomes', max, Math.round((max * ok.length) / tested.length), 'warn',
      `${ok.length} de ${tested.length} servidores responderam. Com problema: ${whyList}.`, fix);
  }
  if (serials.length > 1) {
    return mk('nshealth', 'Saúde dos servidores de nomes', max, 12, 'warn',
      `Os servidores respondem, mas com número de série (SOA) diferente: ${ok.map((p) => `${p.ns}=${p.serial}`).join(', ')}. A zona pode estar dessincronizada (ou a propagação ainda está em andamento).`,
      'Verifique a replicação entre o servidor primário e os secundários.');
  }
  return mk('nshealth', 'Saúde dos servidores de nomes', max, max, 'pass',
    `Todos os ${ok.length} servidores responderam diretamente e estão sincronizados (serial ${serials[0]}).`, null,
    ok.map((p) => `${p.ns} (${p.ip}) ${p.ms} ms`).join('\n'));
}

// ---------- 2. Sanidade do SOA ----------
function checkSoa(soa) {
  if (!soa) return null;
  const issues = [];
  if (soa.refresh < 1200) issues.push(`refresh muito curto (${soa.refresh}s; recomendado ≥ 1200)`);
  else if (soa.refresh > 86400) issues.push(`refresh muito longo (${soa.refresh}s; recomendado ≤ 86400)`);
  if (soa.retry >= soa.refresh) issues.push(`retry (${soa.retry}s) deveria ser menor que o refresh (${soa.refresh}s)`);
  if (soa.expire < 604800) issues.push(`expire curto (${soa.expire}s; recomendado ≥ 604800, ou 7 dias)`);
  if (soa.minttl > 86400) issues.push(`cache negativo longo (minimum ${soa.minttl}s): respostas "não existe" ficam em cache por muito tempo`);
  else if (soa.minttl < 60) issues.push(`cache negativo muito curto (minimum ${soa.minttl}s)`);
  const value = `${soa.nsname} ${soa.hostmaster} serial ${soa.serial} refresh ${soa.refresh} retry ${soa.retry} expire ${soa.expire} minimum ${soa.minttl}`;
  return issues.length
    ? mk('soa', 'SOA (parâmetros da zona)', 10, Math.max(4, 10 - 3 * issues.length), 'warn', `Parâmetros fora do recomendado: ${issues.join('; ')}.`,
      'Valores usuais: refresh 7200, retry 3600, expire 1209600, minimum 3600.', value)
    : mk('soa', 'SOA (parâmetros da zona)', 10, 10, 'pass', 'Parâmetros dentro das faixas recomendadas.', null, value);
}

// ---------- 3. TTL ----------
function checkTtl(ttl) {
  if (ttl === null) return null;
  if (ttl < 60) return mk('ttl', 'TTL do endereço (A/AAAA)', 5, 3, 'warn', `TTL de ${ttl}s é muito baixo: aumenta a carga nos servidores de nomes. É normal apenas se houver failover/CDN que exija troca rápida.`, 'Para sites estáveis, use 300 a 3600 segundos.', `${ttl}s`);
  if (ttl > 86400) return mk('ttl', 'TTL do endereço (A/AAAA)', 5, 3, 'warn', `TTL de ${ttl}s é muito alto: mudanças de IP demoram a propagar.`, 'Reduza para 3600 a 86400 segundos (e baixe antes de migrações).', `${ttl}s`);
  return mk('ttl', 'TTL do endereço (A/AAAA)', 5, 5, 'pass', `TTL de ${ttl}s (medido direto no servidor autoritativo).`, null, `${ttl}s`);
}

// ---------- 4. Diversidade de rede dos NS ----------
const netKey = (ip) => (ip.includes(':') ? ip.toLowerCase().split(':').slice(0, 3).join(':') : ip.split('.').slice(0, 3).join('.'));

function checkDiversity(probes) {
  const withIp = probes.filter((p) => p.ips.length);
  if (withIp.length < 2) return null;
  const groups = new Set(withIp.map((p) => netKey(p.ips[0])));
  return groups.size >= 2
    ? mk('diversity', 'Diversidade de rede dos NS', 10, 10, 'pass', `Os servidores de nomes estão em ${groups.size} redes diferentes.`)
    : mk('diversity', 'Diversidade de rede dos NS', 10, 4, 'warn', 'Todos os servidores de nomes estão na mesma rede: uma falha de rede ou do provedor derruba todos de uma vez.',
      'Use servidores de nomes em redes (de preferência provedores) diferentes.', withIp.map((p) => `${p.ns} ${p.ips[0]}`).join('\n'));
}

// ---------- 5. Riscos de CNAME ----------
async function cnameChain(host, resolver) {
  const chain = [];
  let name = host;
  for (let i = 0; i < 6; i++) {
    const r = await attempt(() => resolver.resolveCname(name));
    if (!(r.s === 'ok' && r.data.length)) break;
    name = String(r.data[0]).replace(/\.$/, '').toLowerCase();
    chain.push(name);
  }
  return chain;
}

async function checkCnameRisks(host, resolver) {
  const [chain, mx] = await Promise.all([cnameChain(host, resolver), attempt(() => resolver.resolveMx(registrable(host)))]);
  const mxCname = [];
  for (const m of (mx.data || []).slice(0, 5)) {
    const r = await attempt(() => resolver.resolveCname(m.exchange));
    if (r.s === 'ok' && r.data.length) mxCname.push(`${m.exchange} → ${r.data[0]}`);
  }
  if (!chain.length && !mxCname.length) return null;

  const final = chain[chain.length - 1];
  const notes = [];
  let pts = 10;
  let status = 'pass';
  const fail = (p, msg) => { pts = Math.min(pts, p); status = 'fail'; notes.push(msg); };
  const warn = (p, msg) => { pts = Math.min(pts, p); if (status === 'pass' || status === 'info') status = 'warn'; notes.push(msg); };

  if (chain.length && host === registrable(host)) fail(0, 'há um CNAME na raiz do domínio (apex), inválido pela RFC 1034: conflita com NS/SOA/MX e pode quebrar o e-mail');
  if (chain.length) {
    const [a, aaaa] = await Promise.all([attempt(() => resolver.resolve4(final)), attempt(() => resolver.resolve6(final))]);
    if (a.s === 'nx' && aaaa.s === 'nx') fail(0, `o destino ${final} não existe (NXDOMAIN): risco de "subdomain takeover" (alguém registrar o destino e assumir o subdomínio)`);
  }
  if (mxCname.length) warn(5, `MX apontando para CNAME (${mxCname.join('; ')}), proibido pela RFC 2181; alguns servidores de e-mail rejeitam`);

  const provider = chain.length ? providerOf(final) : null;
  if (provider && status === 'pass') {
    status = 'info';
    notes.push(`aponta para ${provider} (${final}). Confirme que o recurso ainda existe e é seu: CNAMEs esquecidos para serviços de terceiros permitem "subdomain takeover"`);
  }
  const value = [chain.length ? `${host} → ${chain.join(' → ')}` : null, ...mxCname].filter(Boolean).join('\n');
  if (!notes.length) return mk('cname', 'Riscos de CNAME', 10, 10, 'pass', `O CNAME aponta para ${final}, que resolve normalmente.`, null, value);
  return mk('cname', 'Riscos de CNAME', 10, pts, status, `${notes[0].charAt(0).toUpperCase()}${notes[0].slice(1)}${notes.length > 1 ? `; ${notes.slice(1).join('; ')}` : ''}.`,
    status === 'info' ? null : 'Corrija ou remova o registro; para e-mail, aponte o MX diretamente para um nome com registro A/AAAA.', value);
}

async function checkDns(host, { resolver = defaultResolver(), serverQuery = defaultServerQuery, dohQuery } = {}) {
  const names = climb(host);
  const [a, aaaa, cname, ns, caa] = await Promise.all([
    attempt(() => resolver.resolve4(host)),
    attempt(() => resolver.resolve6(host)),
    attempt(() => resolver.resolveCname(host)),
    firstWith(names, (n) => resolver.resolveNs(n)),
    firstWith(names, (n) => resolver.resolveCaa(n)),
  ]);

  if ([a, aaaa, cname].every((r) => r.s === 'nx')) throw new Error(`O domínio ${host} não existe (NXDOMAIN).`);
  if ([a, aaaa, cname].every((r) => r.s === 'err')) throw new Error(`Falha ao consultar o DNS (${a.code}). Tente novamente em instantes.`);

  const v4 = a.data;
  const v6 = aaaa.data;
  const cn = cname.data;
  const checks = [];

  // Resolução: o essencial para o site existir
  if (v4.length) checks.push(mk('addr', 'Resolução (IPv4)', 35, 35, 'pass', `Resolve para ${v4.length} endereço(s) IPv4.`, null, v4.join(', ')));
  else if (v6.length) checks.push(mk('addr', 'Resolução (IPv4)', 35, 18, 'warn', 'Resolve apenas por IPv6: quem usa só IPv4 não consegue acessar.', 'Adicione um registro A com o IPv4 do servidor.', v6.join(', ')));
  else if (cn.length) checks.push(mk('addr', 'Resolução (IPv4)', 35, 0, 'fail', `Há um CNAME para ${cn[0]}, mas o destino não resolve: risco de "subdomain takeover" (alguém registrar o destino e assumir o subdomínio).`, 'Corrija o destino do CNAME ou remova o registro.', cn.join(', ')));
  else checks.push(mk('addr', 'Resolução (IPv4)', 35, 0, 'fail', 'O nome não resolve para nenhum endereço (sem A nem AAAA).', 'Crie um registro A (ou CNAME) apontando para o servidor.'));

  checks.push(v6.length
    ? mk('ipv6', 'IPv6 (AAAA)', 15, 15, 'pass', `${v6.length} endereço(s) IPv6.`, null, v6.join(', '))
    : mk('ipv6', 'IPv6 (AAAA)', 15, 0, 'warn', 'Sem IPv6. Não é um erro, mas é recomendado se a hospedagem oferecer.', 'Adicione um registro AAAA se o servidor tiver IPv6.'));

  const nsList = ns.data;
  if (nsList.length >= 2) checks.push(mk('ns', 'Servidores de nomes (NS)', 30, 30, 'pass', `${nsList.length} servidores de nomes na zona ${ns.name}.`, null, nsList.join('\n')));
  else if (nsList.length === 1) checks.push(mk('ns', 'Servidores de nomes (NS)', 30, 21, 'warn', 'Apenas 1 servidor de nomes: sem redundância, se ele cair o domínio some.', 'Use pelo menos 2 servidores de nomes, de preferência em redes diferentes.', nsList.join('\n')));
  else if (ns.s === 'err') checks.push(mk('ns', 'Servidores de nomes (NS)', 30, 0, 'warn', `Não foi possível consultar os servidores de nomes (${ns.code}).`));
  else checks.push(mk('ns', 'Servidores de nomes (NS)', 30, 0, 'fail', 'Nenhum servidor de nomes encontrado para a zona.', 'Confira a delegação do domínio no registrador.'));

  const caaList = caa.data.map(fmtCaa);
  if (caaList.length) {
    const inherited = caa.name !== host ? ' (vale também para este subdomínio)' : '';
    checks.push(mk('caa', 'CAA (quem pode emitir certificados)', 20, 20, 'pass', `CAA publicado em ${caa.name}${inherited}.`, null, caaList.join('\n')));
  } else if (caa.s === 'err') checks.push(mk('caa', 'CAA (quem pode emitir certificados)', 20, 0, 'warn', `Não foi possível consultar o CAA (${caa.code}).`));
  else checks.push(mk('caa', 'CAA (quem pode emitir certificados)', 20, 0, 'warn',
    'Sem registro CAA: qualquer autoridade certificadora pode emitir certificados para o domínio.',
    'Exemplo (ajuste para a sua CA): 0 issue "letsencrypt.org"'));

  // ---- verificações avançadas ----
  const zone = ns.name;
  const probes = nsList.length && zone ? await probeNameservers(nsList, zone, { resolver, serverQuery }) : [];
  checks.push(checkNsHealth(probes));

  // SOA: prefere o que o servidor autoritativo respondeu (valores reais); senão, o do resolvedor
  let soa = (probes.find((p) => p.state === 'ok') || {}).soa || null;
  if (!soa && zone) {
    const r = await attempt(async () => resolver.resolveSoa(zone));
    if (r.s === 'ok' && r.data) soa = Array.isArray(r.data) ? r.data[0] : r.data;
  }
  const soaCheck = checkSoa(soa);
  if (soaCheck) checks.push(soaCheck);

  // TTL: só vale medido no servidor autoritativo (o do resolvedor vem reduzido pelo cache)
  let ttl = null;
  const first = probes.find((p) => p.state === 'ok');
  if (first && (v4.length || v6.length)) {
    for (const type of v4.length ? ['A', 'AAAA'] : ['AAAA']) {
      try {
        const rows = await serverQuery(first.ip, host, type);
        const ttls = (rows || []).map((r) => r.ttl).filter((t) => Number.isFinite(t));
        if (ttls.length) { ttl = Math.min(...ttls); break; }
      } catch { /* sem TTL medido */ }
    }
  }
  const ttlCheck = checkTtl(ttl);
  if (ttlCheck) checks.push(ttlCheck);

  const divCheck = checkDiversity(probes);
  if (divCheck) checks.push(divCheck);

  checks.push(await checkDnssec(host, dohQuery ? { dohQuery } : {}));

  const cnameCheck = await checkCnameRisks(host, resolver);
  if (cnameCheck) checks.push(cnameCheck);

  const lines = [
    `Nome consultado: ${host}${zone ? ` · zona: ${zone}` : ''}`,
    `A: ${v4.join(', ') || '-'}`,
    `AAAA: ${v6.join(', ') || '-'}`,
    `CNAME: ${cn.join(', ') || '-'}`,
    `NS: ${nsList.join(', ') || '-'}`,
    `CAA: ${caaList.join(' | ') || '-'}`,
  ];
  const details = [{ label: 'Registros encontrados', lines }];
  if (probes.length) {
    details.push({
      label: 'Consulta direta aos servidores de nomes',
      lines: probes.map((p) => {
        if (p.state === 'ok') return `${p.ns} [${p.ip}] respondeu: serial ${p.serial} (${p.ms} ms)`;
        if (p.state === 'fail') return `${p.ns}${p.ip ? ` [${p.ip}]` : ''} sem resposta válida: ${p.err}`;
        return `${p.ns}: não testado (endereço IP não resolvido)`;
      }),
    });
  }
  return { ...finish(checks), details };
}

module.exports = { checkDns };
