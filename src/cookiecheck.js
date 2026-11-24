'use strict';
// Cookies e privacidade (orientativo, fora da nota geral).
// O que vê: cookies definidos pelo SERVIDOR (Set-Cookie, inclusive nos redirects) e o HTML inicial da página
// (rastreadores, plataformas de consentimento, links de política). O que NÃO vê: cookies criados por JavaScript
// nem o comportamento do banner. Por isso o resultado fala em "indícios", nunca em conformidade com a LGPD.
// Valores de cookies nunca são guardados nem exibidos: só nome e atributos.
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const zlib = require('node:zlib');
const { validateUrl, resolvePublic } = require('./ssrf');
const { mk } = require('./common');

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8000;
const MAX_HTML = 400 * 1024;
const UA = 'CorevaHeadersScanner/0.1';
const DAY = 86400;

// ---------- coleta ----------
function requestPage(u, addr) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const req = lib.request({
      hostname: host, port: u.port || undefined, path: u.pathname + u.search, method: 'GET',
      servername: net.isIP(host) ? undefined : host,
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*;q=0.5', 'Accept-Encoding': 'identity', 'Accept-Language': 'pt-BR,pt;q=0.9' },
      lookup: (_h, opts, cb) => (opts && opts.all ? cb(null, [{ address: addr.address, family: addr.family }]) : cb(null, addr.address, addr.family)),
    });
    const timer = setTimeout(() => req.destroy(new Error('Tempo esgotado (8s)')), TIMEOUT_MS);
    req.on('response', (res) => {
      const out = { status: res.statusCode, headers: res.headers };
      const loc = res.headers.location;
      const isHtml = /html/i.test(res.headers['content-type'] || 'text/html');
      if ((res.statusCode >= 300 && res.statusCode < 400 && loc) || res.statusCode >= 400 || !isHtml) { clearTimeout(timer); res.destroy(); return resolve({ ...out, html: null }); }
      let stream = res;
      const enc = String(res.headers['content-encoding'] || '').toLowerCase();
      if (enc === 'gzip') stream = res.pipe(zlib.createGunzip());
      else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
      else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
      const chunks = [];
      let size = 0, truncated = false, done = false;
      const finish = () => { if (done) return; done = true; clearTimeout(timer); res.destroy(); resolve({ ...out, html: Buffer.concat(chunks).toString('utf8'), truncated }); };
      stream.on('data', (c) => {
        size += c.length;
        if (size > MAX_HTML) { truncated = true; chunks.push(c.subarray(0, c.length - (size - MAX_HTML))); finish(); } else chunks.push(c);
      });
      stream.on('end', finish);
      stream.on('error', () => finish()); // corpo corrompido: usa o que veio
    });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

// Segue redirects (revalidando cada salto contra SSRF), juntando os Set-Cookie de todas as respostas.
async function fetchPage(rawUrl) {
  let u = validateUrl(rawUrl);
  const chain = [];
  const setCookies = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const addr = await resolvePublic(u.hostname);
    let res;
    try { res = await requestPage(u, addr); } catch (e) { throw new Error(`Falha ao conectar em ${u.host}: ${e.message}${e.code ? ` (${e.code})` : ''}`); }
    chain.push({ url: u.href, status: res.status });
    const sc = res.headers['set-cookie'];
    if (sc) for (const c of Array.isArray(sc) ? sc : [sc]) setCookies.push({ raw: c, host: u.hostname, https: u.protocol === 'https:' });
    const loc = res.headers.location;
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      if (i === MAX_REDIRECTS) throw new Error('Redirects demais (limite 5)');
      u = validateUrl(new URL(loc, u).href);
      continue;
    }
    return { finalUrl: u.href, status: res.status, chain, setCookies, html: res.html, truncated: !!res.truncated };
  }
  throw new Error('Redirects demais');
}

// ---------- cookies ----------
function parseSetCookie(raw, now = Date.now()) {
  const parts = String(raw).split(';').map((s) => s.trim());
  const eq = parts[0].indexOf('=');
  const name = (eq < 0 ? parts[0] : parts[0].slice(0, eq)).trim();
  const c = { name, domain: null, path: null, secure: false, httpOnly: false, sameSite: null, lifetime: null /* segundos; null = sessão */ };
  let maxAge = null, expires = null;
  for (const p of parts.slice(1)) {
    const i = p.indexOf('=');
    const k = (i < 0 ? p : p.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : p.slice(i + 1).trim();
    if (k === 'secure') c.secure = true;
    else if (k === 'httponly') c.httpOnly = true;
    else if (k === 'samesite') c.sameSite = v.toLowerCase();
    else if (k === 'domain') c.domain = v.replace(/^\./, '').toLowerCase();
    else if (k === 'path') c.path = v;
    else if (k === 'max-age' && /^-?\d+$/.test(v)) maxAge = Number(v);
    else if (k === 'expires') { const t = Date.parse(v); if (!Number.isNaN(t)) expires = t; }
  }
  if (maxAge !== null) c.lifetime = maxAge;
  else if (expires !== null) c.lifetime = Math.round((expires - now) / 1000);
  return c;
}

// Classificação ESTIMADA pelo nome (categorias do guia da ANPD: necessários, analíticos/estatísticos, publicidade...).
const COOKIE_RULES = [
  ['analitica', /^(_ga|_ga_.+|_gid|_gat.*|__utm[a-z]|_hj.+|_clck|_clsk|ajs_.+|mp_.+|amplitude_id.*|_pk_.+|_pendo.*|_vwo.*|_vis_opt.*|__hstc|_dc_gtm_.+|ph_.+|_pla.*)$/i, 'Analítica'],
  ['marketing', /^(_fbp|_fbc|fr|_gcl_.+|ide|test_cookie|nid|anid|1p_jar|__gads|__gpi|_uet.+|muid|_ttp|_tt_.+|li_.+|bcookie|lidc|_pin_unauth|_scid|__hssc|__hs.+|hubspotutk|_rdt_uuid|personalization_id|guest_id|ar_debug|_kuid_|_fbq)$/i, 'Publicidade/marketing'],
  ['preferencias', /^(cookieconsent_.+|cookieconsent|cookiebot|optanonconsent|optanonalertboxclosed|euconsent-v2|_iub_cs-.+|cookielawinfo-.+|cmplz_.+|viewed_cookie_policy|cookie_notice_accepted|termly.*|lang|locale|language)$/i, 'Preferências/consentimento'],
  ['necessario', /^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid.+|connect\.sid|laravel_session|sessionid|session|sid|ci_session|_session_id|xsrf-token|csrftoken|_csrf|csrf.*|__cf_bm|cf_clearance|__cfduid|awsalb.*|awsalbcors|arraffinity.*|bigipserver.+|wordpress_test_cookie|wp-settings-.+|wordpress_logged_in_.+|woocommerce_.+|wp_woocommerce_session_.+|__host-.+|__secure-.+)$/i, 'Necessário (estimado)'],
];
function classifyCookie(name) {
  for (const [cat, re, label] of COOKIE_RULES) if (re.test(name)) return { cat, label };
  return { cat: 'desconhecido', label: 'Não classificado' };
}
const SESSION_LIKE = /(sess|sid\b|auth|token|login|jwt)/i;
const CSRF_LIKE = /(csrf|xsrf)/i;

// ---------- HTML ----------
const TRACKERS = [
  ['Google Analytics', 'analitica', ['google-analytics.com', 'analytics.google.com', 'googletagmanager.com/gtag/js', 'googleanalyticsobject']],
  ['Google Tag Manager', 'gerenciador', ['googletagmanager.com/gtm.js', 'googletagmanager.com/ns.html']],
  ['Google Ads / DoubleClick', 'marketing', ['doubleclick.net', 'googleadservices.com', 'googlesyndication.com']],
  ['Meta (Facebook) Pixel/SDK', 'marketing', ['connect.facebook.net', 'facebook.com/tr']],
  ['Hotjar', 'analitica', ['static.hotjar.com', 'hotjar.com']],
  ['Microsoft Clarity', 'analitica', ['clarity.ms']],
  ['Microsoft Advertising (UET)', 'marketing', ['bat.bing.com']],
  ['LinkedIn Insight Tag', 'marketing', ['snap.licdn.com', 'px.ads.linkedin.com']],
  ['TikTok Pixel', 'marketing', ['analytics.tiktok.com']],
  ['X (Twitter) Pixel', 'marketing', ['static.ads-twitter.com', 'analytics.twitter.com']],
  ['Pinterest Tag', 'marketing', ['s.pinimg.com/ct/core.js']],
  ['HubSpot', 'marketing', ['js.hs-scripts.com', 'js.hsforms.net', 'js.hs-analytics.net']],
  ['Segment', 'analitica', ['cdn.segment.com']],
  ['Mixpanel', 'analitica', ['cdn.mxpnl.com', 'mixpanel.com']],
  ['Matomo', 'analitica', ['matomo.js', 'piwik.js', 'matomo.php']],
  ['Plausible', 'analitica', ['plausible.io/js']],
  ['YouTube incorporado', 'externo', ['youtube.com/embed', 'youtube-nocookie.com/embed']],
  ['Google Fonts (servidores do Google)', 'externo', ['fonts.googleapis.com', 'fonts.gstatic.com']],
];
const CMPS = [
  ['Cookiebot', ['consent.cookiebot.com', 'cookiebot.com', 'cybotcookiebot']],
  ['OneTrust', ['cdn.cookielaw.org', 'onetrust.com', 'optanon']],
  ['iubenda', ['iubenda.com', '_iub.']],
  ['Termly', ['termly.io']],
  ['CookieServe', ['cookieserve.com']],
  ['CookieYes', ['cookieyes.com', 'cky-consent']],
  ['Complianz', ['complianz', 'cmplz']],
  ['Osano', ['osano.com']],
  ['Usercentrics', ['usercentrics.eu', 'usercentrics.com']],
  ['Didomi', ['didomi.io', 'privacy-center.org']],
  ['Quantcast Choice', ['quantcast.mgr.consensu.org']],
  ['TrustArc', ['trustarc.com', 'truste.com']],
  ['Cookie Script', ['cookie-script.com']],
  ['Axeptio', ['axept.io']],
  ['Google Funding Choices', ['fundingchoicesmessages.google.com']],
  ['Cookie Notice / CookieLawInfo (WordPress)', ['cookie-notice', 'cookie-law-info']],
  ['CookieConsent (código aberto)', ['cookieconsent.min.js', 'cookieconsent.js']],
  ['Klaro', ['klaro.js', 'klaro.min.js']],
];
const BANNER_HINT = /(?:id|class)\s*=\s*["'][^"']*cookie[-_ ]?(?:banner|consent|notice|bar|law|popup|alert|warning)|aceitar\s+(?:todos\s+os\s+)?cookies|aceito\s+os\s+cookies|(?:usamos|utilizamos|este\s+site\s+usa|nosso\s+site\s+usa)\s+cookies/i;
const POLICY_ANCHOR = /<a\b[^>]*>/gi;

function scanHtml(html) {
  const low = html.toLowerCase();
  const trackers = TRACKERS.filter(([, , pats]) => pats.some((p) => low.includes(p))).map(([nome, cat]) => ({ nome, cat }));
  const cmps = CMPS.filter(([, pats]) => pats.some((p) => low.includes(p))).map(([nome]) => nome);
  const bannerHint = BANNER_HINT.test(html);
  let privacy = false, cookiePolicy = false;
  for (const m of html.matchAll(/<a\b[^>]*>([\s\S]{0,200}?)<\/a>/gi)) {
    const tag = m[0].slice(0, m[0].indexOf('>') + 1);
    const href = (/href\s*=\s*["']([^"']*)["']/i.exec(tag) || [])[1] || '';
    const hay = `${href} ${m[1].replace(/<[^>]*>/g, ' ')}`.toLowerCase();
    if (/privacidade|privacy|lgpd|prote[cç][aã]o[ -]de[ -]dados|termos[ -]de[ -]uso/.test(hay)) privacy = true;
    if (/cookie/.test(hay)) cookiePolicy = true;
  }
  void POLICY_ANCHOR;
  return { trackers, cmps, bannerHint, privacy, cookiePolicy };
}

// ---------- verificações ----------
const NOTE_JS = 'Só vemos cookies definidos pelo servidor e o HTML inicial: cookies criados por JavaScript e o comportamento do banner exigem um navegador de verdade.';
const isTracking = (t) => t.cat === 'analitica' || t.cat === 'marketing';

function checkBefore(cookies) {
  const lines = cookies.map((c) => `${c.name} — ${c.cls.label}`);
  if (!cookies.length) return mk('ckpre', 'Cookies antes do consentimento', 0, 0, 'pass', 'O servidor não definiu nenhum cookie na primeira visita. ' + NOTE_JS);
  const tracking = cookies.filter((c) => c.cls.cat === 'analitica' || c.cls.cat === 'marketing');
  if (tracking.length) {
    return mk('ckpre', 'Cookies antes do consentimento', 0, 0, 'warn',
      `${tracking.length} cookie${tracking.length > 1 ? 's' : ''} de analítica ou marketing já na primeira resposta (${tracking.map((c) => c.name).join(', ')}). Cookies desse tipo costumam exigir consentimento antes de serem gravados.`,
      'Só carregue as ferramentas que criam esses cookies depois que o visitante consentir. Configure o gerenciador de tags ou a plataforma de consentimento para bloqueá-las até lá.', lines.join('\n'));
  }
  const unk = cookies.filter((c) => c.cls.cat === 'desconhecido');
  if (unk.length) return mk('ckpre', 'Cookies antes do consentimento', 0, 0, 'info', `${unk.length} cookie${unk.length > 1 ? 's' : ''} que não conseguimos classificar pelo nome (${unk.map((c) => c.name).join(', ')}). Confira para que servem: se não forem estritamente necessários, podem exigir consentimento.`, null, lines.join('\n'));
  return mk('ckpre', 'Cookies antes do consentimento', 0, 0, 'pass', 'Só cookies que parecem necessários ou de preferências (classificação estimada pelo nome). ' + NOTE_JS, null, lines.join('\n'));
}

function checkFlags(cookies) {
  if (!cookies.length) return mk('ckflags', 'Atributos de segurança dos cookies', 0, 0, 'pass', 'Nenhum cookie para avaliar.');
  const probs = [];
  let severe = false;
  for (const c of cookies) {
    const miss = [];
    if (c.https && !c.secure) miss.push('Secure');
    if (!c.sameSite) miss.push('SameSite');
    if (SESSION_LIKE.test(c.name) && !CSRF_LIKE.test(c.name) && !c.httpOnly) miss.push('HttpOnly');
    if (c.sameSite === 'none' && !c.secure) { miss.push('Secure (obrigatório com SameSite=None)'); severe = true; }
    if (SESSION_LIKE.test(c.name) && !CSRF_LIKE.test(c.name) && (miss.includes('Secure') || miss.includes('HttpOnly'))) severe = true;
    if (miss.length) probs.push(`${c.name}: falta ${miss.join(', ')}`);
  }
  return probs.length
    ? mk('ckflags', 'Atributos de segurança dos cookies', 0, 0, severe ? 'fail' : 'warn', `Atributos ausentes — ${probs.join('; ')}.`, 'Set-Cookie: sessao=...; Secure; HttpOnly; SameSite=Lax; Path=/\n\nCookies de sessão e de autenticação devem ter Secure e HttpOnly.')
    : mk('ckflags', 'Atributos de segurança dos cookies', 0, 0, 'pass', 'Os cookies têm os atributos de segurança esperados.');
}

function checkExpiry(cookies) {
  const long = cookies.filter((c) => c.cls.cat !== 'necessario' && c.lifetime !== null && c.lifetime > 395 * DAY);
  const lines = cookies.map((c) => `${c.name} — ${c.lifetime === null ? 'sessão' : c.lifetime <= 0 ? 'expira agora (remoção)' : `${Math.round(c.lifetime / DAY)} dia(s)`}`);
  if (long.length) {
    return mk('ckexpiry', 'Validade dos cookies', 0, 0, 'warn',
      `${long.length} cookie${long.length > 1 ? 's' : ''} não essencial${long.length > 1 ? 'is' : ''} com validade acima de 13 meses (${long.map((c) => `${c.name}: ${Math.round(c.lifetime / DAY)} dias`).join(', ')}). Esse prazo costuma ser usado como referência de boas práticas.`,
      'Reduza a validade dos cookies não essenciais (Max-Age) ao mínimo necessário e informe os prazos na política de cookies.', lines.join('\n'));
  }
  return mk('ckexpiry', 'Validade dos cookies', 0, 0, cookies.length ? 'pass' : 'pass', cookies.length ? 'Nenhum cookie não essencial com validade excessiva.' : 'Sem cookies para avaliar.', null, lines.join('\n') || null);
}

function checkTrackers(page, scan, tracking) {
  if (page.html == null) return mk('cktrackers', 'Rastreadores e recursos de terceiros', 0, 0, 'info', 'Não foi possível ler o HTML da página (resposta sem HTML ou com erro), então não procuramos rastreadores.');
  const lines = scan.trackers.map((t) => `${t.nome} — ${{ analitica: 'analítica', marketing: 'publicidade/marketing', gerenciador: 'gerenciador de tags', externo: 'recurso externo' }[t.cat]}`);
  const tr = scan.trackers.filter(isTracking);
  const trail = page.truncated ? ' (analisamos só o início do HTML)' : '';
  if (!scan.trackers.length) return mk('cktrackers', 'Rastreadores e recursos de terceiros', 0, 0, 'pass', `Nenhum rastreador conhecido no HTML inicial${trail}. Ferramentas carregadas por JavaScript depois do carregamento não aparecem aqui.`);
  if (tr.length) {
    return scan.cmps.length
      ? mk('cktrackers', 'Rastreadores e recursos de terceiros', 0, 0, 'info', `Rastreadores no HTML: ${tr.map((t) => t.nome).join(', ')}. Há plataforma de consentimento, mas confirme que eles só carregam depois do aceite.`, 'Teste em uma janela anônima: abra o site, não aceite nada e veja (DevTools → Rede) se esses scripts já carregam.', lines.join('\n'))
      : mk('cktrackers', 'Rastreadores e recursos de terceiros', 0, 0, 'warn', `Rastreadores no HTML: ${tr.map((t) => t.nome).join(', ')}, sem plataforma de consentimento detectada.`, 'Carregue esses scripts somente após o consentimento, por meio de uma plataforma de gestão de consentimento ou de um banner próprio.', lines.join('\n'));
  }
  const fonts = scan.trackers.some((t) => t.nome.startsWith('Google Fonts'));
  return mk('cktrackers', 'Rastreadores e recursos de terceiros', 0, 0, 'info',
    `Recursos de terceiros no HTML: ${scan.trackers.map((t) => t.nome).join(', ')}.${fonts ? ' Fontes carregadas dos servidores do Google enviam o IP do visitante ao Google; considere hospedar as fontes no próprio site.' : ''}`, null, lines.join('\n'));
}

function checkCmp(page, scan, cookies) {
  const tracking = scan.trackers.some(isTracking) || cookies.some((c) => c.cls.cat === 'analitica' || c.cls.cat === 'marketing');
  if (page.html == null) return mk('ckcmp', 'Banner de consentimento', 0, 0, 'info', 'Não foi possível ler o HTML da página, então não procuramos o banner.');
  if (scan.cmps.length) return mk('ckcmp', 'Banner de consentimento', 0, 0, 'pass', `Plataforma de consentimento detectada: ${scan.cmps.join(', ')}. Não conseguimos testar se ela bloqueia os rastreadores até o aceite.`, null, scan.cmps.join('\n'));
  if (scan.bannerHint) return mk('ckcmp', 'Banner de consentimento', 0, 0, 'info', 'Há indícios de um banner de cookies próprio (texto ou elementos na página). Não conseguimos confirmar como ele funciona.', 'Confirme que o banner permite recusar tão facilmente quanto aceitar e que os rastreadores só carregam após o aceite.');
  return tracking
    ? mk('ckcmp', 'Banner de consentimento', 0, 0, 'warn', 'Não detectamos banner nem plataforma de consentimento, mas há rastreadores ou cookies de analítica/marketing. (Banners criados por JavaScript podem não aparecer na nossa leitura.)',
      'Implemente um banner de consentimento com opção clara de aceitar, recusar e personalizar, e bloqueio prévio dos rastreadores. Pode ser uma plataforma de gestão de consentimento ou uma solução própria.')
    : mk('ckcmp', 'Banner de consentimento', 0, 0, 'info', 'Não detectamos banner de consentimento. Ele pode ser dispensável se o site usa apenas cookies estritamente necessários, mas isso depende da análise de cada caso.');
}

function checkPolicy(page, scan, tracking) {
  if (page.html == null) return mk('ckpolicy', 'Política de privacidade e de cookies', 0, 0, 'info', 'Não foi possível ler o HTML da página, então não procuramos os links de política.');
  if (scan.privacy && (scan.cookiePolicy || !tracking)) return mk('ckpolicy', 'Política de privacidade e de cookies', 0, 0, 'pass', `Encontramos link para política de privacidade${scan.cookiePolicy ? ' e menção a cookies' : ''} na página inicial.`);
  if (scan.privacy) return mk('ckpolicy', 'Política de privacidade e de cookies', 0, 0, 'warn', 'Há link para a política de privacidade, mas não encontramos referência a cookies, embora existam rastreadores ou cookies de analítica/marketing.', 'Publique uma política de cookies (ou uma seção na política de privacidade) listando os cookies, suas finalidades, prazos e como recusá-los.');
  return mk('ckpolicy', 'Política de privacidade e de cookies', 0, 0, 'warn', 'Não encontramos link para política de privacidade na página inicial (links criados por JavaScript podem não aparecer).', 'Publique a política de privacidade e deixe o link visível em todas as páginas, normalmente no rodapé. A LGPD pede informação clara e de fácil acesso sobre o tratamento de dados.');
}

async function checkPrivacy(input, { fetchPage: fp = fetchPage, now = Date.now() } = {}) {
  const raw = /^[a-z][a-z0-9+.-]*:\/\//i.test(String(input).trim()) ? String(input).trim() : `https://${String(input).trim()}`;
  const page = await fp(raw);
  const cookies = page.setCookies.map((s) => {
    const c = parseSetCookie(s.raw, now);
    return { ...c, https: s.https, cls: classifyCookie(c.name) };
  });
  const scan = page.html != null ? scanHtml(page.html) : { trackers: [], cmps: [], bannerHint: false, privacy: false, cookiePolicy: false };
  const tracking = scan.trackers.some(isTracking) || cookies.some((c) => c.cls.cat === 'analitica' || c.cls.cat === 'marketing');
  const checks = [
    checkBefore(cookies), checkFlags(cookies), checkExpiry(cookies),
    checkTrackers(page, scan, tracking), checkCmp(page, scan, cookies), checkPolicy(page, scan, tracking),
  ];
  const warnings = [];
  if (page.status >= 400) warnings.push(`O site respondeu HTTP ${page.status}. Os cookies e o HTML lidos podem ser de uma página de erro ou bloqueio, e não do site real.`);
  return {
    ok: true, informativa: true, checks,
    nota: 'Aba orientativa: não entra na nota geral. São indícios técnicos a partir do que o servidor entrega na primeira visita, e não um parecer jurídico sobre a LGPD.',
    warnings,
    meta: { finalUrl: page.finalUrl, status: page.status, redirects: page.chain },
    details: [
      { label: 'Cookies recebidos do servidor (valores não são guardados)', lines: cookies.length ? cookies.map((c) => `${c.name} | ${c.cls.label} | ${c.secure ? 'Secure ' : ''}${c.httpOnly ? 'HttpOnly ' : ''}${c.sameSite ? `SameSite=${c.sameSite}` : ''}`.trim()) : ['(nenhum)'] },
      { label: 'Rastreadores e plataformas de consentimento detectados no HTML', lines: [...scan.trackers.map((t) => `${t.nome} (${t.cat})`), ...scan.cmps.map((m) => `${m} (consentimento)`)].length ? [...scan.trackers.map((t) => `${t.nome} (${t.cat})`), ...scan.cmps.map((m) => `${m} (consentimento)`)] : ['(nenhum)'] },
    ],
  };
}

module.exports = { checkPrivacy, fetchPage, parseSetCookie, classifyCookie, scanHtml, TRACKERS, CMPS };
