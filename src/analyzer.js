'use strict';

/**
 * Analisa os cabeçalhos de uma resposta HTTP e gera nota (0–100), conceito (A+ a F)
 * e uma lista de verificações com explicação e correção sugerida.
 * Módulo puro: não faz rede, então é fácil de testar.
 *
 * Pesos (somam 100): CSP 25 · HSTS 15 · HTTPS/TLS 4 · X-Frame-Options 10 · X-Content-Type-Options 8 ·
 * Referrer-Policy 8 · Permissions-Policy 6 · COOP 4 · COEP 3 · CORP 3 · Cookies 10 · Vazamento de versão 4
 */

const MAX_VALUE_LEN = 300;
const clip = (s) => (s && s.length > MAX_VALUE_LEN ? `${s.slice(0, MAX_VALUE_LEN)}…` : s);
const round1 = (n) => Math.round(n * 10) / 10;

function mk(id, name, max, earned, { value = null, message, fix = null } = {}) {
  const e = Math.max(0, Math.min(max, earned));
  const ratio = max ? e / max : 1;
  return {
    id,
    name,
    max,
    earned: round1(e),
    status: ratio >= 1 ? 'pass' : ratio >= 0.5 ? 'warn' : 'fail',
    value: value == null ? null : clip(String(value)),
    message,
    fix,
  };
}

function parseDirectives(value) {
  const map = new Map();
  for (const part of String(value).split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (!tokens[0]) continue;
    const name = tokens[0].toLowerCase();
    if (!map.has(name)) map.set(name, tokens.slice(1));
  }
  return map;
}

// ------------------------------------------------------------------ verificações

function checkTransport(ctx) {
  const { isHttps, tls, chain } = ctx;
  const upgraded = chain.length > 1 && chain[0].url.startsWith('http://') && isHttps;
  if (!isHttps) {
    return mk('https', 'HTTPS / certificado', 4, 0, {
      value: 'http://',
      message: 'O endereço final usa HTTP, sem criptografia. Todo o tráfego (e os cookies) pode ser lido ou alterado.',
      fix: 'Habilite HTTPS (ex.: Let’s Encrypt) e redirecione todo o tráfego HTTP para HTTPS.',
    });
  }
  if (tls && tls.authorized === false) {
    return mk('https', 'HTTPS / certificado', 4, 0, {
      value: tls.authorizationError || 'certificado não confiável',
      message: `O certificado TLS não é confiável (${tls.authorizationError || 'erro de validação'}). Navegadores exibirão alerta.`,
      fix: 'Instale um certificado válido, emitido por uma CA confiável, com a cadeia completa e o domínio correto.',
    });
  }
  if (tls && (tls.protocol === 'TLSv1' || tls.protocol === 'TLSv1.1' || tls.protocol === 'SSLv3')) {
    return mk('https', 'HTTPS / certificado', 4, 1, {
      value: tls.protocol,
      message: `Versão de TLS obsoleta (${tls.protocol}).`,
      fix: 'Desative TLS 1.0/1.1 e mantenha apenas TLS 1.2 e 1.3.',
    });
  }
  return mk('https', 'HTTPS / certificado', 4, 4, {
    value: tls && tls.protocol ? tls.protocol : 'https://',
    message: upgraded
      ? 'HTTPS com certificado válido; o HTTP é redirecionado para HTTPS.'
      : 'HTTPS com certificado válido.',
  });
}

function checkHsts(ctx) {
  const v = ctx.h('strict-transport-security');
  const fix =
    'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (use preload só após testar todos os subdomínios).';
  if (!ctx.isHttps) {
    return mk('hsts', 'Strict-Transport-Security (HSTS)', 15, 0, {
      message: 'O HSTS só tem efeito em respostas HTTPS.',
      fix: 'Habilite HTTPS primeiro e depois adicione o cabeçalho HSTS.',
    });
  }
  if (!v) {
    return mk('hsts', 'Strict-Transport-Security (HSTS)', 15, 0, {
      message: 'Ausente. O navegador pode aceitar conexões HTTP e fica exposto a ataques de downgrade (SSL stripping).',
      fix,
    });
  }
  const d = parseDirectives(v);
  const maxAge = Number((d.get('max-age') || [''])[0].replace(/"/g, ''));
  const sub = d.has('includesubdomains');
  const preload = d.has('preload');
  if (!Number.isFinite(maxAge) || maxAge <= 0) {
    return mk('hsts', 'Strict-Transport-Security (HSTS)', 15, 0, {
      value: v,
      message: 'max-age ausente, inválido ou zero: o HSTS está desativado na prática.',
      fix,
    });
  }
  if (maxAge < 15552000) {
    return mk('hsts', 'Strict-Transport-Security (HSTS)', 15, 6, {
      value: v,
      message: `max-age de ${maxAge}s é curto (recomendado: no mínimo 15552000, ou 1 ano = 31536000).`,
      fix,
    });
  }
  const notes = [];
  if (!sub) notes.push('adicione includeSubDomains');
  if (!preload) notes.push('considere preload');
  return mk('hsts', 'Strict-Transport-Security (HSTS)', 15, 12 + (sub ? 2 : 0) + (preload ? 1 : 0), {
    value: v,
    message: notes.length ? `HSTS ativo. Para reforçar: ${notes.join(' e ')}.` : 'HSTS bem configurado.',
    fix: notes.length ? fix : null,
  });
}

function checkCsp(ctx) {
  const csp = ctx.h('content-security-policy');
  const reportOnly = ctx.h('content-security-policy-report-only');
  const name = 'Content-Security-Policy (CSP)';
  const fix =
    "Comece por: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'";

  if (!csp) {
    return mk('csp', name, 25, reportOnly ? 3 : 0, {
      value: reportOnly || null,
      message: reportOnly
        ? 'Só existe em modo Report-Only: relata violações, mas não bloqueia nada.'
        : 'Ausente. A CSP é a principal defesa em profundidade contra XSS e injeção de conteúdo.',
      fix,
    });
  }

  const d = parseDirectives(csp);
  const issues = [];
  let loss = 0;
  const scriptSrc = d.get('script-src') ?? d.get('default-src');
  if (!scriptSrc) {
    loss += 8;
    issues.push('sem script-src nem default-src (scripts liberados de qualquer origem)');
  } else {
    const s = scriptSrc.map((t) => t.toLowerCase());
    const protectedByNonce = s.some((t) => /^'(nonce-|sha(256|384|512)-)/.test(t)) || s.includes("'strict-dynamic'");
    if (s.includes("'unsafe-inline'") && !protectedByNonce) {
      loss += 8;
      issues.push("'unsafe-inline' em script-src permite scripts inline (anula a proteção contra XSS)");
    }
    if (s.includes("'unsafe-eval'")) {
      loss += 4;
      issues.push("'unsafe-eval' em script-src permite eval()");
    }
    if (s.some((t) => t === '*' || t === 'http:' || t === 'https:' || t === 'data:')) {
      loss += 6;
      issues.push('script-src aceita origens muito amplas (*, http:, https: ou data:)');
    }
  }
  const objectSrc = d.get('object-src') ?? d.get('default-src');
  if (!objectSrc || !objectSrc.map((t) => t.toLowerCase()).includes("'none'")) {
    loss += 2;
    issues.push("object-src não está como 'none'");
  }
  if (!d.has('base-uri')) {
    loss += 2;
    issues.push('base-uri ausente');
  }

  return mk('csp', name, 25, issues.length ? Math.max(5, 25 - loss) : 25, {
    value: csp,
    message: issues.length ? `CSP presente, mas com pontos fracos: ${issues.join('; ')}.` : 'CSP presente e sem fraquezas comuns.',
    fix: issues.length ? fix : null,
  });
}

function checkFraming(ctx) {
  const name = 'Proteção contra clickjacking (X-Frame-Options / frame-ancestors)';
  const csp = ctx.h('content-security-policy');
  const fa = csp ? parseDirectives(csp).get('frame-ancestors') : null;
  const xfo = ctx.h('x-frame-options');
  if (fa) {
    return mk('framing', name, 10, 10, { value: `frame-ancestors ${fa.join(' ')}`, message: 'Protegido pela diretiva frame-ancestors da CSP.' });
  }
  const fix = "X-Frame-Options: DENY (ou SAMEORIGIN), ou frame-ancestors 'self' na CSP.";
  if (!xfo) {
    return mk('framing', name, 10, 0, {
      message: 'Ausente. A página pode ser embutida em iframes de outros sites (clickjacking).',
      fix,
    });
  }
  const v = xfo.trim().toUpperCase();
  if (v === 'DENY' || v === 'SAMEORIGIN') return mk('framing', name, 10, 10, { value: xfo, message: 'Protegido pelo X-Frame-Options.' });
  if (v.startsWith('ALLOW-FROM')) {
    return mk('framing', name, 10, 4, { value: xfo, message: 'ALLOW-FROM é obsoleto e ignorado pelos navegadores atuais.', fix });
  }
  return mk('framing', name, 10, 2, { value: xfo, message: 'Valor inválido para X-Frame-Options.', fix });
}

function checkNosniff(ctx) {
  const v = ctx.h('x-content-type-options');
  const ok = v && v.toLowerCase().split(',').map((t) => t.trim()).includes('nosniff');
  return mk('nosniff', 'X-Content-Type-Options', 8, ok ? 8 : 0, {
    value: v,
    message: ok ? 'nosniff ativo.' : v ? 'Valor inválido (o único valor aceito é "nosniff").' : 'Ausente. Navegadores podem “adivinhar” o tipo do conteúdo (MIME sniffing).',
    fix: ok ? null : 'X-Content-Type-Options: nosniff',
  });
}

function checkReferrer(ctx) {
  const v = ctx.h('referrer-policy');
  const fix = 'Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer / same-origin para mais privacidade).';
  if (!v) {
    return mk('referrer', 'Referrer-Policy', 8, 2, {
      message: 'Ausente. Os navegadores modernos assumem strict-origin-when-cross-origin, mas é melhor declarar explicitamente.',
      fix,
    });
  }
  const strong = new Set(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']);
  const medium = new Set(['no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin']);
  const last = v.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean).pop(); // o último valor válido prevalece
  if (strong.has(last)) return mk('referrer', 'Referrer-Policy', 8, 8, { value: v, message: 'Política restritiva e adequada.' });
  if (medium.has(last)) return mk('referrer', 'Referrer-Policy', 8, 4, { value: v, message: 'Política aceitável, mas pode expor URLs completas ou origens em excesso.', fix });
  return mk('referrer', 'Referrer-Policy', 8, 0, {
    value: v,
    message: last === 'unsafe-url' ? 'unsafe-url envia a URL completa para qualquer site (vaza caminhos e parâmetros).' : 'Valor desconhecido ou inválido.',
    fix,
  });
}

function checkPermissions(ctx) {
  const v = ctx.h('permissions-policy');
  const legacy = ctx.h('feature-policy');
  const fix = 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()';
  if (v && v.trim()) return mk('permissions', 'Permissions-Policy', 6, 6, { value: v, message: 'Recursos do navegador restringidos explicitamente.' });
  if (legacy) return mk('permissions', 'Permissions-Policy', 6, 3, { value: legacy, message: 'Usa apenas o Feature-Policy, que foi substituído.', fix });
  return mk('permissions', 'Permissions-Policy', 6, 0, {
    message: 'Ausente. Câmera, microfone, geolocalização etc. não foram restringidos para esta página e seus iframes.',
    fix,
  });
}

function checkCoop(ctx) {
  const v = ctx.h('cross-origin-opener-policy');
  const l = v && v.trim().toLowerCase();
  const fix = 'Cross-Origin-Opener-Policy: same-origin';
  if (l === 'same-origin') return mk('coop', 'Cross-Origin-Opener-Policy (COOP)', 4, 4, { value: v, message: 'Janela isolada de outras origens.' });
  if (l === 'same-origin-allow-popups') return mk('coop', 'Cross-Origin-Opener-Policy (COOP)', 4, 3, { value: v, message: 'Isolamento parcial (permite popups).' });
  if (l === 'unsafe-none') return mk('coop', 'Cross-Origin-Opener-Policy (COOP)', 4, 1, { value: v, message: 'unsafe-none equivale a não ter proteção.', fix });
  return mk('coop', 'Cross-Origin-Opener-Policy (COOP)', 4, 0, { value: v, message: 'Ausente. Reforço contra ataques entre janelas (ex.: XS-Leaks, Spectre).', fix });
}

function checkCoep(ctx) {
  const v = ctx.h('cross-origin-embedder-policy');
  const l = v && v.trim().toLowerCase();
  const fix = 'Cross-Origin-Embedder-Policy: require-corp (ou credentialless). Atenção: pode quebrar recursos de terceiros.';
  if (l === 'require-corp' || l === 'credentialless') return mk('coep', 'Cross-Origin-Embedder-Policy (COEP)', 3, 3, { value: v, message: 'Ativo.' });
  return mk('coep', 'Cross-Origin-Embedder-Policy (COEP)', 3, 0, { value: v, message: 'Ausente. Necessário para isolamento total de origem (cross-origin isolation).', fix });
}

function checkCorp(ctx) {
  const v = ctx.h('cross-origin-resource-policy');
  const l = v && v.trim().toLowerCase();
  const fix = 'Cross-Origin-Resource-Policy: same-origin (ou same-site).';
  if (l === 'same-origin' || l === 'same-site') return mk('corp', 'Cross-Origin-Resource-Policy (CORP)', 3, 3, { value: v, message: 'Recursos protegidos contra carregamento por outras origens.' });
  if (l === 'cross-origin') return mk('corp', 'Cross-Origin-Resource-Policy (CORP)', 3, 2, { value: v, message: 'Liberado para qualquer origem (adequado só para recursos públicos).' });
  return mk('corp', 'Cross-Origin-Resource-Policy (CORP)', 3, 0, { value: v, message: 'Ausente.', fix });
}

function parseCookie(raw) {
  const parts = String(raw).split(';').map((p) => p.trim());
  const name = (parts[0].split('=')[0] || '').trim();
  const attrs = new Map();
  for (const p of parts.slice(1)) {
    const [k, ...rest] = p.split('=');
    attrs.set(k.trim().toLowerCase(), rest.join('=').trim());
  }
  return {
    name: name || '(sem nome)',
    secure: attrs.has('secure'),
    httpOnly: attrs.has('httponly'),
    sameSite: attrs.has('samesite') ? attrs.get('samesite') || 'inválido' : null,
  };
}

function checkCookies(ctx) {
  const name = 'Cookies (Secure, HttpOnly, SameSite)';
  const cookies = ctx.cookies;
  if (cookies.length === 0) {
    return mk('cookies', name, 10, 10, { message: 'Nenhum cookie definido nesta resposta.' });
  }
  let flags = 0;
  let ok = 0;
  const issues = [];
  for (const c of cookies) {
    flags += 3;
    if (c.secure) ok += 1;
    else issues.push(`${c.name}: sem Secure`);
    if (c.httpOnly) ok += 1;
    else issues.push(`${c.name}: sem HttpOnly`);
    if (c.sameSite) ok += 1;
    else issues.push(`${c.name}: sem SameSite`);
  }
  const value = cookies
    .map((c) => `${c.name} [${[c.secure && 'Secure', c.httpOnly && 'HttpOnly', c.sameSite && `SameSite=${c.sameSite}`].filter(Boolean).join(', ') || 'sem flags'}]`)
    .join(' · ');
  return mk('cookies', name, 10, (10 * ok) / flags, {
    value,
    message: issues.length
      ? `Flags ausentes: ${issues.join('; ')}. (HttpOnly é essencial para cookies de sessão; cookies lidos por JavaScript podem legitimamente não tê-lo.)`
      : 'Todos os cookies têm Secure, HttpOnly e SameSite.',
    fix: issues.length ? 'Set-Cookie: sessao=...; Secure; HttpOnly; SameSite=Lax; Path=/' : null,
  });
}

function checkDisclosure(ctx) {
  const leaks = [];
  const server = ctx.h('server');
  if (server && /\d+\.\d+|\/\d/.test(server)) leaks.push(`Server: ${server}`);
  for (const hn of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const v = ctx.h(hn);
    if (v) leaks.push(`${hn}: ${v}`);
  }
  if (leaks.length === 0) {
    return mk('disclosure', 'Vazamento de tecnologia/versão', 4, 4, { message: 'Nenhuma versão de software exposta nos cabeçalhos.' });
  }
  return mk('disclosure', 'Vazamento de tecnologia/versão', 4, 4 - 2 * leaks.length, {
    value: leaks.join(' · '),
    message: 'Os cabeçalhos revelam tecnologia ou versão, o que facilita a busca por vulnerabilidades conhecidas.',
    fix: 'Remova X-Powered-By e oculte a versão do Server (ex.: server_tokens off no nginx, ServerTokens Prod no Apache).',
  });
}

// ------------------------------------------------------------------ nota

function gradeFor(score, isHttps) {
  const order = ['F', 'D', 'C', 'B', 'A', 'A+'];
  let g = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 72 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : 'F';
  if (!isHttps && order.indexOf(g) > order.indexOf('D')) g = 'D'; // sem HTTPS: no máximo D
  return g;
}

/**
 * @param {{finalUrl:string,status:number,headers:object,setCookie?:string[],tls?:object|null,chain?:object[]}} f
 */
function analyze(f) {
  const headers = {};
  for (const [k, v] of Object.entries(f.headers || {})) {
    headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  const chain = f.chain && f.chain.length ? f.chain : [{ url: f.finalUrl, status: f.status }];
  const ctx = {
    h: (name) => headers[name],
    isHttps: String(f.finalUrl).startsWith('https://'),
    tls: f.tls || null,
    chain,
    cookies: (f.setCookie || []).map(parseCookie),
  };

  const checks = [
    checkTransport(ctx),
    checkCsp(ctx),
    checkHsts(ctx),
    checkFraming(ctx),
    checkNosniff(ctx),
    checkReferrer(ctx),
    checkPermissions(ctx),
    checkCoop(ctx),
    checkCoep(ctx),
    checkCorp(ctx),
    checkCookies(ctx),
    checkDisclosure(ctx),
  ];

  const score = Math.round(checks.reduce((s, c) => s + c.earned, 0));
  return {
    url: f.finalUrl,
    httpStatus: f.status,
    score,
    grade: gradeFor(score, ctx.isHttps),
    summary: {
      pass: checks.filter((c) => c.status === 'pass').length,
      warn: checks.filter((c) => c.status === 'warn').length,
      fail: checks.filter((c) => c.status === 'fail').length,
    },
    checks,
    redirects: chain,
    // Só nomes e flags: os VALORES dos cookies nunca são repassados ao usuário.
    cookies: ctx.cookies,
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { analyze, parseDirectives, parseCookie, gradeFor };
