'use strict';
// Orquestra as quatro verificações em UMA chamada (um único token Turnstile por análise).
// Cada seção é independente: se uma falhar, as outras continuam.
const net = require('node:net');
const { scan, normalize } = require('./scanner');
const { validateUrl } = require('./ssrf');
const { checkTls } = require('./tlscheck');
const { checkDns } = require('./dnscheck');
const { checkEmail } = require('./emailcheck');
const { gradeOf } = require('./common');

const SECTION_DEADLINE_MS = 18000;
const WEIGHTS = { headers: 35, tls: 25, email: 25, dns: 15 }; // peso de cada seção na nota geral
const ORDER = ['headers', 'tls', 'email', 'dns'];
const NOT_APPLICABLE = 'Disponível apenas para nomes de domínio públicos (não para endereços IP nem nomes locais).';

const withDeadline = (p, ms) => Promise.race([
  p,
  new Promise((_, rej) => setTimeout(() => rej(new Error('Tempo esgotado nesta verificação.')), ms).unref()),
]);

function headersSection(r) {
  return {
    ok: true, score: r.score, grade: r.grade, checks: r.checks, warnings: r.warnings,
    meta: { finalUrl: r.finalUrl, status: r.status, redirects: r.redirects },
    details: [{ label: 'Todos os headers recebidos', lines: Object.entries(r.headers).flatMap(([k, v]) => arr(v).map((x) => `${k}: ${x}`)) }],
  };
}
const arr = (x) => (Array.isArray(x) ? x : [x]);

async function fullScan(input, { dkim } = {}) {
  const raw = normalize(input);
  const u = validateUrl(raw);
  if (dkim && !/^[a-z0-9._-]{1,63}$/i.test(dkim)) throw new Error('Seletor DKIM inválido (use letras, números, ponto, hífen ou sublinhado).');
  const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  const isName = !net.isIP(host) && host.includes('.');

  const jobs = {
    headers: () => scan(raw).then(headersSection),
    tls: () => checkTls(host),
    email: () => (isName ? checkEmail(host, { dkim }) : Promise.reject(new Error(NOT_APPLICABLE))),
    dns: () => (isName ? checkDns(host) : Promise.reject(new Error(NOT_APPLICABLE))),
  };
  const settled = await Promise.allSettled(ORDER.map((k) => withDeadline(jobs[k](), SECTION_DEADLINE_MS)));
  const sections = {};
  ORDER.forEach((k, i) => {
    const s = settled[i];
    sections[k] = s.status === 'fulfilled' ? s.value : { ok: false, error: s.reason && s.reason.message ? s.reason.message : 'Falha inesperada.' };
  });

  const okKeys = ORDER.filter((k) => sections[k].ok);
  if (!okKeys.length) throw new Error(sections.headers.error || 'Não foi possível analisar este endereço.');
  const w = okKeys.reduce((s, k) => s + WEIGHTS[k], 0);
  const score = Math.round(okKeys.reduce((s, k) => s + WEIGHTS[k] * sections[k].score, 0) / w);
  return {
    target: raw, host, scannedAt: new Date().toISOString(),
    overall: { score, grade: gradeOf(score), sections: okKeys.length },
    sections,
  };
}

module.exports = { fullScan, WEIGHTS, ORDER };
