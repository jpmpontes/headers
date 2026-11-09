'use strict';
// Peças comuns às verificações de TLS, DNS e e-mail.
const dns = require('node:dns');

const GRADES = [[95, 'A+'], [85, 'A'], [70, 'B'], [55, 'C'], [40, 'D'], [25, 'E'], [0, 'F']];
const ORDER = GRADES.map((g) => g[1]).reverse(); // F ... A+

const gradeOf = (score) => GRADES.find(([min]) => score >= min)[1];
const capGrade = (grade, limit) => (ORDER.indexOf(grade) > ORDER.indexOf(limit) ? limit : grade);

// Um item do relatório. max = 0 significa "opcional": não entra na base de cálculo e só pode dar bônus.
const mk = (id, name, max, points, status, message, fix, value) => ({
  id, name, max, points: Math.max(0, Math.round(points * 10) / 10), status, message, fix: fix || null, value: value || null,
});

// Soma os pontos, limita a 100 (bônus não passam disso) e aplica tetos de nota (ex.: certificado inválido => no máximo D).
function finish(checks, caps = []) {
  const max = checks.reduce((s, c) => s + c.max, 0);
  const got = checks.reduce((s, c) => s + c.points, 0);
  const score = max ? Math.min(100, Math.round((got / max) * 100)) : 0;
  let grade = gradeOf(score);
  for (const c of caps) grade = capGrade(grade, c);
  return { ok: true, score, grade, checks };
}

// Sufixos de segundo nível comuns (heurística: não usamos a lista completa da Public Suffix List).
const SECOND_LEVEL = new Set([
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'art.br', 'blog.br', 'eco.br', 'emp.br', 'eng.br', 'esp.br', 'far.br', 'fm.br',
  'imb.br', 'ind.br', 'inf.br', 'jus.br', 'leg.br', 'mus.br', 'psc.br', 'radio.br', 'srv.br', 'tec.br', 'tv.br', 'vet.br', 'adv.br',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.za', 'com.ar', 'com.mx', 'com.co', 'com.pe',
  'com.uy', 'com.py', 'com.bo', 'com.ve', 'co.in', 'com.cn', 'com.tr', 'com.pt',
]);

// www.corevatech.com.br -> corevatech.com.br ; a.b.example.com -> example.com
function registrable(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const last2 = labels.slice(-2).join('.');
  return SECOND_LEVEL.has(last2) ? labels.slice(-3).join('.') : last2;
}

// a.b.example.com -> [a.b.example.com, b.example.com, example.com] (do mais específico até o domínio registrável)
function climb(host) {
  const reg = registrable(host);
  const out = [];
  let name = String(host).toLowerCase().replace(/\.$/, '');
  while (name !== reg && name.includes('.')) { out.push(name); name = name.slice(name.indexOf('.') + 1); }
  out.push(reg);
  return out;
}

// Executa uma consulta DNS e classifica: ok | none (sem registro) | nx (domínio não existe) | err (falha de rede/servidor).
async function attempt(fn) {
  try { return { s: 'ok', data: await fn() }; } catch (e) {
    const code = e && e.code ? String(e.code) : 'ERRO';
    if (code === 'ENODATA') return { s: 'none', data: [] };
    if (code === 'ENOTFOUND') return { s: 'nx', data: [] };
    return { s: 'err', code, data: [] };
  }
}

const defaultResolver = () => new dns.promises.Resolver({ timeout: 3000, tries: 2 });

module.exports = { gradeOf, capGrade, mk, finish, registrable, climb, attempt, defaultResolver };
