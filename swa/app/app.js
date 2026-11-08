'use strict';
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const ICON = { pass: '✔', warn: '▲', fail: '✖', info: 'ℹ' };

let siteKey = null;   // preenchido por /api/config quando o Turnstile está ativo
let widgetId = null;
let token = null;

function render(d) {
  const w = $('warnings');
  w.replaceChildren();
  for (const msg of d.warnings || []) {
    const box = el('div', 'warning');
    box.append(el('strong', null, '⚠ Atenção: '), document.createTextNode(msg));
    w.append(box);
  }
  const g = $('grade');
  g.textContent = d.grade;
  g.className = 'grade g-' + d.grade[0];
  $('score').textContent = `Pontuação: ${d.score}/100`;
  $('final').textContent = `${d.finalUrl} · HTTP ${d.status}` + (d.redirects.length > 1 ? ` · ${d.redirects.length - 1} redirect(s)` : '');
  const box = $('checks');
  box.replaceChildren();
  for (const c of d.checks) {
    const card = el('div', 'check ' + c.status);
    const h = el('h3');
    h.append(el('span', null, `${ICON[c.status]} ${c.name}`), el('span', 'pts', `${c.points}/${c.max}`));
    card.append(h, el('p', null, c.message));
    if (c.value) card.append(el('pre', null, c.value));
    if (c.fix) { const f = el('div', 'fix'); f.append(el('pre', null, c.fix)); card.append(f); }
    box.append(card);
  }
  $('raw').textContent = Object.entries(d.headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join('\n' + k + ': ') : v}`).join('\n');
  $('result').hidden = false;
}

function resetCaptcha() {
  token = null;
  if (widgetId !== null && window.turnstile) window.turnstile.reset(widgetId); // o token vale para uma única análise
}

async function initCaptcha() {
  try {
    const cfg = await (await fetch('/api/config')).json();
    siteKey = cfg.turnstileSiteKey;
  } catch { return; }
  if (!siteKey) return;
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.onload = () => {
    widgetId = window.turnstile.render('#ts', {
      sitekey: siteKey,
      language: 'pt-br',
      callback: (t) => { token = t; },
      'expired-callback': () => { token = null; },
      'error-callback': () => { token = null; },
    });
  };
  document.head.append(s);
}

$('form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const status = $('status'), btn = $('go');
  status.className = '';
  if (siteKey && !token) { status.className = 'error'; status.textContent = 'Conclua a verificação anti-robô antes de analisar.'; return; }
  status.textContent = 'Analisando…'; btn.disabled = true; $('result').hidden = true;
  try {
    let api = '/api/scan?url=' + encodeURIComponent($('url').value);
    if (siteKey) api += '&cf-turnstile-response=' + encodeURIComponent(token);
    const r = await fetch(api);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Erro desconhecido');
    status.textContent = ''; render(d);
  } catch (e) { status.className = 'error'; status.textContent = e.message; }
  finally { btn.disabled = false; if (siteKey) resetCaptcha(); }
});

initCaptcha();
const q = new URLSearchParams(location.search).get('url');
if (q) $('url').value = q; // pré-preenche; com captcha o usuário confirma antes de analisar
