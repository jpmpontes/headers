'use strict';
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const GLOSS = window.GLOSS || {};
const ICON = { pass: '✔', warn: '!', fail: '✖', info: 'i' };
const SVGNS = 'http://www.w3.org/2000/svg';
const svg = (tag, attrs) => { const e = document.createElementNS(SVGNS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
const SECTIONS = [['headers', 'Headers HTTP'], ['tls', 'Certificado TLS'], ['email', 'E-mail (SPF/DKIM/DMARC)'], ['dns', 'DNS']];

let siteKey = null;   // preenchido por /api/config quando o Turnstile está ativo
let widgetId = null;
let token = null;
let lastResult = null; // último relatório exibido (usado no nome do PDF)

// Pontos de cada item: "10/25"; itens opcionais mostram "+4" (bônus) ou "info".
const ptsLabel = (c) => (c.max === 0 ? (c.points > 0 ? `+${c.points}` : 'info') : `${c.points}/${c.max}`);

function renderPanel(id, title, sec) {
  const panel = el('div', 'panel');
  panel.id = 'panel-' + id;
  panel.setAttribute('role', 'tabpanel');
  panel.setAttribute('aria-labelledby', 'tab-' + id);
  panel.append(el('h2', 'sec-title', title));

  if (!sec.ok) { panel.append(el('div', 'sec-error', `Não foi possível concluir esta verificação: ${sec.error}`)); return panel; }

  for (const msg of sec.warnings || []) {
    const box = el('div', 'warning');
    box.append(el('strong', null, '⚠ Atenção: '), document.createTextNode(msg));
    panel.append(box);
  }
  const head = el('div', 'sec-head');
  head.append(el('div', 'grade sm g-' + sec.grade[0], sec.grade));
  const info = el('div');
  info.append(el('div', 'score', `Pontuação: ${sec.score}/100`));
  if (sec.meta) info.append(el('div', 'muted', `${sec.meta.finalUrl} · HTTP ${sec.meta.status}` + (sec.meta.redirects.length > 1 ? ` · ${sec.meta.redirects.length - 1} redirect(s)` : '')));
  head.append(info);
  panel.append(head);

  for (const c of sec.checks) {
    const card = el('div', 'check ' + c.status);
    const h = el('h3');
    const ttl = el('span', 'ttl');
    ttl.append(el('i', 'ico ' + c.status, ICON[c.status]), el('span', null, c.name));
    h.append(ttl, el('span', 'pts', ptsLabel(c)));
    card.append(h, el('p', null, c.message));
    if (GLOSS[c.id]) { const a = el('a', 'learn', 'O que é isso? →'); a.href = `/glossario/${GLOSS[c.id]}.html`; a.target = '_blank'; a.rel = 'noopener'; card.append(a); }
    if (c.value) card.append(el('pre', null, c.value));
    if (c.fix) { const f = el('details', 'fix'); f.open = c.status === 'fail'; f.append(el('summary', null, 'Como corrigir'), el('pre', null, c.fix)); card.append(f); }
    panel.append(card);
  }
  for (const d of sec.details || []) {
    const det = el('details');
    det.append(el('summary', null, d.label), el('pre', null, d.lines.join('\n')));
    panel.append(det);
  }
  return panel;
}

function show(id) {
  for (const [sid] of SECTIONS) {
    $('panel-' + sid).hidden = sid !== id;
    $('tab-' + sid).setAttribute('aria-selected', String(sid === id));
  }
}

// Medidor circular e barras por seção: SVG feito com atributos (a CSP do site proíbe style="").
function drawGauge(score, letter) {
  const old = $('gauge').querySelector('svg');
  if (old) old.remove();
  const s = svg('svg', { viewBox: '0 0 120 120', 'aria-hidden': 'true', class: 'gauge-svg' });
  s.append(svg('circle', { cx: 60, cy: 60, r: 52, class: 'g-track', pathLength: 100 }));
  s.append(svg('circle', { cx: 60, cy: 60, r: 52, class: 'g-arc g-' + letter, pathLength: 100, 'stroke-dasharray': `${Math.max(0, Math.min(100, score))} 100`, transform: 'rotate(-90 60 60)' }));
  $('gauge').prepend(s);
}
function drawBars(d) {
  const box = $('bars');
  box.replaceChildren();
  for (const [id, title] of SECTIONS) {
    const sec = d.sections[id];
    const row = el('button', 'bar-row');
    row.type = 'button';
    row.append(el('span', 'bar-name', title));
    const sv = svg('svg', { viewBox: '0 0 100 8', preserveAspectRatio: 'none', 'aria-hidden': 'true', class: 'bar-svg' });
    sv.append(svg('rect', { x: 0, y: 0, width: 100, height: 8, class: 'bar-track' }));
    if (sec.ok) sv.append(svg('rect', { x: 0, y: 0, width: sec.score, height: 8, class: 'bar-fill g-' + sec.grade[0] }));
    row.append(sv, sec.ok ? el('span', 'chip g-' + sec.grade[0], sec.grade) : el('span', 'chip off', '!'));
    row.setAttribute('aria-label', `${title}: ${sec.ok ? 'nota ' + sec.grade : 'não concluída'}. Abrir detalhes`);
    row.addEventListener('click', () => { show(id); $('tabs').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    box.append(row);
  }
}

function render(d) {
  lastResult = d;
  const hs = d.sections.headers;
  $('ph-url').textContent = hs && hs.ok ? hs.meta.finalUrl : d.target;
  $('ph-date').textContent = new Date(d.scannedAt).toLocaleString('pt-BR');
  $('ph-host').textContent = location.host;

  const g = $('grade');
  g.textContent = d.overall.grade;
  g.className = 'gauge-grade g-' + d.overall.grade[0];
  drawGauge(d.overall.score, d.overall.grade[0]);
  drawBars(d);
  $('pillars').hidden = true; $('trust').hidden = true;
  document.body.classList.add('has-result'); // recolhe o hero para o resultado subir na tela
  $('score').textContent = `Nota geral: ${d.overall.score}/100`;
  $('final').textContent = `${d.host} · ${d.overall.sections} de ${SECTIONS.length} verificações concluídas`;

  const tabs = $('tabs');
  const panels = $('panels');
  tabs.replaceChildren();
  panels.replaceChildren();
  for (const [id, title] of SECTIONS) {
    const sec = d.sections[id];
    const btn = el('button', 'tab');
    btn.type = 'button';
    btn.id = 'tab-' + id;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-controls', 'panel-' + id);
    btn.append(el('span', null, title), sec.ok ? el('span', 'chip g-' + sec.grade[0], sec.grade) : el('span', 'chip off', '⚠'));
    btn.addEventListener('click', () => show(id));
    tabs.append(btn);
    panels.append(renderPanel(id, title, sec));
  }
  show(SECTIONS[0][0]);
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
  status.textContent = 'Analisando headers, certificado, DNS e e-mail…'; btn.disabled = true; $('result').hidden = true;
  try {
    let api = '/api/scan?url=' + encodeURIComponent($('url').value);
    const dkim = $('dkim').value.trim();
    if (dkim) api += '&dkim=' + encodeURIComponent(dkim);
    if (siteKey) api += '&cf-turnstile-response=' + encodeURIComponent(token);
    const r = await fetch(api);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Erro desconhecido');
    status.textContent = ''; render(d);
  } catch (e) { status.className = 'error'; status.textContent = e.message; }
  finally { btn.disabled = false; if (siteKey) resetCaptcha(); }
});

// ---- Exportar PDF: usa a impressão do navegador ("Salvar como PDF") ----
// O título da página vira o nome sugerido do arquivo, e os blocos "detalhes" são expandidos só durante a impressão.
let prevTitle = null;
let prevOpen = null;
window.addEventListener('beforeprint', () => {
  if ($('result').hidden || !lastResult || prevTitle !== null) return; // idempotente: alguns navegadores disparam o evento mais de uma vez
  const host = String(lastResult.host).replace(/[^a-z0-9.-]/gi, '-');
  prevTitle = document.title;
  document.title = `verifica-${host}-${lastResult.scannedAt.slice(0, 10)}`;
  const dets = [...document.querySelectorAll('#result details')];
  prevOpen = dets.map((d) => d.open);
  dets.forEach((d) => { d.open = true; });
});
window.addEventListener('afterprint', () => {
  if (prevTitle !== null) document.title = prevTitle;
  if (prevOpen !== null) [...document.querySelectorAll('#result details')].forEach((d, i) => { d.open = prevOpen[i]; });
  prevTitle = null; prevOpen = null;
});
$('pdf').addEventListener('click', () => window.print());
$('issues').addEventListener('click', (ev) => {
  const on = ev.currentTarget.getAttribute('aria-pressed') !== 'true';
  ev.currentTarget.setAttribute('aria-pressed', String(on));
  $('panels').classList.toggle('only-issues', on);
});

initCaptcha();
const q = new URLSearchParams(location.search).get('url');
if (q) $('url').value = q; // pré-preenche; com captcha o usuário confirma antes de analisar
