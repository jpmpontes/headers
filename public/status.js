'use strict';
// Painel de status. Todo texto entra via textContent e não há estilos inline, por causa da CSP.
const LABEL = { operacional: 'Operacional', degradado: 'Degradado', indisponivel: 'Indisponível', semdados: 'Sem dados', informativo: 'Informativo' };
const SVGNS = 'http://www.w3.org/2000/svg';

// Continentes simplificados (longitude, latitude). Mapa esquemático, não cartográfico.
const LAND = [
  [[-168, 66], [-141, 70], [-125, 70], [-95, 72], [-82, 68], [-62, 60], [-56, 52], [-66, 44], [-76, 38], [-81, 31], [-80, 25], [-90, 29], [-97, 26], [-97, 20], [-90, 16], [-84, 10], [-78, 8], [-86, 12], [-95, 16], [-105, 22], [-110, 24], [-117, 32], [-124, 40], [-124, 48], [-135, 58], [-150, 60], [-165, 55]],
  [[-78, 8], [-72, 12], [-62, 10], [-52, 5], [-50, 0], [-35, -5], [-35, -9], [-39, -18], [-41, -22], [-48, -26], [-53, -34], [-58, -38], [-65, -42], [-68, -52], [-72, -54], [-74, -45], [-73, -37], [-71, -30], [-70, -18], [-76, -14], [-81, -5], [-80, 0]],
  [[-10, 36], [-9, 43], [-2, 47], [-5, 50], [5, 53], [8, 57], [10, 59], [5, 62], [15, 69], [28, 71], [45, 68], [60, 70], [80, 73], [105, 77], [130, 72], [160, 70], [180, 68], [180, 62], [160, 58], [142, 52], [140, 46], [130, 42], [122, 40], [122, 30], [110, 20], [106, 10], [100, 13], [104, 2], [98, 8], [93, 20], [88, 22], [80, 15], [77, 8], [73, 20], [67, 25], [57, 25], [50, 30], [44, 36], [36, 36], [30, 36], [26, 40], [22, 37], [18, 40], [12, 42], [8, 44], [3, 43], [-1, 37]],
  [[35, 30], [34, 28], [43, 13], [52, 15], [59, 22], [56, 26], [50, 30], [39, 32]],
  [[-17, 21], [-10, 30], [-6, 36], [10, 37], [20, 32], [32, 31], [34, 28], [43, 12], [51, 12], [40, -3], [40, -15], [35, -24], [32, -29], [20, -35], [18, -32], [12, -17], [13, -6], [9, 4], [-8, 4], [-17, 14]],
  [[114, -22], [122, -18], [131, -12], [137, -12], [142, -11], [146, -19], [153, -26], [150, -37], [141, -38], [131, -31], [115, -34]],
  [[-55, 60], [-45, 60], [-22, 70], [-20, 82], [-60, 82], [-70, 76]],
];
const px = (lon) => lon + 180;
const py = (lat) => 90 - lat;

function el(tag, attrs, text) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text != null) e.textContent = text;
  return e;
}
function svg(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}
const ago = (iso) => {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  return s < 90 ? 'agora há pouco' : s < 5400 ? `há ${Math.round(s / 60)} min` : s < 129600 ? `há ${Math.round(s / 3600)} h` : `há ${Math.round(s / 86400)} dias`;
};
const safeUrl = (u) => (/^https:\/\//.test(u || '') ? u : null);

function badge(estado) { return el('span', { class: `badge st-${estado}` }, LABEL[estado] || estado); }

function card(p) {
  const c = el('article', { class: `pcard st-${p.estado}-border` });
  const h = el('h3');
  h.append(el('span', {}, p.nome), badge(p.estado));
  c.append(h);
  if (p.estado === 'semdados') {
    c.append(el('p', { class: 'why' }, p.motivo || 'Sem dados.'));
    const l = safeUrl(p.fonte && p.fonte.url);
    if (l) c.append(el('a', { href: l, target: '_blank', rel: 'noopener noreferrer' }, 'Ver página oficial'));
    if (p.fonte && p.fonte.tipo === 'sem fonte pública') c.append(el('p', { class: 'src' }, 'Sem fonte pública confiável'));
    return c;
  }
  const src = el('p', { class: 'src' }, `Reportado pelo fornecedor · atualizado ${ago(p.atualizadoEm)}${p.fonte && p.fonte.validada === false ? ' · fonte em validação' : ''}${p.parcial ? ' · leitura parcial' : ''}`);
  c.append(src);
  if (p.desatualizado) c.append(el('p', { class: 'stale' }, 'Dado desatualizado: a fonte não respondeu na última tentativa.'));
  const inc = (p.incidentes || []).slice(0, 5);
  if (!inc.length) c.append(el('p', { class: 'ok' }, 'Nenhum incidente ativo informado.'));
  else {
    const ul = el('ul', { class: 'inc' });
    for (const i of inc) {
      const li = el('li');
      const u = safeUrl(i.url);
      li.append(u ? el('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, i.titulo) : el('span', {}, i.titulo));
      const meta = [(i.produtos || []).join(', '), (i.regioes || []).join(', ')].filter(Boolean).join(' · ');
      if (meta) li.append(el('small', {}, meta));
      ul.append(li);
    }
    c.append(ul);
  }
  return c;
}

function brCard(b) {
  const c = el('article', { class: `pcard st-${b.estado}-border` });
  const h = el('h3');
  h.append(el('span', {}, b.provedor), badge(b.estado));
  c.append(h, el('p', { class: 'src' }, b.regiao));
  if (b.estado === 'semdados') c.append(el('p', { class: 'why' }, b.motivo || 'Sem dados regionais.'));
  if (b.desatualizado) c.append(el('p', { class: 'stale' }, 'Dado desatualizado.'));
  return c;
}

function drawMap(host, provedores) {
  host.replaceChildren();
  const s = svg('svg', { viewBox: '0 0 360 160', role: 'img', 'aria-label': 'Mapa esquemático das regiões de nuvem' });
  s.append(svg('rect', { class: 'sea', x: 0, y: 0, width: 360, height: 160 }));
  for (const poly of LAND) s.append(svg('polygon', { class: 'land', points: poly.map(([lo, la]) => `${px(lo)},${py(la) - 10}`).join(' ') }));
  const regs = [];
  for (const p of provedores) for (const r of p.regioes || []) regs.push({ ...r, prov: p.nome, pid: p.id });
  // Problemas por cima: desenha operacionais primeiro.
  const ord = { operacional: 0, semdados: 0, degradado: 1, indisponivel: 2 };
  regs.sort((a, b) => (ord[a.estado] || 0) - (ord[b.estado] || 0));
  for (const r of regs) {
    const br = r.lat < 6 && r.lat > -34 && r.lon > -75 && r.lon < -34;
    const g = svg('g');
    const x = px(r.lon) + (r.pid === 'aws' ? 2.2 : 0);
    const c = svg('circle', { class: `mk st-${r.estado}${br ? ' br' : ''}`, cx: x, cy: py(r.lat) - 10, r: br ? 3.2 : 2.2 });
    const t = svg('title');
    t.textContent = `${r.prov} · ${r.nome} (${r.id}): ${LABEL[r.estado] || r.estado}`;
    c.append(t); g.append(c); s.append(g);
  }
  host.append(s);
}

function render(data) {
  const notice = document.getElementById('notice');
  if (!data.provedores || !data.provedores.length) { notice.textContent = 'Não foi possível carregar o status agora. Tente novamente em instantes.'; return; }
  const bad = data.provedores.filter((p) => p.estado === 'degradado' || p.estado === 'indisponivel');
  notice.className = bad.length ? 'warning' : 'warning calm';
  notice.textContent = `${bad.length ? `${bad.length} fornecedor(es) com problema informado: ${bad.map((p) => p.nome).join(', ')}. ` : 'Nenhum problema informado pelos fornecedores com fonte pública. '}Atualizado ${ago(data.geradoEm)}; a página se atualiza sozinha a cada minuto.`;
  const fill = (id, nodes) => document.getElementById(id).replaceChildren(...nodes);
  fill('brasil', (data.brasil || []).map(brCard));
  fill('cloud', data.provedores.filter((p) => p.grupo === 'cloud').map(card));
  fill('saas', data.provedores.filter((p) => p.grupo === 'saas').map(card));
  drawMap(document.getElementById('map'), data.provedores);
}

async function load() {
  try {
    const r = await fetch('/api/status', { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error(String(r.status));
    render(await r.json());
  } catch {
    document.getElementById('notice').textContent = 'Não foi possível carregar o status agora. Tente novamente em instantes.';
  }
}
load();
setInterval(load, 60000);
