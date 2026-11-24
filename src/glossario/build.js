'use strict';
// Gera as páginas estáticas do glossário (uma por verbete + índice) e o sitemap. Sem dependências.
const { VERBETES, CATEGORIAS, CHECK_MAP } = require('./index');

const BASE = 'https://verifica.corevatech.com.br';
const REVISAO = 'novembro de 2026';
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const norm = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const bySlug = Object.fromEntries(VERBETES.map((v) => [v.slug, v]));
const cat = Object.fromEntries(CATEGORIAS.map((c) => [c.id, c]));
const cut = (s, n) => (s.length <= n ? s : `${s.slice(0, n - 1).replace(/\s+\S*$/, '')}…`);

const LABEL = {
  importa: (c) => (c === 'ataques' ? 'Por que é perigoso' : 'Por que importa'),
  verifica: (c) => (c === 'ataques' || c === 'conceitos' ? 'Onde o Verifica ajuda' : 'Como o Verifica verifica'),
  corrigir: (c) => (c === 'ataques' ? 'Como se proteger' : c === 'conceitos' ? 'Por onde começar' : 'Como corrigir'),
};
const CODE_LINE = /^(?:[A-Z][A-Za-z-]+: |\S+\.\s+(?:TXT|CAA|MX)\s|version: |return |ssl_)/;

// Texto livre em parágrafos; blocos que parecem configuração viram <pre>; linhas "1. ..." viram lista numerada.
function blocks(text) {
  return text.split(/\n\n+/).map((p) => {
    const lines = p.split('\n');
    if (lines.every((l) => /^\d+\.\s/.test(l))) return `<ol>${lines.map((l) => `<li>${esc(l.replace(/^\d+\.\s/, ''))}</li>`).join('')}</ol>`;
    if (CODE_LINE.test(lines[0])) return `<pre>${esc(p)}</pre>`;
    return `<p>${esc(p).replace(/\n/g, '<br>')}</p>`;
  }).join('\n      ');
}

const HEAD = (title, desc, canonical) => `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(desc)}">
  <link rel="canonical" href="${canonical}">
  <meta property="og:title" content="${esc(title)}">
  <meta property="og:description" content="${esc(desc)}">
  <meta property="og:type" content="article">
  <meta property="og:url" content="${canonical}">
  <link rel="icon" href="/favicon.ico" sizes="any">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="stylesheet" href="/style.css">
  <meta property="og:image" content="https://verifica.corevatech.com.br/og.png">
  <meta name="twitter:card" content="summary_large_image">
  <script src="/theme.js"></script>
</head>`;
const NAV = () => '<nav class="nav" aria-label="Seções"><a href="/">Verifica Segurança</a><a href="/status">Status de nuvens e serviços</a><a href="/glossario/" aria-current="page">Glossário</a></nav>';
const TOPBAR = `<div class="topbar"><div class="topbar-in"><a class="brand" href="https://corevatech.com.br" aria-label="Coreva Tech"><img src="/favicon.svg" alt="" width="36" height="36"><span>Coreva Tech</span></a>${NAV()}<button id="theme" class="theme-btn" type="button" aria-label="Alternar tema claro ou escuro">☾</button><a class="btn-cta" href="https://corevatech.com.br" target="_blank" rel="noopener">Fale com a Coreva</a></div></div>`;
const FOOT = `<footer>
      <p class="foot-links"><a href="/">Verifica</a> · <a href="/status">Status</a> · <a href="/glossario/">Glossário</a> · <a href="/privacidade">Privacidade</a></p>
      Conteúdo educativo, atualizado em ${REVISAO}; não substitui consultoria especializada. Encontrou um erro ou quer sugerir um termo? Escreva para <a href="mailto:contato@corevatech.com.br">contato@corevatech.com.br</a>.<br>
      <a href="/privacidade">Política de Privacidade</a>
    </footer>`;
const CTA = `<aside class="cta">
      <strong>Quer ajuda para aplicar isso na sua empresa?</strong>
      <span>A Coreva Tech atua em Infraestrutura, Segurança da Informação e Governança de TI.</span>
      <a href="https://corevatech.com.br" target="_blank" rel="noopener">Fale com a Coreva Tech →</a>
    </aside>`;

function verbete(v) {
  const c = cat[v.categoria];
  const url = `${BASE}/glossario/${v.slug}.html`;
  const sec = (h, body) => `<section><h2>${h}</h2>\n      ${body}\n    </section>`;
  const parts = [sec(LABEL.importa(v.categoria), blocks(v.importa))];
  if (v.verifica) parts.push(sec(LABEL.verifica(v.categoria), blocks(v.verifica)));
  if (v.corrigir) parts.push(sec(LABEL.corrigir(v.categoria), blocks(v.corrigir)));
  if ((v.relacionados || []).length) parts.push(sec('Veja também', `<ul class="chips">${v.relacionados.map((s) => `<li><a href="/glossario/${s}.html">${esc(bySlug[s].termo)}</a></li>`).join('')}</ul>`));
  if ((v.refs || []).length) parts.push(sec('Referências', `<ul class="refs">${v.refs.map(([t, u]) => `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a></li>`).join('')}</ul>`));
  const isCheck = ['headers', 'tls', 'dns', 'email'].includes(v.categoria);
  return `${HEAD(`${v.termo}: o que é e como funciona | Glossário Verifica`, cut(v.resumo, 155), url)}
<body>
  <a class="skip" href="#main">Ir para o conteúdo</a>
  ${TOPBAR}
  <main id="main" class="article">
    <header>
      <p class="crumb"><a href="/glossario/">Glossário</a> › <a href="/glossario/#${v.categoria}">${esc(c.nome)}</a></p>
      <h1>${esc(v.termo)}</h1>
      <p class="lead">${esc(v.resumo)}</p>
    </header>
    ${parts.join('\n    ')}
    ${isCheck ? '<p class="try"><a class="btn" href="/">Analisar o meu domínio agora →</a></p>' : ''}
    ${CTA}
    ${FOOT}
  </main>
</body>
</html>
`;
}

function indice() {
  const sections = CATEGORIAS.map((c) => {
    const items = VERBETES.filter((v) => v.categoria === c.id).sort((a, b) => a.termo.localeCompare(b.termo, 'pt-BR'));
    return `<section id="${c.id}" class="gcat">
      <h2>${esc(c.nome)} <small>${items.length}</small></h2>
      <p class="muted-p">${esc(c.desc)}</p>
      <div class="grid">
        ${items.map((v) => `<a class="tcard" href="/glossario/${v.slug}.html" data-busca="${esc(norm([v.termo, ...(v.busca || []), v.resumo].join(' ')))}"><strong>${esc(v.termo)}</strong><span>${esc(cut(v.resumo, 110))}</span></a>`).join('\n        ')}
      </div>
    </section>`;
  }).join('\n    ');
  return `${HEAD('Glossário de segurança da informação | Verifica — Coreva Tech', `Glossário de segurança da informação com ${VERBETES.length} verbetes: headers HTTP, TLS, DNS, e-mail, ataques e governança, em português e com orientação prática.`, `${BASE}/glossario/`)}
<body>
  <a class="skip" href="#main">Ir para o conteúdo</a>
  ${TOPBAR}
  <main id="main" class="wide">
    <header>
      <h1>Glossário de <span>segurança da informação</span></h1>
      <p>${VERBETES.length} verbetes em português: o que cada verificação do Verifica significa, os principais ataques e os conceitos de governança, sempre com o que fazer a respeito.</p>
    </header>
    <div class="searchbox"><label for="q" class="sr">Buscar no glossário</label><input id="q" type="search" placeholder="Buscar: dmarc, xss, lgpd…" autocomplete="off"></div>
    <p id="nores" class="muted-p" hidden>Nenhum verbete encontrado. Tente outro termo ou sinônimo.</p>
    ${sections}
    ${CTA}
    ${FOOT}
  </main>
  <script src="/glossario.js"></script>
</body>
</html>
`;
}

function sitemap() {
  const urls = ['/', '/status', '/privacidade', '/glossario/', ...VERBETES.map((v) => `/glossario/${v.slug}.html`)];
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${BASE}${u}</loc></url>`).join('\n')}\n</urlset>\n`;
}

// Retorna { 'glossario/hsts.html': '<html…', … } para gravar em public/ (ou comparar nos testes).
function render() {
  const out = { 'glossario/index.html': indice(), 'sitemap.xml': sitemap(), 'glossario-mapa.js': `'use strict';\n// Gerado por scripts/build-glossario.js: id da verificação -> verbete do glossário.\nwindow.GLOSS = ${JSON.stringify(CHECK_MAP)};\n` };
  for (const v of VERBETES) out[`glossario/${v.slug}.html`] = verbete(v);
  return out;
}
module.exports = { render, norm };
