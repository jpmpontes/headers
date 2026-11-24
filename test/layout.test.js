'use strict';
// Layout compartilhado: cabeçalho único, tema, skip link, imagem OG e CSP (sem inline).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { render } = require('../src/glossario/build');

const pub = path.join(__dirname, '..', 'public');
const pages = {
  'index.html': fs.readFileSync(path.join(pub, 'index.html'), 'utf8'),
  'status.html': fs.readFileSync(path.join(pub, 'status.html'), 'utf8'),
  'privacidade.html': fs.readFileSync(path.join(pub, 'privacidade.html'), 'utf8'),
  'glossario/index.html': render()['glossario/index.html'],
  'glossario/csp.html': render()['glossario/csp.html'],
};

test('todas as páginas têm barra única, botão de tema, skip link, main#main e theme.js', () => {
  for (const [n, h] of Object.entries(pages)) {
    assert.match(h, /class="topbar"/, n);
    assert.match(h, /id="theme"/, n);
    assert.match(h, /<a class="skip" href="#main">/, n);
    assert.match(h, /<main id="main"/, n);
    assert.match(h, /<script src="\/theme\.js"><\/script>/, n);
    assert.match(h, /href="\/glossario\/"/, n);
  }
});
test('páginas não usam script, estilo ou handlers inline (CSP)', () => {
  for (const [n, h] of Object.entries(pages)) {
    assert.ok(!/<script(?![^>]*\bsrc=)/i.test(h) && !/<style/i.test(h) && !/\sstyle=/i.test(h) && !/\son[a-z]+=/i.test(h), n);
  }
});
test('metadados de compartilhamento apontam para a imagem OG', () => {
  for (const n of ['index.html', 'status.html', 'glossario/index.html']) {
    assert.match(pages[n], /og:image" content="https:\/\/verifica\.corevatech\.com\.br\/og\.png"/, n);
    assert.match(pages[n], /twitter:card" content="summary_large_image"/, n);
  }
});
test('og.png é um PNG de 1200x630', () => {
  const b = fs.readFileSync(path.join(pub, 'og.png'));
  assert.strictEqual(b.slice(1, 4).toString(), 'PNG');
  assert.strictEqual(b.readUInt32BE(16), 1200);
  assert.strictEqual(b.readUInt32BE(20), 630);
  assert.ok(b.length < 600 * 1024);
});
test('index tem hero, skeleton, medidor e CTA contextual; status tem skeleton', () => {
  for (const id of ['id="skeleton"', 'id="gauge"', 'id="bars"', 'id="cta-title"', 'id="issues"', 'id="pillars"']) assert.ok(pages['index.html'].includes(id), id);
  assert.ok(pages['status.html'].includes('skel-pc'));
});
test('app.js e theme.js: sem innerHTML/eval; tema guarda em try/catch', () => {
  for (const f of ['app.js', 'theme.js']) {
    const s = fs.readFileSync(path.join(pub, f), 'utf8');
    assert.ok(!/innerHTML|eval\(|document\.write/.test(s), f);
  }
  const t = fs.readFileSync(path.join(pub, 'theme.js'), 'utf8');
  assert.ok((t.match(/try \{/g) || []).length >= 2);
});
test('CSS: variáveis de tema, foco visível, movimento reduzido e contraste do botão claro', () => {
  const c = fs.readFileSync(path.join(pub, 'style.css'), 'utf8');
  for (const k of [':root[data-theme=light]', ':root[data-theme=dark]', ':focus-visible', 'prefers-reduced-motion', '--accent:#087560']) assert.ok(c.includes(k), k);
});
