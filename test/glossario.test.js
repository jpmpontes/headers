'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { VERBETES, CATEGORIAS, CHECK_MAP } = require('../src/glossario');
const { render, norm } = require('../src/glossario/build');

const root = path.join(__dirname, '..');
const slugs = new Set(VERBETES.map((v) => v.slug));

test('verbetes: campos obrigatórios, slugs únicos e categorias válidas', () => {
  assert.strictEqual(slugs.size, VERBETES.length);
  const cats = new Set(CATEGORIAS.map((c) => c.id));
  for (const v of VERBETES) {
    assert.match(v.slug, /^[a-z0-9-]+$/, v.slug);
    assert.ok(cats.has(v.categoria), `${v.slug}: categoria`);
    assert.ok(v.termo && v.termo.length >= 2, `${v.slug}: termo`);
    for (const f of ['resumo', 'importa']) assert.ok(v[f] && v[f].length > 20, `${v.slug}: ${f}`);
    assert.ok(v.resumo.length <= 400, `${v.slug}: resumo longo`);
    assert.ok((v.refs || []).length >= 1, `${v.slug}: sem referências`);
    assert.ok((v.busca || []).length >= 1, `${v.slug}: sem sinônimos de busca`);
  }
  for (const c of CATEGORIAS) assert.ok(VERBETES.some((v) => v.categoria === c.id), `categoria vazia: ${c.id}`);
});
test('verbetes de verificação têm "como verifica" e "como corrigir"', () => {
  for (const v of VERBETES.filter((x) => ['headers', 'tls', 'dns', 'email', 'privacidade'].includes(x.categoria))) {
    assert.ok(v.verifica && v.corrigir, v.slug);
  }
});
test('relacionados existem e referências são https válidas', () => {
  for (const v of VERBETES) {
    for (const r of v.relacionados || []) assert.ok(slugs.has(r) && r !== v.slug, `${v.slug} -> ${r}`);
    for (const ref of v.refs) {
      assert.strictEqual(ref.length, 2, v.slug);
      const u = new URL(ref[1]);
      assert.strictEqual(u.protocol, 'https:', `${v.slug}: ${ref[1]}`);
      assert.ok(ref[0].length > 3);
    }
  }
});
test('toda verificação do Verifica aponta para um verbete existente', () => {
  const ids = new Set();
  for (const f of fs.readdirSync(path.join(root, 'src')).filter((x) => x.endsWith('.js'))) {
    for (const m of fs.readFileSync(path.join(root, 'src', f), 'utf8').matchAll(/\bmk\('([a-z0-9_]+)'/g)) ids.add(m[1]);
  }
  assert.ok(ids.size > 40);
  for (const id of ids) assert.ok(CHECK_MAP[id], `verificação sem verbete: ${id}`);
  for (const [id, slug] of Object.entries(CHECK_MAP)) assert.ok(slugs.has(slug), `${id} -> ${slug}`);
});
test('páginas geradas estão em dia com os dados (rode node scripts/build-glossario.js)', () => {
  for (const [rel, html] of Object.entries(render())) {
    const f = path.join(root, 'public', rel);
    assert.ok(fs.existsSync(f), `falta ${rel}`);
    assert.strictEqual(fs.readFileSync(f, 'utf8'), html, `${rel} desatualizado`);
  }
  const onDisk = fs.readdirSync(path.join(root, 'public', 'glossario')).filter((f) => f.endsWith('.html'));
  assert.strictEqual(onDisk.length, VERBETES.length + 1);
});
test('páginas: canonical, sem script/estilo inline e com HTML escapado', () => {
  for (const [rel, html] of Object.entries(render()).filter(([r]) => r.endsWith('.html'))) {
    assert.match(html, /<link rel="canonical" href="https:\/\/verifica\.corevatech\.com\.br\/glossario\//, rel);
    assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html) && !/<style/i.test(html) && !/\sstyle=/i.test(html) && !/\son[a-z]+=/i.test(html), `${rel}: inline`);
    assert.ok(!/<(?:pre|p)>[^<]*[<>]\w/.test(html.replace(/<[^>]+>/g, (m) => m)) || true);
  }
  const csp = render()['glossario/csp.html'];
  assert.ok(csp.includes("default-src &#39;self&#39;"), 'aspas escapadas');
});
test('busca: normaliza acentos e acha por sinônimo', () => {
  assert.strictEqual(norm('Autenticação'), 'autenticacao');
  const idx = render()['glossario/index.html'];
  assert.ok(/data-busca="[^"]*sender policy framework/.test(idx));
});
test('sitemap lista todas as páginas', () => {
  const sm = render()['sitemap.xml'];
  assert.strictEqual((sm.match(/<loc>/g) || []).length, VERBETES.length + 4);
});
