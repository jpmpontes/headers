#!/usr/bin/env node
'use strict';
// Gera public/glossario/*.html e public/sitemap.xml a partir de src/glossario/. Rode após editar os verbetes.
const fs = require('node:fs');
const path = require('node:path');
const { render } = require('../src/glossario/build');

const root = path.join(__dirname, '..', 'public');
const files = render();
fs.mkdirSync(path.join(root, 'glossario'), { recursive: true });
// Remove páginas de verbetes que não existem mais.
for (const f of fs.readdirSync(path.join(root, 'glossario'))) if (f.endsWith('.html') && !files[`glossario/${f}`]) fs.unlinkSync(path.join(root, 'glossario', f));
for (const [rel, html] of Object.entries(files)) fs.writeFileSync(path.join(root, rel), html);
console.log(`glossário: ${Object.keys(files).length} arquivos gerados em public/`);
