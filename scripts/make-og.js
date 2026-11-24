'use strict';
// Gera public/og.png (1200x630) para o compartilhamento em redes sociais.
// Uso: node scripts/make-og.js   (precisa do Playwright; é uma ferramenta de desenvolvimento, não roda em produção)
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.join(__dirname, '..', 'public');
const logo = 'data:image/svg+xml;base64,' + fs.readFileSync(path.join(root, 'favicon.svg')).toString('base64');
const html = `<!doctype html><meta charset="utf-8"><style>
*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;background:#0e1420;color:#e6ebf5;font:400 32px/1.4 system-ui,'Segoe UI',Roboto,Arial,sans-serif;position:relative;overflow:hidden}
.glow{position:absolute;right:-160px;top:-160px;width:640px;height:640px;border-radius:50%;background:radial-gradient(circle,rgba(61,214,176,.28),transparent 65%)}
.wrap{position:absolute;inset:0;padding:68px 80px;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:16px;font-weight:700;font-size:30px;color:#c4cde0}.brand img{width:56px;height:56px;border-radius:14px}
h1{margin:auto 0 0;font-size:76px;line-height:1.05;letter-spacing:-.03em;font-weight:800;max-width:900px}h1 span{color:#3dd6b0}
p{margin:22px 0 0;color:#8a96ad;font-size:32px;max-width:860px}
.row{margin-top:34px;display:flex;gap:14px}.pill{padding:8px 20px;border:1px solid #27324a;border-radius:99px;background:#161e2e;font-size:24px;color:#c4cde0}
.url{position:absolute;right:80px;top:78px;font-size:26px;color:#3dd6b0;font-weight:600}
</style><div class="glow"></div><div class="wrap"><div class="brand"><img src="${logo}" alt="">Coreva Tech</div><div class="url">verifica.corevatech.com.br</div>
<h1>Veja como o seu domínio aparece <span>para um atacante</span></h1><p>Headers, TLS, DNS e e-mail analisados em segundos, com o passo a passo para corrigir.</p>
<div class="row"><span class="pill">Gratuito</span><span class="pill">Sem cadastro</span><span class="pill">Nota de A+ a F</span></div></div>`;
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1200, height: 630 } });
  await p.setContent(html);
  await p.screenshot({ path: path.join(root, 'og.png') });
  await b.close();
  console.log('public/og.png gerado');
})();
