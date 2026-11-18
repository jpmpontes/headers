'use strict';
// Leitor mínimo de RSS 2.0 (sem dependências). Suficiente para feeds de status: itens com title, pubDate, description e link.
const ENT = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&apos;': "'" };
const decode = (s) => s.replace(/&(amp|lt|gt|quot|apos|#39);/g, (m) => ENT[m]);
const tag = (block, name) => {
  const m = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i').exec(block);
  if (!m) return '';
  const cdata = /^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/.exec(m[1]);
  return (cdata ? cdata[1] : decode(m[1])).trim();
};
function parseRss(xml) {
  if (typeof xml !== 'string' || !/<rss|<feed|<channel/i.test(xml)) throw new Error('feed inválido');
  const items = [];
  for (const m of xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)) {
    const b = m[1];
    const d = new Date(tag(b, 'pubDate'));
    items.push({ title: tag(b, 'title'), description: tag(b, 'description').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(), link: tag(b, 'link'), date: Number.isNaN(+d) ? null : d });
  }
  return items;
}
module.exports = { parseRss };
