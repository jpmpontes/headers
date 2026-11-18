'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { getStatus, resetForTests } = require('../src/status');
const { parseRss } = require('../src/status/xml');

const GCP = JSON.stringify([
  { id: 'a1', begin: '2026-11-12T10:00:00Z', end: null, external_desc: 'Latência no Cloud Storage', status_impact: 'SERVICE_DISRUPTION', severity: 'medium', uri: 'incidents/a1',
    affected_products: [{ title: 'Cloud Storage', id: 'x' }], currently_affected_locations: [{ title: 'São Paulo (southamerica-east1)', id: 'southamerica-east1' }] },
  { id: 'a2', begin: '2026-10-01T10:00:00Z', end: '2026-10-01T12:00:00Z', external_desc: 'Antigo', status_impact: 'SERVICE_OUTAGE', currently_affected_locations: [{ id: 'us-east1' }] },
]);
const WS = JSON.stringify([{ id: 'w1', begin: '2026-11-12T09:00:00Z', end: null, external_desc: 'Aviso', status_impact: 'SERVICE_INFORMATION', affected_products: [{ title: 'Gmail' }] }]);
const rss = (title, date) => `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title><item><title><![CDATA[${title}]]></title><pubDate>${date}</pubDate><description>desc &amp; mais</description><link>https://x</link></item></channel></rss>`;
const NOW = Date.parse('2026-11-12T12:00:00Z');
const RECENT = 'Thu, 12 Nov 2026 11:00:00 GMT';

const feeds = (over = {}) => async (url) => {
  if (url in over) { const v = over[url]; if (v instanceof Error) throw v; return v; }
  if (url.includes('incidents.json') && url.includes('cloud.google')) return GCP;
  if (url.includes('appsstatus')) return WS;
  if (url.includes('ec2-sa-east-1')) return rss('[RESOLVED] Increased API Error Rates', RECENT);
  if (url.includes('s3-sa-east-1')) return rss('Increased Error Rates', RECENT);
  throw new Error('fora do ar');
};
const get = (r, id) => r.provedores.find((p) => p.id === id);

test('Google Cloud: incidente ativo em São Paulo; encerrado é ignorado', async () => {
  resetForTests();
  const r = await getStatus({ fetchText: feeds(), now: NOW });
  const g = get(r, 'gcp');
  assert.strictEqual(g.estado, 'degradado');
  assert.strictEqual(g.incidentes.length, 1);
  assert.strictEqual(g.regioes.find((x) => x.id === 'southamerica-east1').estado, 'degradado');
  assert.strictEqual(g.regioes.find((x) => x.id === 'us-east1').estado, 'operacional');
  assert.strictEqual(r.brasil.find((b) => b.id === 'gcp').estado, 'degradado');
  assert.strictEqual(g.fonte.validada, true);
});
test('AWS: pior estado entre os feeds; feeds fora do ar marcam parcial', async () => {
  resetForTests();
  const a = get(await getStatus({ fetchText: feeds(), now: NOW }), 'aws');
  assert.strictEqual(a.estado, 'degradado');
  assert.strictEqual(a.parcial, true);
  assert.strictEqual(a.fonte.validada, false);
  assert.strictEqual(a.incidentes[0].produtos[0], 'S3');
});
test('Workspace: aviso informativo não conta como problema', async () => {
  resetForTests();
  const w = get(await getStatus({ fetchText: feeds(), now: NOW }), 'workspace');
  assert.strictEqual(w.estado, 'operacional');
  assert.strictEqual(w.incidentes[0].estado, 'informativo');
});
test('fornecedores sem fonte pública nunca aparecem como operacionais', async () => {
  resetForTests();
  const r = await getStatus({ fetchText: feeds(), now: NOW });
  for (const id of ['azure', 'alibaba', 'm365', 'apple', 'zoho']) {
    assert.strictEqual(get(r, id).estado, 'semdados'); assert.ok(get(r, id).motivo);
  }
  assert.strictEqual(r.brasil.find((b) => b.id === 'azure').estado, 'semdados');
});
test('todas as fontes fora do ar: "sem dados", nunca "operacional", e sem exceção', async () => {
  resetForTests();
  const r = await getStatus({ fetchText: async () => { throw new Error('rede'); }, now: NOW });
  for (const id of ['gcp', 'aws', 'workspace']) assert.strictEqual(get(r, id).estado, 'semdados');
  assert.ok(r.brasil.every((b) => b.estado === 'semdados'));
});
test('fonte com formato inesperado vira "sem dados"', async () => {
  resetForTests();
  const r = await getStatus({ fetchText: feeds({ 'https://status.cloud.google.com/incidents.json': '{"nao":"array"}' }), now: NOW });
  assert.strictEqual(get(r, 'gcp').estado, 'semdados');
  assert.strictEqual(get(r, 'workspace').estado, 'operacional'); // uma fonte quebrada não afeta as outras
});
test('cache de 60 s; depois, dado antigo é mantido como desatualizado por até 10 min', async () => {
  resetForTests();
  let calls = 0;
  const f = async (u) => { calls++; return feeds()(u); };
  await getStatus({ fetchText: f, now: NOW });
  const c1 = calls;
  await getStatus({ fetchText: f, now: NOW + 30000 });
  assert.strictEqual(calls, c1); // veio do cache
  const down = async () => { throw new Error('rede'); };
  const r2 = await getStatus({ fetchText: down, now: NOW + 5 * 60000 });
  assert.strictEqual(get(r2, 'gcp').desatualizado, true);
  assert.strictEqual(get(r2, 'gcp').estado, 'degradado');
  const r3 = await getStatus({ fetchText: down, now: NOW + 20 * 60000 });
  assert.strictEqual(get(r3, 'gcp').estado, 'semdados');
});
test('fonte que trava não trava o painel (timeout)', async () => {
  resetForTests();
  const hang = () => new Promise(() => {});
  const t0 = Date.now();
  const r = await getStatus({ fetchText: hang, now: NOW, timeoutMs: 150 });
  assert.ok(Date.now() - t0 < 2000);
  assert.strictEqual(get(r, 'gcp').estado, 'semdados');
});
test('RSS: CDATA, entidades e datas inválidas', () => {
  const [i] = parseRss(rss('Título &amp; <b>x</b>', RECENT));
  assert.strictEqual(i.title, 'Título &amp; <b>x</b>'); // CDATA fica literal
  assert.strictEqual(i.description, 'desc & mais');
  assert.ok(i.date instanceof Date);
  assert.throws(() => parseRss('<html></html>'));
});
