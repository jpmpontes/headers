'use strict';
// Agregador do painel de status. Isolado do scanner: nenhuma exceção sai daqui, e cada fonte tem timeout próprio.
// Cache em memória (~60 s) e, se uma fonte falhar, mantém o último dado bom por até 10 min marcado como desatualizado.
const { google, workspace, aws } = require('./adapters');
const { SEM_FONTE } = require('./catalog');

const CACHE_MS = 60 * 1000;
const STALE_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 4000;
const MAX_BYTES = 2 * 1024 * 1024;

async function defaultFetchText(url) {
  if (process.env.STATUS_FETCH === '0') throw new Error('leitura externa desativada'); // testes
  const res = await fetch(url, { headers: { 'user-agent': 'Verifica-Status-CorevaTech/1.0 (+https://verifica.corevatech.com.br/status)', accept: 'application/json, application/rss+xml, text/xml, */*' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error('resposta grande demais');
  return text;
}

const lastGood = new Map();
let cache = null;
let inflight = null;

async function collect(adapter, fetchText, now) {
  if (adapter.parseFeeds) {
    const results = await Promise.all(adapter.feeds.map(async (f) => ({ servico: f.servico, text: await fetchText(f.url).catch(() => null) })));
    return adapter.parseFeeds(results, now);
  }
  return adapter.parse(await fetchText(adapter.url));
}

async function runAdapter(adapter, fetchText, now, timeoutMs) {
  const base = { id: adapter.id, nome: adapter.nome, grupo: adapter.grupo, fonte: { tipo: 'reportado pelo fornecedor', url: adapter.pagina || adapter.url, validada: adapter.verificada } };
  try {
    let timer;
    const limite = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), timeoutMs); });
    const data = await Promise.race([collect(adapter, fetchText, now), limite]).finally(() => clearTimeout(timer));
    const ok = { ...base, ...data, atualizadoEm: new Date(now).toISOString() };
    lastGood.set(adapter.id, { at: now, ok });
    return ok;
  } catch {
    const prev = lastGood.get(adapter.id);
    if (prev && now - prev.at < STALE_MS) return { ...prev.ok, desatualizado: true };
    return { ...base, estado: 'semdados', incidentes: [], regioes: [], motivo: 'Não foi possível ler a fonte do fornecedor agora.' };
  }
}

const semFonte = (p) => ({ id: p.id, nome: p.nome, grupo: p.grupo, estado: 'semdados', incidentes: [], regioes: [], motivo: p.motivo, fonte: { tipo: 'sem fonte pública', url: p.url, validada: true } });

async function build({ fetchText, now, timeoutMs }) {
  const ativos = await Promise.all([google, aws, workspace].map((a) => runAdapter(a, fetchText, now, timeoutMs)));
  const provedores = [...ativos, ...SEM_FONTE.map(semFonte)];
  const byId = Object.fromEntries(provedores.map((p) => [p.id, p]));
  const regiao = (p, id) => (p.regioes || []).find((r) => r.id === id);
  const sp = (p, id) => {
    const r = regiao(p, id);
    return { provedor: p.nome, id: p.id, regiao: 'São Paulo', estado: r ? r.estado : 'semdados', motivo: r ? null : (p.motivo || 'Sem dados regionais publicados pelo fornecedor.'), desatualizado: Boolean(p.desatualizado) };
  };
  const brasil = [sp(byId.gcp, 'southamerica-east1'), sp(byId.aws, 'sa-east-1'), sp(byId.azure, 'brazilsouth'), sp(byId.alibaba, 'br')];
  return { geradoEm: new Date(now).toISOString(), provedores, brasil };
}

// opts.fetchText e opts.now são injetáveis nos testes; opts.fresh ignora o cache.
async function getStatus(opts = {}) {
  const fetchText = opts.fetchText || defaultFetchText;
  const now = opts.now || Date.now();
  if (!opts.fresh && cache && now - cache.at < CACHE_MS) return cache.data;
  if (!opts.fresh && inflight) return inflight;
  inflight = build({ fetchText, now, timeoutMs: opts.timeoutMs || FETCH_TIMEOUT_MS * 2 }).then((data) => { cache = { at: now, data }; return data; }).catch(() => cache ? cache.data : { geradoEm: new Date(now).toISOString(), provedores: [], brasil: [], erro: 'indisponivel' }).finally(() => { inflight = null; });
  return inflight;
}
const resetForTests = () => { cache = null; inflight = null; lastGood.clear(); };

module.exports = { getStatus, resetForTests };
