'use strict';
// Cada adaptador recebe fetchText(url) e devolve { estado, incidentes, regioes?, parcial? }.
// Se a fonte mudar de formato, só o adaptador correspondente precisa de ajuste.
const { parseRss } = require('./xml');
const { GCP_REGIONS } = require('./catalog');

const RANK = { operacional: 0, degradado: 1, indisponivel: 2 };
const worst = (list) => list.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'operacional');
const arr = (x) => (Array.isArray(x) ? x : []);
const str = (x, n = 200) => String(x == null ? '' : x).slice(0, n);

// Mapeia o impacto declarado pelo Google (Cloud e Workspace) para o estado normalizado.
function impactToState(i) {
  const impact = String(i.status_impact || '').toUpperCase();
  if (impact === 'SERVICE_OUTAGE') return 'indisponivel';
  if (impact === 'SERVICE_DISRUPTION') return 'degradado';
  if (impact === 'SERVICE_INFORMATION') return 'informativo';
  return String(i.severity || '').toLowerCase() === 'high' ? 'indisponivel' : 'degradado';
}

function googleIncidents(json, baseUrl) {
  if (!Array.isArray(json)) throw new Error('formato inesperado');
  return json.filter((i) => i && !i.end).map((i) => ({
    id: str(i.id, 40),
    titulo: str(i.external_desc || i.service_name || 'Incidente', 160),
    estado: impactToState(i),
    inicio: i.begin || null,
    produtos: arr(i.affected_products).map((p) => str(p.title, 60)).slice(0, 8),
    regioes: arr(i.currently_affected_locations).map((l) => str(l.id, 40)),
    url: i.uri ? `${baseUrl}/${String(i.uri).replace(/^\/+/, '')}` : baseUrl,
  }));
}

const google = {
  id: 'gcp', nome: 'Google Cloud', grupo: 'cloud',
  url: 'https://status.cloud.google.com/incidents.json', pagina: 'https://status.cloud.google.com', verificada: true,
  parse(text) {
    const incidentes = googleIncidents(JSON.parse(text), 'https://status.cloud.google.com');
    const regioes = GCP_REGIONS.map((r) => ({ ...r, estado: worst(incidentes.filter((i) => i.regioes.includes(r.id)).map((i) => i.estado)) }));
    return { estado: worst(incidentes.map((i) => i.estado)), incidentes, regioes };
  },
};

const workspace = {
  id: 'workspace', nome: 'Google Workspace', grupo: 'saas',
  url: 'https://www.google.com/appsstatus/dashboard/incidents.json', pagina: 'https://www.google.com/appsstatus/dashboard/', verificada: false,
  parse(text) {
    const incidentes = googleIncidents(JSON.parse(text), 'https://www.google.com/appsstatus/dashboard');
    return { estado: worst(incidentes.map((i) => i.estado)), incidentes, regioes: [] };
  },
};

// AWS: um feed RSS por serviço e região (padrão a confirmar). Estado = o do evento mais recente de cada feed.
const AWS_SERVICES = ['ec2', 's3', 'rds', 'lambda', 'dynamodb'];
function awsState(item, now) {
  const text = `${item.title} ${item.description}`.toLowerCase();
  if (!item.date || now - item.date.getTime() > 48 * 3600 * 1000) return 'operacional';
  if (/\[resolved\]|operating normally|resolved/.test(text)) return 'operacional';
  if (/service is (unavailable|down)|disruption|outage|unavailable/.test(text)) return 'indisponivel';
  return 'degradado';
}
const aws = {
  id: 'aws', nome: 'Amazon Web Services', grupo: 'cloud', pagina: 'https://health.aws.amazon.com/health/status', verificada: false,
  feeds: AWS_SERVICES.map((s) => ({ servico: s, url: `https://status.aws.amazon.com/rss/${s}-sa-east-1.rss` })),
  parseFeeds(results, now = Date.now()) { // results: [{servico, text|null}]
    const ok = results.filter((r) => r.text != null);
    if (!ok.length) throw new Error('nenhum feed disponível');
    const incidentes = [];
    const estados = [];
    for (const r of ok) {
      const items = parseRss(r.text).sort((a, b) => (b.date || 0) - (a.date || 0));
      const last = items[0];
      const estado = last ? awsState(last, now) : 'operacional';
      estados.push(estado);
      if (last && estado !== 'operacional') incidentes.push({ id: `${r.servico}-${last.date && last.date.getTime()}`, titulo: str(last.title, 160), estado, inicio: last.date ? last.date.toISOString() : null, produtos: [r.servico.toUpperCase()], regioes: ['sa-east-1'], url: 'https://health.aws.amazon.com/health/status' });
    }
    const estado = worst(estados);
    return { estado, incidentes, regioes: [{ id: 'sa-east-1', nome: 'São Paulo', lat: -23.55, lon: -46.63, estado }], parcial: ok.length < results.length };
  },
};

module.exports = { google, workspace, aws, worst, impactToState };
