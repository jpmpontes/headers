'use strict';
// Regiões conhecidas (id do fornecedor, nome, latitude, longitude) e fornecedores sem fonte pública confiável.
const GCP_REGIONS = [
  ['us-central1', 'Iowa', 41.26, -95.86], ['us-east1', 'Carolina do Sul', 33.2, -80.0], ['us-east4', 'Virgínia', 39.0, -77.5], ['us-east5', 'Columbus', 39.96, -83.0],
  ['us-south1', 'Dallas', 32.78, -96.8], ['us-west1', 'Oregon', 45.6, -121.2], ['us-west2', 'Los Angeles', 34.05, -118.24], ['us-west3', 'Salt Lake City', 40.76, -111.89],
  ['us-west4', 'Las Vegas', 36.17, -115.14], ['northamerica-northeast1', 'Montreal', 45.5, -73.57], ['northamerica-northeast2', 'Toronto', 43.65, -79.38],
  ['northamerica-south1', 'Querétaro', 20.59, -100.39], ['southamerica-east1', 'São Paulo', -23.55, -46.63], ['southamerica-west1', 'Santiago', -33.45, -70.67],
  ['europe-west1', 'Bélgica', 50.45, 3.82], ['europe-west2', 'Londres', 51.5, -0.12], ['europe-west3', 'Frankfurt', 50.11, 8.68], ['europe-west4', 'Países Baixos', 53.44, 6.84],
  ['europe-west6', 'Zurique', 47.37, 8.54], ['europe-west8', 'Milão', 45.46, 9.19], ['europe-west9', 'Paris', 48.85, 2.35], ['europe-north1', 'Finlândia', 60.57, 27.2],
  ['europe-southwest1', 'Madri', 40.42, -3.7], ['europe-central2', 'Varsóvia', 52.23, 21.01], ['me-west1', 'Tel Aviv', 32.08, 34.78], ['me-central2', 'Dammam', 26.43, 50.1],
  ['asia-east1', 'Taiwan', 24.05, 120.5], ['asia-east2', 'Hong Kong', 22.3, 114.17], ['asia-northeast1', 'Tóquio', 35.68, 139.69], ['asia-northeast2', 'Osaka', 34.69, 135.5],
  ['asia-northeast3', 'Seul', 37.56, 126.98], ['asia-south1', 'Mumbai', 19.08, 72.88], ['asia-south2', 'Délhi', 28.61, 77.2], ['asia-southeast1', 'Singapura', 1.35, 103.82],
  ['asia-southeast2', 'Jacarta', -6.2, 106.85], ['australia-southeast1', 'Sydney', -33.87, 151.21], ['australia-southeast2', 'Melbourne', -37.81, 144.96], ['africa-south1', 'Joanesburgo', -26.2, 28.05],
].map(([id, nome, lat, lon]) => ({ id, nome, lat, lon }));

// Fornecedores em que NÃO há fonte pública confiável (validado em 12/11/2026): aparecem como "sem dados", nunca como "operacional".
const SEM_FONTE = [
  { id: 'azure', nome: 'Microsoft Azure', grupo: 'cloud', motivo: 'A página pública mostra só eventos que afetam todo o Azure. O detalhe por região (como Brazil South) fica no Azure Service Health, que exige login.', url: 'https://azure.status.microsoft/' },
  { id: 'alibaba', nome: 'Alibaba Cloud', grupo: 'cloud', motivo: 'A API de saúde dos serviços está ligada a plano de suporte e a termos próprios; fonte pública não confirmada.', url: 'https://status.aliyun.com/' },
  { id: 'm365', nome: 'Microsoft 365', grupo: 'saas', motivo: 'A API oficial é por tenant e exige autenticação; não há feed público confiável.', url: 'https://status.cloud.microsoft/' },
  { id: 'apple', nome: 'Apple', grupo: 'saas', motivo: 'Não há API oficial documentada; a página de status é conhecida por atrasos.', url: 'https://www.apple.com/support/systemstatus/' },
  { id: 'zoho', nome: 'Zoho', grupo: 'saas', motivo: 'O status é publicado por região em domínios próprios, sem feed ou API documentados.', url: 'https://us.zohostatus.com/' },
];
module.exports = { GCP_REGIONS, SEM_FONTE };
