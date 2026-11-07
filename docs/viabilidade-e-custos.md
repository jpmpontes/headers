# Coreva Headers — viabilidade, custos e plano

> Serviço gratuito/freemium de análise de headers de segurança HTTP para a Coreva Tech, na linha do securityheaders.com.
> Documento criado em 05/11/2026. Valores de preço são estimativas: confirme nos sites oficiais antes de contratar.

## 1. É viável?

Sim. É um dos serviços de segurança mais simples de construir. Um MVP em Node, Python ou Go sai em um fim de semana até 2 semanas, conforme o acabamento.

### Como funciona

1. O usuário informa uma URL.
2. O backend faz uma requisição HTTP, seguindo os redirects.
3. Lê os headers da resposta e confere cada um.
4. Calcula uma nota (A+ a F) e mostra a explicação e a correção sugerida de cada item.

### O que é verificado

| Item | Peso no MVP |
|---|---|
| Content-Security-Policy (CSP) | 25 |
| Strict-Transport-Security (HSTS) | 20 |
| X-Content-Type-Options | 10 |
| Clickjacking (X-Frame-Options ou CSP `frame-ancestors`) | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| Flags de cookies (`Secure`, `HttpOnly`, `SameSite`) | 10 |
| HTTPS | 5 |
| Cross-Origin-* (COOP, CORP, COEP) | 5 |
| Vazamento de versão (`Server`, `X-Powered-By`) | 5 |

Regras de teto: sem CSP a nota máxima é B; sem HTTPS a nota máxima é D.

## 2. Pontos de atenção

- **SSRF (o mais importante).** O servidor acessa URLs informadas pelo usuário. É preciso bloquear IPs privados e locais, o endpoint de metadata de cloud (`169.254.169.254`), DNS rebinding e redirects para esses destinos. Também é preciso limitar tempo, número de redirects e portas.
- **Abuso.** Rate limit por IP e captcha (o Cloudflare Turnstile é gratuito).
- **Marca.** Não copiar nome, layout ou textos do securityheaders.com. Usar identidade própria da Coreva Tech.
- **Referência aberta.** O MDN HTTP Observatory (Mozilla) tem código aberto no GitHub (licença MPL 2.0) e serve de base ou referência para os critérios.
- **Escanear só o que é público.** O serviço lê apenas headers de resposta de URLs públicas. Se um dia houver scan "profundo" ou agendado, incluir termos de uso.

## 3. Custos na Web (estimativas aproximadas)

| Item | Custo |
|---|---|
| Domínio .com.br | ~R$ 40/ano |
| Domínio .com | ~US$ 10–15/ano |
| Frontend estático (Cloudflare Pages, Vercel, Netlify) | Grátis no plano inicial |
| Backend em serverless/Workers (plano grátis) | R$ 0 para baixo volume |
| Backend em VPS pequena (Hetzner, DigitalOcean etc.) | ~US$ 5–7/mês |
| Captcha (Turnstile) e CDN/DNS (Cloudflare) | Grátis |
| Banco de dados para histórico (opcional) | SQLite grátis; Postgres gerenciado ~US$ 0–15/mês |

- **MVP em produção:** R$ 0 a R$ 40 por mês, mais o domínio.
- **Com tráfego relevante:** ~US$ 20–100 por mês (servidor, banco, monitoramento).
- **Maior custo real:** tempo de desenvolvimento, não hospedagem.

## 4. Arquitetura do MVP (implementada)

```
Navegador ──GET /api/scan?url=…──▶ server.js (rate limit, limite de concorrência)
                                      │
                                      ▼
                               src/scanner.js  ── analisa headers → nota + checks
                                      │
                                      ▼
                               src/fetcher.js  ── GET, redirects manuais (máx. 5), timeout 8 s
                                      │
                                      ▼
                               src/ssrf.js     ── valida URL, resolve DNS, bloqueia IP não público,
                                                  fixa o IP resolvido na conexão (anti DNS rebinding)
```

- Node ≥ 20, **zero dependências** externas.
- Cada redirect é revalidado (esquema, porta, IP).
- O corpo da resposta nunca é lido: só os headers.
- O próprio site usa os headers que recomenda (CSP restritiva, HSTS, etc.).

## 4.1 Opções de hospedagem avaliadas

| Opção | Código | Custo | Observações |
|---|---|---|---|
| **Azure Static Web Apps (Free)** — escolhida para o teste do MVP | Pasta `swa/` (API vira Azure Function) | US$ 0 | Sem SLA, sem firewall de saída, rate limit por instância. Ver `DEPLOY-AZURE.md` |
| VPS + Docker + Caddy | `Dockerfile`, `docker-compose.yml` | ~US$ 5–7/mês | Controle total, firewall de saída. Ver `DEPLOY.md` |
| Google Cloud Run | Mesmo `Dockerfile`, sem mudanças | Quase zero (faixa gratuita: 2 mi req., 180 mil vCPU-s e 360 mil GiB-s por mês) | Mapeamento de domínio ainda em Preview e fora de São Paulo; usar `us-east1`. Não implementado |

Preços e limites mudam: confirmar nas páginas oficiais antes de contratar.

## 5. Roadmap sugerido

**Fase 1 — MVP (feito)**
- Scanner com 10 verificações, nota e correções sugeridas
- Proteção SSRF, rate limit, testes automatizados

**Fase 2 — Pronto para publicar (código feito em 05/11/2026; falta só o deploy)**
- Cloudflare Turnstile no formulário (ativa por variável de ambiente; falha fechada se o verificador cair)
- Limite por IP **e** por domínio-alvo (evita usar o serviço para martelar sites de terceiros)
- Logs JSON com IP anonimizado (hash diário) e `/healthz` para monitoramento
- Identidade Coreva Tech: marca, favicon, textos, chamada para contato
- Dockerfile e docker-compose com Caddy (HTTPS automático), `.env.example` e guia `DEPLOY.md`
- Pendente (depende de você): VPS, registro DNS, chaves do Turnstile, firewall de saída
- Rate limit continua em memória (1 instância). Para várias instâncias, usar Redis ou regra na Cloudflare

**Fase 3 — Valor para a Coreva Tech**
- Histórico de scans e comparação ao longo do tempo (SQLite/Postgres)
- Exportar relatório em PDF com a marca da Coreva Tech
- Checagens extras: TLS (versão/cifras/certificado), `security.txt`, DNS (SPF/DKIM/DMARC, CAA), cookies em várias páginas
- Captura de leads: "quer ajuda para corrigir? fale com a Coreva Tech"
- API com chave para clientes e monitoramento agendado (alertas se a nota cair)

## 6. Decisões em aberto

- ~~Nome e domínio~~ **Decidido: `verifica.corevatech.com.br`** (nome curto, em português e amplo o bastante para receber TLS/DNS na Fase 3).
- Página de privacidade e e-mail de contato de segurança (`security.txt`): falta definir o e-mail.
- Gratuito aberto, ou com cadastro/e-mail para liberar relatório completo?
- Onde hospedar (VPS própria ou serverless)?
- Pesos e regras de nota: ajustar após testar com sites reais.
