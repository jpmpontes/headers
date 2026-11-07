<<<<<<< HEAD
# Coreva Headers (MVP)

Analisador de headers de segurança HTTP. Node ≥ 20, sem dependências.

## Executar

```bash
npm start                 # http://localhost:3000
npm test                  # testes automatizados
```

Abra `http://localhost:3000`, digite um domínio e clique em **Analisar**.
API: `GET /api/scan?url=exemplo.com.br` (retorna JSON com nota, checks e headers).

## Variáveis de ambiente

| Variável | Padrão | Função |
|---|---|---|
| `PORT` | 3000 | Porta do servidor |
| `HOST` | 0.0.0.0 | Interface de escuta |
| `RATE_LIMIT` | 10 | Scans por minuto por IP |
| `TARGET_RATE_LIMIT` | 6 | Scans por minuto para o mesmo domínio-alvo |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | (off) | Ativam o captcha Cloudflare Turnstile |
| `CLIENT_IP_HEADER` | x-forwarded-for | Header com o IP real (use `cf-connecting-ip` atrás da Cloudflare) |
| `LOG_SALT` | aleatório | Sal para anonimizar IPs nos logs |
| `TRUST_PROXY` | (off) | `1` confia no header de IP do proxy (só atrás de proxy confiável) |
| `ALLOW_PRIVATE` | (off) | `1` desliga as travas SSRF. **Só para testes locais. Nunca em produção.** |

## Estrutura

```
server.js          servidor HTTP, rate limit, headers de segurança do próprio site
src/turnstile.js   verificação do captcha Cloudflare Turnstile
src/ssrf.js        validação de URL e bloqueio de IPs não públicos
src/fetcher.js     requisição com redirects revalidados e IP fixado
src/scanner.js     as verificações e o cálculo da nota
public/            frontend (HTML/CSS/JS sem inline, compatível com a CSP)
test/              testes (node:test)
docs/              viabilidade, custos e roadmap
Dockerfile, docker-compose.yml, Caddyfile, .env.example, DEPLOY.md   publicação em VPS
swa/, scripts/sync-swa.sh, DEPLOY-AZURE.md                            publicação no Azure Static Web Apps
```

## Testar um alvo local (modo dev)

```bash
ALLOW_PRIVATE=1 npm start
curl "localhost:3000/api/scan?url=http://127.0.0.1:8080"
```

## Limitações conhecidas do MVP

- Rate limit em memória (some ao reiniciar; não serve com várias instâncias).
- Sem histórico e sem checagem de TLS/DNS.
- Analisa só a página informada (não rastreia o site).
- Um certificado TLS inválido faz o scan falhar (mensagem de erro de conexão).

Publicação (alvo: `verifica.corevatech.com.br`):
- Azure Static Web Apps: [DEPLOY-AZURE.md](DEPLOY-AZURE.md) (pasta `swa/`)
- VPS com Docker e Caddy: [DEPLOY.md](DEPLOY.md)

Mais detalhes em [docs/viabilidade-e-custos.md](docs/viabilidade-e-custos.md).
=======
# Headers

Projeto de um site para testar a segurança de uma página http referente ao seu cabeçalho (header)
>>>>>>> 2a9f1fac06ee4f640f966f1ecae227c4134f36ad
