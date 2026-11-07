# Deploy: verifica.corevatech.com.br

Caminho recomendado: uma VPS pequena (1 vCPU / 1 GB, ~US$ 5–7/mês) com Docker, Caddy para HTTPS e Cloudflare Turnstile como captcha.

## 1. Pré-requisitos

- VPS Linux com Docker e Docker Compose instalados
- Acesso ao DNS de `corevatech.com.br`
- Conta gratuita na Cloudflare (só para o Turnstile; o DNS pode continuar onde está)

## 2. DNS

Crie um registro **A** (e **AAAA**, se a VPS tiver IPv6) apontando `verifica` para o IP da VPS. Aguarde propagar e confirme com `dig verifica.corevatech.com.br`.

## 3. Turnstile

1. Cloudflare → **Turnstile** → **Add widget**.
2. Hostname: `verifica.corevatech.com.br`. Modo: **Managed**.
3. Guarde a **Site Key** e a **Secret Key**.

## 4. Subir o serviço

```bash
git clone <repositório>   # ou envie a pasta do projeto
cd coreva-headers
cp .env.example .env
nano .env                 # DOMAIN, chaves do Turnstile, LOG_SALT (openssl rand -hex 16)
docker compose up -d --build
docker compose logs -f
```

O Caddy obtém o certificado sozinho (as portas 80 e 443 precisam estar liberadas). Teste:

```bash
curl -s https://verifica.corevatech.com.br/healthz
curl -sI https://verifica.corevatech.com.br/ | grep -i content-security
```

## 5. Firewall e isolamento (importante contra SSRF)

O código já bloqueia IPs privados, mas aplique uma segunda camada:

- Libere de entrada apenas as portas 22 (de preferência restrita ao seu IP), 80 e 443.
- Se a VPS tiver rede privada ou o provedor tiver endpoint de metadata, **bloqueie a saída** do servidor para `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` e `169.254.0.0/16`. Exemplo com `ufw`:
  ```bash
  ufw deny out to 10.0.0.0/8
  ufw deny out to 172.16.0.0/12
  ufw deny out to 192.168.0.0/16
  ufw deny out to 169.254.0.0/16
  ```
  Cuidado: se a resolução de DNS da VPS usa um IP privado, libere esse IP antes.
- Mantenha o sistema atualizado (`unattended-upgrades`).

## 6. Se colocar a Cloudflare na frente (proxy laranja)

- No `.env`: `CLIENT_IP_HEADER=cf-connecting-ip`.
- Só faça isso se a VPS aceitar conexões **apenas** dos IPs da Cloudflare (lista em https://www.cloudflare.com/ips/). Sem esse bloqueio, qualquer pessoa pode forjar o header e burlar o rate limit.
- Modo SSL/TLS: **Full (strict)**.
- Regra de rate limiting na Cloudflare para `/api/scan` é uma ótima camada extra (grátis no plano básico, com limites).

## 7. Operação

| Tarefa | Comando |
|---|---|
| Ver logs | `docker compose logs -f app` |
| Atualizar | `git pull && docker compose up -d --build` |
| Reiniciar | `docker compose restart app` |
| Status | `docker compose ps` (a saúde do app aparece na coluna STATUS) |

Os logs são JSON, uma linha por evento. Exemplo: `{"t":"…","ev":"scan","ok":true,"host":"exemplo.com","grade":"B","score":78,"ms":412,"ip":"a1b2c3d4e5f6"}`.

- O IP **não** é gravado em claro: só um hash de 12 caracteres que muda a cada dia (`LOG_SALT` + data). Isso ajuda na conformidade com a LGPD. Se publicar o serviço, inclua uma linha de privacidade (já há uma no rodapé).
- Monitoramento simples: UptimeRobot ou Better Stack (planos gratuitos) apontando para `/healthz`.

## 8. Checklist antes de divulgar

- [ ] `https://verifica.corevatech.com.br` abre com cadeado válido
- [ ] Turnstile aparece e bloqueia scan sem verificação
- [ ] Scan de um site real funciona
- [ ] `http://127.0.0.1`, `http://169.254.169.254` e `http://localhost` são recusados
- [ ] Firewall de saída aplicado (seção 5)
- [ ] Monitoramento de `/healthz` configurado
- [ ] O próprio site recebe nota A+ no verifica (dogfooding)
