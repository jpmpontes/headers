# Deploy no Azure Static Web Apps (verifica.corevatech.com.br)

A pasta `swa/` é a versão pronta para o Azure Static Web Apps:

```
swa/app/                  frontend + staticwebapp.config.json (headers de segurança do site)
swa/api/                  API em Azure Functions (Node 20): /api/scan e /api/config
swa/api/src/lib/          lógica compartilhada (cópia de src/, gerada pelo script)
```

> **Não edite** `swa/app/*` (exceto `staticwebapp.config.json`) nem `swa/api/src/lib/{ssrf,fetcher,scanner,turnstile}.js`.
> Edite os originais em `public/` e `src/` e rode `./scripts/sync-swa.sh`.

## 1. Pré-requisitos

- Conta Azure (o plano **Free** do Static Web Apps basta para o teste)
- Repositório no GitHub com este projeto (para o deploy automático), ou o SWA CLI para publicar da sua máquina
- Acesso ao DNS de `corevatech.com.br`

## 2. Criar o recurso

1. Portal Azure → **Criar recurso** → **Static Web App**.
2. Plano: **Free**. Região: a mais próxima do Brasil entre as oferecidas.
3. Origem da implantação: escolha **Outro** (não GitHub). Assim o Azure não cria um workflow próprio e usamos o que já está em `.github/workflows/azure-static-web-apps.yml`.
4. Depois de criado, abra o recurso → **Gerenciar token de implantação** → copie o token.
5. No GitHub: **Settings → Secrets and variables → Actions → New repository secret**, nome `AZURE_STATIC_WEB_APPS_API_TOKEN`, valor = o token.
6. Faça push na branch `main`. O workflow roda os testes e publica `swa/app` + `swa/api`.

Sem GitHub, a partir da sua máquina:

```bash
./scripts/sync-swa.sh
(cd swa/api && npm install --omit=dev)
npx @azure/static-web-apps-cli deploy ./swa/app --api-location ./swa/api --deployment-token <TOKEN> --env production
```

## 3. Variáveis de ambiente

No recurso → **Configurações → Variáveis de ambiente** (Environment variables):

| Nome | Valor | Obrigatória |
|---|---|---|
| `TURNSTILE_SITE_KEY` | chave do site (Cloudflare Turnstile) | Recomendada |
| `TURNSTILE_SECRET_KEY` | chave secreta | Recomendada |
| `LOG_SALT` | texto aleatório (`openssl rand -hex 16`) | Opcional |
| `RATE_LIMIT`, `TARGET_RATE_LIMIT` | padrões 10 e 6 | Opcional |

**Nunca** defina `ALLOW_PRIVATE`: ela desliga a proteção contra SSRF.

## 4. Domínio verifica.corevatech.com.br

1. Recurso → **Domínios personalizados** → **Adicionar** → "Domínio personalizado em outro DNS".
2. Informe `verifica.corevatech.com.br`. O Azure mostra o destino do CNAME (o endereço `*.azurestaticapps.net` do seu app).
3. No DNS da Coreva Tech, crie: `verifica` **CNAME** → esse endereço.
4. Volte ao portal e valide. O certificado HTTPS é emitido e renovado automaticamente.
5. Se houver registros CAA no domínio, autorize as CAs que o Azure indicar.

## 5. Turnstile

Cloudflare → **Turnstile** → **Add widget**, hostname `verifica.corevatech.com.br`, modo **Managed**. Cole as chaves nas variáveis acima. A CSP do site (`staticwebapp.config.json`) já libera `challenges.cloudflare.com`.

## 6. Checklist de teste

- [ ] `https://verifica.corevatech.com.br` abre com certificado válido
- [ ] Escanear um site público real (ex.: o da Coreva Tech) devolve nota e checks
- [ ] Com Turnstile configurado: o widget aparece e a análise só roda depois dele
- [ ] `127.0.0.1`, `169.254.169.254` e `localhost` são recusados
- [ ] `https://verifica.corevatech.com.br/api/config` responde JSON
- [ ] O próprio site recebe nota alta ao ser escaneado por ele mesmo

## 7. Limitações desta hospedagem (leia antes de divulgar)

- **Rate limit é "de melhor esforço".** Fica em memória de cada instância e zera em partida a frio. Por isso o Turnstile é a defesa principal: **não divulgue o link antes de ativá-lo.**
- **Sem firewall de saída.** No plano Free não há como restringir a rede de saída da função. A proteção contra SSRF fica só no código (já testada contra loopback, redes privadas e o endpoint de metadata). Para a segunda camada do `DEPLOY.md`, seria preciso outro tipo de hospedagem.
- **Partida a frio:** a primeira análise depois de um tempo parado é mais lenta.
- **Limite de 25 s por análise** no código (o Azure também impõe um limite de tempo por requisição; confira os limites atuais na documentação do serviço).
- **Plano Free não tem SLA.**
- **Logs:** as funções registram JSON com IP anonimizado. Para consultá-los no Azure, habilite o Application Insights no recurso (pode gerar custo conforme o volume).
- **IP do cliente:** o código lê `x-forwarded-for` e remove a porta. Confirme no primeiro teste que o limite por IP age sobre o IP do usuário e não sobre um IP do Azure.

## 8. Atualizar

```bash
# edite public/ ou src/
./scripts/sync-swa.sh
npm test
git add -A && git commit -m "..." && git push
```
