#!/usr/bin/env bash
# Copia o frontend e a lógica compartilhada (src/) para a pasta swa/ (Azure Static Web Apps).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p swa/app swa/api/src/lib
cp public/* swa/app/
cp src/ssrf.js src/fetcher.js src/scanner.js src/turnstile.js swa/api/src/lib/
echo "swa/ sincronizado a partir de public/ e src/"
