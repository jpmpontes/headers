'use strict';
const { app } = require('@azure/functions');
const { getStatus } = require('../lib/status');
const { JSON_HEADERS } = require('../lib/handler');

// Independente de /api/scan: só lê fontes públicas de URL fixa (sem SSRF, sem limite por domínio) e usa cache em memória.
app.http('status', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'status', // => /api/status
  handler: async () => ({ status: 200, headers: { ...JSON_HEADERS, 'Cache-Control': 'public, max-age=30' }, jsonBody: await getStatus() }),
});
