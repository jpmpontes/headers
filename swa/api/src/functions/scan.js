'use strict';
const { app } = require('@azure/functions');
const { handleScan, clientIp, JSON_HEADERS } = require('../lib/handler');

app.http('scan', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'scan', // => /api/scan
  handler: async (request, context) => {
    const r = await handleScan({
      target: request.query.get('url'),
      token: request.query.get('cf-turnstile-response'),
      dkim: request.query.get('dkim'),
      ip: clientIp(request.headers.get('x-forwarded-for')),
      log: (o) => context.log(JSON.stringify({ t: new Date().toISOString(), ...o })),
    });
    return { status: r.status, headers: JSON_HEADERS, jsonBody: r.body };
  },
});
