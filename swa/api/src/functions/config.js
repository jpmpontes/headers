'use strict';
const { app } = require('@azure/functions');
const { getConfig, JSON_HEADERS } = require('../lib/handler');

app.http('config', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'config', // => /api/config
  handler: async () => {
    const r = getConfig();
    return { status: r.status, headers: JSON_HEADERS, jsonBody: r.body };
  },
});
