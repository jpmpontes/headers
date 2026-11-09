'use strict';
process.env.DNSSEC_DOH = '0'; // testes nunca consultam o resolvedor DoH real
// Resolvedor DNS simulado: a tabela mapeia "TIPO nome" -> valor. Ausente => ENODATA (ou ENOTFOUND se nxdomain).
function fakeResolver(table, { nxdomain = false } = {}) {
  const get = (type, name) => {
    const v = table[`${type} ${name}`];
    if (v === undefined) { const e = new Error('sem dados'); e.code = nxdomain ? 'ENOTFOUND' : 'ENODATA'; throw e; }
    if (v === 'SERVFAIL') { const e = new Error('falha'); e.code = 'ESERVFAIL'; throw e; }
    if (v === 'NXDOMAIN') { const e = new Error('não existe'); e.code = 'ENOTFOUND'; throw e; } // NXDOMAIN só para este nome
    return v;
  };
  return {
    resolveSoa: async (n) => get('SOA', n),
    resolveNs: async (n) => get('NS', n),
    resolve4: async (n) => get('A', n),
    resolve6: async (n) => get('AAAA', n),
    resolveCname: async (n) => get('CNAME', n),
    resolveCaa: async (n) => get('CAA', n),
    resolveMx: async (n) => get('MX', n),
    resolveTxt: async (n) => get('TXT', n).map((s) => [s]), // um único chunk por registro
  };
}
module.exports = { fakeResolver };
