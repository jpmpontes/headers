'use strict';
const verificacoes = require('./verificacoes');
const ameacas = require('./ameacas');
const privacidade = require('./privacidade');

const CATEGORIAS = [
  { id: 'headers', nome: 'Headers de segurança HTTP', desc: 'Os cabeçalhos que o navegador usa para proteger quem visita o seu site.' },
  { id: 'tls', nome: 'Certificado e TLS', desc: 'Como a conexão é criptografada e como o certificado prova a identidade do servidor.' },
  { id: 'dns', nome: 'DNS', desc: 'O sistema que traduz nomes em endereços e as proteções que o cercam.' },
  { id: 'email', nome: 'Autenticação e segurança de e-mail', desc: 'Como provar que um e-mail é do seu domínio e protegê-lo em trânsito.' },
  { id: 'privacidade', nome: 'Cookies e privacidade', desc: 'Cookies, consentimento, rastreadores e política de privacidade, sob a ótica da LGPD.' },
  { id: 'ataques', nome: 'Ataques e ameaças', desc: 'Os principais ataques, o impacto que causam e como se proteger.' },
  { id: 'conceitos', nome: 'Conceitos e governança', desc: 'Fundamentos de segurança da informação, normas e legislação.' },
];

// Id de cada verificação do Verifica -> verbete do glossário que a explica.
const CHECK_MAP = {
  https: 'https', csp: 'csp', hsts: 'hsts', xcto: 'x-content-type-options', nosniff: 'x-content-type-options', framing: 'clickjacking', referrer: 'referrer-policy',
  permissions: 'permissions-policy', coop: 'isolamento-cross-origin', coep: 'isolamento-cross-origin', corp: 'isolamento-cross-origin', cookies: 'cookies-seguros',
  disclosure: 'vazamento-de-informacoes', leak: 'vazamento-de-informacoes',
  trust: 'certificado-tls', hostname: 'certificado-tls', expiry: 'certificado-tls', key: 'certificado-tls', chain: 'certificado-tls', sigalg: 'certificado-tls', lifetime: 'certificado-tls',
  tls13: 'versoes-tls', tls12: 'versoes-tls', legacy: 'versoes-tls', http2: 'versoes-tls', cipher: 'cifras-fracas', weakciphers: 'cifras-fracas', pfs: 'pfs',
  revocation: 'revogacao-ocsp', ct: 'certificate-transparency', redirect: 'redirecionamento-http-https', hsts_: 'hsts',
  addr: 'dns-servidores-de-nomes', ns: 'dns-servidores-de-nomes', nshealth: 'dns-servidores-de-nomes', soa: 'dns-servidores-de-nomes', ttl: 'dns-servidores-de-nomes', diversity: 'dns-servidores-de-nomes',
  ipv6: 'ipv6', caa: 'caa', dnssec: 'dnssec', cname: 'subdomain-takeover',
  mx: 'registro-mx', mxrdns: 'registro-mx', spf: 'spf', dkim: 'dkim', dmarc: 'dmarc', dmarcrep: 'dmarc', mtasts: 'mta-sts', mtastspol: 'mta-sts', tlsrpt: 'tls-rpt',
  starttls: 'starttls', mxcert: 'starttls', dane: 'dane', bimi: 'bimi',
  ckpre: 'cookies-e-consentimento', ckexpiry: 'cookies-e-consentimento', ckflags: 'cookies-seguros', cktrackers: 'rastreadores-e-pixels', ckcmp: 'plataformas-de-consentimento', ckpolicy: 'politica-de-privacidade',
};
delete CHECK_MAP.hsts_;

const VERBETES = [...verificacoes, ...privacidade, ...ameacas];
module.exports = { VERBETES, CATEGORIAS, CHECK_MAP };
