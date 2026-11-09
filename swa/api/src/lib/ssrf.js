'use strict';
// Proteção contra SSRF: valida a URL, resolve o DNS e bloqueia IPs não públicos.
// ALLOW_PRIVATE=1 desliga as travas (SOMENTE para testes locais).
const net = require('node:net');
const dns = require('node:dns').promises;

const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], // inclui metadata de cloud (169.254.169.254)
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv4'));
[
  ['::', 128], ['::1', 128],
  ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv6'));

function isBlockedIP(ip) {
  const fam = net.isIP(ip);
  if (!fam) return true;
  // IPv4-mapped (::ffff:x:y) é bloqueado por inteiro. Normaliza a forma antes de testar.
  // (Não dá para usar addSubnet('::ffff:0:0/96'): o BlockList do Node passa a bloquear todo IPv4.)
  if (fam === 6) {
    let n = ip;
    try { n = new URL(`http://[${ip}]/`).hostname.replace(/^\[|\]$/g, ''); } catch { return true; }
    if (/^::ffff:/i.test(n)) return true;
  }
  return blocked.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

function validateUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('URL inválida'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Apenas http:// e https:// são permitidos');
  if (u.username || u.password) throw new Error('URLs com usuário/senha não são permitidas');
  if (!ALLOW_PRIVATE && u.port && !['80', '443'].includes(u.port)) throw new Error('Apenas as portas 80 e 443 são permitidas');
  if (u.hostname.length > 253) throw new Error('Hostname muito longo');
  return u;
}

// Resolve o host e devolve UM IP público validado. A conexão deve usar este IP
// (pinning), o que impede DNS rebinding entre a checagem e o connect.
async function resolveAllPublic(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  let addrs;
  if (net.isIP(host)) addrs = [{ address: host, family: net.isIP(host) }];
  else {
    try { addrs = await dns.lookup(host, { all: true }); }
    catch { throw new Error('Não foi possível resolver o domínio'); }
  }
  if (!addrs.length) throw new Error('Domínio sem endereço IP');
  if (!ALLOW_PRIVATE && addrs.some((a) => isBlockedIP(a.address))) {
    throw new Error('Destino bloqueado: o domínio aponta para um endereço não público');
  }
  return addrs;
}

// Primeiro IP público validado (usado pelo scanner de headers).
const resolvePublic = async (hostname) => (await resolveAllPublic(hostname))[0];

module.exports = { isBlockedIP, validateUrl, resolvePublic, resolveAllPublic };
