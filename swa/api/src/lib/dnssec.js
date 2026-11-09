'use strict';
// DNSSEC: o Node não expõe o bit AD nem registros DS/DNSKEY, então perguntamos a um resolvedor validador público
// (Cloudflare, via DNS-over-HTTPS) APENAS o nome do domínio analisado (dado público). Injetável via "dohQuery" para testes.
// Regra: se não der para testar (sem rede, DoH indisponível), o item fica de fora da nota (max 0).
const { mk, registrable } = require('./common');

const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const T_DS = 43, T_DNSKEY = 48;
const WEAK_ALGS = { 1: 'RSAMD5', 3: 'DSA', 5: 'RSASHA1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1' };

async function defaultDohQuery(name, type, { cd = false } = {}) {
  const u = new URL(DOH_URL);
  u.search = new URLSearchParams({ name, type, do: '1', ...(cd ? { cd: '1' } : {}) }).toString();
  const res = await fetch(u, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
  return res.json(); // { Status, AD, Answer:[{type,data}] }
}

const disabled = () => process.env.DNSSEC_DOH === '0' || process.env.ALLOW_PRIVATE === '1';
const NAME = 'DNSSEC (assinatura da zona)';
const FIX = 'Ative o DNSSEC no provedor de DNS e publique o registro DS no registrador (Registro.br, por exemplo).';

async function checkDnssec(host, { dohQuery = defaultDohQuery } = {}) {
  const zone = registrable(host);
  const untested = (why) => mk('dnssec', NAME, 0, 0, 'info', `Não foi possível verificar o DNSSEC (${why}). Fora da nota.`);
  if (dohQuery === defaultDohQuery && disabled()) return untested('verificação desativada neste ambiente');
  const q = async (type, o) => { try { return await dohQuery(zone, type, o); } catch { return null; } };

  const ds = await q('DS');
  if (!ds) return untested('resolvedor validador indisponível');

  if (ds.Status === 2) { // SERVFAIL: ou o DNSSEC está quebrado, ou o problema é outro. Com CD=1 (sem validar) distingue.
    const raw = await q('A', { cd: true });
    if (raw && raw.Status === 0) {
      return mk('dnssec', NAME, 15, 0, 'fail',
        'DNSSEC quebrado: resolvedores que validam (como 1.1.1.1 e 8.8.8.8) rejeitam este domínio, que fica inacessível para boa parte dos usuários.',
        'Há DS no registrador sem chave correspondente na zona (ou assinaturas expiradas). Corrija as chaves ou remova o DS no registrador.');
    }
    return untested('o resolvedor retornou erro para o domínio');
  }
  if (ds.Status === 3) return untested('domínio inexistente');

  const dsRecs = (ds.Answer || []).filter((r) => r.type === T_DS);
  const keys = ((await q('DNSKEY')) || {}).Answer || [];
  const hasKey = keys.some((r) => r.type === T_DNSKEY);

  if (!dsRecs.length) {
    return hasKey
      ? mk('dnssec', NAME, 15, 5, 'warn', 'A zona tem chaves DNSSEC, mas não há registro DS no registrador: a cadeia de confiança está incompleta e o DNSSEC não tem efeito.', FIX)
      : mk('dnssec', NAME, 15, 0, 'warn', 'DNSSEC não está ativo: respostas de DNS não têm assinatura e podem ser forjadas (cache poisoning).', FIX);
  }

  const parsed = dsRecs.map((r) => String(r.data).trim().split(/\s+/));
  const algs = [...new Set(parsed.map((p) => Number(p[1])))];
  const digests = parsed.map((p) => Number(p[2]));
  const value = dsRecs.map((r) => r.data).join('\n');

  const a = await q('A');
  if (a && a.Status === 0 && a.AD !== true) {
    return mk('dnssec', NAME, 15, 5, 'warn', 'Há registro DS, mas a resposta não foi validada pelo resolvedor (AD ausente): confira se as chaves da zona correspondem ao DS.', 'Revise as chaves DNSKEY e o DS publicado.', value);
  }
  const weak = algs.filter((x) => WEAK_ALGS[x]).map((x) => WEAK_ALGS[x]);
  if (weak.length && algs.every((x) => WEAK_ALGS[x])) {
    return mk('dnssec', NAME, 15, 10, 'warn', `DNSSEC válido, mas usa algoritmo defasado (${weak.join(', ')}).`, 'Migre para ECDSA P-256 (algoritmo 13) ou Ed25519 (15).', value);
  }
  if (digests.every((d) => d === 1)) {
    return mk('dnssec', NAME, 15, 12, 'warn', 'DNSSEC válido, mas o DS usa apenas digest SHA-1.', 'Publique também o DS com digest SHA-256 (tipo 2).', value);
  }
  return mk('dnssec', NAME, 15, 15, 'pass', 'DNSSEC ativo e validado pelo resolvedor (cadeia de confiança íntegra).', null, value);
}

module.exports = { checkDnssec };
