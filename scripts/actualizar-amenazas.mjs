// Centinela — actualiza data/amenazas.json: inteligencia de amenazas reciente para el panel de inicio.
//
// Fuentes públicas, sin claves:
//   CISA KEV        vulnerabilidades explotadas activamente (catálogo oficial en GitHub de CISA)
//   NVD 2.0         CVE críticos publicados en los últimos 7 días (y cuántos altos)
//   FIRST EPSS      probabilidad de explotación de esos CVE
//   ThreatFox       IOCs (IP:puerto, dominios, URLs, hashes) compartidos en las últimas 48 h  (abuse.ch)
//   URLhaus         URLs de distribución de malware recientes y cuántas siguen activas      (abuse.ch)
// Se ejecuta desde GitHub Actions (.github/workflows/amenazas.yml) cada hora. El navegador solo lee este JSON
// estático del propio sitio: sin CORS, sin backend y sin enviar la IP del visitante a terceros.
//
// Seguridad: los IOCs se guardan "desactivados" (hxxp://, [.]) y la página los muestra como texto, nunca como enlace.
// Robustez: si una fuente falla se conserva su sección del archivo anterior; si fallan todas, el archivo no se toca.
//
// Uso:  node scripts/actualizar-amenazas.mjs
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'data', 'amenazas.json');
const UA = 'Centinela/1.0 (+https://github.com; actualizacion de data/amenazas.json)';
const DAY = 864e5;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function get(url, type = 'json') {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(url, { headers: { 'user-agent': UA, accept: type === 'json' ? 'application/json' : 'text/plain' }, signal: AbortSignal.timeout(60_000) });
      if (r.ok) return type === 'json' ? r.json() : r.text();
      if ((r.status === 429 || r.status >= 500) && i < 2) { await sleep(8_000 * (i + 1)); continue; }
      throw new Error(url + ' → HTTP ' + r.status);
    } catch (e) { if (i === 2) throw e; await sleep(5_000); }
  }
}

// "Desactiva" un indicador para que no pueda abrirse por accidente
function defang(v, type) {
  v = String(v || '').trim();
  if (/hash/.test(type || '')) return v;
  return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s; };
const top = (arr, n) => { const m = new Map(); arr.forEach(k => { if (k) m.set(k, (m.get(k) || 0) + 1); }); return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n); };

async function kev() {
  const j = await get('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json');
  const v = Array.isArray(j.vulnerabilities) ? j.vulnerabilities : [];
  if (v.length < 500) throw new Error('KEV: lista sospechosamente corta');
  const now = Date.now(), age = d => (now - Date.parse(d + 'T00:00:00Z')) / DAY;
  const last30 = v.filter(x => age(x.dateAdded) <= 30);
  const items = v.slice().sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)) || String(b.cveID).localeCompare(String(a.cveID))).slice(0, 15)
    .map(x => ({ cve: x.cveID, vendor: clip(x.vendorProject, 40), product: clip(x.product, 50), name: clip(x.vulnerabilityName, 110), added: x.dateAdded, due: x.dueDate, ransomware: x.knownRansomwareCampaignUse === 'Known' }));
  return { total: v.length, version: j.catalogVersion || '', added7: v.filter(x => age(x.dateAdded) <= 7).length, added30: last30.length, ransomware30: last30.filter(x => x.knownRansomwareCampaignUse === 'Known').length, items };
}

async function nvd() {
  const end = new Date(), start = new Date(end - 7 * DAY), iso = d => d.toISOString().replace(/\.\d+Z$/, '.000Z');
  const base = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${iso(start)}&pubEndDate=${iso(end)}`;
  const crit = await get(base + '&cvssV3Severity=CRITICAL&resultsPerPage=200');
  await sleep(7_000);   // NVD sin clave: 5 consultas cada 30 s
  const high = await get(base + '&cvssV3Severity=HIGH&resultsPerPage=1');
  const score = m => { for (const k of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40']) { const a = m && m[k]; if (a && a.length) { const p = a.find(x => x.type === 'Primary') || a[0]; return { s: p.cvssData.baseScore, v: p.cvssData.version }; } } return null; };
  const items = (crit.vulnerabilities || []).map(x => x.cve).filter(c => c && c.vulnStatus !== 'Rejected')
    .map(c => { const sc = score(c.metrics), d = (c.descriptions || []).find(x => x.lang === 'en'); const af = c.affected && c.affected[0] && c.affected[0].affectedData && c.affected[0].affectedData[0];
      return { cve: c.id, published: c.published, cvss: sc ? sc.s : null, cvssVersion: sc ? sc.v : '', vendor: af ? clip(af.vendor, 40) : '', product: af ? clip(af.product, 50) : '', desc: clip(d && d.value, 180) }; })
    .sort((a, b) => String(b.published).localeCompare(String(a.published))).slice(0, 15);
  return { critical7: crit.totalResults || items.length, high7: high.totalResults || 0, items };
}

async function epss(ids) {
  if (!ids.length) return {};
  const j = await get('https://api.first.org/data/v1/epss?cve=' + ids.join(','));
  const m = {}; (j.data || []).forEach(x => { m[x.cve] = { epss: +x.epss, pct: +x.percentile }; }); return m;
}

async function threatfox() {
  const j = await get('https://threatfox.abuse.ch/export/json/recent/');
  const all = Object.values(j).flat().filter(x => x && x.ioc_value);
  const now = Date.now(), ts = x => Date.parse(String(x.first_seen_utc).replace(' ', 'T') + 'Z');
  const d24 = all.filter(x => now - ts(x) <= DAY);
  const kind = t => /hash/.test(t) ? 'hash' : t === 'ip:port' ? 'ip' : t === 'domain' ? 'domain' : t === 'url' ? 'url' : 'otro';
  const types = { ip: 0, domain: 0, url: 0, hash: 0, otro: 0 }; d24.forEach(x => { types[kind(x.ioc_type)]++; });
  const items = all.slice().sort((a, b) => ts(b) - ts(a)).slice(0, 12)
    .map(x => ({ ioc: clip(defang(x.ioc_value, x.ioc_type), 90), type: kind(x.ioc_type), malware: clip(x.malware_printable, 40), threat: x.threat_type || '', confidence: x.confidence_level, seen: x.first_seen_utc }));
  return { total48: all.length, total24: d24.length, types, families: top(d24.map(x => x.malware_printable).filter(m => m && m !== 'Unknown malware'), 6), items };
}

async function urlhaus() {
  const t = await get('https://urlhaus.abuse.ch/downloads/csv_recent/', 'text');
  const rows = t.split('\n').filter(l => l && !l.startsWith('#')).map(l => (l.match(/"([^"]*)"/g) || []).map(s => s.slice(1, -1))).filter(r => r.length >= 7);
  const items = rows.slice(0, 8).map(r => ({ url: clip(defang(r[2], 'url'), 90), status: r[3], threat: r[5], tags: r[6] === 'None' ? '' : clip(r[6], 40), added: r[1] }));
  return { total: rows.length, online: rows.filter(r => r[3] === 'online').length, threats: top(rows.map(r => r[6] === 'None' ? '' : r[6].split(',')[0]), 5), items };
}

const prev = existsSync(OUT) ? (() => { try { return JSON.parse(readFileSync(OUT, 'utf8')); } catch { return {}; } })() : {};
const res = {}, errores = [];
for (const [k, f] of [['kev', kev], ['nvd', nvd], ['threatfox', threatfox], ['urlhaus', urlhaus]]) {
  try { res[k] = await f(); console.log('✓', k); } catch (e) { errores.push(k + ': ' + e.message); console.error('✗', k, e.message); if (prev[k]) res[k] = prev[k]; }
}
if (errores.length === 4) { console.error('Todas las fuentes fallaron; no se modifica', OUT); process.exit(1); }
// EPSS de los CVE mostrados (KEV y NVD) en una sola consulta
try {
  const ids = [...new Set([...(res.kev ? res.kev.items : []), ...(res.nvd ? res.nvd.items : [])].map(x => x.cve))].slice(0, 100);
  const m = await epss(ids);
  [res.kev, res.nvd].forEach(s => s && s.items.forEach(x => { if (m[x.cve]) { x.epss = m[x.cve].epss; x.epssPct = m[x.cve].pct; } }));
} catch (e) { errores.push('epss: ' + e.message); }

const out = { generado: new Date().toISOString(), fuentes: { kev: 'CISA KEV', nvd: 'NVD (NIST)', epss: 'FIRST EPSS', threatfox: 'ThreatFox (abuse.ch)', urlhaus: 'URLhaus (abuse.ch)' }, ...res, errores };
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('Escrito', OUT, (JSON.stringify(out).length / 1024).toFixed(1) + ' KB', errores.length ? '· errores: ' + errores.join(' | ') : '');
