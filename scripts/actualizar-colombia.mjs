// Centinela — actualiza data/colombia.json con los ciberataques conocidos en Colombia.
//
// Fuente: ransomware.live (API v2 pública, sin clave), dos conjuntos complementarios:
//   /v2/countrycyberattacks/CO  Ataques CONFIRMADOS: la víctima o la prensa informaron el incidente (con la noticia).
//   /v2/countryvictims/CO       RECLAMACIONES: un grupo de ransomware publicó a la víctima en su sitio de filtraciones.
// Se ejecuta desde GitHub Actions (.github/workflows/colombia.yml) cada 6 horas, así el navegador lee un JSON
// estático del propio sitio: sin CORS, sin backend y respetando el límite de la API (1 consulta/minuto).
//
// Privacidad y ética: nunca se guardan enlaces a los sitios de filtración (.onion) ni datos filtrados; solo
// metadatos públicos del incidente. De las descripciones se eliminan correos y números de teléfono.
//
// Uso:  node scripts/actualizar-colombia.mjs        (escribe data/colombia.json; si la API falla, no lo toca)
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'data', 'colombia.json');
const API = 'https://api.ransomware.live/v2';
const UA = 'Centinela/1.0 (+https://github.com; actualizacion de data/colombia.json)';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function getJson(path) {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(API + path, { headers: { 'user-agent': UA, accept: 'application/json' } });
    if (r.ok) return r.json();
    if (r.status === 429 && i < 2) { await sleep(65_000); continue; }   // límite: 1 consulta por minuto
    throw new Error(path + ' → HTTP ' + r.status);
  }
}

const SECTORES = {
  'Professional Services': 'Servicios profesionales', 'Manufacturing': 'Manufactura', 'Technology': 'Tecnología',
  'Agriculture and Food Production': 'Agro y alimentos', 'Financial Services': 'Servicios financieros', 'Transportation': 'Transporte',
  'Energy & Utilities': 'Energía y servicios públicos', 'Healthcare': 'Salud', 'Government & Defense': 'Gobierno y defensa',
  'Retail & E-Commerce': 'Comercio', 'Education': 'Educación', 'Hospitality': 'Turismo y hotelería', 'Telecommunication': 'Telecomunicaciones',
  'Construction': 'Construcción', 'Business Services': 'Servicios empresariales', 'Consumer Services': 'Servicios al consumidor',
  'Public Sector': 'Sector público', 'Media': 'Medios', 'Legal': 'Legal', 'Not Found': 'Sin clasificar', 'Other': 'Otro', '': 'Sin clasificar',
};
// Sector de los ataques confirmados (la API no lo da): deducido del dominio o del nombre
const sectorDe = (dom, nombre) => {
  const s = (dom + ' ' + nombre).toLowerCase();
  if (/\.gov\.co|\.mil\.co|ministerio|alcald|gobernaci|prefect|secretar|fiscal|dian|canciller|invias|justicia/.test(s)) return 'Gobierno y defensa';
  if (/eps|salud|cl[ií]nica|hospital|cancer|ese|sanitas|cafam/.test(s)) return 'Salud';
  if (/\.edu\.co|universi|colegio|aula/.test(s)) return 'Educación';
  if (/energ|petrol|emcali|air-e|epm|gas\b/.test(s)) return 'Energía y servicios públicos';
  if (/banco|financ|seguros|valores/.test(s)) return 'Servicios financieros';
  if (/caracol|noticias|radio|tv\b|televis/.test(s)) return 'Medios';
  if (/networks|telecom|masivian|claro|movistar|tigo/.test(s)) return 'Tecnología';
  if (/nutresa|aliment/.test(s)) return 'Agro y alimentos';
  return 'Sin clasificar';
};

const GRUPOS = { lockbit3: 'LockBit 3.0', lockbit2: 'LockBit 2.0', lockbit5: 'LockBit 5.0', alphv: 'ALPHV/BlackCat', thegentlemen: 'The Gentlemen',
  ransomhub: 'RansomHub', safepay: 'SafePay', killsec: 'KillSec', clop: 'Cl0p', arcusmedia: 'Arcus Media', nightspire: 'NightSpire',
  babuk2: 'Babuk 2.0', akira: 'Akira', funksec: 'FunkSec', stormous: 'Stormous', meow: 'Meow', arvinclub: 'Arvin Club', incransom: 'INC Ransom',
  spacebears: 'Space Bears', everest: 'Everest', nova: 'Nova', apt73: 'APT73', tengu: 'Tengu', qilin: 'Qilin', gunra: 'Gunra', medusa: 'Medusa',
  blackbasta: 'Black Basta', play: 'Play', rhysida: 'Rhysida', hunters: 'Hunters International', '8base': '8Base', bianlian: 'BianLian' };
const nombreGrupo = g => GRUPOS[String(g).toLowerCase()] || String(g).replace(/^./, c => c.toUpperCase());

// Tipos de datos MENCIONADOS por el actor o por la noticia (inglés, español o francés). Es una
// clasificación orientativa por palabras clave, no una verificación de lo filtrado.
const TIPOS = [
  ['Datos personales', /personal data|datos personales|\bPII\b|personal information|informaci[oó]n personal|donn[ée]es personnelles/i],
  ['Datos de empleados', /employees?\b|empleados?\b|employ[ée]s|recursos humanos|n[oó]mina|payroll/i],
  ['Datos de clientes o usuarios', /customers?\b|clientes?\b|clients?\b|usuarios\b|users\b|utilisateurs|comptes d/i],
  ['Documentos de identidad', /passports?\b|pasaportes?|c[eé]dulas?\b|ID cards?|identity documents?|documentos? de identidad|passeports?/i],
  ['Datos financieros o tributarios', /financial|financier|bank accounts?|cuentas bancarias|invoices?\b|facturas?\b|accounting|contabilidad|\btax(es)?\b|impuestos|tributari|imp[oô]ts/i],
  ['Datos médicos', /medical|m[eé]dicos?\b|patients?\b|pacientes?\b|health records?|historias? cl[ií]nicas?|radioth/i],
  ['Contratos y documentos legales', /contracts?\b|contratos?\b|legal documents?|documentos legales|\bNDAs?\b|agreements?\b/i],
  ['Bases de datos', /database|base de datos|\bSQL\b|\bDB\b/i],
  ['Correos electrónicos', /e-?mails?\b|correos?\b|mailbox|buz[oó]n/i],
  ['Credenciales', /password|contrase[ñn]a|credential|credencial|login/i],
  ['Planos y propiedad intelectual', /blueprint|plano|drawing|intellectual property|propiedad intelectual|source code|c[oó]digo fuente/i],
];
const tiposDatos = txt => TIPOS.filter(([, re]) => re.test(txt || '')).map(([n]) => n);

const limpiar = s => String(s || '')
  .replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, '[correo omitido]')
  .replace(/\+?\d[\d\s().-]{7,}\d/g, m => (m.replace(/\D/g, '').length >= 9 && !/^\d{4}-\d{2}-\d{2}$/.test(m) ? '[teléfono omitido]' : m))
  .replace(/https?:\/\/\S+\.onion\S*/gi, '')
  .replace(/\s+/g, ' ').trim().slice(0, 600);
const dominio = s => String(s || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#\s]/)[0];
const normNombre = s => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\b(s\.?a\.?s?|ltda|e\.?s\.?p|sas|inc|corp)\b/g, '').replace(/[^a-z0-9]/g, '');
const fecha = s => { const d = String(s || '').slice(0, 10); return /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : null; };
const httpsSeguro = u => typeof u === 'string' && /^https:\/\//i.test(u) && !/\.onion\b/i.test(u) ? u : null;

function infostealer(d) {
  if (!d || typeof d !== 'object') return null;
  const fam = Object.entries(d.infostealer_stats || {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ familia: k === 'UNKNOWN' ? 'Desconocida' : k, equipos: n }));
  const out = { empleados: d.employees || 0, usuarios: d.users || 0, terceros: d.thirdparties || 0, familias: fam,
    ultimoEmpleado: fecha(d.last_employee_compromised), ultimoUsuario: fecha(d.last_user_compromised) };
  return out.empleados || out.usuarios || out.terceros ? out : null;
}

async function main() {
  const ataques = await getJson('/countrycyberattacks/CO');
  await sleep(2_000);
  const victimas = await getJson('/countryvictims/CO');
  if (!Array.isArray(ataques) || !Array.isArray(victimas)) throw new Error('Formato inesperado de la API');

  const items = [];
  // 1) Reclamaciones de grupos de ransomware
  for (const v of victimas) {
    const desc = v.description && v.description !== 'N/A' ? limpiar(v.description) : '';
    items.push({
      tipo: 'reclamado',
      victima: String(v.post_title || '').trim().slice(0, 120) || 'Sin nombre',
      dominio: dominio(v.website),
      sector: SECTORES[v.activity] || v.activity || 'Sin clasificar',
      fecha: fecha(v.published) || fecha(v.discovered),
      detectado: fecha(v.discovered),
      actor: v.group_name ? nombreGrupo(v.group_name) : null,
      actorId: v.group_name ? String(v.group_name).toLowerCase() : null,
      filtracion: { descripcion: desc, tipos: tiposDatos(desc), volumen: v.data_size || null, rescate: v.ransom || null, publicada: true },
      infostealer: null,
      noticia: null,
      fuentes: [v.group_name ? { nombre: 'Perfil del grupo en ransomware.live', url: 'https://www.ransomware.live/group/' + encodeURIComponent(String(v.group_name).toLowerCase()) } : null].filter(Boolean),
    });
  }
  // 2) Ataques confirmados: se unen a su reclamación si coinciden dominio o nombre (±150 días)
  for (const a of ataques) {
    const dom = dominio(a.domain), nom = normNombre(a.victim), fa = fecha(a.date) || fecha(a.added);
    const actorClaim = a.claim_gang && a.claim_gang !== true ? String(a.claim_gang) : null;
    const near = it => !fa || !it.fecha || Math.abs(new Date(fa) - new Date(it.fecha)) <= 150 * 864e5;
    let m = items.find(it => it.tipo === 'reclamado' && near(it) && ((dom && it.dominio && (it.dominio === dom || it.dominio.endsWith('.' + dom) || dom.endsWith('.' + it.dominio))) || (nom && normNombre(it.victima) === nom)));
    const noticia = { titulo: limpiar(a.title).slice(0, 200), resumen: limpiar(a.summary || a.description), url: httpsSeguro(a.url) };
    const fuentes = [noticia.url ? { nombre: 'Noticia', url: noticia.url } : null, httpsSeguro(a.link) ? { nombre: 'Ficha en ransomware.live', url: a.link } : null,
      httpsSeguro(a.claim_url) ? { nombre: 'Reclamación en ransomware.live', url: a.claim_url } : null].filter(Boolean);
    if (m) {
      m.tipo = 'ambos'; m.noticia = noticia; m.infostealer = infostealer(a.infostealer_data);
      m.filtracion.tipos = tiposDatos(m.filtracion.descripcion + ' ' + noticia.titulo + ' ' + noticia.resumen);
      m.fecha = fa && m.fecha && fa < m.fecha ? fa : (m.fecha || fa);
      m.fuentes = [...fuentes, ...m.fuentes];
      continue;
    }
    items.push({
      tipo: actorClaim ? 'ambos' : 'confirmado',
      victima: String(a.victim || dom || 'Sin nombre').trim().slice(0, 120),
      dominio: dom, sector: sectorDe(dom, a.victim || ''), fecha: fa, detectado: fecha(a.added),
      actor: actorClaim ? nombreGrupo(actorClaim) : null, actorId: actorClaim ? actorClaim.toLowerCase() : null,
      filtracion: { descripcion: '', tipos: tiposDatos(noticia.resumen + ' ' + noticia.titulo), volumen: null, rescate: null, publicada: !!actorClaim },
      infostealer: infostealer(a.infostealer_data), noticia, fuentes,
    });
  }
  items.sort((x, y) => String(y.fecha || '').localeCompare(String(x.fecha || '')));
  items.forEach((it, i) => { it.id = (it.fecha || 's-f') + '-' + (it.dominio || normNombre(it.victima)).replace(/[^a-z0-9.-]/g, '').slice(0, 40) + '-' + i; });

  const out = {
    generado: new Date().toISOString(),
    pais: 'CO',
    fuente: { nombre: 'ransomware.live', url: 'https://www.ransomware.live/country/co', licencia: 'Datos públicos agregados por ransomware.live; reutilización sujeta a sus condiciones.' },
    totales: { incidentes: items.length, confirmados: items.filter(i => i.tipo !== 'reclamado').length, reclamados: items.filter(i => i.tipo !== 'confirmado').length },
    incidentes: items,
  };
  // No sobrescribir con un resultado vacío o sospechosamente pequeño (p. ej., la API devolvió una lista parcial)
  if (existsSync(OUT)) {
    try { const prev = JSON.parse(readFileSync(OUT, 'utf8')); if (items.length < prev.incidentes.length * 0.5) throw new Error('La API devolvió ' + items.length + ' incidentes (antes ' + prev.incidentes.length + '); se conserva el archivo anterior'); }
    catch (e) { if (/se conserva/.test(e.message)) throw e; }
  }
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
  console.log('data/colombia.json: ' + items.length + ' incidentes (' + out.totales.confirmados + ' confirmados, ' + out.totales.reclamados + ' reclamados)');
}

main().catch(e => { console.error('No se actualizó data/colombia.json: ' + e.message); process.exitCode = 1; });
