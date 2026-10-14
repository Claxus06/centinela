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

// ---- Unificación de incidentes ----
// Publicaciones de la misma víctima separadas por menos de VENTANA días son el mismo incidente
// (reposteos del mismo grupo, otro grupo que se adjudica o republica el ataque, o varias noticias del caso).
// Más separadas, se consideran ataques distintos (p. ej., EPM en 2022 y en 2026).
const VENTANA = 180;
// Grupos que republican víctimas antiguas de otros grupos: su publicación se une al incidente original hasta 2 años después
const REPUBLICADORES = new Set(['babuk2']);
const VENTANA_REPUBLICACION = 730;
function agrupar(lista, clave, dias = VENTANA) {
  const limite = typeof dias === 'function' ? dias : () => dias;
  const porClave = new Map();
  for (const x of lista) { const k = clave(x) || ('sin-clave-' + porClave.size); (porClave.get(k) || porClave.set(k, []).get(k)).push(x); }
  const out = [];
  for (const g of porClave.values()) {
    g.sort((a, b) => String(a.fecha || '').localeCompare(String(b.fecha || '')));
    let actual = [g[0]];
    for (let i = 1; i < g.length; i++) {
      const prev = actual[actual.length - 1].fecha, cur = g[i].fecha;
      if (prev && cur && (new Date(cur) - new Date(prev)) / 864e5 > limite(g[i])) { out.push(actual); actual = [g[i]]; } else actual.push(g[i]);
    }
    out.push(actual);
  }
  return out;
}
// El nombre más legible: el que no es un dominio y tiene más palabras
const esDominio = s => /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(String(s).trim());
const mejorNombre = nombres => [...nombres].sort((a, b) => (esDominio(a) - esDominio(b)) || (b.split(/\s+/).length - a.split(/\s+/).length) || a.length - b.length)[0]
  .replace(/^[a-z0-9.-]+\.[a-z]{2,}\s+-\s+/i, '');   // "icvc.co - Instituto…" → "Instituto…"
// Volumen escrito dentro de la descripción del actor ("Data Size: 20,2 GB", "[Size: 2.7 GB")
const volumenEn = s => { const m = String(s || '').match(/(?:data\s*size|size|tama[ñn]o)\s*[:=]?\s*([\d.,]+\s*[KMGT]i?B)\b/i); return m ? m[1].replace(/\s+/, ' ') : null; };
const unicas = fuentes => { const vistos = new Set(); return fuentes.filter(f => f && f.url && !vistos.has(f.url) && vistos.add(f.url)); };

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

  const perfil = id => ({ nombre: 'Perfil de ' + nombreGrupo(id) + ' en ransomware.live', url: 'https://www.ransomware.live/group/' + encodeURIComponent(id) });

  // 1) Reclamaciones de grupos de ransomware (una por publicación)
  const reclamos = victimas.map(v => {
    const desc = v.description && v.description !== 'N/A' ? limpiar(v.description) : '';
    const gid = v.group_name ? String(v.group_name).toLowerCase() : null;
    return {
      victima: String(v.post_title || '').trim().slice(0, 120) || 'Sin nombre',
      dominio: dominio(v.website),
      sector: SECTORES[v.activity] || v.activity || 'Sin clasificar',
      fecha: fecha(v.published) || fecha(v.discovered),
      detectado: fecha(v.discovered),
      actorId: gid,
      descripcion: desc,
      volumen: v.data_size || volumenEn(desc),
      rescate: v.ransom || null,
    };
  });

  // 2) Unificar: la misma víctima publicada varias veces (por el mismo grupo o por otro que la republica,
  //    p. ej. Babuk 2.0) en menos de VENTANA días es UN incidente con varios actores.
  const items = [];
  for (const grupo of agrupar(reclamos, r => r.dominio || normNombre(r.victima), r => (REPUBLICADORES.has(r.actorId) ? VENTANA_REPUBLICACION : VENTANA))) {
    const pub = grupo.sort((a, b) => String(a.fecha).localeCompare(String(b.fecha)));
    const actores = [...new Set(pub.map(p => p.actorId).filter(Boolean))];
    const desc = pub.map(p => p.descripcion).sort((a, b) => b.length - a.length)[0] || '';
    items.push({
      tipo: 'reclamado',
      victima: mejorNombre(pub.map(p => p.victima)),
      dominio: pub[0].dominio,
      sector: (pub.find(p => p.sector !== 'Sin clasificar') || pub[0]).sector,
      fecha: pub[0].fecha,
      detectado: pub[0].detectado,
      actor: actores[0] ? nombreGrupo(actores[0]) : null,
      actorId: actores[0] || null,
      actores: actores.map(nombreGrupo),
      publicaciones: pub.map((p, i) => ({ actor: p.actorId ? nombreGrupo(p.actorId) : null, fecha: p.fecha, republicacion: i > 0 && REPUBLICADORES.has(p.actorId) })),
      filtracion: { descripcion: desc, tipos: tiposDatos(pub.map(p => p.descripcion).join(' ')),
        volumen: (pub.find(p => p.volumen) || {}).volumen || null, rescate: (pub.find(p => p.rescate) || {}).rescate || null, publicada: true },
      infostealer: null,
      noticia: null,
      noticias: [],
      fuentes: actores.map(perfil),
    });
  }

  // 3) Ataques confirmados (prensa o víctima). Varias noticias del mismo caso → un solo incidente.
  const confirmados = agrupar(ataques.map(a => ({ a, fecha: fecha(a.date) || fecha(a.added) })),
    x => normNombre(x.a.victim) || dominio(x.a.domain)).map(g => g.sort((x, y) => String(x.fecha).localeCompare(String(y.fecha))));

  for (const g of confirmados) {
    const a = g[0].a, fa = g[0].fecha, doms = [...new Set(g.map(x => dominio(x.a.domain)).filter(Boolean))], nom = normNombre(a.victim);
    const claims = [...new Set(g.map(x => x.a.claim_gang).filter(c => c && c !== true).map(c => String(c).toLowerCase()))];
    const noticias = g.map(x => ({ titulo: limpiar(x.a.title).slice(0, 200), resumen: limpiar(x.a.summary || x.a.description), url: httpsSeguro(x.a.url), fecha: x.fecha }));
    const fuentes = g.flatMap(x => [httpsSeguro(x.a.link) ? { nombre: 'Ficha en ransomware.live', url: x.a.link } : null,
      httpsSeguro(x.a.claim_url) ? { nombre: 'Reclamación en ransomware.live', url: x.a.claim_url } : null]).filter(Boolean);
    const stealer = infostealer((g.find(x => x.a.has_infostealer_info) || g[0]).a.infostealer_data);
    const near = it => !fa || !it.fecha || Math.abs(new Date(fa) - new Date(it.fecha)) <= VENTANA * 864e5;
    const sameDom = d => doms.some(x => d && (d === x || d.endsWith('.' + x) || x.endsWith('.' + d)));
    const m = items.find(it => it.tipo === 'reclamado' && near(it) && (sameDom(it.dominio) || (nom && normNombre(it.victima) === nom)));
    const textoNoticias = noticias.map(n => n.titulo + ' ' + n.resumen).join(' ');
    if (m) {
      m.tipo = 'ambos'; m.noticia = noticias[0]; m.noticias = noticias; m.infostealer = stealer;
      m.filtracion.tipos = tiposDatos(m.filtracion.descripcion + ' ' + textoNoticias);
      if (fa && (!m.fecha || fa < m.fecha)) m.fecha = fa;
      claims.filter(c => !m.actores.includes(nombreGrupo(c))).forEach(c => { m.actores.push(nombreGrupo(c)); m.fuentes.push(perfil(c)); });
      m.fuentes = unicas([...noticias.filter(n => n.url).map(n => ({ nombre: 'Noticia', url: n.url })), ...fuentes, ...m.fuentes]);
      continue;
    }
    items.push({
      tipo: claims.length ? 'ambos' : 'confirmado',
      victima: String(a.victim || doms[0] || 'Sin nombre').trim().slice(0, 120),
      dominio: doms[0] || '', sector: sectorDe(doms[0] || '', a.victim || ''), fecha: fa, detectado: fecha(a.added),
      actor: claims[0] ? nombreGrupo(claims[0]) : null, actorId: claims[0] || null,
      actores: claims.map(nombreGrupo), publicaciones: [],
      filtracion: { descripcion: '', tipos: tiposDatos(textoNoticias), volumen: null, rescate: null, publicada: claims.length > 0 },
      infostealer: stealer, noticia: noticias[0], noticias,
      fuentes: unicas([...noticias.filter(n => n.url).map(n => ({ nombre: 'Noticia', url: n.url })), ...fuentes, ...claims.map(perfil)]),
    });
  }

  // 4) Identificador estable (no cambia al llegar incidentes nuevos): fecha + dominio o nombre
  items.sort((x, y) => String(y.fecha || '').localeCompare(String(x.fecha || '')) || x.victima.localeCompare(y.victima));
  const usados = new Map();
  items.forEach(it => {
    const base = (it.fecha || 'sin-fecha') + '-' + ((it.dominio || normNombre(it.victima)).replace(/[^a-z0-9.-]/g, '').slice(0, 40) || 'victima');
    const n = (usados.get(base) || 0) + 1; usados.set(base, n);
    it.id = n > 1 ? base + '-' + n : base;
  });
  // Comprobación final: ninguna víctima puede quedar repetida dentro de la ventana de unificación
  const dup = agrupar(items, it => it.dominio || normNombre(it.victima)).filter(g => g.length > 1 && !g.every(x => x.tipo !== 'confirmado'));
  if (dup.length) console.warn('Aviso: posibles duplicados tras unificar: ' + dup.map(g => g.map(x => x.id).join(' = ')).join('; '));

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
