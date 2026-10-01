// Generado por backend/build.mjs — no editar a mano: modifica worker-filtraciones.js / worker-sandbox.js y vuelve a construir.
import { connect } from 'cloudflare:sockets';
globalThis.CF_CONNECT = connect;   // sockets TCP para el análisis TLS (/sbx/tls)

/* Centinela — rutas del Cloudflare Worker (centinela-backend) para el módulo "Filtraciones"

   Sin backend, el módulo consulta directamente XposedOrNot y la lista pública de brechas de
   Have I Been Pwned (ambos permiten CORS). Estas tres rutas completan el resto:

     GET /hibp?email=...          Have I Been Pwned por correo (requiere clave de pago, secreto HIBP_KEY)
     GET /hudsonrock?email=...    Hudson Rock: ¿el correo aparece en un equipo con infostealer?
     GET /hudsonrock?domain=...   Hudson Rock: empleados/usuarios del dominio con credenciales robadas
     GET /ransomware?q=...        ransomware.live: víctimas publicadas por grupos de ransomware
     GET /rdap?domain=...|ip=...  RDAP (registrador, hosting y contacto de abuso) para "Retirar contenido"

   Hudson Rock y ransomware.live son gratuitos pero no envían cabeceras CORS, por eso el navegador
   no puede llamarlos directamente y hace falta este paso por el Worker.

   Cómo añadirlas:
   1. (Solo para /hibp) En Cloudflare → tu Worker → Settings → Variables, crea el secreto HIBP_KEY
      (o:  npx wrangler secret put HIBP_KEY). Sin él, /hibp responde 500 y el resto sigue funcionando.
   2. Copia las funciones de este archivo en el código del Worker.
   3. En el enrutador del Worker (donde ya atiende /verify y /headers) añade:
        const leak = await handleLeakRoutes(url, env, request);
        if (leak) return leak;
   4. Publica el Worker y pon su URL en Centinela → Ajustes → "URL del backend". */

const LEAK_CORS = {
  'Access-Control-Allow-Origin': '*',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};
const leakJson = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: LEAK_CORS });
const LEAK_EMAIL = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const LEAK_DOMAIN = /^[a-z0-9.-]+\.[a-z]{2,}$/i;

async function leakPassThrough(target, headers = {}) {
  const r = await fetch(target, { headers: { 'user-agent': 'Centinela-Worker', accept: 'application/json', ...headers } });
  return new Response(await r.text(), { status: r.status, headers: LEAK_CORS });
}

// request es opcional por compatibilidad; pásalo para aplicar ALLOWED_ORIGINS y SBX_LIMIT (ver worker-sandbox.js)
async function handleLeakRoutes(url, env, request) {
  if (!/^\/(hibp|hudsonrock|rdap|ransomware)$/.test(url.pathname)) return null;
  if (request && typeof centinelaGuard === 'function') return centinelaGuard(request, env, () => leakRoutes(url, env));
  return leakRoutes(url, env);
}
async function leakRoutes(url, env) {
  const p = url.pathname;

  if (p === '/hibp') {
    const email = (url.searchParams.get('email') || '').trim().toLowerCase();
    if (!LEAK_EMAIL.test(email)) return leakJson({ error: 'Correo no válido' }, 400);
    if (!env.HIBP_KEY) return leakJson({ error: 'Falta el secreto HIBP_KEY en el Worker' }, 500);
    const r = await fetch(
      'https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email) + '?truncateResponse=false',
      { headers: { 'hibp-api-key': env.HIBP_KEY, 'user-agent': 'Centinela-Worker' } }
    );
    if (r.status === 404) return new Response('[]', { status: 404, headers: LEAK_CORS });
    if (r.status === 429) return leakJson({ error: 'Límite de consultas de HIBP alcanzado; espera unos segundos' }, 429);
    if (!r.ok) return leakJson({ error: 'HIBP respondió ' + r.status }, 502);
    return new Response(await r.text(), { status: 200, headers: LEAK_CORS });
  }

  if (p === '/hudsonrock') {
    const base = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/';
    const email = (url.searchParams.get('email') || '').trim().toLowerCase();
    const domain = (url.searchParams.get('domain') || '').trim().toLowerCase();
    if (email) {
      if (!LEAK_EMAIL.test(email)) return leakJson({ error: 'Correo no válido' }, 400);
      return leakPassThrough(base + 'search-by-email?email=' + encodeURIComponent(email));
    }
    if (!LEAK_DOMAIN.test(domain)) return leakJson({ error: 'Dominio no válido' }, 400);
    return leakPassThrough(base + 'search-by-domain?domain=' + encodeURIComponent(domain));
  }

  if (p === '/rdap') {
    // Respaldo para "Retirar contenido": sigue la redirección de rdap.org hasta el registro correspondiente
    const domain = (url.searchParams.get('domain') || '').trim().toLowerCase();
    const ip = (url.searchParams.get('ip') || '').trim();
    if (domain && LEAK_DOMAIN.test(domain)) return leakPassThrough('https://rdap.org/domain/' + encodeURIComponent(domain), { accept: 'application/rdap+json' });
    if (/^[0-9a-f:.]{3,45}$/i.test(ip)) return leakPassThrough('https://rdap.org/ip/' + encodeURIComponent(ip), { accept: 'application/rdap+json' });
    return leakJson({ error: 'Indica domain= o ip=' }, 400);
  }

  if (p === '/ransomware') {
    const q = (url.searchParams.get('q') || '').trim();
    if (q.length < 3 || q.length > 80) return leakJson({ error: 'Palabra clave no válida' }, 400);
    return leakPassThrough('https://api.ransomware.live/v2/searchvictims/' + encodeURIComponent(q));
  }

  return null;
}


/* Centinela — rutas del Cloudflare Worker (centinela-backend) para el módulo "Sandbox de archivos"

   El análisis estático se hace en el navegador (sandbox-worker.js). Estas rutas añaden reputación del hash
   y el sandbox dinámico de VirusTotal. Las claves de API se guardan como secretos del Worker y nunca llegan
   al navegador:

     GET  /sbx/hashlookup?hash=<sha256>   CIRCL hashlookup (archivos conocidos / NSRL; sin clave)
     GET  /sbx/vt?hash=<sha256>           VirusTotal: detecciones, etiqueta, sandboxes y técnicas ATT&CK observadas (VT_KEY)
     POST /sbx/vt/upload?name=<archivo>   Sube el archivo (≤ 32 MB) al sandbox de VirusTotal (VT_KEY) → {id}
     GET  /sbx/vt/analysis?id=<id>        Estado del análisis de VirusTotal
     GET  /sbx/mb?hash=<sha256>           MalwareBazaar (abuse.ch) (ABUSECH_KEY o MB_KEY: Auth-Key gratuita de abuse.ch)
     GET  /sbx/ha?hash=<sha256>           Hybrid Analysis (HA_KEY)
     GET  /kev                            Catálogo CISA KEV con CORS (también lo usa "Análisis de vulnerabilidades")
     GET  /headers?url=<url>              Cabeceras HTTP de seguridad de un sitio (módulo "Cabeceras HTTP")
     GET  /verify?url=<url>               Google Safe Browsing (GSB_KEY) y VirusTotal (VT_KEY) para el módulo Phishing
     GET  /sbx/url?u=<url>                Descarga aislada de una URL (sigue redirecciones, máx. 5 MB) para analizarla
                                          en el sandbox sin que el usuario visite el sitio. Bloquea destinos internos.
     GET  /sbx/urlhaus?q=<url|host>       URLhaus (abuse.ch)   (ABUSECH_KEY o MB_KEY: la misma Auth-Key de abuse.ch)
     GET  /sbx/threatfox?q=<ioc>          ThreatFox (abuse.ch) (ABUSECH_KEY o MB_KEY)
     GET  /sbx/tls?host=<host>&port=443   Versiones TLS admitidas, cifrado, certificado (X.509), HSTS y redirección a HTTPS.
                                          Usa sockets TCP: en el Worker (formato de módulos) añade al principio
                                            import { connect } from 'cloudflare:sockets'; globalThis.CF_CONNECT = connect;
                                          Limitación de Cloudflare: los Workers no pueden abrir sockets hacia sitios que
                                          están detrás de Cloudflare.

   Cómo añadirlas:
   1. Crea los secretos que vayas a usar:  npx wrangler secret put VT_KEY  (y MB_KEY, HA_KEY).
      Sin un secreto, su ruta responde 501 y el resto sigue funcionando.
   2. Copia este archivo en el código del Worker.
   3. En el enrutador del Worker (donde ya atiende /verify, /headers y las rutas de filtraciones) añade:
        const sbx = await handleSandboxRoutes(request, url, env);
        if (sbx) return sbx;
   4. Define la variable ALLOWED_ORIGINS con la URL de tu Centinela publicado (p.ej. https://tuusuario.github.io):
      sin ella, cualquier sitio web podría usar tu Worker, tus claves y tus cuotas.
   5. Publica el Worker y pon su URL en Centinela → Ajustes → "URL del backend".
   Aviso: lo que se sube a VirusTotal queda disponible para su comunidad; la página pide confirmación expresa. */

/* ---- Protección del backend publicado (compartida por las rutas de Centinela) ----
   ALLOWED_ORIGINS (variable del Worker): orígenes autorizados separados por comas, p.ej.
     https://tuusuario.github.io,http://localhost:8080
   Si está definida, solo esas páginas pueden usar el Worker desde un navegador y la respuesta CORS
   devuelve ese origen (no "*"). Recomendado: sin ella, cualquier sitio podría usar tus claves y cuotas.
   SBX_LIMIT (binding opcional de Rate Limiting de Cloudflare): límite de peticiones por IP.
   Nota: un cliente que no sea un navegador puede falsificar Origin; para un control estricto combina
   ALLOWED_ORIGINS con SBX_LIMIT o con Cloudflare Access. */
async function centinelaGuard(request, env, inner) {
  const origin = request && request.headers ? (request.headers.get('Origin') || '') : '';
  const allowed = String((env && env.ALLOWED_ORIGINS) || '').split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);
  const deny = (status, error) => new Response(JSON.stringify({ error }), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Vary': 'Origin' } });
  if (allowed.length && !allowed.includes(origin)) return deny(403, 'Origen no autorizado para usar este backend');
  if (env && env.SBX_LIMIT && typeof env.SBX_LIMIT.limit === 'function') {
    const ip = (request.headers.get('CF-Connecting-IP') || 'anon');
    try { const { success } = await env.SBX_LIMIT.limit({ key: ip }); if (!success) return deny(429, 'Demasiadas peticiones; espera un momento'); } catch (e) {}
  }
  const res = await inner();
  if (!res || !allowed.length) return res;
  const h = new Headers(res.headers); h.set('Access-Control-Allow-Origin', origin); h.set('Vary', 'Origin');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

const SBX_CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};
const sbxJson = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: SBX_CORS });
const SBX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const SBX_VT_MAX = 32 * 1024 * 1024;

async function sbxFetchJson(target, init = {}) {
  const r = await fetch(target, init);
  let j = null; try { j = await r.json(); } catch (e) {}
  return { status: r.status, ok: r.ok, j };
}

async function handleSandboxRoutes(request, url, env) {
  if (!['/kev', '/headers', '/verify'].includes(url.pathname) && !url.pathname.startsWith('/sbx/')) return null;
  return centinelaGuard(request, env, () => sbxRoutes(request, url, env));
}
async function sbxRoutes(request, url, env) {
  const p = url.pathname;
  if (p === '/kev') {
    // Catálogo CISA KEV con CORS (cisa.gov no lo envía); caché de 12 h en el borde de Cloudflare
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { cf: { cacheTtl: 43200, cacheEverything: true }, headers: { 'user-agent': 'Centinela-Worker' } });
    if (!r.ok) return sbxJson({ error: 'CISA respondió ' + r.status }, 502);
    return new Response(await r.text(), { status: 200, headers: Object.assign({}, SBX_CORS, { 'Cache-Control': 'public, max-age=43200' }) });
  }
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: SBX_CORS });
  if (p === '/headers') return sbxHeaders(url.searchParams.get('url') || '');
  if (p === '/verify') return sbxVerify(url.searchParams.get('url') || '', env);
  if (!p.startsWith('/sbx/')) return null;
  const hash = (url.searchParams.get('hash') || '').trim().toLowerCase();

  if (p === '/sbx/hashlookup') {
    if (!/^[a-f0-9]{64}$/.test(hash)) return sbxJson({ error: 'Hash SHA-256 no válido' }, 400);
    const r = await sbxFetchJson('https://hashlookup.circl.lu/lookup/sha256/' + hash, { headers: { accept: 'application/json', 'user-agent': 'Centinela-Worker' } });
    if (r.status === 404) return sbxJson({ message: 'Non existing SHA-256' }, 404);
    return sbxJson(r.j || {}, r.ok ? 200 : 502);
  }

  if (p === '/sbx/vt') {
    if (!SBX_HASH.test(hash)) return sbxJson({ error: 'Hash no válido' }, 400);
    if (!env.VT_KEY) return sbxJson({ error: 'Falta el secreto VT_KEY en el Worker' }, 501);
    const H = { 'x-apikey': env.VT_KEY, accept: 'application/json' };
    const [f, mt] = await Promise.all([
      sbxFetchJson('https://www.virustotal.com/api/v3/files/' + hash, { headers: H }),
      sbxFetchJson('https://www.virustotal.com/api/v3/files/' + hash + '/behaviour_mitre_trees', { headers: H }),
    ]);
    if (f.status === 404) return sbxJson({ found: false }, 404);
    if (f.status === 429) return sbxJson({ error: 'Cuota de VirusTotal agotada; espera un minuto' }, 429);
    if (!f.ok || !f.j || !f.j.data) return sbxJson({ error: 'VirusTotal respondió ' + f.status }, 502);
    const a = f.j.data.attributes || {};
    const mitre = new Set();
    if (mt.ok && mt.j && mt.j.data) for (const sb of Object.values(mt.j.data)) for (const t of (sb.tactics || [])) for (const te of (t.techniques || [])) if (te.id) mitre.add(te.id);
    const sandbox = Object.entries(a.sandbox_verdicts || {}).map(([k, v]) => k + ': ' + (v.category || '') + (v.malware_names ? ' (' + v.malware_names.join(', ') + ')' : ''));
    return sbxJson({
      found: true,
      stats: a.last_analysis_stats || {},
      label: (a.popular_threat_classification && a.popular_threat_classification.suggested_threat_label) || '',
      type: a.type_description || '',
      names: (a.names || []).slice(0, 10),
      first: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : '',
      reputation: a.reputation,
      sandbox: sandbox.slice(0, 10),
      yara: (a.crowdsourced_yara_results || []).map(y => y.rule_name).slice(0, 15),
      sigma: a.sigma_analysis_stats || null,
      mitre: [...mitre].slice(0, 200),
    });
  }

  if (p === '/sbx/vt/upload') {
    if (request.method !== 'POST') return sbxJson({ error: 'Usa POST' }, 405);
    if (!env.VT_KEY) return sbxJson({ error: 'Falta el secreto VT_KEY en el Worker' }, 501);
    const name = (url.searchParams.get('name') || 'muestra.bin').replace(/[\r\n"\\]/g, '_').slice(0, 200);
    const len = +(request.headers.get('content-length') || 0);
    if (len > SBX_VT_MAX) return sbxJson({ error: 'Máximo 32 MB' }, 413);
    const body = await request.arrayBuffer();
    if (!body.byteLength || body.byteLength > SBX_VT_MAX) return sbxJson({ error: 'Archivo vacío o mayor de 32 MB' }, 413);
    const fd = new FormData(); fd.append('file', new Blob([body]), name);
    const r = await sbxFetchJson('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: { 'x-apikey': env.VT_KEY }, body: fd });
    if (!r.ok || !r.j || !r.j.data) return sbxJson({ error: 'VirusTotal respondió ' + r.status }, 502);
    return sbxJson({ id: r.j.data.id });
  }

  if (p === '/sbx/vt/analysis') {
    const id = (url.searchParams.get('id') || '').trim();
    if (!/^[A-Za-z0-9=_:-]{8,200}$/.test(id)) return sbxJson({ error: 'Identificador no válido' }, 400);
    if (!env.VT_KEY) return sbxJson({ error: 'Falta el secreto VT_KEY en el Worker' }, 501);
    const r = await sbxFetchJson('https://www.virustotal.com/api/v3/analyses/' + encodeURIComponent(id), { headers: { 'x-apikey': env.VT_KEY } });
    if (!r.ok || !r.j || !r.j.data) return sbxJson({ error: 'VirusTotal respondió ' + r.status }, 502);
    const a = r.j.data.attributes || {};
    return sbxJson({ status: a.status || 'queued', stats: a.stats || {} });
  }

  if (p === '/sbx/mb') {
    if (!SBX_HASH.test(hash)) return sbxJson({ error: 'Hash no válido' }, 400);
    const mbKey = env.ABUSECH_KEY || env.MB_KEY;
    if (!mbKey) return sbxJson({ error: 'Falta el secreto ABUSECH_KEY (o MB_KEY) en el Worker' }, 501);
    const r = await sbxFetchJson('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST', headers: { 'Auth-Key': mbKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_info&hash=' + encodeURIComponent(hash),
    });
    if (!r.ok || !r.j) return sbxJson({ error: 'MalwareBazaar respondió ' + r.status }, 502);
    if (r.j.query_status !== 'ok' || !r.j.data || !r.j.data[0]) return sbxJson({ found: false }, 404);
    const d = r.j.data[0];
    return sbxJson({ found: true, signature: d.signature || '', tags: d.tags || [], first: d.first_seen || '', fileType: d.file_type || '', delivery: d.delivery_method || '' });
  }

  if (p === '/sbx/ha') {
    if (!SBX_HASH.test(hash)) return sbxJson({ error: 'Hash no válido' }, 400);
    if (!env.HA_KEY) return sbxJson({ error: 'Falta el secreto HA_KEY en el Worker' }, 501);
    const H = { 'api-key': env.HA_KEY, 'user-agent': 'Falcon Sandbox', accept: 'application/json' };
    let r = await sbxFetchJson('https://hybrid-analysis.com/api/v2/search/hash?hash=' + hash, { headers: H });
    if (r.status === 404 || r.status === 405) r = await sbxFetchJson('https://hybrid-analysis.com/api/v2/search/hash', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, H), body: 'hash=' + hash });
    if (!r.ok || !r.j) return sbxJson({ error: 'Hybrid Analysis respondió ' + r.status }, 502);
    const reports = Array.isArray(r.j) ? r.j : (r.j.reports || []);
    if (!reports.length) return sbxJson({ found: false }, 404);
    const rank = { malicious: 3, suspicious: 2, 'no specific threat': 1, whitelisted: 0 };
    const best = reports.slice().sort((a, b) => (rank[b.verdict] || 0) - (rank[a.verdict] || 0))[0];
    return sbxJson({ found: true, verdict: best.verdict || '', family: best.vx_family || '', score: best.threat_score != null ? best.threat_score : null, reports: reports.length });
  }

  if (p === '/sbx/url') return sbxFetchUrl(url.searchParams.get('u') || '');
  if (p === '/sbx/tls') return sbxTls(url.searchParams.get('host') || '', +(url.searchParams.get('port') || 443));

  if (p === '/sbx/urlhaus' || p === '/sbx/threatfox') {
    const key = env.ABUSECH_KEY || env.MB_KEY;
    if (!key) return sbxJson({ error: 'Falta el secreto ABUSECH_KEY (o MB_KEY) en el Worker' }, 501);
    const q = (url.searchParams.get('q') || '').trim();
    if (q.length < 3 || q.length > 2048) return sbxJson({ error: 'Indicador no válido' }, 400);
    if (p === '/sbx/urlhaus') {
      const isUrl = /^https?:\/\//i.test(q);
      const r = await sbxFetchJson('https://urlhaus-api.abuse.ch/v1/' + (isUrl ? 'url/' : 'host/'), {
        method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: (isUrl ? 'url=' : 'host=') + encodeURIComponent(q),
      });
      if (!r.ok || !r.j) return sbxJson({ error: 'URLhaus respondió ' + r.status }, 502);
      if (r.j.query_status !== 'ok') return sbxJson({ found: false }, 404);
      const j = r.j;
      return sbxJson({ found: true, status: j.url_status || (j.urls && j.urls[0] && j.urls[0].url_status) || '', threat: j.threat || (j.urls && j.urls[0] && j.urls[0].threat) || '',
        tags: (j.tags || (j.urls && j.urls[0] && j.urls[0].tags) || []).slice(0, 10), first: j.date_added || j.firstseen || '', urls: j.url_count != null ? j.url_count : undefined, blacklists: j.blacklists || null });
    }
    const r = await sbxFetchJson('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: q, exact_match: true }),
    });
    if (!r.ok || !r.j) return sbxJson({ error: 'ThreatFox respondió ' + r.status }, 502);
    if (r.j.query_status !== 'ok' || !Array.isArray(r.j.data) || !r.j.data.length) return sbxJson({ found: false }, 404);
    const d = r.j.data[0];
    return sbxJson({ found: true, threat: d.threat_type_desc || d.threat_type || '', malware: d.malware_printable || '', confidence: d.confidence_level, first: d.first_seen || '', tags: (d.tags || []).slice(0, 10), reports: r.j.data.length });
  }

  return sbxJson({ error: 'Ruta no encontrada' }, 404);
}

/* ---- Descarga aislada de una URL para analizarla sin que el usuario la visite.
   Sigue redirecciones una a una (máx. 8), limita tiempo y tamaño, y bloquea destinos internos (SSRF). */
const SBX_URL_MAX = 5 * 1024 * 1024;
function sbxBlockedHost(h) {
  h = h.toLowerCase().replace(/^\[|\]$/g, '');
  if (!h || h === 'localhost' || /\.(local|localhost|internal|intranet|lan|home|corp|arpa)$/.test(h)) return true;
  if (/^\d+$/.test(h) || /^0x/i.test(h)) return true; // IP en formato decimal/hex
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [+m[1], +m[2]];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (h.includes(':')) return h === '::1' || /^(fc|fd|fe8|fe9|fea|feb|::ffff:)/.test(h);
  return false;
}
async function sbxFetchUrl(raw) {
  let cur;
  try { cur = new URL(String(raw).trim()); } catch (e) { return sbxJson({ error: 'URL no válida' }, 400); }
  const chain = [];
  const t0 = Date.now();
  for (let hop = 0; hop < 9; hop++) {
    if (!/^https?:$/.test(cur.protocol)) return sbxJson({ error: 'Solo se admiten http y https', chain }, 400);
    if (sbxBlockedHost(cur.hostname)) return sbxJson({ error: 'Destino interno o no permitido: ' + cur.hostname, chain }, 400);
    if (cur.port && !['80', '443', '8080', '8443'].includes(cur.port)) return sbxJson({ error: 'Puerto no permitido: ' + cur.port, chain }, 400);
    const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 15000);
    let r;
    try {
      r = await fetch(cur.href, { redirect: 'manual', signal: ctrl.signal, headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
        accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'es-CO,es;q=0.9,en;q=0.8' } });
    } catch (e) { clearTimeout(to); return sbxJson({ error: e.name === 'AbortError' ? 'Tiempo de espera agotado' : 'No se pudo conectar: ' + e.message, chain }, 502); }
    clearTimeout(to);
    const loc = r.headers.get('location');
    chain.push({ url: cur.href, status: r.status, location: loc || '', server: r.headers.get('server') || '', type: r.headers.get('content-type') || '' });
    if (r.status >= 300 && r.status < 400 && loc) { try { cur = new URL(loc, cur); } catch (e) { break; } continue; }
    // Respuesta final: leer como máximo SBX_URL_MAX bytes
    const reader = r.body ? r.body.getReader() : null; const parts = []; let n = 0; let truncated = false;
    if (reader) for (;;) { const { value, done } = await reader.read(); if (done) break; parts.push(value); n += value.length; if (n >= SBX_URL_MAX) { truncated = true; try { await reader.cancel(); } catch (e) {} break; } }
    const buf = new Uint8Array(Math.min(n, SBX_URL_MAX)); let o = 0; for (const p of parts) { const k = Math.min(p.length, buf.length - o); buf.set(p.subarray(0, k), o); o += k; if (o >= buf.length) break; }
    let bin = ''; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    const disp = r.headers.get('content-disposition') || '';
    const pick = h => r.headers.get(h) || '';
    return sbxJson({ final: cur.href, status: r.status, type: pick('content-type'), disposition: disp, size: n, truncated, ms: Date.now() - t0, chain,
      headers: { server: pick('server'), 'x-powered-by': pick('x-powered-by'), 'strict-transport-security': pick('strict-transport-security'), 'content-security-policy': pick('content-security-policy').slice(0, 300) },
      body: btoa(bin) });
  }
  return sbxJson({ error: 'Demasiadas redirecciones', chain }, 508);
}

/* ---- Análisis TLS por sockets TCP (sin completar el handshake: solo ClientHello → ServerHello/Certificate).
   openSocket(host, port) → { write(Uint8Array), read() → Uint8Array|null, close() } (Cloudflare: cloudflare:sockets) */
const TLS_V = { 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const TLS_SUITES = { 0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256', 0xc030: 'ECDHE-RSA-AES256-GCM-SHA384', 0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256', 0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305', 0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305', 0xc013: 'ECDHE-RSA-AES128-SHA', 0xc014: 'ECDHE-RSA-AES256-SHA',
  0xc009: 'ECDHE-ECDSA-AES128-SHA', 0xc00a: 'ECDHE-ECDSA-AES256-SHA', 0x009c: 'RSA-AES128-GCM-SHA256', 0x009d: 'RSA-AES256-GCM-SHA384',
  0x002f: 'RSA-AES128-SHA', 0x0035: 'RSA-AES256-SHA', 0x000a: 'RSA-3DES-EDE-CBC-SHA', 0x0005: 'RSA-RC4-128-SHA' };
const TLS12_SUITES = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xc013, 0xc014, 0xc009, 0xc00a, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a, 0x0005];
function tlsClientHello(host, ver) {
  const rnd = n => crypto.getRandomValues(new Uint8Array(n));
  const u16 = v => [v >> 8 & 255, v & 255];
  const ext = (type, body) => [...u16(type), ...u16(body.length), ...body];
  const sni = new TextEncoder().encode(host);
  const is13 = ver === 0x0304;
  const suites = is13 ? [0x1301, 0x1302, 0x1303] : TLS12_SUITES;
  const exts = [
    ...ext(0x0000, [...u16(sni.length + 3), 0, ...u16(sni.length), ...sni]),                       // server_name
    ...ext(0x000a, [...u16(6), ...u16(0x001d), ...u16(0x0017), ...u16(0x0018)]),                    // supported_groups
    ...ext(0x000b, [1, 0]),                                                                          // ec_point_formats
    ...ext(0x000d, (() => { const a = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203]; return [...u16(a.length * 2), ...a.flatMap(u16)]; })()), // signature_algorithms
    ...ext(0xff01, [0])                                                                              // renegotiation_info
  ];
  if (is13) {
    exts.push(...ext(0x002b, [2, ...u16(0x0304)]));                                                  // supported_versions: solo 1.3
    const ks = rnd(32); exts.push(...ext(0x0033, [...u16(36), ...u16(0x001d), ...u16(32), ...ks]));   // key_share x25519
    exts.push(...ext(0x002d, [1, 1]));                                                               // psk_key_exchange_modes
  }
  const body = [...u16(is13 ? 0x0303 : ver), ...rnd(32), 32, ...rnd(32), ...u16(suites.length * 2), ...suites.flatMap(u16), 1, 0, ...u16(exts.length), ...exts];
  const hs = [1, body.length >> 16 & 255, body.length >> 8 & 255, body.length & 255, ...body];
  return new Uint8Array([0x16, 0x03, 0x01, ...u16(hs.length), ...hs]);
}
/* Lee registros TLS hasta obtener ServerHello (+ Certificate en ≤ 1.2) o una alerta */
async function tlsHandshake(openSocket, host, port, ver, wantCert) {
  let sock;
  const t0 = Date.now();
  try { sock = await openSocket(host, port); } catch (e) { return { error: 'No se pudo conectar: ' + (e && e.message || e) }; }
  try {
    await sock.write(tlsClientHello(host, ver));
    let buf = new Uint8Array(0); const hsBuf = []; let hsBytes = new Uint8Array(0); const out = {};
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && buf.length < 131072) {
      const chunk = await Promise.race([sock.read(), new Promise(r => setTimeout(() => r('timeout'), Math.max(1, deadline - Date.now())))]);
      if (chunk === 'timeout' || chunk === null) break;
      const nb = new Uint8Array(buf.length + chunk.length); nb.set(buf); nb.set(chunk, buf.length); buf = nb;
      // procesar registros completos
      while (buf.length >= 5) {
        const type = buf[0], len = buf[3] << 8 | buf[4]; if (buf.length < 5 + len) break;
        const frag = buf.subarray(5, 5 + len); buf = buf.slice(5 + len);
        if (type === 0x15) { out.alert = frag[1]; return out; }
        if (type !== 0x16) continue;
        const nh = new Uint8Array(hsBytes.length + frag.length); nh.set(hsBytes); nh.set(frag, hsBytes.length); hsBytes = nh;
        while (hsBytes.length >= 4) {
          const ht = hsBytes[0], hl = hsBytes[1] << 16 | hsBytes[2] << 8 | hsBytes[3]; if (hsBytes.length < 4 + hl) break;
          const m = hsBytes.subarray(4, 4 + hl); hsBytes = hsBytes.slice(4 + hl);
          if (ht === 2) { // ServerHello
            let o = 0; const sv = m[o] << 8 | m[o + 1]; o += 2 + 32; o += 1 + m[o]; const cs = m[o] << 8 | m[o + 1]; o += 3;
            let neg = sv;
            if (o + 2 <= m.length) { const el = m[o] << 8 | m[o + 1]; o += 2; const end = o + el; while (o + 4 <= end) { const et = m[o] << 8 | m[o + 1], len2 = m[o + 2] << 8 | m[o + 3]; if (et === 0x002b && len2 === 2) neg = m[o + 4] << 8 | m[o + 5]; o += 4 + len2; } }
            out.version = neg; out.cipher = cs; out.ms = Date.now() - t0;
            if (!wantCert || neg === 0x0304) return out;
          } else if (ht === 11) { // Certificate (TLS ≤ 1.2)
            let o = 3; const certs = []; const tot = m[0] << 16 | m[1] << 8 | m[2];
            while (o < 3 + tot && certs.length < 4) { const cl = m[o] << 16 | m[o + 1] << 8 | m[o + 2]; o += 3; certs.push(m.slice(o, o + cl)); o += cl; }
            out.certs = certs; return out;
          } else if (ht === 14) return out; // ServerHelloDone
        }
      }
    }
    return Object.keys(out).length ? out : { error: 'Sin respuesta TLS' };
  } catch (e) { return { error: String(e && e.message || e) }; }
  finally { try { await sock.close(); } catch (e) {} }
}
/* ---- X.509 (DER) mínimo: emisor, sujeto, validez, clave, firma, SAN */
const OIDS = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519',
  '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS', '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512' };
function derRead(b, o) { const tag = b[o]; let len = b[o + 1], hl = 2; if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[o + 2 + i]; hl = 2 + n; } return { tag, start: o + hl, len, end: o + hl + len }; }
function derChildren(b, node) { const out = []; let o = node.start; while (o < node.end) { const c = derRead(b, o); out.push(c); o = c.end; } return out; }
function derOid(b, n) { const v = b.subarray(n.start, n.end); const a = [Math.floor(v[0] / 40), v[0] % 40]; let x = 0; for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { a.push(x); x = 0; } } return a.join('.'); }
function derStr(b, n) { return new TextDecoder(n.tag === 0x1e ? 'utf-16be' : 'utf-8').decode(b.subarray(n.start, n.end)); }
function derTime(b, n) { const s = new TextDecoder().decode(b.subarray(n.start, n.end)); const m = n.tag === 0x17 ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/) : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/); if (!m) return null; let y = +m[1]; if (n.tag === 0x17) y += y < 50 ? 2000 : 1900; return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))).toISOString(); }
function derName(b, n) { const o = {}; derChildren(b, n).forEach(set => derChildren(b, set).forEach(atv => { const [oid, val] = derChildren(b, atv); const k = OIDS[derOid(b, oid)]; if (k && !o[k]) o[k] = derStr(b, val); })); return o; }
function x509(der) {
  const b = der; const cert = derRead(b, 0); const [tbs, sigAlg] = derChildren(b, cert);
  let f = derChildren(b, tbs); if (f[0].tag === 0xa0) f = f.slice(1);
  const [serial, , issuer, validity, subject, spki] = f; const ext = f.find(x => x.tag === 0xa3);
  const [nb, na] = derChildren(b, validity);
  const [algSeq, bits] = derChildren(b, spki); const alg = derChildren(b, algSeq); const keyType = OIDS[derOid(b, alg[0])] || derOid(b, alg[0]);
  let keyBits = null, curve = null;
  if (keyType === 'RSA') { const bs = b.subarray(bits.start + 1, bits.end); const rsa = derRead(bs, 0); const mod = derChildren(bs, rsa)[0]; let l = mod.len, s = mod.start; while (l > 0 && bs[s] === 0) { s++; l--; } keyBits = l * 8 - Math.clz32(bs[s]) + 24; }
  else if (keyType === 'EC' && alg[1]) { curve = OIDS[derOid(b, alg[1])] || derOid(b, alg[1]); keyBits = { 'P-256': 256, 'P-384': 384, 'P-521': 521 }[curve] || null; }
  else if (keyType === 'Ed25519') keyBits = 256;
  const sans = [];
  if (ext) { derChildren(b, derChildren(b, ext)[0]).forEach(e => { const p = derChildren(b, e); if (derOid(b, p[0]) === '2.5.29.17') { const os = p[p.length - 1]; const seq = derRead(b, os.start); derChildren(b, seq).forEach(g => { if (g.tag === 0x82) sans.push(new TextDecoder().decode(b.subarray(g.start, g.end))); }); } }); }
  const sig = OIDS[derOid(b, derChildren(b, sigAlg)[0])] || derOid(b, derChildren(b, sigAlg)[0]);
  const sub = derName(b, subject), iss = derName(b, issuer);
  return { subject: sub, issuer: iss, notBefore: derTime(b, nb), notAfter: derTime(b, na), keyType, keyBits, curve, sigAlg: sig, sans: sans.slice(0, 100),
    serial: Array.from(b.subarray(serial.start, serial.end), x => x.toString(16).padStart(2, '0')).join(':'), selfSigned: JSON.stringify(sub) === JSON.stringify(iss) };
}
const tlsNameMatch = (host, names) => names.some(n => { n = n.toLowerCase(); return n === host || (n.startsWith('*.') && host.endsWith(n.slice(1)) && host.split('.').length === n.split('.').length); });
async function tlsProbe(openSocket, host, port) {
  const versions = {}; let best = null; let certInfo = null; let certErr = null;
  for (const v of [0x0304, 0x0303, 0x0302, 0x0301]) {
    const r = await tlsHandshake(openSocket, host, port, v, v !== 0x0304 && !certInfo);   // en ≤ 1.2 el certificado viaja sin cifrar
    const ok = !!r.version && r.version === v;
    versions[TLS_V[v]] = r.error && !r.alert && !r.version ? null : ok;
    if (ok && !best) best = { version: TLS_V[v], cipher: TLS_SUITES[r.cipher] || ('0x' + r.cipher.toString(16).padStart(4, '0')), ms: r.ms };
    if (v !== 0x0304 && ok && !certInfo) { if (r.certs && r.certs.length) { try { certInfo = x509(r.certs[0]); certInfo.chain = r.certs.length; if (r.certs[1]) { try { certInfo.issuerCert = x509(r.certs[1]).subject; } catch (e) {} } } catch (e) { certErr = 'Certificado no interpretable: ' + e.message; } } }
    if (v === 0x0303 && ok) versions.cipher12 = TLS_SUITES[r.cipher] || ('0x' + r.cipher.toString(16));
    if (r.error && v === 0x0304 && /conectar/.test(r.error)) return { error: r.error };
  }
  if (certInfo) { certInfo.nameMatch = tlsNameMatch(host, certInfo.sans.length ? certInfo.sans : [certInfo.subject.CN || '']); certInfo.daysLeft = certInfo.notAfter ? Math.floor((Date.parse(certInfo.notAfter) - Date.now()) / 864e5) : null; }
  else if (!certErr) certErr = (versions['TLS 1.2'] || versions['TLS 1.1'] || versions['TLS 1.0']) ? 'El servidor no envió el certificado' : 'El servidor solo admite TLS 1.3, donde el certificado viaja cifrado y no puede leerse sin completar el handshake';
  return { host, port, versions, best, cert: certInfo, certError: certErr };
}

/* Adaptador de cloudflare:sockets a la interfaz { write, read, close } del sondeo */
async function cfOpenSocket(host, port) {
  const s = globalThis.CF_CONNECT({ hostname: host, port });
  if (s.opened) await s.opened;
  const w = s.writable.getWriter(), r = s.readable.getReader();
  return { write: u => w.write(u), read: async () => { const { value, done } = await r.read(); return done ? null : value; }, close: () => s.close() };
}
async function sbxTls(host, port) {
  host = String(host).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/:].*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return sbxJson({ error: 'Nombre de host no válido' }, 400);
  if (sbxBlockedHost(host)) return sbxJson({ error: 'Destino interno o no permitido' }, 400);
  if (![443, 8443, 465, 993, 995].includes(port)) return sbxJson({ error: 'Puerto no permitido (443, 8443, 465, 993, 995)' }, 400);
  if (typeof globalThis.CF_CONNECT !== 'function') return sbxJson({ error: "El Worker no tiene sockets habilitados: añade import { connect } from 'cloudflare:sockets'; globalThis.CF_CONNECT = connect;" }, 501);
  const r = await tlsProbe(cfOpenSocket, host, port);
  if (r.error) return sbxJson({ error: /proxy|cloudflare|refused|prohibited/i.test(r.error) ? r.error + ' (si el sitio está detrás de Cloudflare, los Workers no pueden abrir sockets hacia él)' : r.error }, 502);
  if (port === 443) {
    try { const h = await fetch('https://' + host + '/', { method: 'GET', redirect: 'manual', headers: { 'user-agent': 'Centinela-Worker' } }); r.hsts = h.headers.get('strict-transport-security') || ''; } catch (e) { r.hsts = null; }
    try { const h = await fetch('http://' + host + '/', { method: 'GET', redirect: 'manual', headers: { 'user-agent': 'Centinela-Worker' } }); const loc = h.headers.get('location') || ''; r.httpRedirect = h.status >= 300 && h.status < 400 ? (/^https:/i.test(loc) ? 'https' : 'otro') : 'no'; } catch (e) { r.httpRedirect = null; }
  }
  return sbxJson(r);
}

/* ---- /headers: cabeceras de respuesta de un sitio (siguiendo redirecciones con las mismas comprobaciones SSRF) */
async function sbxHeaders(raw) {
  let cur;
  try { cur = new URL(/^https?:\/\//i.test(String(raw).trim()) ? String(raw).trim() : 'https://' + String(raw).trim()); } catch (e) { return sbxJson({ error: 'URL no válida' }, 400); }
  for (let hop = 0; hop < 6; hop++) {
    if (!/^https?:$/.test(cur.protocol) || sbxBlockedHost(cur.hostname) || (cur.port && !['80', '443', '8080', '8443'].includes(cur.port))) return sbxJson({ error: 'Destino no permitido: ' + cur.hostname }, 400);
    let r;
    try { r = await fetch(cur.href, { method: 'GET', redirect: 'manual', headers: { 'user-agent': 'Mozilla/5.0 (compatible; Centinela-Worker)' } }); } catch (e) { return sbxJson({ error: 'No se pudo conectar: ' + e.message }, 502); }
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { try { cur = new URL(loc, cur); continue; } catch (e) { break; } }
    const headers = {}; r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v.slice(0, 2000); });
    try { if (r.body) await r.body.cancel(); } catch (e) {}
    return sbxJson({ url: cur.href, status: r.status, headers });
  }
  return sbxJson({ error: 'Demasiadas redirecciones' }, 508);
}

/* ---- /verify: reputación de una URL en Google Safe Browsing y VirusTotal (cada una solo si su clave existe) */
async function sbxVerify(raw, env) {
  let u; try { u = new URL(String(raw).trim()); } catch (e) { return sbxJson({ error: 'URL no válida' }, 400); }
  if (!/^https?:$/.test(u.protocol)) return sbxJson({ error: 'Solo http y https' }, 400);
  const out = { gsb: null, vt: null };
  const jobs = [];
  if (env.GSB_KEY) jobs.push((async () => {
    const r = await sbxFetchJson('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(env.GSB_KEY), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client: { clientId: 'centinela', clientVersion: '1.0' }, threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: u.href }] } }) });
    out.gsb = !r.ok ? 'error' : (r.j && r.j.matches && r.j.matches.length ? 'listed' : 'clean');
  })());
  if (env.VT_KEY) jobs.push((async () => {
    const id = btoa(u.href).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const r = await sbxFetchJson('https://www.virustotal.com/api/v3/urls/' + id, { headers: { 'x-apikey': env.VT_KEY } });
    if (r.status === 404) out.vt = { malicious: 0, found: false };
    else if (r.ok && r.j && r.j.data) { const st = r.j.data.attributes.last_analysis_stats || {}; out.vt = { malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, found: true }; }
    else out.vt = { error: 'VirusTotal respondió ' + r.status };
  })());
  await Promise.all(jobs.map(j => j.catch(() => {})));
  if (!env.GSB_KEY && !env.VT_KEY) out.note = 'Configura GSB_KEY y/o VT_KEY en el Worker';
  return sbxJson(out);
}


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      const leak = await handleLeakRoutes(url, env, request);
      if (leak) return leak;
      const sbx = await handleSandboxRoutes(request, url, env);
      if (sbx) return sbx;
      if (url.pathname === '/') return new Response('Centinela backend: operativo.', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
      return new Response(JSON.stringify({ error: 'Ruta no encontrada' }), { status: 404, headers: { 'content-type': 'application/json; charset=utf-8' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Error interno del backend' }), { status: 500, headers: { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' } });
    }
  }
};
