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
