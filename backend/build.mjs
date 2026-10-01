// Ensambla el Worker de Centinela (dist/worker.js) a partir de los archivos del proyecto:
//   ../worker-filtraciones.js  (filtraciones: HIBP, Hudson Rock, ransomware.live, RDAP)
//   ../worker-sandbox.js       (reputación, sandbox dinámico, enlaces, TLS, KEV, cabeceras, verificación)
// Uso:  node build.mjs   y después   npx wrangler deploy
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = f => readFileSync(join(here, '..', f), 'utf8');

const entry = `// Generado por backend/build.mjs — no editar a mano: modifica worker-filtraciones.js / worker-sandbox.js y vuelve a construir.
import { connect } from 'cloudflare:sockets';
globalThis.CF_CONNECT = connect;   // sockets TCP para el análisis TLS (/sbx/tls)

${src('worker-filtraciones.js')}

${src('worker-sandbox.js')}

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
`;
mkdirSync(join(here, 'dist'), { recursive: true });
writeFileSync(join(here, 'dist', 'worker.js'), entry);
console.log('dist/worker.js generado (' + Math.round(entry.length / 1024) + ' KB). Siguiente paso: npx wrangler deploy');
