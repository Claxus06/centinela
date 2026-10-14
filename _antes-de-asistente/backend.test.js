// Pruebas de las rutas del backend (Cloudflare Worker) sin red: protección de orígenes, límite de peticiones
// y bloqueo de destinos internos (SSRF). Se ejecutan con las API web nativas de Node (Request/Response/Headers).
'use strict';
const fs = require('fs'); const path = require('path');
const { ok, section, summary, ROOT } = require('./lib');
const src = ['worker-sandbox.js', 'worker-filtraciones.js'].map(f => fs.readFileSync(path.join(ROOT, f), 'utf8')).join('\n');
const W = new Function(src + '\nreturn { handleSandboxRoutes, handleLeakRoutes, sbxBlockedHost };')();

const call = async (p, { origin, env = {}, leak = false } = {}) => {
  const url = new URL('https://w.example' + p);
  const req = new Request(url, { headers: origin ? { Origin: origin } : {} });
  const r = leak ? await W.handleLeakRoutes(url, env, req) : await W.handleSandboxRoutes(req, url, env);
  return r ? { status: r.status, acao: r.headers.get('access-control-allow-origin'), body: await r.json().catch(() => null) } : null;
};

(async () => {
  section('Orígenes permitidos (ALLOWED_ORIGINS)');
  const env = { ALLOWED_ORIGINS: 'https://usuario.github.io, http://localhost:8080/' };
  let r = await call('/sbx/ping', { origin: 'https://otro.com' });
  ok(r.acao === '*', 'sin ALLOWED_ORIGINS responde a cualquier origen (compatibilidad)');
  r = await call('/sbx/ping', { origin: 'https://usuario.github.io', env });
  ok(r.status === 404 && r.acao === 'https://usuario.github.io', 'origen permitido: CORS devuelve ese origen, no "*"');
  r = await call('/sbx/ping', { origin: 'http://localhost:8080', env });
  ok(r.acao === 'http://localhost:8080', 'la barra final en la configuración se ignora');
  r = await call('/sbx/ping', { origin: 'https://atacante.com', env });
  ok(r.status === 403, 'origen no permitido: 403');
  r = await call('/sbx/ping', { env });
  ok(r.status === 403, 'petición sin Origin: 403');
  r = await call('/ransomware?q=entidad', { origin: 'https://atacante.com', env, leak: true });
  ok(r.status === 403, 'las rutas de filtraciones también aplican la protección');
  ok(await call('/otra-ruta', { origin: 'https://atacante.com', env }) === null, 'rutas ajenas a Centinela no se gestionan');

  section('Límite de peticiones (SBX_LIMIT)');
  let n = 0; const lim = { SBX_LIMIT: { limit: async () => ({ success: ++n <= 2 }) } };
  const st = []; for (let i = 0; i < 3; i++) st.push((await call('/sbx/ping', { env: lim })).status);
  ok(st.join() === '404,404,429', 'la tercera petición recibe 429: ' + st.join(', '));

  section('Destinos internos (SSRF)');
  for (const h of ['localhost', '127.0.0.1', '10.1.2.3', '172.16.5.4', '192.168.0.1', '169.254.169.254', '100.64.0.1', '2130706433', '0x7f000001', '[::1]', 'fd00::1', 'intranet.local', 'servidor.internal'])
    ok(W.sbxBlockedHost(h), 'bloquea ' + h);
  for (const h of ['example.com', '8.8.8.8', '1.1.1.1']) ok(!W.sbxBlockedHost(h), 'permite ' + h);
  r = await call('/sbx/url?u=' + encodeURIComponent('http://169.254.169.254/latest/meta-data/'));
  ok(r.status === 400 && /interno/.test(r.body.error), 'análisis de enlaces: rechaza la dirección de metadatos de la nube');
  r = await call('/sbx/url?u=' + encodeURIComponent('file:///etc/passwd'));
  ok(r.status === 400, 'análisis de enlaces: rechaza file://');
  r = await call('/sbx/tls?host=localhost');
  ok(r.status === 400, 'análisis TLS: rechaza hosts internos');
  r = await call('/sbx/tls?host=example.com&port=22');
  ok(r.status === 400 && /Puerto no permitido/.test(r.body.error), 'análisis TLS: solo puertos TLS permitidos');

  section('Secretos ausentes');
  r = await call('/sbx/vt?hash=' + 'a'.repeat(64));
  ok(r.status === 501 && /VT_KEY/.test(r.body.error), 'VirusTotal sin clave: 501 con el nombre del secreto');
  r = await call('/sbx/urlhaus?q=example.com');
  ok(r.status === 501 && /ABUSECH_KEY/.test(r.body.error), 'URLhaus sin clave: 501 con el nombre del secreto');

  section('Worker ensamblado (backend/build.mjs)');
  const { execFileSync } = require('child_process'); const os = require('os');
  execFileSync(process.execPath, [path.join(ROOT, 'backend', 'build.mjs')], { stdio: 'ignore' });
  const built = fs.readFileSync(path.join(ROOT, 'backend', 'dist', 'worker.js'), 'utf8');
  ok(/^import \{ connect \} from 'cloudflare:sockets';/m.test(built) && /export default \{/.test(built), 'genera dist/worker.js con sockets y punto de entrada');
  // Cargar el módulo en Node sustituyendo cloudflare:sockets (sin red: solo rutas que no salen a Internet)
  const tmp = path.join(os.tmpdir(), 'centinela-worker-' + process.pid + '.mjs');
  fs.writeFileSync(tmp, built.replace("import { connect } from 'cloudflare:sockets';", 'const connect = () => { throw new Error("sin red en pruebas"); };'));
  const Wk = (await import(require('url').pathToFileURL(tmp).href)).default; fs.unlinkSync(tmp);
  const wcall = async (p, origin, e) => { const r = await Wk.fetch(new Request('https://w.example' + p, { headers: origin ? { Origin: origin } : {} }), e || {}); return { status: r.status, acao: r.headers.get('access-control-allow-origin'), body: await r.text() }; };
  ok((await wcall('/')).status === 200, 'la raíz responde (comprobación de salud)');
  ok((await wcall('/no-existe')).status === 404, 'rutas desconocidas: 404');
  ok((await wcall('/headers?url=example.com', 'https://atacante.com', { ALLOWED_ORIGINS: 'https://usuario.github.io' })).status === 403, 'aplica ALLOWED_ORIGINS a /headers');
  ok((await wcall('/headers?url=http://169.254.169.254/')).status === 400, '/headers bloquea destinos internos');
  ok(/Configura GSB_KEY/.test((await wcall('/verify?url=https://example.com/')).body), '/verify indica qué claves faltan');
  ok((await wcall('/sbx/tls?host=localhost')).status === 400, '/sbx/tls bloquea hosts internos');
  summary('Pruebas del backend');
})().catch(e => { console.error(e); process.exitCode = 1; });
