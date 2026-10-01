// Utilidades de las pruebas: servidor estático de la app y control de Chrome/Edge headless por DevTools Protocol.
'use strict';
const http = require('http'); const fs = require('fs'); const path = require('path'); const os = require('os');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.json': 'application/json', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8' };
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* Mini marco de aserciones */
let passed = 0, failed = 0; const failures = [];
function ok(cond, msg) { if (cond) { passed++; console.log('  ✓ ' + msg); } else { failed++; failures.push(msg); console.log('  ✗ ' + msg); } }
function section(t) { console.log('\n' + t); }
function summary(name) {
  console.log(`\n${name}: ${passed} correctas, ${failed} fallidas`);
  if (failed) { console.log('Fallos:\n - ' + failures.join('\n - ')); process.exitCode = 1; }
}

/* Servidor estático (sin backend: las pruebas no dependen de servicios externos) */
function serve(port = 0) {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x'); const p = decodeURIComponent(u.pathname === '/' ? '/index.html' : u.pathname);
      const f = path.join(ROOT, p);
      if (!f.startsWith(ROOT) || f.includes(path.sep + 'tests' + path.sep) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); res.end('no'); return; }
      res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream' }); fs.createReadStream(f).pipe(res);
    });
    srv.listen(port, '127.0.0.1', () => resolve({ url: 'http://127.0.0.1:' + srv.address().port, close: () => srv.close() }));
  });
}

/* Localiza Chrome/Edge: variable CHROME_PATH o rutas habituales */
function findBrowser() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const c = ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'];
  const f = c.find(p => fs.existsSync(p)); if (!f) throw new Error('No se encontró Chrome/Edge; define CHROME_PATH');
  return f;
}

async function browser(port = 9400) {
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'centinela-test-'));
  const proc = spawn(findBrowser(), ['--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run', '--remote-debugging-port=' + port, '--user-data-dir=' + prof, '--window-size=1400,1000', 'about:blank'], { stdio: 'ignore' });
  let tgt; for (let i = 0; i < 80 && !tgt; i++) { await sleep(250); try { tgt = (await (await fetch('http://127.0.0.1:' + port + '/json')).json()).find(t => t.type === 'page'); } catch (e) {} }
  if (!tgt) throw new Error('El navegador no arrancó');
  const ws = new WebSocket(tgt.webSocketDebuggerUrl); await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0; const pend = {}; const errs = [];
  ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id && pend[d.id]) { pend[d.id](d); delete pend[d.id]; }
    if (d.method === 'Runtime.exceptionThrown') errs.push(d.params.exceptionDetails.exception ? d.params.exceptionDetails.exception.description : d.params.exceptionDetails.text);
    if (d.method === 'Log.entryAdded' && d.params.entry.level === 'error' && /Content Security Policy|Refused to/.test(d.params.entry.text)) errs.push('CSP: ' + d.params.entry.text); };
  const send = (method, params = {}) => new Promise(r => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = await send('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }); if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception ? r.result.exceptionDetails.exception.description : r.result.exceptionDetails.text); return r.result.result.value; };
  await send('Runtime.enable'); await send('Page.enable'); await send('Log.enable');
  const go = async (url, wait = 2500) => { await send('Page.navigate', { url }); await sleep(wait); };
  const close = async () => { try { ws.close(); } catch (e) {} proc.kill(); await sleep(500); try { fs.rmSync(prof, { recursive: true, force: true }); } catch (e) {} };
  return { ev, send, go, close, errs, sleep };
}

/* Muestras sintéticas e inofensivas generadas en memoria */
const zlib = require('zlib');
function zip(entries) {
  const L = [], C = []; let off = 0;
  for (const [name, data, opt] of entries) {
    const nb = Buffer.from(name, 'utf8'), raw = Buffer.from(data), comp = zlib.deflateRawSync(raw), crc = zlib.crc32(raw), fl = 0x800 | ((opt && opt.enc) ? 1 : 0);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(fl, 6); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nb.length, 26);
    L.push(lh, nb, comp);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(fl, 8); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(off, 42);
    C.push(ch, nb); off += 30 + nb.length + comp.length;
  }
  const cd = Buffer.concat(C), e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(entries.length, 8); e.writeUInt16LE(entries.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...L, cd, e]);
}
// MS-OVBA "comprimido" solo con literales (formato válido según la especificación)
function ovba(txt) { const src = Buffer.from(txt, 'latin1'); const out = [1]; for (let i = 0; i < src.length; i += 4096) { const ch = src.subarray(i, i + 4096); const body = []; for (let j = 0; j < ch.length; j += 8) { body.push(0); for (let k = j; k < Math.min(j + 8, ch.length); k++) body.push(ch[k]); } const hdr = 0xB000 | ((body.length - 1) & 0xfff); out.push(hdr & 0xff, hdr >> 8, ...body); } return Buffer.from(out); }
// PE mínimo y válido de 1 sección (sin código ejecutable real) para probar el analizador
function tinyPE() {
  const b = Buffer.alloc(1024); b.write('MZ', 0); b.writeUInt32LE(0x40, 0x3C); b.write('PE\0\0', 0x40, 'latin1');
  const coff = 0x44; b.writeUInt16LE(0x8664, coff); b.writeUInt16LE(1, coff + 2); b.writeUInt32LE(1700000000, coff + 4); b.writeUInt16LE(240, coff + 16); b.writeUInt16LE(0x0022, coff + 18);
  const opt = coff + 20; b.writeUInt16LE(0x20b, opt); b.writeUInt32LE(0x1000, opt + 16); b.writeUInt16LE(3, opt + 68); b.writeUInt16LE(0x0140, opt + 70); b.writeUInt32LE(16, opt + 108);
  const sh = opt + 240; b.write('.text', sh, 'latin1'); b.writeUInt32LE(0x200, sh + 8); b.writeUInt32LE(0x1000, sh + 12); b.writeUInt32LE(0x200, sh + 16); b.writeUInt32LE(0x200, sh + 20); b.writeUInt32LE(0x60000020, sh + 36);
  b.write('Centinela prueba de analizador PE', 0x200, 'latin1');
  return b;
}
const ab = b => b.buffer.slice(b.byteOffset, b.byteOffset + b.length);

module.exports = { ROOT, ok, section, summary, serve, browser, sleep, zip, ovba, tinyPE, ab };
