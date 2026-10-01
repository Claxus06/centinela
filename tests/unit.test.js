// Pruebas unitarias del motor del sandbox (sandbox-worker.js) con muestras sintéticas e inofensivas.
'use strict';
const zlib = require('zlib');
const { ok, section, summary, zip, ovba, tinyPE, ab } = require('./lib');
const E = require('../sandbox-worker.js');
const enc = s => Buffer.from(s, 'utf8');
const run = (name, data, opts) => E.analyze(name, ab(Buffer.isBuffer(data) ? data : enc(data)), opts);
const titles = r => r.findings.filter(f => f.sev !== 'info').map(f => f.title).join(' | ');

(async () => {
  section('Hashes');
  ok(E.md5(new Uint8Array()) === 'd41d8cd98f00b204e9800998ecf8427e', 'MD5 de cadena vacía (RFC 1321)');
  ok(E.md5(enc('abc')) === '900150983cd24fb0d6963f7d28e17f72', 'MD5("abc") (RFC 1321)');
  const r0 = await run('a.txt', 'abc');
  ok(r0.hashes.sha256 === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256("abc") (FIPS 180)');

  section('Ejecutable PE');
  const pe = await run('programa.exe', tinyPE());
  ok(pe.type.id === 'pe-exe' && pe.pe && pe.pe.arch.startsWith('x64'), 'detecta PE x64 y su arquitectura');
  ok(pe.pe.sections.length === 1 && pe.pe.sections[0].name === '.text', 'lee la tabla de secciones');
  const disfrazado = await run('factura.pdf', tinyPE());
  ok(disfrazado.mismatch && disfrazado.findings.some(f => f.sev === 'crit' && /no coincide con el contenido/.test(f.title)), 'ejecutable con extensión .pdf: crítico por enmascaramiento');
  const doble = await run('factura.pdf.exe', tinyPE());
  ok(doble.findings.some(f => /Doble extensión/.test(f.title) && f.attack.includes('T1036.007')), 'doble extensión → T1036.007');

  section('Documentos Office');
  const vba = 'Attribute VB_Name = "ThisDocument"\r\nSub Document_Open()\r\n MsgBox "Hola"\r\nEnd Sub\r\n';
  const docx = zip([['[Content_Types].xml', '<Types/>'], ['word/document.xml', '<w:document/>'], ['word/vbaProject.bin', Buffer.concat([Buffer.from('\0_VBA_PROJECT\0'), ovba(vba), Buffer.alloc(8)])],
    ['word/_rels/settings.xml.rels', '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://plantillas.example.net/t.dotm" TargetMode="External"/></Relationships>']]);
  const d = await run('informe.docx', docx);
  ok(d.zip && d.zip.macros.length === 1 && /MsgBox "Hola"/.test(d.zip.macros[0].code), 'extrae el código VBA (descompresión MS-OVBA)');
  ok(/Inyección de plantilla remota/.test(titles(d)) && /extensión sin macros/.test(titles(d)), 'plantilla remota y macros en .docx');
  ok(d.attack.includes('T1221') && d.attack.includes('T1204.002'), 'técnicas ATT&CK T1221 y T1204.002');

  section('PDF');
  const js = zlib.deflateSync(Buffer.from('app.alert("Bienvenido");'));
  const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n2 0 obj<</S/J#61vaScript/JS 3 0 R>>endobj\n3 0 obj<</Length ' + js.length + '/Filter/FlateDecode>>stream\n'), js, Buffer.from('\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF\n')]);
  const p = await run('aviso.pdf', pdf);
  ok(p.pdf.inflated === 1 && p.pdf.javascript.length === 1, 'descomprime el stream Flate y extrae el JavaScript');
  ok(/JavaScript que se ejecuta automáticamente/.test(titles(p)) && /escapes hexadecimales/.test(titles(p)), 'JavaScript automático y nombres ofuscados (/J#61vaScript)');

  section('Contenedores e imágenes');
  const z = await run('fotos.zip', zip([['leeme.txt', 'hola'], ['privado.txt', 'x', { enc: 1 }]]));
  ok(/protegido con contraseña/.test(titles(z)), 'ZIP cifrado');
  const png = Buffer.concat([Buffer.from('89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4890000000A49444154789C6300010000050001C5A0F2CB0000000049454E44AE426082', 'hex'), Buffer.alloc(2048, 0x41)]);
  ok(/Datos ocultos tras el final de la imagen/.test(titles(await run('foto.png', png))), 'imagen con datos añadidos');

  section('Falsos positivos (regresiones)');
  const page = '<html><body><svg><path d="M0"/></svg><script>var a=1</script><a href="https://x.org/setup.exe">x</a><script src="https://cdn.x.org/app.js"></script>' + '<p>Lorem ipsum dolor sit amet.</p>'.repeat(300) + '<img src="data:image/png;base64,' + 'iVBORw0KGgo'.repeat(600) + '"></body></html>';
  const pg = await run('pagina.html', page);
  ok(pg.score < 15 && !/SVG con código|Base64/.test(titles(pg)), 'página web normal (icono SVG, scripts, enlaces, imagen incrustada en Base64) no se marca como sospechosa');
  const smug = await run('factura.html', '<script>var d="' + 'QUJD'.repeat(6000) + '";var b=new Blob([atob(d)]);</script>');
  ok(/Bloques Base64 extensos/.test(titles(smug)), 'un bloque Base64 grande dentro de un script sí se marca');
  ok(/SVG con código ejecutable/.test(titles(await run('img.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))), 'SVG con script dentro sí se marca');
  const benign = await run('readme.txt', 'Instrucciones de instalación del programa. Visite https://www.example.com para más información.');
  ok(benign.score === 0, 'texto inofensivo: puntuación 0');

  section('Manifiestos de dependencias');
  ok(JSON.stringify((await run('requirements.txt', 'django==2.2.0\nrequests==2.19.0\n')).manifest.packages) === '[{"name":"django","version":"2.2.0"},{"name":"requests","version":"2.19.0"}]', 'requirements.txt');
  ok((await run('package.json', JSON.stringify({ dependencies: { lodash: '4.17.15', axios: '^0.21.0' } }))).manifest.packages.length === 2, 'package.json');

  section('Reglas de comportamiento (texto inerte)');
  const det = async (txt, re, tech) => { const r = await run('nota.txt', txt); const f = r.findings.find(x => re.test(x.title)); return !!f && (!tech || f.attack.includes(tech)); };
  ok(await det(String.raw`msbuild.exe C:\proyectos\build.xml`, /MSBuild/, 'T1127.001'), 'MSBuild con proyecto XML → T1127.001');
  ok(await det('netsh advfirewall set allprofiles state off', /firewall/, 'T1562.004'), 'desactivar el firewall → T1562.004');
  ok(await det('net user soporte Clave123 /add', /cuenta local/, 'T1136.001'), 'crear cuenta local → T1136.001');
  ok(await det('Set-WmiInstance -Class __EventFilter -Namespace root\subscription', /WMI/, 'T1546.003'), 'suscripción WMI → T1546.003');
  ok(await det('function _0x3f2a(){return 1}', /ofuscador/, 'T1027'), 'ofuscador javascript-obfuscator → T1027');
  ok(!(await det('Guía: para activar el firewall ejecute netsh advfirewall set allprofiles state on', /firewall/)), 'activar el firewall NO se marca (falso positivo evitado)');
  ok(!(await det('Use net user para listar las cuentas del equipo.', /cuenta local/)), 'listar cuentas NO se marca como creación de cuentas');

  section('Excel 97-2003 (BIFF8)');
  const bs = (name, hidden, dt) => { const n = Buffer.from(name, 'latin1'); const r = Buffer.alloc(12 + n.length); r.writeUInt16LE(0x0085, 0); r.writeUInt16LE(8 + n.length, 2); r.writeUInt32LE(0x1000, 4); r[8] = hidden; r[9] = dt; r[10] = n.length; r[11] = 0; n.copy(r, 12); return r; };
  const xls = Buffer.concat([Buffer.from('D0CF11E0A1B11AE1', 'hex'), Buffer.alloc(504), Buffer.from('Workbook', 'utf16le'), Buffer.alloc(64), bs('Hoja1', 0, 0), bs('Macro1', 2, 1), Buffer.alloc(256)]);
  const xr = await run('libro.xls', xls);
  ok(xr.findings.some(f => /Hoja de macros Excel 4\.0 \(XLM\) muy oculta/.test(f.title) && f.sev === 'crit' && f.attack.includes('T1564')), 'detecta hoja de macros XLM muy oculta → crítica + T1564');
  const xls2 = Buffer.concat([Buffer.from('D0CF11E0A1B11AE1', 'hex'), Buffer.alloc(504), Buffer.from('Workbook', 'utf16le'), Buffer.alloc(64), bs('Hoja1', 0, 0), bs('Hoja2', 0, 0), Buffer.alloc(256)]);
  ok(!(await run('normal.xls', xls2)).findings.some(f => /XLM|muy ocultas/.test(f.title)), 'libro .xls normal: sin hallazgos de XLM');

  section('Rendimiento');
  const big = Array.from({ length: 120000 }, (_, i) => 'linea ' + i + ' _0xabc texto normal con datos ' + (i % 97)).join('\n');
  const t0 = Date.now(); await run('grande.txt', big); const ms = Date.now() - t0;
  ok(ms < 8000, 'texto de ' + (big.length / 1048576).toFixed(1) + ' MB analizado en ' + ms + ' ms (sin expresiones regulares lentas)');

  section('Reglas YARA');
  const rules = `rule es_pe : ejecutable { meta: severity = "medium" attack = "T1204.002" condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }
rule texto { strings: $a = "prueba de analizador" nocase $b = { 43 65 6E [2-4] 6C 61 } condition: all of them and filesize < 1MB }
rule ancha { strings: $w = "Centinela" wide condition: $w }
rule rota { condition: $x }`;
  const c = E.yaraCompile(rules);
  ok(c.rules.length === 3 && c.errors.length === 1 && /rota/.test(c.errors[0]), 'compila 3 reglas válidas e informa de la rota');
  const y = await run('programa.exe', tinyPE(), { yara: rules });
  const m = y.yara.matched.map(x => x.rule);
  ok(m.includes('es_pe') && m.includes('texto') && !m.includes('ancha'), 'uint32 anidado, hex con saltos, nocase y wide');
  ok(y.findings.some(f => f.cat === 'Reglas YARA' && f.sev === 'med' && f.attack.includes('T1204.002')), 'meta severity/attack aplicados al hallazgo');

  section('Reglas YARA base (yara/centinela-base.yar)');
  const base = require('fs').readFileSync(require('path').join(__dirname, '..', 'yara', 'centinela-base.yar'), 'utf8');
  const cb = E.yaraCompile(base);
  ok(cb.rules.length === 7 && cb.errors.length === 0, 'las 7 reglas base compilan sin errores' + (cb.errors.length ? ': ' + cb.errors.join(' | ') : ''));
  const hit = async (name, data) => ((await run(name, data, { yara: base })).yara.matched || []).map(m => m.rule);
  ok((await hit('aviso.pdf', pdf)).includes('Centinela_PDF_javascript_al_abrir'), 'PDF con JavaScript al abrir');
  ok((await hit('paquete.zip', zip([['factura.pdf.exe', 'x']]))).includes('Centinela_Comprimido_doble_extension'), 'ZIP con doble extensión');
  const upx = tinyPE(); upx.write('UPX0', 0x300, 'latin1'); upx.write('UPX1', 0x310, 'latin1');
  ok((await hit('p.exe', upx)).includes('Centinela_PE_empaquetado_UPX'), 'PE con secciones UPX');
  ok((await hit('readme.txt', 'Documento de texto normal.')).length === 0, 'texto normal: ninguna regla base coincide');
  summary('Pruebas unitarias');
})().catch(e => { console.error(e); process.exitCode = 1; });
