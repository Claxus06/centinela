/* Centinela — Sandbox de análisis estático de archivos (Web Worker)

   Aislamiento:
   - Corre en un Web Worker dedicado: sin acceso al DOM, a cookies ni al almacenamiento de la página.
   - El archivo NUNCA se ejecuta, renderiza ni interpreta: solo se leen sus bytes como ArrayBuffer.
   - Este worker no hace peticiones de red; toda consulta externa (reputación, CVE, OSV) la hace la
     página con los hashes/identificadores que devuelve este análisis.
   - La página lo termina si supera el tiempo máximo y crea uno nuevo para el siguiente archivo.

   Mensaje de entrada:  {id, name, buf:ArrayBuffer}
   Mensaje de salida:   {id, ok:true, report} | {id, ok:false, error}

   Todo el motor vive dentro de centinelaSandboxEngine() para poder arrancarlo de tres formas:
   1) como Web Worker desde este archivo (modo normal, p.ej. en GitHub Pages);
   2) como Web Worker creado desde memoria (Blob) con el código de esta función, cuando el navegador no
      permite cargar el worker desde archivo (index.html abierto como file://, archivo no publicado…);
   3) en la propia página (modo compatibilidad) si el navegador no admite workers.
   En ningún caso se ejecuta el archivo analizado.                                                    */
function centinelaSandboxEngine() {
'use strict';

const SCAN_MAX = 48 * 1024 * 1024;      // bytes analizados para cadenas/reglas
const TEXT_MAX = 6 * 1024 * 1024;       // texto máximo sobre el que se aplican las reglas
const MAX_STRINGS = 20000;
const INFLATE_MAX = 24 * 1024 * 1024;   // total descomprimido (PDF/ZIP) permitido

/* ============================================================ utilidades */
const u8at = (u8, o) => (o >= 0 && o < u8.length) ? u8[o] : 0;
const rd16 = (u8, o) => u8at(u8, o) | (u8at(u8, o + 1) << 8);
const rd32 = (u8, o) => (u8at(u8, o) | (u8at(u8, o + 1) << 8) | (u8at(u8, o + 2) << 16) | (u8at(u8, o + 3) << 24)) >>> 0;
const rd64 = (u8, o) => rd32(u8, o) + rd32(u8, o + 4) * 4294967296;
const hex = (u8) => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const startsWith = (u8, sig, off = 0) => { for (let i = 0; i < sig.length; i++) if (u8[off + i] !== sig[i]) return false; return true; };
const latin1 = (u8, a = 0, b = u8.length) => { let s = ''; const C = 0x8000; for (let i = a; i < b; i += C) s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(b, i + C))); return s; };
const cstr = (u8, o, max = 256) => { let s = ''; for (let i = 0; i < max && o + i < u8.length; i++) { const c = u8[o + i]; if (!c) break; s += String.fromCharCode(c); } return s; };
const uniq = (a) => [...new Set(a)];
const fmtHexOff = (n) => '0x' + n.toString(16).toUpperCase();

/* ============================================================ hashes */
// MD5 (RFC 1321) — WebCrypto no lo ofrece y sigue siendo el identificador más usado en CTI
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = new Int32Array(64).map((_, i) => (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0);
function md5(u8) {
  const n = u8.length, total = ((n + 8) >>> 6) + 1, words = new Int32Array(total * 16);
  for (let i = 0; i < n; i++) words[i >> 2] |= u8[i] << ((i % 4) * 8);
  words[n >> 2] |= 0x80 << ((n % 4) * 8);
  words[total * 16 - 2] = (n * 8) | 0; words[total * 16 - 1] = Math.floor(n / 536870912);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  for (let blk = 0; blk < words.length; blk += 16) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + words[blk + g]) | 0;
      A = D; D = C; C = B;
      B = (B + ((F << MD5_S[i]) | (F >>> (32 - MD5_S[i])))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new Uint8Array(16), dv = new DataView(out.buffer);
  dv.setInt32(0, a0, true); dv.setInt32(4, b0, true); dv.setInt32(8, c0, true); dv.setInt32(12, d0, true);
  return hex(out);
}
async function digest(algo, u8) { return hex(new Uint8Array(await crypto.subtle.digest(algo, u8))); }

/* ============================================================ entropía */
function entropy(u8, a = 0, b = u8.length) {
  const len = b - a; if (len <= 0) return 0;
  const f = new Uint32Array(256); for (let i = a; i < b; i++) f[u8[i]]++;
  let e = 0; for (let i = 0; i < 256; i++) if (f[i]) { const p = f[i] / len; e -= p * Math.log2(p); }
  return Math.round(e * 1000) / 1000;
}
function entropyBlocks(u8, n = 96) {
  if (!u8.length) return [];
  const bs = Math.max(256, Math.ceil(u8.length / n)); const out = [];
  for (let i = 0; i < u8.length; i += bs) out.push({ off: i, e: entropy(u8, i, Math.min(u8.length, i + bs)) });
  return out;
}

/* ============================================================ tipo de archivo (firmas) */
const EXT_CLASS = {
  exec: ['exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'sys', 'drv', 'ocx', 'msi', 'msp', 'msix', 'msixbundle', 'appx', 'appxbundle', 'jar', 'apk', 'elf', 'so', 'dylib', 'bin', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'xll', 'wll', 'efi'],
  script: ['js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'wsc', 'hta', 'ps1', 'psm1', 'psd1', 'bat', 'cmd', 'sh', 'bash', 'zsh', 'py', 'pyw', 'pl', 'rb', 'php', 'lnk', 'url', 'scf', 'reg', 'inf', 'chm', 'iqy', 'slk', 'settingcontent-ms', 'library-ms', 'search-ms', 'application', 'appref-ms', 'gadget', 'msc', 'cpl', 'jnlp', 'vb', 'applescript', 'scpt', 'command', 'desktop'],
  container: ['iso', 'img', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'cab', 'gz', 'tgz', 'tar', 'ace', 'arj', 'lzh', 'xz', 'bz2', 'one', 'onepkg', 'udf', 'wim'],
  office_macro: ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pps', 'rtf', 'xlsb', 'mht', 'mhtml'],
  document: ['docx', 'dotx', 'xlsx', 'xltx', 'pptx', 'ppsx', 'potx', 'pdf', 'odt', 'ods', 'odp', 'txt', 'csv', 'md', 'html', 'htm', 'svg', 'xml', 'json', 'eml', 'msg'],
  media: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv', 'webm', 'heic']
};
function extClass(ext) { for (const [k, v] of Object.entries(EXT_CLASS)) if (v.includes(ext)) return k; return 'otro'; }

function isMostlyText(u8) {
  const n = Math.min(u8.length, 8192); if (!n) return true;
  if (u8[0] === 0xFF && u8[1] === 0xFE) return true; if (u8[0] === 0xFE && u8[1] === 0xFF) return true;
  let bad = 0; for (let i = 0; i < n; i++) { const c = u8[i]; if (c === 0) return false; if (c < 9 || (c > 13 && c < 32)) bad++; }
  return bad / n < 0.02;
}
function decodeText(u8) {
  const lim = u8.subarray(0, Math.min(u8.length, TEXT_MAX));
  try {
    if (lim[0] === 0xFF && lim[1] === 0xFE) return new TextDecoder('utf-16le').decode(lim.subarray(2));
    if (lim[0] === 0xFE && lim[1] === 0xFF) return new TextDecoder('utf-16be').decode(lim.subarray(2));
    return new TextDecoder('utf-8', { fatal: false }).decode(lim);
  } catch (e) { return latin1(lim); }
}

function detectType(u8, ext, name) {
  const t = (id, label, family, mime) => ({ id, label, family, mime: mime || '' });
  if (u8.length >= 64 && u8[0] === 0x4D && u8[1] === 0x5A) {
    const pe = rd32(u8, 0x3C);
    if (pe > 0 && pe < u8.length - 4 && startsWith(u8, [0x50, 0x45, 0, 0], pe)) {
      const ch = rd16(u8, pe + 22);
      return (ch & 0x2000) ? t('pe-dll', 'Biblioteca Windows (PE DLL)', 'exec', 'application/x-msdownload') : t('pe-exe', 'Ejecutable Windows (PE)', 'exec', 'application/x-msdownload');
    }
    return t('mz', 'Ejecutable MS-DOS (MZ)', 'exec');
  }
  if (startsWith(u8, [0x7F, 0x45, 0x4C, 0x46])) return t('elf', 'Ejecutable Linux/Unix (ELF)', 'exec', 'application/x-elf');
  const m32 = rd32(u8, 0);
  if ([0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE].includes(m32)) return t('macho', 'Ejecutable macOS (Mach-O)', 'exec');
  if (startsWith(u8, [0xCA, 0xFE, 0xBA, 0xBE])) {
    const n = (u8[4] << 24 | u8[5] << 16 | u8[6] << 8 | u8[7]) >>> 0;
    return n > 0 && n < 30 ? t('macho', 'Ejecutable macOS universal (Mach-O fat)', 'exec') : t('class', 'Clase Java compilada', 'exec');
  }
  if (startsWith(u8, [0x64, 0x65, 0x78, 0x0A])) return t('dex', 'Bytecode Android (DEX)', 'exec');
  if (startsWith(u8, [0x00, 0x61, 0x73, 0x6D])) return t('wasm', 'WebAssembly', 'exec');
  const head = latin1(u8, 0, Math.min(u8.length, 1024));
  if (head.indexOf('%PDF-') >= 0) return t('pdf', 'Documento PDF', 'document', 'application/pdf');
  if (startsWith(u8, [0x50, 0x4B, 0x03, 0x04]) || startsWith(u8, [0x50, 0x4B, 0x05, 0x06])) return t('zip', 'Archivo ZIP', 'container', 'application/zip');
  if (startsWith(u8, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return t('ole', 'Documento OLE2 (Office 97-2003 / MSI / MSG)', 'office_macro');
  if (head.startsWith('{\\rt')) return t('rtf', 'Documento RTF', 'office_macro', 'application/rtf');
  if (startsWith(u8, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return t('lnk', 'Acceso directo de Windows (LNK)', 'script');
  if (startsWith(u8, [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D])) return t('one', 'Bloc de notas OneNote (.one)', 'container');
  if (startsWith(u8, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])) return t('rar', 'Archivo RAR', 'container');
  if (startsWith(u8, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return t('7z', 'Archivo 7-Zip', 'container');
  if (startsWith(u8, [0x1F, 0x8B])) return t('gz', 'Archivo GZIP', 'container');
  if (startsWith(u8, [0x4D, 0x53, 0x43, 0x46])) return t('cab', 'Archivo CAB', 'container');
  if (startsWith(u8, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) return t('xz', 'Archivo XZ', 'container');
  if (startsWith(u8, [0x42, 0x5A, 0x68])) return t('bz2', 'Archivo BZIP2', 'container');
  if ([0x8001, 0x8801, 0x9001].some(o => startsWith(u8, [0x43, 0x44, 0x30, 0x30, 0x31], o))) return t('iso', 'Imagen de disco ISO 9660', 'container');
  if (startsWith(u8, [0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65])) return t('vhdx', 'Disco virtual VHDX', 'container');
  if (u8.length > 512 && latin1(u8, u8.length - 512, u8.length - 504) === 'conectix') return t('vhd', 'Disco virtual VHD', 'container');
  if (startsWith(u8, [0x89, 0x50, 0x4E, 0x47])) return t('png', 'Imagen PNG', 'media', 'image/png');
  if (startsWith(u8, [0xFF, 0xD8, 0xFF])) return t('jpg', 'Imagen JPEG', 'media', 'image/jpeg');
  if (head.startsWith('GIF87a') || head.startsWith('GIF89a')) return t('gif', 'Imagen GIF', 'media', 'image/gif');
  if (head.startsWith('RIFF') && head.substr(8, 4) === 'WEBP') return t('webp', 'Imagen WEBP', 'media');
  if (head.startsWith('ITSF')) return t('chm', 'Ayuda HTML compilada (CHM)', 'script');
  if (isMostlyText(u8)) {
    const s = head.replace(/^\uFEFF/, '').trimStart().slice(0, 600).toLowerCase();
    const byExt = {
      ps1: ['ps1', 'Script PowerShell'], psm1: ['ps1', 'Módulo PowerShell'], bat: ['bat', 'Script por lotes (BAT)'], cmd: ['bat', 'Script por lotes (CMD)'],
      vbs: ['vbs', 'Script VBScript'], vbe: ['vbs', 'VBScript codificado'], js: ['js', 'Script JavaScript'], jse: ['js', 'JScript codificado'], mjs: ['js', 'Módulo JavaScript'],
      wsf: ['wsf', 'Windows Script File'], hta: ['hta', 'Aplicación HTML (HTA)'], sh: ['sh', 'Script de shell'], py: ['py', 'Script Python'],
      php: ['php', 'Script PHP'], pl: ['pl', 'Script Perl'], rb: ['rb', 'Script Ruby'], reg: ['reg', 'Archivo de registro de Windows'],
      url: ['url', 'Acceso directo a Internet (.url)'], scf: ['scf', 'Archivo de comando del Explorador (SCF)'], inf: ['inf', 'Archivo de instalación (INF)'],
      svg: ['svg', 'Imagen SVG'], html: ['html', 'Documento HTML'], htm: ['html', 'Documento HTML'], xml: ['xml', 'Documento XML'], json: ['json', 'JSON'],
      eml: ['eml', 'Correo electrónico (EML)'], csv: ['csv', 'CSV'], txt: ['txt', 'Texto plano'], md: ['txt', 'Markdown'], iqy: ['iqy', 'Consulta web de Excel (IQY)'],
      slk: ['slk', 'Hoja SYLK'], lock: ['txt', 'Archivo de bloqueo'], mod: ['txt', 'Manifiesto'], toml: ['txt', 'TOML'], yml: ['txt', 'YAML'], yaml: ['txt', 'YAML']
    };
    const fam = { ps1: 'script', bat: 'script', vbs: 'script', js: 'script', wsf: 'script', hta: 'script', sh: 'script', py: 'script', php: 'script', pl: 'script', rb: 'script', reg: 'script', url: 'script', scf: 'script', inf: 'script', iqy: 'script', slk: 'office_macro', svg: 'document', html: 'document', xml: 'document', json: 'document', eml: 'document', csv: 'document', txt: 'document' };
    if (s.startsWith('#!')) { const sh = /python/.test(s.slice(0, 80)) ? ['py', 'Script Python'] : /node/.test(s.slice(0, 80)) ? ['js', 'Script JavaScript (Node)'] : ['sh', 'Script de shell']; return t(sh[0], sh[1], 'script', 'text/plain'); }
    if (/^<\?xml[^>]*>\s*(<!--[\s\S]*?-->\s*)*<svg|^<svg/.test(s)) return t('svg', 'Imagen SVG', 'document', 'image/svg+xml');
    if (/^<!doctype html|^<html|<head|<body|<script/.test(s)) return t(ext === 'hta' ? 'hta' : 'html', ext === 'hta' ? 'Aplicación HTML (HTA)' : 'Documento HTML', ext === 'hta' ? 'script' : 'document', 'text/html');
    if (/^(return-path|received|from|delivered-to|mime-version|x-[a-z-]+|message-id):/m.test(s)) return t('eml', 'Correo electrónico (EML)', 'document', 'message/rfc822');
    if (byExt[ext]) return t(byExt[ext][0], byExt[ext][1], fam[byExt[ext][0]] || 'document', 'text/plain');
    if (/^\s*[{[]/.test(s)) return t('json', 'JSON', 'document', 'application/json');
    return t('txt', 'Texto plano', 'document', 'text/plain');
  }
  return t('bin', 'Binario sin firma reconocida', 'otro');
}
// ¿El tipo real coincide con la extensión declarada?
const TYPE_EXTS = {
  'pe-exe': ['exe', 'scr', 'com', 'pif', 'cpl', 'sys', 'efi', 'mui'], 'pe-dll': ['dll', 'ocx', 'cpl', 'sys', 'drv', 'xll', 'wll', 'ax', 'mui', 'node', 'pyd'], mz: ['exe', 'com'],
  elf: ['elf', 'so', 'bin', 'o', 'ko', ''], macho: ['dylib', 'bundle', 'app', ''], class: ['class'], dex: ['dex'], wasm: ['wasm'], pdf: ['pdf', 'ai'],
  zip: ['zip', 'docx', 'docm', 'dotx', 'dotm', 'xlsx', 'xlsm', 'xltx', 'xltm', 'xlam', 'xlsb', 'pptx', 'pptm', 'ppsx', 'ppsm', 'potx', 'jar', 'apk', 'aab', 'odt', 'ods', 'odp', 'epub', 'vsix', 'nupkg', 'whl', 'xpi', 'crx', 'msix', 'appx', 'ipa', 'kmz', '3mf', 'vsdx'],
  ole: ['doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pps', 'pot', 'msi', 'msp', 'msg', 'pub', 'vsd', 'mpp', 'db'], rtf: ['rtf', 'doc'], lnk: ['lnk'], one: ['one'],
  rar: ['rar'], '7z': ['7z'], gz: ['gz', 'tgz'], cab: ['cab'], xz: ['xz', 'txz'], bz2: ['bz2', 'tbz2'], iso: ['iso', 'img', 'udf'], vhdx: ['vhdx'], vhd: ['vhd'],
  png: ['png'], jpg: ['jpg', 'jpeg', 'jpe', 'jfif'], gif: ['gif'], webp: ['webp'], chm: ['chm']
};

/* ============================================================ cadenas e IOCs */
function extractStrings(u8, min = 6) {
  const out = []; const lim = Math.min(u8.length, SCAN_MAX); let cur = '';
  for (let i = 0; i < lim; i++) {
    const c = u8[i];
    if (c >= 0x20 && c < 0x7F || c === 9) { cur += String.fromCharCode(c); if (cur.length > 4096) { out.push(cur); cur = ''; } }
    else { if (cur.length >= min) { out.push(cur); if (out.length >= MAX_STRINGS) break; } cur = ''; }
  }
  if (cur.length >= min) out.push(cur);
  // UTF-16LE (cadenas "anchas" de Windows)
  const wide = []; cur = '';
  for (let i = 0; i + 1 < lim; i += 2) {
    const c = u8[i], z = u8[i + 1];
    if (z === 0 && (c >= 0x20 && c < 0x7F || c === 9)) cur += String.fromCharCode(c);
    else { if (cur.length >= min) { wide.push(cur); if (wide.length >= MAX_STRINGS / 2) break; } cur = ''; }
  }
  if (cur.length >= min) wide.push(cur);
  // segunda pasada desplazada un byte para las cadenas anchas que empiezan en posición impar
  cur = '';
  for (let i = 1; i + 1 < lim && wide.length < MAX_STRINGS / 2; i += 2) {
    const c = u8[i], z = u8[i + 1];
    if (z === 0 && (c >= 0x20 && c < 0x7F || c === 9)) cur += String.fromCharCode(c);
    else { if (cur.length >= min) wide.push(cur); cur = ''; }
  }
  return { ascii: out, wide: uniq(wide) };
}

const IOC_TLDS = 'com|net|org|io|ru|cn|xyz|top|info|biz|co|me|tk|ml|ga|cf|gq|pw|cc|su|onion|online|site|club|shop|live|app|dev|link|click|in|uk|de|fr|br|mx|es|it|nl|pl|ua|kr|jp|tv|ws|us|eu|gov|edu|mil|ly|to|sh|gg|lol|zip|mov|icu|buzz|rest|cyou|sbs|bond|vip|pro|cloud|host|space|website|tech|store|fun|ir|kp|vn|tr|id|ar|cl|pe|ve|ec|uy|bo|py|za|ng|ke|ch|at|be|se|no|fi|dk|cz|ro|hu|gr|pt|ca|au|nz|sg|hk|tw|th|my|ph';
const RE_URL = /\b(?:https?|ftp|wss?):\/\/[^\s"'<>`{}|\\^\[\]\x00-\x1f]{4,400}/gi;
const RE_IP = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])/g;
const RE_DOM = new RegExp('\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:' + IOC_TLDS + ')\\b', 'gi');
const RE_MAIL = /\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,200}\.[a-z]{2,24}\b/gi;
const RE_REG = /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)\\[^\s"'<>\x00]{3,220}/gi;
const RE_PATH = /(?:\b[a-zA-Z]:\\|%(?:APPDATA|TEMP|TMP|LOCALAPPDATA|PROGRAMDATA|USERPROFILE|PUBLIC|WINDIR|SYSTEMROOT|ALLUSERSPROFILE|COMSPEC)%\\)[^\s"'<>|*?\x00]{2,220}/gi;
const RE_CVE = /\bCVE-(?:19|20)\d{2}-\d{4,7}\b/gi;
const RE_BTC = /\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const RE_XMR = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;
// Dominios de infraestructura legítima que aparecen en casi todos los binarios y documentos (ruido)
const BENIGN_DOM = /(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|msft\.net|live\.com|office\.com|w3\.org|openxmlformats\.org|purl\.org|adobe\.com|apple\.com|mozilla\.org|apache\.org|verisign\.com|digicert\.com|symantec\.com|symauth\.com|thawte\.com|globalsign\.com|globalsign\.net|sectigo\.com|usertrust\.com|comodoca\.com|comodo\.net|entrust\.net|godaddy\.com|letsencrypt\.org|lencr\.org|xmlsoap\.org|schemas\.xmlsoap\.org|ns\.adobe\.com|iptc\.org|oasis-open\.org|python\.org|gnu\.org|sourceforge\.net|github\.com|npmjs\.org|nodejs\.org|google\.com|gstatic\.com|googleapis\.com|jquery\.com|cloudflare\.com|w3schools\.com|example\.com|example\.org|schema\.org|ietf\.org|unicode\.org|java\.com|oracle\.com|sun\.com|openssl\.org|zlib\.net|qt\.io|intel\.com|amd\.com|nvidia\.com)$/i;
const FILE_EXT_TLD = /\.(dll|exe|sys|ocx|js|vbs|ps1|bat|cmd|txt|log|dat|ini|xml|json|png|jpg|gif|bmp|ico|htm|html|php|asp|aspx|jsp|so|pdb|lib|obj|cpp|h|cs|py|rb|pl|sh|md|zip|rar|7z|cab|msi|tmp|bin|cfg|conf|config|manifest|mui|res|resx|rc)$/i;

function extractIOCs(text) {
  const cap = (a, n = 300) => uniq(a).slice(0, n);
  const urls = cap((text.match(RE_URL) || []).map(u => u.replace(/[).,;:'"\]]+$/, '')));
  const benignUrl = u => { try { return BENIGN_DOM.test(new URL(u).hostname); } catch (e) { return false; } };
  const ips = cap((text.match(RE_IP) || []).filter(ip => {
    const p = ip.split('.').map(Number);
    if (p[0] === 0 || p[0] === 255 || p[0] >= 224) return false;
    if (p.every(x => x < 10)) return false;               // 1.0.0.1, 6.0.0.0 … casi siempre versiones
    if (ip === '127.0.0.1') return false;
    if (/^(1\.3\.6\.1|2\.5\.\d+\.\d+|1\.2\.840)/.test(ip)) return false; // OIDs de certificados
    return true;
  }));
  const doms = cap((text.match(RE_DOM) || []).map(d => d.toLowerCase().replace(/^www\./, '')).filter(d => !FILE_EXT_TLD.test(d) && !/^\d+\.\d+$/.test(d) && d.split('.').every(l => l.length > 0)));
  const emails = cap((text.match(RE_MAIL) || []).map(e => e.toLowerCase()).filter(e => !/\.(png|jpg|gif|dll|exe)$/.test(e)));
  const reg = cap(text.match(RE_REG) || [], 150);
  const paths = cap((text.match(RE_PATH) || []).map(p => p.replace(/[)\],;]+$/, '')), 150);
  const cves = cap((text.match(RE_CVE) || []).map(c => c.toUpperCase()), 100);
  let crypto = [];
  if (/bitcoin|btc|wallet|monero|xmr|ransom|pay/i.test(text)) crypto = cap([...(text.match(RE_BTC) || []).filter(a => a.startsWith('bc1') || /[a-z]/.test(a) && /[A-Z]/.test(a) && /\d/.test(a)), ...(text.match(RE_XMR) || [])], 30);
  const onion = doms.filter(d => d.endsWith('.onion'));
  return {
    urls: urls.filter(u => !benignUrl(u)), urlsBenign: urls.filter(benignUrl).length,
    domains: doms.filter(d => !BENIGN_DOM.test(d)), domainsBenign: doms.filter(d => BENIGN_DOM.test(d)).length,
    ips, ipsPrivate: ips.filter(ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ip)),
    emails, registry: reg, paths, cves, crypto, onion
  };
}

/* ============================================================ reglas de comportamiento (texto) → MITRE ATT&CK
   Cada regla: [id, regex, severidad, título, detalle, técnicas ATT&CK, CVEs asociados, ámbito]
   ámbito: 'any' (cualquier archivo), 'script' (texto de scripts/documentos/macros), 'bin' (cadenas de binarios)  */
const RULES = [
  // Ejecución por intérpretes
  ['ps-enc', /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s-(?:e|en|enc|enco|encodedcommand|ec)\s+[A-Za-z0-9+/=]{24,}/i, 'high', 'PowerShell con comando codificado en Base64', 'Técnica típica de descargadores para ocultar el comando real a la vista y a filtros simples.', ['T1059.001', 'T1027', 'T1140'], [], 'any'],
  ['ps-iex', /\b(?:IEX|Invoke-Expression)\b\s*[(\$'"]/i, 'high', 'PowerShell ejecuta código dinámico (Invoke-Expression / IEX)', 'Evalúa en memoria texto construido o descargado en tiempo de ejecución (cradle de ejecución sin archivo).', ['T1059.001'], [], 'any'],
  ['ps-hidden', /(?:-w(?:indowstyle)?\s+h(?:id(?:den)?)?\b|-nop(?:rofile)?\b[^\n]{0,60}-(?:ep|exec(?:utionpolicy)?)\s+bypass|-(?:ep|executionpolicy)\s+bypass)/i, 'med', 'PowerShell con ventana oculta y/o política de ejecución omitida', 'Parámetros usados para ejecutar sin que el usuario lo note y saltarse la política de ejecución.', ['T1564.003', 'T1059.001'], [], 'any'],
  ['dl-cradle', /(?:Net\.WebClient|DownloadString\s*\(|DownloadFile\s*\(|DownloadData\s*\(|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|\biwr\s+-?u|\birm\s+https?|Net\.Http\.HttpClient|XMLHTTP|WinHttp\.WinHttpRequest|MSXML2\.ServerXMLHTTP|URLDownloadToFile)/i, 'high', 'Descarga de contenido remoto (downloader)', 'El código descarga archivos o código desde Internet: patrón típico de la primera etapa de una infección.', ['T1105', 'T1071.001'], [], 'any'],
  ['amsi', /(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|AmsiOpenSession)/i, 'crit', 'Intento de evadir AMSI (antimalware de Windows)', 'Referencias para desactivar la inspección de scripts de AMSI; casi exclusivo de código malicioso.', ['T1562.001'], [], 'script'],
  ['defender', /(?:Set-MpPreference\b[^\n]{0,80}-Disable|Add-MpPreference\b[^\n]{0,40}-Exclusion|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|Windows Defender\\Exclusions)/i, 'crit', 'Desactiva o crea exclusiones en Microsoft Defender', 'Manipula la protección antimalware para que la carga útil no sea detectada.', ['T1562.001'], [], 'any'],
  ['wsh', /(?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject|WScript\.CreateObject|CreateObject\s*\(\s*["'](?:WScript|Shell|Scripting|MSXML2|ADODB))/i, 'med', 'Automatización COM de Windows Script Host (WScript/Shell/ADODB)', 'Permite ejecutar comandos, escribir archivos y descargar desde scripts VBS/JS o macros.', ['T1059.005', 'T1059.007'], [], 'script'],
  ['activex', /new\s+ActiveXObject\s*\(/i, 'med', 'Objeto ActiveX creado desde JavaScript', 'JScript con ActiveX puede ejecutar comandos y escribir archivos fuera del navegador (HTA/WSH).', ['T1059.007'], [], 'script'],
  ['js-eval', /(?:\beval\s*\(\s*(?:unescape|atob|String\.fromCharCode|decodeURIComponent|function|\w+\s*\()|new\s+Function\s*\(|document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent))/i, 'high', 'Ejecución de código ofuscado (eval / new Function / document.write)', 'El script decodifica y ejecuta código en tiempo de ejecución, técnica común de ofuscación.', ['T1027', 'T1140', 'T1059.007'], [], 'script'],
  ['charcode', /(?:String\.fromCharCode\s*\((?:\s*\d+\s*,){10}|(?:Chr[WB]?\s*\(\s*\d+\s*\)\s*[&+]\s*){8}|(?:\[char\]\s*\d+\s*\+?\s*){8})/i, 'med', 'Cadenas construidas carácter a carácter (Chr/fromCharCode)', 'Ofuscación para evitar que palabras clave (URLs, comandos) aparezcan en claro.', ['T1027', 'T1140'], [], 'script'],
  ['b64', /(?:FromBase64String|\batob\s*\(|base64_decode\s*\(|b64decode\s*\(|-decode\s|Convert\]::FromBase64|\bbase64\s+(?:-d|--decode))/i, 'med', 'Decodificación Base64 en tiempo de ejecución', 'Suele usarse para desempaquetar cargas útiles o comandos ocultos.', ['T1140'], [], 'any'],
  ['cmd', /\bcmd(?:\.exe)?\s+\/[ckr]\s/i, 'med', 'Ejecuta comandos mediante cmd.exe /c', 'Lanza el intérprete de comandos de Windows desde otro proceso o script.', ['T1059.003'], [], 'any'],
  ['certutil', /certutil(?:\.exe)?\s+[^\n]{0,80}-(?:urlcache|decode|decodehex|split|verifyctl)/i, 'high', 'Uso de certutil para descargar o decodificar (LOLBin)', 'Binario legítimo de Windows abusado para descargar o decodificar cargas útiles.', ['T1105', 'T1140'], [], 'any'],
  ['bitsadmin', /bitsadmin(?:\.exe)?\s+[^\n]{0,40}\/(?:transfer|addfile|SetNotifyCmdLine)/i, 'high', 'Uso de BITSAdmin para transferir archivos (LOLBin)', 'Descarga persistente y sigilosa mediante el servicio BITS.', ['T1197', 'T1105'], [], 'any'],
  ['mshta', /mshta(?:\.exe)?\s+[^\n]{0,20}(?:https?:|vbscript:|javascript:|about:)/i, 'high', 'Ejecución de HTA remoto o en línea con mshta', 'mshta ejecuta código HTML/VBScript/JScript con permisos completos del usuario.', ['T1218.005'], [], 'any'],
  ['regsvr32', /regsvr32(?:\.exe)?\s+[^\n]{0,60}(?:\/i:\s*https?|scrobj\.dll)/i, 'high', 'Regsvr32 con scriptlet remoto ("Squiblydoo")', 'Carga y ejecuta un scriptlet COM desde Internet saltándose AppLocker.', ['T1218.010'], [], 'any'],
  ['rundll32', /rundll32(?:\.exe)?\s+[^\n]{0,120}(?:,\s*#?\w+|javascript:|url\.dll|shell32\.dll,\s*ShellExec_RunDLL)/i, 'med', 'Ejecución proxy con rundll32', 'Rundll32 invoca funciones de DLL; abusado para ejecutar cargas maliciosas con un binario firmado.', ['T1218.011'], [], 'any'],
  ['msiexec', /msiexec(?:\.exe)?\s+[^\n]{0,40}\/(?:i|q|package)\b[^\n]{0,60}https?:/i, 'high', 'Instalación silenciosa de MSI remoto con msiexec', 'Descarga e instala un paquete desde Internet sin intervención del usuario.', ['T1218.007', 'T1105'], [], 'any'],
  ['wmi', /(?:wmic(?:\.exe)?\s+[^\n]{0,60}process\s+call\s+create|Win32_Process\b[^\n]{0,40}Create|Invoke-WmiMethod|Invoke-CimMethod)/i, 'med', 'Creación de procesos vía WMI', 'WMI permite ejecutar procesos de forma indirecta, dificultando la trazabilidad.', ['T1047'], [], 'any'],
  // Persistencia
  ['schtasks', /(?:schtasks(?:\.exe)?\s+\/create|Register-ScheduledTask|New-ScheduledTaskAction)/i, 'high', 'Crea tareas programadas (persistencia)', 'Programa la ejecución recurrente o al inicio de sesión de un binario o script.', ['T1053.005'], [], 'any'],
  ['runkey', /\\(?:CurrentVersion|Windows NT\\CurrentVersion)\\(?:Run|RunOnce|RunServices|Winlogon|Policies\\Explorer\\Run)\b/i, 'high', 'Acceso a claves de inicio automático del registro (Run/RunOnce/Winlogon)', 'Ubicación clásica de persistencia: el programa se ejecuta en cada inicio de sesión.', ['T1547.001', 'T1112'], [], 'any'],
  ['startup', /(?:\\Start Menu\\Programs\\Startup|shell:startup|\\Startup\\[^\n\\]{1,60}\.(?:lnk|exe|vbs|bat|js))/i, 'high', 'Escritura en la carpeta de Inicio', 'Deja un acceso directo o script en Inicio para ejecutarse en cada sesión.', ['T1547.001'], [], 'any'],
  ['service', /(?:\bsc(?:\.exe)?\s+create\s|New-Service\b|CreateServiceW?\b)/i, 'med', 'Crea un servicio de Windows', 'Los servicios se ejecutan con privilegios elevados y sobreviven a reinicios.', ['T1543.003'], [], 'any'],
  ['reg-mod', /(?:\breg(?:\.exe)?\s+add\s|New-ItemProperty\b[^\n]{0,80}HK|Set-ItemProperty\b[^\n]{0,80}HK|RegWrite\s*\()/i, 'med', 'Modifica el registro de Windows', 'Escritura en el registro, usada para persistencia o para desactivar controles.', ['T1112'], [], 'any'],
  ['uac', /(?:fodhelper|computerdefaults|eventvwr\.exe|sdclt\.exe|ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command|ConsentPromptBehaviorAdmin|EnableLUA)/i, 'high', 'Técnica de evasión del Control de cuentas de usuario (UAC)', 'Referencias típicas de bypass de UAC para obtener privilegios elevados sin aviso.', ['T1548.002'], [], 'any'],
  // Evasión / anti-análisis
  ['antivm', /(?:vboxservice|vboxtray|VBoxGuest|vmtoolsd|vmwaretray|VMware Tools|SbieDll|sbiedll\.dll|qemu-ga|wine_get_unix_file_name|Xen HVM|prl_tools|\bcuckoo\b|joeboxcontrol|\bsandboxie\b|Win32_ComputerSystem[^\n]{0,60}Model)/i, 'med', 'Detección de máquinas virtuales o sandbox', 'El código comprueba si corre en un entorno de análisis para cambiar su comportamiento.', ['T1497'], [], 'any'],
  ['antidbg', /(?:\bollydbg\b|x64dbg|x32dbg|\bidaq(?:64)?\b|ImmunityDebugger|\bprocmon\b|\bprocexp\b|wireshark|fiddler|\bpestudio\b|ProcessHacker|dnSpy)/i, 'med', 'Busca herramientas de análisis (depuradores, monitores de procesos o red)', 'Enumera herramientas de analistas para detenerse o cambiar su comportamiento.', ['T1622', 'T1497'], [], 'any'],
  ['sleep', /(?:Start-Sleep\s+-s(?:econds)?\s+\d{3,}|WScript\.Sleep\s*\(?\s*\d{5,}|timeout\s+\/t\s+\d{3,}|ping\s+-n\s+\d{2,}\s+127\.0\.0\.1)/i, 'low', 'Retardo deliberado de la ejecución', 'Esperas largas para agotar el tiempo de las sandbox automáticas.', ['T1497.003'], [], 'script'],
  ['evtlog', /(?:wevtutil(?:\.exe)?\s+cl\b|Clear-EventLog|Remove-EventLog|wevtutil\s+sl\s+[^\n]{0,40}\/e:false)/i, 'high', 'Borra registros de eventos de Windows', 'Elimina evidencias forenses tras la intrusión.', ['T1070.001'], [], 'any'],
  ['histclr', /(?:history\s+-c\b|unset\s+HISTFILE|HISTFILESIZE=0|Remove-Item\s+[^\n]{0,40}ConsoleHost_history)/i, 'med', 'Borra el historial de comandos', 'Oculta la actividad del atacante en la consola.', ['T1070.003'], [], 'any'],
  ['reflect', /(?:\[Reflection\.Assembly\]::Load|Reflection\.Assembly\]::LoadFile|Assembly\.Load\s*\(\s*(?:\$|\w+Bytes|Convert)|System\.Reflection\.Assembly)/i, 'high', 'Carga reflexiva de ensamblados .NET en memoria', 'Ejecuta un binario .NET directamente en memoria sin escribirlo a disco.', ['T1620'], [], 'script'],
  ['shellcode-ps', /(?:VirtualAlloc|RtlMoveMemory|CreateThread|VirtualProtect)[^\n]{0,400}(?:DllImport|Add-Type|GetDelegateForFunctionPointer|Marshal\]::Copy)|(?:DllImport|GetDelegateForFunctionPointer)[^\n]{0,400}(?:VirtualAlloc|RtlMoveMemory|CreateThread)/i, 'crit', 'Cargador de shellcode desde script (API nativas)', 'Reserva memoria ejecutable y lanza código binario desde PowerShell/C#: comportamiento propio de loaders maliciosos.', ['T1055', 'T1106', 'T1620'], [], 'script'],
  ['dllimport', /(?:Add-Type\b[^\n]{0,200}DllImport|\[DllImport\s*\(\s*["'](?:kernel32|ntdll|user32|advapi32))/i, 'med', 'Llamadas a API nativas de Windows desde script', 'Acceso directo a funciones del sistema desde PowerShell/C#.', ['T1106'], [], 'script'],
  // Credenciales
  ['mimikatz', /(?:mimikatz|sekurlsa::|lsadump::|kerberos::golden|Invoke-Mimikatz|privilege::debug|gentilkiwi)/i, 'crit', 'Referencias a Mimikatz (robo de credenciales)', 'Herramienta de volcado de credenciales de Windows; indicador fuerte de actividad ofensiva.', ['T1003.001'], [], 'any'],
  ['lsass', /(?:procdump(?:64)?(?:\.exe)?\s+[^\n]{0,40}lsass|comsvcs(?:\.dll)?[^\n]{0,40}MiniDump|MiniDumpWriteDump|lsass\.(?:exe|dmp))/i, 'high', 'Volcado de memoria de LSASS', 'Extrae hashes y credenciales en memoria del proceso de autenticación de Windows.', ['T1003.001'], [], 'any'],
  ['browsercreds', /(?:\\Google\\Chrome\\User Data|\\Microsoft\\Edge\\User Data|\\BraveSoftware\\|Mozilla\\Firefox\\Profiles|\\Opera Software\\|Login Data\b|Web Data\b|logins\.json|key4\.db|CryptUnprotectData|encrypted_key)/i, 'high', 'Acceso a credenciales y cookies del navegador', 'Rutas y funciones usadas por infostealers para robar contraseñas y sesiones guardadas.', ['T1555.003'], [], 'any'],
  ['wallets', /(?:wallet\.dat|\\Electrum\\wallets|\\Exodus\\exodus\.wallet|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|\\Coinomi\\|\\atomic\\Local Storage|Ethereum\\keystore)/i, 'high', 'Búsqueda de monederos de criptomonedas', 'Patrón de infostealers que roban carteras y extensiones de cripto.', ['T1005', 'T1555'], [], 'any'],
  ['keylog', /(?:WH_KEYBOARD_LL|\[Keylogger\]|\bkeylogger\b|\bkeylogs?\.txt|GetAsyncKeyState[^\n]{0,200}(?:DllImport|Add-Type)|(?:DllImport|Add-Type)[^\n]{0,300}GetAsyncKeyState)/i, 'high', 'Captura de pulsaciones de teclado (keylogger)', 'Registra lo que teclea el usuario, incluidas contraseñas.', ['T1056.001'], [], 'any'],
  ['screen', /(?:CopyFromScreen|screenshot\.(?:png|jpg|bmp)|System\.Drawing\.Bitmap[^\n]{0,80}Screen)/i, 'med', 'Captura de pantalla', 'Toma imágenes del escritorio del usuario (espionaje).', ['T1113'], [], 'any'],
  ['clip', /(?:Get-Clipboard|Clipboard\]::GetText|Clipboard\.GetText|Windows\.Forms\.Clipboard)/i, 'low', 'Lectura del portapapeles', 'Puede usarse para robar datos copiados o sustituir direcciones de cripto (clipper).', ['T1115'], [], 'any'],
  // Descubrimiento
  ['disc-user', /(?:\bwhoami(?:\.exe)?\b|\bnet(?:1)?\s+(?:user|group|localgroup)\b|Get-LocalUser|query\s+user)/i, 'low', 'Enumeración de usuarios y grupos', 'Reconocimiento del equipo comprometido.', ['T1033', 'T1087'], [], 'script'],
  ['disc-sys', /(?:\bsysteminfo(?:\.exe)?\b|\bipconfig\s+\/all|\bnltest\b|Get-ComputerInfo|\bhostname(?:\.exe)?\b[^\n]{0,20}(?:&|\|))/i, 'low', 'Reconocimiento del sistema y la red', 'Obtiene información del sistema, dominio y configuración de red.', ['T1082', 'T1016'], [], 'script'],
  ['disc-av', /(?:SecurityCenter2|AntiVirusProduct|Get-MpComputerStatus|\bavp\.exe|MsMpEng|\bekrn\.exe|\bbdagent)/i, 'med', 'Detección del antivirus instalado', 'Identifica el software de seguridad para adaptarse o desactivarlo.', ['T1518.001'], [], 'any'],
  // C2 / exfiltración
  ['tg-discord', /(?:api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services)/i, 'high', 'Exfiltración por bots/webhooks (Telegram, Discord, Slack)', 'Canal muy usado por infostealers para enviar los datos robados.', ['T1567', 'T1102'], [], 'any'],
  ['paste', /(?:pastebin\.com\/raw|paste\.ee\/r|hastebin\.com\/raw|rentry\.co|transfer\.sh|temp\.sh|anonfiles|gofile\.io|file\.io\b|0x0\.st|catbox\.moe|filebin\.net|raw\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|bitbucket\.org\/[^\s/]+\/[^\s/]+\/downloads)/i, 'med', 'Descarga desde servicios de pegado o alojamiento de archivos', 'Servicios públicos usados para hospedar etapas siguientes o configuración de C2.', ['T1102', 'T1105'], [], 'any'],
  ['dyndns', /(?:\.ngrok(?:-free)?\.(?:io|app)|trycloudflare\.com|\.duckdns\.org|\.no-ip\.(?:org|biz|com)|\.ddns\.net|\.hopto\.org|\.zapto\.org|serveo\.net|\.portmap\.io|\.loca\.lt|\.serveousercontent\.com)/i, 'med', 'Infraestructura de DNS dinámico o túneles (ngrok, DuckDNS, No-IP…)', 'Usados para C2 porque permiten cambiar de servidor sin cambiar el nombre.', ['T1568', 'T1071.001'], [], 'any'],
  ['onion', /\b[a-z2-7]{56}\.onion\b|\btor2web\b|\.onion\.(?:ws|to|ly|pet)\b/i, 'high', 'Dirección de la red Tor (.onion)', 'Frecuente en notas de rescate y en C2 anónimo.', ['T1090.003'], [], 'any'],
  ['rat', /(?:AnyDesk|TeamViewer|ScreenConnect|ConnectWise Control|AteraAgent|NetSupport|Client32\.ini|RustDesk|SimpleHelp|Splashtop|LogMeIn|Remcos|njRAT|AsyncRAT|QuasarRAT|DarkComet|NanoCore)/i, 'med', 'Referencias a herramientas de acceso remoto (legítimas o RAT)', 'El acceso remoto no autorizado es un vector frecuente; los nombres de RAT conocidos son un indicador fuerte.', ['T1219'], [], 'any'],
  // Impacto
  ['vss', /(?:vssadmin(?:\.exe)?\s+[^\n]{0,20}delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|bcdedit(?:\.exe)?\s+[^\n]{0,60}recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)|Win32_ShadowCopy[^\n]{0,40}Delete)/i, 'crit', 'Elimina copias de seguridad / instantáneas (preparación de ransomware)', 'Impide la recuperación del sistema; paso casi universal antes de cifrar.', ['T1490'], [], 'any'],
  ['ransom', /(?:your (?:files|documents|network)[^\n]{0,40}(?:have been|are|were) (?:encrypted|locked)|all your files|decrypt(?:ion|or)?\s+(?:tool|key|software|price)|to (?:recover|restore) your files|README[_-]?(?:TO|FOR)?[_-]?DECRYPT|HOW[_-]TO[_-](?:DECRYPT|RECOVER)|\bransom(?:ware)?\b)/i, 'crit', 'Texto de nota de rescate', 'Mensajes característicos de ransomware que exigen pago para descifrar.', ['T1486'], [], 'any'],
  ['miner', /(?:stratum\+(?:tcp|ssl):\/\/|\bxmrig\b|cryptonight|minexmr|nanopool\.org|supportxmr|--donate-level)/i, 'high', 'Minería de criptomonedas', 'Uso no autorizado de los recursos del equipo para minar.', ['T1496'], [], 'any'],
  // Linux / Unix
  ['curl-sh', /(?:curl|wget)\s+[^\n|;]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i, 'high', 'Descarga y ejecución directa (curl|wget … | sh)', 'Ejecuta en el acto un script descargado, sin verificación.', ['T1105', 'T1059.004'], [], 'any'],
  ['revshell', /(?:\/dev\/tcp\/\d{1,3}\.|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+\/bin\/(?:ba)?sh|bash\s+-i\s+>&|socat\s+[^\n]{0,80}exec:|python\d?\s+-c\s+['"][^\n]{0,80}socket[^\n]{0,200}(?:dup2|pty\.spawn)|mkfifo\s+\/tmp\/)/i, 'crit', 'Reverse shell (shell inversa)', 'Abre una consola remota hacia el atacante.', ['T1059.004', 'T1071'], [], 'any'],
  ['cron', /(?:crontab\s+-|\/etc\/cron\.|\/var\/spool\/cron|@reboot\s)/i, 'med', 'Persistencia mediante cron', 'Programa la ejecución periódica o al arranque en Linux.', ['T1053.003'], [], 'any'],
  ['sshkeys', /\.ssh\/authorized_keys/i, 'med', 'Modifica llaves SSH autorizadas', 'Añadir una llave propia garantiza acceso persistente al servidor.', ['T1098.004'], [], 'any'],
  ['shadow', /\/etc\/shadow\b|\/etc\/passwd\b[^\n]{0,40}(?:>>|echo|cat)/i, 'med', 'Acceso a /etc/shadow o /etc/passwd', 'Lectura o modificación de las cuentas y hashes del sistema.', ['T1003.008'], [], 'any'],
  ['ldpreload', /(?:\/etc\/ld\.so\.preload|LD_PRELOAD=)/i, 'high', 'Secuestro del enlazador dinámico (LD_PRELOAD)', 'Técnica de rootkits de usuario para interceptar funciones.', ['T1574.006'], [], 'any'],
  ['systemd', /(?:\/etc\/systemd\/system\/[^\n]{1,60}\.service|systemctl\s+enable\s)/i, 'low', 'Crea o habilita un servicio systemd', 'Persistencia en Linux mediante servicios.', ['T1543.002'], [], 'script'],
  ['chmodx', /chmod\s+(?:\+x|[0-7]*7[0-7]{2})\s+\/(?:tmp|dev\/shm|var\/tmp)\//i, 'med', 'Hace ejecutable un archivo en /tmp o /dev/shm', 'Patrón típico de droppers en servidores Linux comprometidos.', ['T1222.002', 'T1105'], [], 'any'],
  ['shellrc', /(?:>>\s*~?\/?(?:root|home\/\w+)?\/?\.bashrc|>>\s*\/etc\/profile|\.bash_profile)/i, 'low', 'Modifica archivos de inicio de la shell', 'Persistencia al abrir una sesión de terminal.', ['T1546.004'], [], 'script'],
  // Documentos: macros y explotación
  ['vba-auto', /\b(?:Auto_?Open|AutoExec|AutoClose|Document_Open|Document_Close|DocumentOpen|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|Auto_Close|Presentation_Open)\b/i, 'high', 'Macro con ejecución automática al abrir el documento', 'El código VBA se ejecuta en cuanto el usuario habilita el contenido.', ['T1204.002', 'T1059.005'], [], 'script'],
  ['vba-shell', /(?:\bShell\s*\(|\.Run\s*\(|\.Exec\s*\(|\bShellExecute|CreateProcessA?\b|\bMacScript\b|\bExecuteExcel4Macro\b|\bCallByName\b)/i, 'high', 'La macro/script ejecuta comandos o programas', 'Capacidad de lanzar procesos externos desde el documento.', ['T1059.005', 'T1106'], [], 'script'],
  ['vba-write', /(?:\bOpen\s+[^\n]{1,80}\s+For\s+(?:Binary|Output)|ADODB\.Stream|\.SaveToFile\b|\.savetofile|Kill\s+\w+|\bEnviron\s*\(\s*["'](?:TEMP|APPDATA|USERPROFILE))/i, 'med', 'Escribe archivos en disco desde la macro/script', 'Deja una carga útil en carpetas temporales o de usuario.', ['T1105', 'T1059.005'], [], 'script'],
  ['vba-lib', /\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+\w+\s+Lib\s+["'](?:kernel32|ntdll|user32|urlmon|shell32)/i, 'high', 'La macro declara funciones de DLL del sistema', 'Acceso directo a la API de Windows desde VBA (descarga, inyección, ejecución).', ['T1106', 'T1059.005'], [], 'script'],
  ['xlm', /(?:=EXEC\s*\(|=CALL\s*\(|=REGISTER\s*\(|=FORMULA\s*\(|Excel 4\.0 Macro|\bAuto_Open\b[^\n]{0,20}=)/i, 'high', 'Macros de Excel 4.0 (XLM)', 'Macros heredadas muy abusadas porque escapan a muchas defensas.', ['T1059', 'T1204.002'], [], 'any'],
  ['dde', /(?:\bDDEAUTO\b|\{\s*DDE\s|\bDDE\s+["']?c:\\|=cmd\|)/i, 'high', 'Campo DDE que ejecuta comandos', 'Intercambio dinámico de datos usado para ejecutar código sin macros.', ['T1559.002'], [], 'any'],
  ['follina', /(?:ms-msdt:|PCWDiagnostic|IT_RebrowseForFile|IT_BrowseForFile=)/i, 'crit', 'Explotación de MSDT "Follina"', 'Patrón de CVE-2022-30190: ejecución remota de código al abrir o previsualizar el documento.', ['T1203', 'T1221'], ['CVE-2022-30190'], 'any'],
  ['mhtml', /\bmhtml:https?:\/\/[^\n]{0,200}!x-usc:/i, 'crit', 'Referencia MHTML remota en documento', 'Patrón asociado a CVE-2021-40444 (MSHTML): descarga y ejecuta un control ActiveX malicioso.', ['T1203', 'T1221'], ['CVE-2021-40444'], 'any'],
  ['search-ms', /\b(?:search-ms|search|ms-search):[^\s"']{0,40}(?:query=|crumb=location:)/i, 'med', 'URI search-ms (muestra archivos remotos como locales)', 'Truco de phishing para que la víctima abra ejecutables alojados en un servidor WebDAV.', ['T1204.002'], [], 'any'],
  ['unc', /(?:\\\\\d{1,3}(?:\.\d{1,3}){3}(?:@\d+)?\\|file:\/{2,3}\\?\\?\d{1,3}(?:\.\d{1,3}){3}|\\\\[a-z0-9.-]+@SSL\\)/i, 'med', 'Ruta UNC a un servidor remoto', 'Al abrirse puede filtrar el hash NTLM del usuario (autenticación forzada) o cargar recursos remotos.', ['T1187'], [], 'any'],
  ['equation', /(?:Equation\.3|4571756174696f6e2e33|EQNEDT32)/i, 'crit', 'Objeto del Editor de ecuaciones (EQNEDT32)', 'Componente explotado por CVE-2017-11882 y CVE-2018-0802, aún muy usado en campañas.', ['T1203'], ['CVE-2017-11882', 'CVE-2018-0802'], 'any'],
  ['ole-link', /(?:OLE2Link|\\objautlink|\\objupdate|htafile|\{3050F4D8-98B5-11CF-BB82-00AA00BDCE0B\})/i, 'high', 'Objeto OLE enlazado con actualización automática', 'Patrón de CVE-2017-0199: descarga y ejecuta un HTA remoto al abrir el documento.', ['T1203', 'T1221'], ['CVE-2017-0199'], 'any'],
  // PDF (JavaScript de Acrobat con primitivas de exploits históricos)
  ['pdf-exploit', /(?:util\.printf\s*\(|Collab\.(?:collectEmailInfo|getIcon)|media\.newPlayer|\.getAnnots\s*\(|spell\.customDictionaryOpen|app\.setTimeOut\s*\(|this\.exportDataObject\s*\()/i, 'high', 'Funciones de JavaScript de Acrobat usadas en exploits', 'Primitivas asociadas a exploits clásicos de Adobe Reader o a la extracción de adjuntos.', ['T1203', 'T1059.007'], [], 'script'],
  // HTML / phishing
  ['smuggling', /(?:msSaveOrOpenBlob|navigator\.msSaveBlob|new\s+Blob\s*\(\s*\[[^\]]{0,200}\][^)]{0,120}\)[\s\S]{0,600}\.download\s*=|\.download\s*=\s*['"][^'"]{1,120}\.(?:zip|iso|img|exe|js|hta|lnk|vhd|msi|one)['"])/i, 'high', 'HTML smuggling: el documento genera un archivo para descargar', 'El HTML reconstruye una carga útil en el navegador para eludir filtros de correo y proxy.', ['T1027.006', 'T1204.002'], [], 'script'],
  ['cred-form', /<input[^>]{0,200}type\s*=\s*["']?password/i, 'med', 'Formulario que solicita contraseñas', 'Si el archivo llega por correo o no pertenece a un sitio legítimo, es una página de phishing.', ['T1566.001', 'T1056.003'], [], 'script'],
  ['meta-refresh', /<meta[^>]{0,80}http-equiv\s*=\s*["']?refresh[^>]{0,80}url\s*=\s*https?:/i, 'low', 'Redirección automática a un sitio externo', 'Usada en adjuntos HTML de phishing para llevar a la víctima a la página falsa.', ['T1204.001'], [], 'script'],
  ['svg-script', /<svg\b(?:(?!<\/svg>)[\s\S]){0,20000}?<script\b|<svg\b[^>]{0,400}\bon(?:load|error|click|mouseover|begin)\s*=/i, 'high', 'SVG con código ejecutable (script o eventos)', 'Las imágenes SVG pueden llevar JavaScript: vector creciente de phishing y smuggling.', ['T1027.006', 'T1059.007'], [], 'script'],
  ['post-exfil', /(?:\.(?:send|post)\s*\([^)]{0,80}(?:password|passwd|pass|pwd|login|email)|fetch\s*\([^)]{0,200}(?:method\s*:\s*["']POST)[\s\S]{0,300}(?:password|pass|email))/i, 'high', 'Envía credenciales capturadas a un servidor', 'Código que remite usuario/contraseña a un tercero (kit de phishing).', ['T1056.003', 'T1041'], [], 'script'],
  // Ejecución proxy con binarios firmados de Windows (LOLBins)
  ['msbuild', /\bMSBuild(?:\.exe)?\b[^\n]{0,120}\.(?:xml|csproj|proj|targets)\b/i, 'high', 'Ejecución de código mediante MSBuild', 'MSBuild compila y ejecuta código incrustado en un proyecto XML, eludiendo controles de aplicaciones.', ['T1127.001'], [], 'any'],
  ['installutil', /\bInstallUtil(?:\.exe)?\b[^\n]{0,80}(?:\/logfile=|\/u\b|\.dll|\.exe)/i, 'high', 'Ejecución proxy con InstallUtil', 'InstallUtil ejecuta código de ensamblados .NET con un binario firmado de Microsoft.', ['T1218.004'], [], 'any'],
  ['cmstp', /\bcmstp(?:\.exe)?\b[^\n]{0,60}\/(?:s|au|ns)\b[^\n]{0,80}\.inf/i, 'high', 'Ejecución proxy con CMSTP', 'CMSTP instala un perfil .inf que puede ejecutar código y evadir UAC.', ['T1218.003'], [], 'any'],
  ['regasm', /\b(?:regasm|regsvcs)(?:\.exe)?\b[^\n]{0,80}\.dll/i, 'high', 'Ejecución proxy con Regasm/Regsvcs', 'Registran ensamblados .NET ejecutando su código con binarios firmados.', ['T1218.009'], [], 'any'],
  ['odbcconf', /\bodbcconf(?:\.exe)?\b[^\n]{0,60}(?:\/a|-a)\s*\{?\s*regsvr/i, 'high', 'Ejecución proxy con Odbcconf', 'Odbcconf carga una DLL arbitraria con un binario firmado.', ['T1218.008'], [], 'any'],
  ['indirect', /(?:\bforfiles(?:\.exe)?\b[^\n]{0,80}\/c\s|\bpcalua(?:\.exe)?\b[^\n]{0,20}-a\s|\bconhost(?:\.exe)?\s+(?:--headless\s+)?(?:cmd|powershell))/i, 'med', 'Ejecución indirecta de comandos (forfiles, pcalua, conhost)', 'Lanza comandos a través de utilidades del sistema para evitar las reglas que vigilan cmd.exe.', ['T1202'], [], 'any'],
  // Persistencia avanzada
  ['wmi-persist', /(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)/i, 'high', 'Persistencia mediante suscripción de eventos WMI', 'Ejecuta código automáticamente ante eventos del sistema; persistencia sigilosa sin archivos en carpetas de inicio.', ['T1546.003'], [], 'any'],
  ['accessibility', /(?:\\Image File Execution Options\\[^\n]{0,40}(?:sethc|utilman|osk|magnify|narrator|displayswitch)\.exe|\bcopy\b[^\n]{0,60}cmd\.exe[^\n]{0,60}(?:sethc|utilman)\.exe)/i, 'crit', 'Puerta trasera en funciones de accesibilidad (sethc/utilman)', 'Sustituye o depura herramientas de accesibilidad para obtener una consola SYSTEM desde la pantalla de inicio de sesión.', ['T1546.008', 'T1546.012'], [], 'any'],
  ['ifeo', /\\Image File Execution Options\\[^\n]{0,80}\\(?:Debugger|GlobalFlag)/i, 'high', 'Inyección mediante Image File Execution Options', 'Define un "depurador" que se ejecuta cada vez que se abre un programa concreto.', ['T1546.012'], [], 'any'],
  ['comhijack', /\\Software\\Classes\\CLSID\\\{?[0-9A-F-]{36}\}?\\(?:InprocServer32|LocalServer32)/i, 'med', 'Posible secuestro de objetos COM', 'Registra un servidor COM en el perfil del usuario para que otros programas carguen la carga útil.', ['T1546.015'], [], 'any'],
  ['office-startup', /(?:\\Microsoft\\(?:Word|Excel)\\STARTUP|\\XLSTART\\|\\Office\\[\d.]+\\(?:Word|Excel|PowerPoint)\\Options[^\n]{0,40}OPEN|Office test\\Special\\Perf)/i, 'med', 'Persistencia en el arranque de Office', 'Coloca plantillas o complementos que Office carga automáticamente al iniciar.', ['T1137'], [], 'any'],
  // Credenciales
  ['sam-dump', /\breg(?:\.exe)?\s+save\s+(?:hklm|HKEY_LOCAL_MACHINE)\\(?:sam|system|security)\b/i, 'crit', 'Copia de las colmenas SAM/SYSTEM/SECURITY del registro', 'Permite extraer los hashes de las contraseñas locales sin conexión.', ['T1003.002'], [], 'any'],
  ['ntds', /(?:\bntdsutil(?:\.exe)?\b[^\n]{0,60}(?:ifm|snapshot)|\\ntds\.dit\b)/i, 'crit', 'Acceso a la base de datos de Active Directory (NTDS.dit)', 'Contiene los hashes de todas las cuentas del dominio.', ['T1003.003'], [], 'any'],
  ['kerberoast', /(?:Invoke-Kerberoast|\bRubeus(?:\.exe)?\b[^\n]{0,30}(?:kerberoast|asreproast)|\bGetUserSPNs(?:\.py)?\b)/i, 'high', 'Kerberoasting / AS-REP roasting', 'Solicita tickets Kerberos de cuentas de servicio para descifrar sus contraseñas fuera de línea.', ['T1558.003'], [], 'any'],
  // Evasión, cuentas e impacto
  ['firewall-off', /(?:netsh(?:\.exe)?\s+(?:advfirewall\s+set\s+[^\n]{0,30}state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable)|Set-NetFirewallProfile\b[^\n]{0,60}-Enabled\s+(?:False|0))/i, 'high', 'Desactiva el firewall de Windows', 'Elimina la protección de red del equipo para facilitar conexiones del atacante.', ['T1562.004'], [], 'any'],
  ['add-admin', /(?:\bnet(?:1)?\s+user\s+\S+\s+\S+\s+\/add\b|\bnet(?:1)?\s+localgroup\s+(?:administrators|administradores)\s+\S+\s+\/add\b|New-LocalUser\b[^\n]{0,200}Add-LocalGroupMember[^\n]{0,60}Administra)/i, 'high', 'Crea una cuenta local o la añade a Administradores', 'Cuenta de respaldo del atacante para mantener el acceso.', ['T1136.001', 'T1098'], [], 'any'],
  ['rdp-enable', /fDenyTSConnections[^\n]{0,40}(?:\/d\s+0|-Value\s+0|=\s*0|\b0\b)/i, 'med', 'Habilita el Escritorio remoto (RDP)', 'Abre el equipo a conexiones remotas, frecuente antes del movimiento lateral.', ['T1021.001'], [], 'any'],
  ['staging', /(?:Compress-Archive\b[^\n]{0,120}-DestinationPath|\b(?:7z|7za|rar|winrar)(?:\.exe)?\s+a\s+(?:-p\S*\s+)?[^\n]{0,80}\.(?:7z|rar|zip))/i, 'low', 'Compresión de datos para su extracción', 'Agrupar archivos en un comprimido (a veces con contraseña) suele preceder a la exfiltración.', ['T1560.001'], [], 'script'],
  ['wsh-hidden', /\.Run\s*\(\s*[^,\n]{1,300},\s*0\s*(?:,|\))/i, 'med', 'Ejecuta un proceso con la ventana oculta (WScript .Run …, 0)', 'Lanza comandos sin que el usuario vea ninguna ventana.', ['T1564.003', 'T1059.005'], [], 'script'],
  ['script-encoded', /#@~\^[A-Za-z0-9+/=]{6}==/, 'high', 'Script codificado con Windows Script Encoder (VBE/JSE)', 'Formato ofuscado usado para ocultar el código de VBScript o JScript.', ['T1027', 'T1059.005'], [], 'any'],
  ['js-obfuscator', /\b(?:var|const|let|function)\s+_0x[0-9a-f]{4,6}\s*(?:=\s*(?:\[|function)|\()/i, 'med', 'JavaScript procesado con un ofuscador (identificadores _0x…)', 'Patrón del ofuscador javascript-obfuscator, muy usado en kits de phishing y descargadores.', ['T1027'], [], 'script'],
  ['reflective-loader', /\b(?:ReflectiveLoader|_ReflectiveLoader@4|ReflectiveDllInjection)\b/, 'high', 'Cargador reflexivo de DLL', 'Técnica de frameworks de post-explotación para cargar DLL en memoria sin pasar por el cargador de Windows.', ['T1620', 'T1055'], [], 'any'],
  // Enmascaramiento
  ['rtlo', /\u202E/, 'high', 'Carácter de inversión derecha-izquierda (RLO) en el contenido', 'Se usa para disfrazar extensiones de archivo (p.ej. "factura\u202Efdp.exe" se ve como "factura exe.pdf").', ['T1036.002'], [], 'any']
];

// API importadas por ejecutables PE → comportamiento / técnica ATT&CK
const API_RULES = [
  [/^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|NtQueueApcThread|SetThreadContext|NtUnmapViewOfSection|ZwUnmapViewOfSection|NtMapViewOfSection)$/i, 'combo', 'Inyección en otros procesos', ['T1055']],
  [/^(SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices)$/i, 'info', 'Captura de teclado', ['T1056.001']],
  [/^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString[AW]?|NtSetInformationThread)$/i, 'info', 'Anti-depuración', ['T1622']],
  [/^(URLDownloadToFile[AW]?|URLDownloadToCacheFile[AW]?)$/i, 'low', 'Descarga directa a archivo (URLDownloadToFile)', ['T1105']],
  [/^(InternetOpenUrl[AW]?|InternetReadFile|HttpSendRequest[AW]?|HttpOpenRequest[AW]?|WinHttpOpen|WinHttpSendRequest|InternetConnect[AW]?)$/i, 'info', 'Comunicación HTTP / descarga', ['T1071.001', 'T1105']],
  [/^(RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|RegSetKeyValue[AW]?|NtSetValueKey)$/i, 'info', 'Escritura en el registro', ['T1112']],
  [/^(CreateService[AW]?|StartService[AW]?|OpenSCManager[AW]?|ChangeServiceConfig[AW]?)$/i, 'info', 'Gestión de servicios', ['T1543.003']],
  [/^(CryptEncrypt|CryptGenKey|CryptImportKey|BCryptEncrypt|BCryptGenerateSymmetricKey|CryptAcquireContext[AW]?)$/i, 'info', 'Cifrado de datos', ['T1486']],
  [/^(AdjustTokenPrivileges|OpenProcessToken|LookupPrivilegeValue[AW]?|DuplicateTokenEx|ImpersonateLoggedOnUser|SetThreadToken)$/i, 'info', 'Manipulación de tokens / privilegios', ['T1134']],
  [/^(CreateToolhelp32Snapshot|Process32First[W]?|Process32Next[W]?|EnumProcesses|NtQuerySystemInformation)$/i, 'info', 'Enumeración de procesos', ['T1057']],
  [/^(BitBlt|GetDC|CreateCompatibleBitmap|GetDesktopWindow|PrintWindow)$/i, 'info', 'Captura de pantalla', ['T1113']],
  [/^(OpenClipboard|GetClipboardData|SetClipboardData)$/i, 'info', 'Portapapeles', ['T1115']],
  [/^(MiniDumpWriteDump)$/i, 'med', 'Volcado de memoria de procesos', ['T1003.001']],
  [/^(CryptUnprotectData)$/i, 'low', 'Descifrado DPAPI (credenciales guardadas)', ['T1555.003', 'T1555']],
  [/^(WinExec|ShellExecute(Ex)?[AW]?|CreateProcess(AsUser|WithLogon|WithToken)?[AW]?)$/i, 'info', 'Ejecución de procesos', ['T1106']],
  [/^(GetProcAddress|LdrGetProcedureAddress|LoadLibrary(Ex)?[AW]?|LdrLoadDll)$/i, 'info', 'Resolución dinámica de API', ['T1027.007', 'T1129']],
  [/^(FindFirstFile(Ex)?[AW]?|FindNextFile[AW]?)$/i, 'info', 'Recorrido de archivos y carpetas', ['T1083']],
  [/^(GetComputerName(Ex)?[AW]?|GetUserName[AW]?|GetVersionEx[AW]?|GetSystemInfo|GetNativeSystemInfo|GetVolumeInformation[AW]?)$/i, 'info', 'Información del sistema', ['T1082', 'T1033']],
  [/^(WSAStartup|connect|send|recv|socket|gethostbyname|getaddrinfo|WSASocket[AW]?|InternetOpen[AW]?)$/i, 'info', 'Red (sockets)', ['T1071']],
  [/^(VirtualProtect(Ex)?|VirtualAlloc|NtProtectVirtualMemory|NtAllocateVirtualMemory)$/i, 'info', 'Memoria ejecutable', ['T1055']],
  [/^(DeleteFile[AW]?|MoveFileEx[AW]?)$/i, 'info', 'Borrado / movimiento de archivos', ['T1070.004']],
  [/^(Sleep|SleepEx|GetTickCount(64)?|NtDelayExecution|QueryPerformanceCounter)$/i, 'info', 'Temporización', ['T1497.003']],
  [/^(SHGetFolderPath[AW]?|SHGetKnownFolderPath|GetTempPath[AW]?)$/i, 'info', 'Rutas de usuario/temporales', ['T1083']]
];
const PACKER_SECTIONS = [[/^UPX\d?$|^\.UPX/i, 'UPX'], [/^\.aspack$|^\.adata$/i, 'ASPack'], [/^\.MPRESS\d$/i, 'MPRESS'], [/^\.themida$|^\.winlice/i, 'Themida/WinLicense'], [/^\.vmp\d$/i, 'VMProtect'], [/^\.petite$/i, 'Petite'], [/^\.nsp\d$/i, 'NsPack'], [/^\.enigma\d$/i, 'Enigma Protector'], [/^\.pec\d?$|^PEC2/i, 'PECompact'], [/^\.yP$|^\.y0da$/i, 'Yoda Crypter'], [/^\.MaskPE$/i, 'MaskPE'], [/^\.packed$/i, 'Empaquetador genérico'], [/^\.boom$/i, 'The Boomerang'], [/^\.ccg$/i, 'CCG Packer'], [/^\.perplex$/i, 'Perplex'], [/^\.svkp$/i, 'SVKP'], [/^\.taz$/i, 'PESpin'], [/^\.gentee$/i, 'Gentee']];
const MACHINES = { 0x14c: 'x86 (32 bits)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x1c4: 'ARM Thumb-2', 0x200: 'Itanium' };
const SUBSYS = { 1: 'Nativo', 2: 'GUI de Windows', 3: 'Consola de Windows', 7: 'POSIX', 9: 'Windows CE', 10: 'Aplicación EFI', 11: 'Controlador EFI de arranque', 12: 'Controlador EFI de ejecución', 14: 'Xbox', 16: 'Aplicación de arranque' };

/* ============================================================ PE (Windows) */
function parsePE(u8, findings) {
  const pe = rd32(u8, 0x3C); const coff = pe + 4;
  const machine = rd16(u8, coff), nsec = rd16(u8, coff + 2), ts = rd32(u8, coff + 4), optSize = rd16(u8, coff + 16), chars = rd16(u8, coff + 18);
  const opt = coff + 20; const magic = rd16(u8, opt); const is64 = magic === 0x20b;
  const ep = rd32(u8, opt + 16);
  const imageBase = is64 ? rd64(u8, opt + 24) : rd32(u8, opt + 28);
  const checksum = rd32(u8, opt + 64);
  const subsystem = rd16(u8, opt + 68), dllch = rd16(u8, opt + 70);
  const nDirs = rd32(u8, opt + (is64 ? 108 : 92)); const dd = opt + (is64 ? 112 : 96);
  const dir = i => i < Math.min(nDirs, 16) ? { rva: rd32(u8, dd + i * 8), size: rd32(u8, dd + i * 8 + 4) } : { rva: 0, size: 0 };
  const secs = [];
  const sh = opt + optSize;
  for (let i = 0; i < Math.min(nsec, 96); i++) {
    const o = sh + i * 40; if (o + 40 > u8.length) break;
    const name = latin1(u8, o, o + 8).replace(/\0+$/, '').replace(/[^\x20-\x7e]/g, '?');
    const vsize = rd32(u8, o + 8), va = rd32(u8, o + 12), rsize = rd32(u8, o + 16), rptr = rd32(u8, o + 20), ch = rd32(u8, o + 36);
    const a = Math.min(rptr, u8.length), b = Math.min(rptr + rsize, u8.length);
    secs.push({ name, va, vsize, rsize, rptr, ch, entropy: b > a ? entropy(u8, a, b) : 0, exec: !!(ch & 0x20000000), write: !!(ch & 0x80000000), read: !!(ch & 0x40000000) });
  }
  const rva2off = rva => { for (const s of secs) { const span = Math.max(s.vsize, s.rsize); if (rva >= s.va && rva < s.va + span) return rva - s.va + s.rptr; } return rva < (secs[0] ? secs[0].rptr : 0x400) ? rva : -1; };
  // Importaciones
  const imports = []; let impCount = 0; let impTrunc = false;
  const idir = dir(1);
  if (idir.rva) {
    let d = rva2off(idir.rva);
    for (let n = 0; d > 0 && n < 256 && d + 20 <= u8.length; n++, d += 20) {
      const oft = rd32(u8, d), nameRva = rd32(u8, d + 12), ft = rd32(u8, d + 16);
      if (!oft && !nameRva && !ft) break;
      const dll = cstr(u8, rva2off(nameRva), 128);
      if (!dll) continue;
      const funcs = []; let t = rva2off(oft || ft); const step = is64 ? 8 : 4;
      for (let k = 0; t > 0 && k < 2048 && t + step <= u8.length; k++, t += step) {
        const lo = rd32(u8, t), hi = is64 ? rd32(u8, t + 4) : 0;
        if (!lo && !hi) break;
        const ordinal = is64 ? (hi & 0x80000000) : (lo & 0x80000000);
        if (ordinal) funcs.push('ord' + (lo & 0xffff));
        else { const fn = cstr(u8, rva2off(lo & 0x7fffffff) + 2, 256); if (fn) funcs.push(fn); }
      }
      impCount += funcs.length; imports.push({ dll, funcs });
      if (imports.length >= 256) { impTrunc = true; break; }
    }
  }
  // Exportaciones (nombre de la DLL y número de funciones)
  let exportName = '', exportCount = 0; const edir = dir(0);
  if (edir.rva) { const eo = rva2off(edir.rva); if (eo > 0) { exportName = cstr(u8, rva2off(rd32(u8, eo + 12)), 128); exportCount = rd32(u8, eo + 24); } }
  const sec = dir(4), clr = dir(14), tls = dir(9), reloc = dir(5), rsrc = dir(2), dbg = dir(6);
  const lastRaw = secs.reduce((m, s) => Math.max(m, s.rptr + s.rsize), 0);
  let overlay = u8.length > lastRaw ? u8.length - lastRaw : 0;
  if (sec.rva && sec.rva >= lastRaw && sec.rva + sec.size >= u8.length - 8) overlay = Math.max(0, sec.rva - lastRaw);
  // Ruta PDB (información de depuración CodeView)
  let pdb = '';
  if (dbg.rva) { const doff = rva2off(dbg.rva); for (let i = 0; doff > 0 && i < 8 && (i + 1) * 28 <= dbg.size; i++) { const e = doff + i * 28; if (rd32(u8, e + 12) === 2) { const p = rd32(u8, e + 24); if (startsWith(u8, [0x52, 0x53, 0x44, 0x53], p)) pdb = cstr(u8, p + 24, 260); } } }
  const epSec = secs.find(s => ep >= s.va && ep < s.va + Math.max(s.vsize, s.rsize));
  const info = {
    arch: MACHINES[machine] || fmtHexOff(machine), is64, isDll: !!(chars & 0x2000), subsystem: SUBSYS[subsystem] || String(subsystem),
    compiled: ts ? new Date(ts * 1000).toISOString() : null, timestamp: ts, entryPoint: fmtHexOff(ep), entrySection: epSec ? epSec.name : '(fuera de secciones)',
    imageBase: fmtHexOff(imageBase), checksum: fmtHexOff(checksum), sections: secs.map(s => ({ name: s.name, va: fmtHexOff(s.va), vsize: s.vsize, rsize: s.rsize, entropy: s.entropy, flags: (s.read ? 'R' : '-') + (s.write ? 'W' : '-') + (s.exec ? 'X' : '-') })),
    imports: imports.map(i => ({ dll: i.dll, count: i.funcs.length, funcs: i.funcs.slice(0, 400) })), importCount: impCount, importsTruncated: impTrunc,
    exportName, exportCount, signed: !!(sec.rva && sec.size), dotnet: !!clr.rva, tls: !!tls.rva, relocs: !!reloc.rva, resources: !!rsrc.rva,
    aslr: !!(dllch & 0x40), dep: !!(dllch & 0x100), cfg: !!(dllch & 0x4000), highEntropyVA: !!(dllch & 0x20), overlay, pdb
  };
  // --- hallazgos estructurales
  const packers = uniq(secs.map(s => (PACKER_SECTIONS.find(p => p[0].test(s.name)) || [])[1]).filter(Boolean));
  if (packers.length) findings.push({ sev: 'high', cat: 'Estructura del ejecutable', title: 'Empaquetador / protector detectado: ' + packers.join(', '), detail: 'El código real está comprimido o cifrado y solo se revela en memoria; habitual en malware para evadir antivirus (también en algunos programas comerciales).', evidence: 'Secciones: ' + secs.map(s => s.name).join(', '), attack: ['T1027.002'] });
  const hiEnt = secs.filter(s => s.entropy >= 7.2 && s.rsize > 1024);
  if (hiEnt.length && !packers.length) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Secciones con entropía muy alta (≥ 7,2)', detail: 'Contenido comprimido o cifrado dentro del ejecutable: posible empaquetado o carga útil embebida.', evidence: hiEnt.map(s => s.name + ' = ' + s.entropy).join(' · '), attack: ['T1027.002'] });
  const wx = secs.filter(s => s.write && s.exec);
  if (wx.length) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Secciones con escritura y ejecución a la vez (W+X)', detail: 'Permite modificar y ejecutar código en la misma región: típico de desempaquetadores y shellcode.', evidence: wx.map(s => s.name).join(', '), attack: ['T1027.002', 'T1055'] });
  if (epSec && !epSec.exec) findings.push({ sev: 'high', cat: 'Estructura del ejecutable', title: 'El punto de entrada está en una sección no ejecutable (' + epSec.name + ')', detail: 'Anomalía estructural frecuente en binarios manipulados o empaquetados.', attack: ['T1027.002'] });
  else if (epSec && secs.length > 2 && epSec === secs[secs.length - 1] && !info.isDll) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'El punto de entrada está en la última sección (' + epSec.name + ')', detail: 'Patrón habitual de empaquetadores e infectores de archivos.', attack: ['T1027.002'] });
  else if (!epSec && ep) findings.push({ sev: 'high', cat: 'Estructura del ejecutable', title: 'El punto de entrada no pertenece a ninguna sección', detail: 'Cabecera PE manipulada.', attack: ['T1027'] });
  if (secs.some(s => s.rsize === 0 && s.vsize > 65536 && s.exec)) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Sección ejecutable vacía en disco pero grande en memoria', detail: 'Espacio reservado donde se desempaqueta el código en tiempo de ejecución.', attack: ['T1027.002'] });
  if (!info.dotnet && impCount > 0 && impCount < 12 && imports.some(i => i.funcs.some(f => /^(GetProcAddress|LoadLibrary)/i.test(f)))) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Muy pocas importaciones con resolución dinámica de API', detail: 'El programa oculta las funciones que usa y las resuelve en tiempo de ejecución (empaquetado u ofuscación).', evidence: impCount + ' funciones importadas', attack: ['T1027.007'] });
  if (!info.dotnet && idir.rva === 0 && !info.isDll) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Ejecutable sin tabla de importaciones', detail: 'Todas las API se resuelven manualmente: técnica de ofuscación.', attack: ['T1027.007'] });
  const now = Date.now() / 1000;
  if (ts > now + 86400 * 2) findings.push({ sev: 'low', cat: 'Estructura del ejecutable', title: 'Fecha de compilación en el futuro', detail: 'La marca de tiempo fue falsificada (timestomping) o el compilador usa compilaciones reproducibles.', evidence: info.compiled, attack: ['T1070.006'] });
  else if (ts && ts < 946684800 && !info.dotnet) findings.push({ sev: 'info', cat: 'Estructura del ejecutable', title: 'Fecha de compilación anterior al año 2000', detail: 'Marca de tiempo alterada o compilación reproducible (Delphi, Go y otros compiladores usan valores fijos).', evidence: info.compiled });
  if (overlay > 1024) {
    const ovOff = lastRaw; const ovHead = u8.subarray(ovOff, ovOff + 8);
    const ovType = startsWith(ovHead, [0x4D, 0x5A]) ? 'otro ejecutable (MZ)' : startsWith(ovHead, [0x50, 0x4B]) ? 'un ZIP' : startsWith(ovHead, [0x37, 0x7A, 0xBC, 0xAF]) ? 'un 7-Zip' : startsWith(ovHead, [0x52, 0x61, 0x72, 0x21]) ? 'un RAR' : 'datos';
    const ovEnt = entropy(u8, ovOff, Math.min(u8.length, ovOff + 4 * 1024 * 1024));
    findings.push({ sev: ovType.startsWith('otro') ? 'high' : ovEnt > 7.5 ? 'med' : 'low', cat: 'Estructura del ejecutable', title: 'Datos añadidos al final del ejecutable (overlay): ' + (overlay / 1024).toFixed(0) + ' KB de ' + ovType, detail: 'Los instaladores legítimos usan overlays, pero también los droppers para transportar la carga útil.', evidence: 'Desplazamiento ' + fmtHexOff(ovOff) + ' · entropía ' + ovEnt, attack: ['T1027.009'] });
  }
  if (!info.signed) findings.push({ sev: 'low', cat: 'Estructura del ejecutable', title: 'Ejecutable sin firma digital Authenticode', detail: 'No se puede verificar el editor. La mayoría del software comercial está firmado.', attack: [] });
  else findings.push({ sev: 'info', cat: 'Estructura del ejecutable', title: 'Contiene firma Authenticode (' + sec.size + ' bytes)', detail: 'La firma está presente; su validez (cadena de confianza, revocación) debe verificarse con signtool o el servicio de reputación.', attack: [] });
  if (!info.aslr || !info.dep) findings.push({ sev: 'info', cat: 'Estructura del ejecutable', title: 'Mitigaciones de explotación ausentes: ' + [!info.aslr && 'ASLR', !info.dep && 'DEP/NX'].filter(Boolean).join(', '), detail: 'Indica compilador antiguo o binario poco cuidado; facilita la explotación de sus fallos.', attack: [] });
  if (info.tls) findings.push({ sev: 'low', cat: 'Estructura del ejecutable', title: 'Usa callbacks TLS', detail: 'Código que se ejecuta antes del punto de entrada; usado por algunos malware para anti-depuración.', attack: ['T1622'] });
  if (pdb && /(?:\\Users\\[^\\]+\\(?:Desktop|Downloads)|stub|crypter|loader|payload|inject|rat\b|stealer|keylog|ransom|hack)/i.test(pdb)) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Ruta PDB reveladora del entorno del autor', detail: 'La ruta de símbolos de depuración contiene términos asociados a desarrollo de malware.', evidence: pdb, attack: [] });
  // API sospechosas
  const allFuncs = imports.flatMap(i => i.funcs);
  const apiHits = {};
  for (const f of allFuncs) for (const r of API_RULES) if (r[0].test(f)) { const k = r[2]; (apiHits[k] = apiHits[k] || { sev: r[1], attack: r[3], funcs: [] }).funcs.push(f); }
  info.apiBehaviors = Object.entries(apiHits).map(([k, v]) => {
    const funcs = uniq(v.funcs); let sev = v.sev;
    // Inyección: una API aislada es habitual; la cadena reservar→escribir→ejecutar en otro proceso no
    if (sev === 'combo') { const n = funcs.filter(f => /^(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|NtQueueApcThread|SetThreadContext|NtUnmapViewOfSection|ZwUnmapViewOfSection)/i.test(f)).length; sev = n >= 3 ? 'high' : n === 2 ? 'med' : 'info'; }
    return { behavior: k, sev, attack: v.attack, funcs };
  });
  for (const b of info.apiBehaviors) findings.push({ sev: b.sev, cat: 'Capacidades (API importadas)', title: b.behavior, detail: b.sev === 'info' ? 'Capacidad presente en las importaciones; es común en software legítimo y solo es relevante combinada con otros indicadores.' : 'Funciones de Windows que el ejecutable importa y que otorgan esta capacidad.', evidence: b.funcs.slice(0, 20).join(', ') + (b.funcs.length > 20 ? ' …' : ''), attack: b.attack, capability: true });
  // imphash (compatible con pefile para importaciones por nombre)
  const imp = [];
  for (const i of imports) { const lib = i.dll.toLowerCase().replace(/\.(dll|ocx|sys)$/, ''); for (const f of i.funcs) imp.push(lib + '.' + f.toLowerCase()); }
  info.imphash = imp.length ? md5(new TextEncoder().encode(imp.join(','))) : null;
  return info;
}

/* ============================================================ ELF / Mach-O (cabecera) */
function parseELF(u8) {
  const cls = u8[4] === 2 ? 64 : 32, le = u8[5] === 1;
  const r16 = o => le ? rd16(u8, o) : (u8[o] << 8 | u8[o + 1]);
  const types = { 1: 'Objeto reubicable', 2: 'Ejecutable', 3: 'Objeto compartido / PIE', 4: 'Core dump' };
  const mach = { 3: 'x86', 0x3E: 'x86-64', 0x28: 'ARM', 0xB7: 'AArch64', 8: 'MIPS', 0x14: 'PowerPC', 0x15: 'PowerPC64', 0xF3: 'RISC-V', 0x2B: 'SPARC V9', 0x16: 's390' };
  const osabi = { 0: 'System V', 3: 'Linux', 9: 'FreeBSD', 6: 'Solaris' };
  const txt = latin1(u8, 0, Math.min(u8.length, 2 * 1024 * 1024));
  return { bits: cls, endian: le ? 'little-endian' : 'big-endian', type: types[r16(16)] || String(r16(16)), machine: mach[r16(18)] || String(r16(18)), osabi: osabi[u8[7]] || String(u8[7]), stripped: !/\.symtab/.test(txt), upx: /UPX!/.test(txt), golang: /Go build ID|runtime\.gopanic/.test(txt), interp: (txt.match(/\/lib(?:64)?\/ld-[\w.-]+\.so[.\d]*/) || [''])[0] };
}
function parseMachO(u8) {
  const m = rd32(u8, 0); const fat = m === 0xBEBAFECA;
  const cpu = { 7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000C: 'ARM64', 18: 'PowerPC' };
  if (fat) return { fat: true, archs: (u8[4] << 24 | u8[5] << 16 | u8[6] << 8 | u8[7]) >>> 0 };
  const ft = { 1: 'Objeto', 2: 'Ejecutable', 6: 'Biblioteca dinámica (dylib)', 8: 'Bundle', 0xB: 'Kext' };
  const txt = latin1(u8, 0, Math.min(u8.length, 1024 * 1024));
  return { fat: false, bits: (m === 0xFEEDFACF || m === 0xCFFAEDFE) ? 64 : 32, cpu: cpu[rd32(u8, 4)] || fmtHexOff(rd32(u8, 4)), filetype: ft[rd32(u8, 12)] || String(rd32(u8, 12)), signed: /Apple Code Signing|com\.apple\.cs/.test(txt) || txt.indexOf('\xFA\xDE\x0C\xC0') >= 0 };
}

/* ============================================================ Descompresión (DecompressionStream) */
async function inflate(u8, fmt, maxOut) {
  if (typeof DecompressionStream === 'undefined') return null;
  // Los datos reales suelen traer bytes de más al final (EOL antes de endstream, relleno): se conserva
  // lo que se haya descomprimido aunque el flujo termine con error.
  const parts = []; let n = 0;
  try {
    const ds = new DecompressionStream(fmt); const w = ds.writable.getWriter();
    w.write(u8).catch(() => {}); w.close().catch(() => {});
    const r = ds.readable.getReader();
    for (;;) { const { value, done } = await r.read(); if (done) break; parts.push(value); n += value.length; if (n > maxOut) { r.cancel().catch(() => {}); break; } }
  } catch (e) { if (!n) return null; }
  const out = new Uint8Array(Math.min(n, maxOut)); let o = 0;
  for (const p of parts) { if (o >= out.length) break; const k = Math.min(p.length, out.length - o); out.set(p.subarray(0, k), o); o += k; }
  return out;
}

/* ============================================================ VBA (MS-OVBA): extracción de código de macros */
function ovbaDecompress(u8, start) {
  const out = []; let pos = start + 1;
  while (pos + 2 <= u8.length) {
    const hdr = rd16(u8, pos); const size = (hdr & 0x0fff) + 3; const sig = (hdr >> 12) & 7; const compressed = hdr >> 15;
    if (sig !== 3) break;
    const chunkEnd = Math.min(u8.length, pos + size); pos += 2; const decStart = out.length;
    if (!compressed) { for (let i = 0; i < 4096 && pos < u8.length; i++) out.push(u8[pos++]); continue; }
    while (pos < chunkEnd) {
      const fb = u8[pos++];
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (!((fb >> bit) & 1)) out.push(u8[pos++]);
        else {
          if (pos + 1 >= u8.length) return out;
          const tok = rd16(u8, pos); pos += 2;
          const diff = out.length - decStart; let bc = 4; while ((1 << bc) < diff) bc++; if (bc > 12) bc = 12;
          const lenMask = 0xffff >> bc; const len = (tok & lenMask) + 3; const off = (tok >> (16 - bc)) + 1;
          const src = out.length - off; if (src < decStart) return out;
          for (let k = 0; k < len; k++) out.push(out[src + k]);
        }
      }
    }
    if (out.length > 4 * 1024 * 1024) break;
  }
  return out;
}
function extractVBA(u8) {
  // Cada módulo comprimido empieza con 0x01, cabecera de bloque y el literal "Attribut"
  const src = []; const pat = [0x00, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74];
  for (let i = 3; i < u8.length - 9 && src.length < 64; i++) {
    if (u8[i] !== 0x00 || u8[i + 1] !== 0x41 || !startsWith(u8, pat, i)) continue;
    const s = i - 3; if (u8[s] !== 0x01 || ((rd16(u8, s + 1) >> 12) & 7) !== 3) continue;
    const code = String.fromCharCode.apply(null, ovbaDecompress(u8, s).slice(0, 400000).filter(c => c === 9 || c === 10 || c === 13 || c >= 32 && c < 127));
    if (/Attribute VB_/.test(code)) { const name = (code.match(/Attribute VB_Name = "([^"]+)"/) || [])[1] || 'módulo'; src.push({ name, code }); }
  }
  return src;
}

/* ============================================================ ZIP / OOXML / JAR / APK */
async function parseZip(u8, findings, ctx) {
  let eocd = -1;
  for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (rd32(u8, i) === 0x06054b50) { eocd = i; break; }
  const entries = [];
  if (eocd >= 0) {
    let p = rd32(u8, eocd + 16); const total = rd16(u8, eocd + 10);
    for (let n = 0; n < Math.min(total, 5000) && rd32(u8, p) === 0x02014b50; n++) {
      const flags = rd16(u8, p + 8), method = rd16(u8, p + 10), csize = rd32(u8, p + 20), usize = rd32(u8, p + 24);
      const nl = rd16(u8, p + 28), el = rd16(u8, p + 30), cl = rd16(u8, p + 32), lho = rd32(u8, p + 42);
      const name = new TextDecoder(flags & 0x800 ? 'utf-8' : 'latin1').decode(u8.subarray(p + 46, p + 46 + nl));
      entries.push({ name, csize, usize, method, encrypted: !!(flags & 1), lho });
      p += 46 + nl + el + cl;
    }
  } else {
    // Sin directorio central (ZIP truncado): recorrer cabeceras locales
    let p = 0;
    while (p + 30 < u8.length && rd32(u8, p) === 0x04034b50 && entries.length < 5000) {
      const flags = rd16(u8, p + 6), method = rd16(u8, p + 8), csize = rd32(u8, p + 18), usize = rd32(u8, p + 22), nl = rd16(u8, p + 26), el = rd16(u8, p + 28);
      entries.push({ name: latin1(u8, p + 30, p + 30 + nl), csize, usize, method, encrypted: !!(flags & 1), lho: p });
      p += 30 + nl + el + csize;
    }
  }
  const names = entries.map(e => e.name);
  const has = re => names.some(n => re.test(n));
  let kind = 'zip';
  if (has(/^\[Content_Types\]\.xml$/)) kind = has(/^word\//) ? 'docx' : has(/^xl\//) ? 'xlsx' : has(/^ppt\//) ? 'pptx' : has(/^visio\//) ? 'vsdx' : 'ooxml';
  else if (has(/^AndroidManifest\.xml$/) && has(/classes\d*\.dex$/)) kind = 'apk';
  else if (has(/^META-INF\/MANIFEST\.MF$/i)) kind = 'jar';
  else if (has(/^mimetype$/) && has(/^content\.xml$/)) kind = 'odf';
  else if (has(/^Payload\/[^/]+\.app\//)) kind = 'ipa';
  else if (has(/^extension\.vsixmanifest$/)) kind = 'vsix';
  else if (has(/^manifest\.json$/) && has(/\.js$/)) kind = 'ext';
  const kindLabel = { docx: 'Documento Word (OOXML)', xlsx: 'Libro Excel (OOXML)', pptx: 'Presentación PowerPoint (OOXML)', vsdx: 'Diagrama Visio', ooxml: 'Documento Office Open XML', apk: 'Aplicación Android (APK)', jar: 'Archivo Java (JAR)', odf: 'Documento OpenDocument', ipa: 'Aplicación iOS (IPA)', vsix: 'Extensión de Visual Studio (VSIX)', ext: 'Extensión de navegador', zip: 'Archivo ZIP' }[kind];
  const readEntry = async (e, max = 8 * 1024 * 1024) => {
    if (e.encrypted || ctx.inflated > INFLATE_MAX) return null;
    const l = e.lho; if (rd32(u8, l) !== 0x04034b50) return null;
    const start = l + 30 + rd16(u8, l + 26) + rd16(u8, l + 28); const data = u8.subarray(start, start + e.csize);
    let out = null;
    if (e.method === 0) out = data.subarray(0, max); else if (e.method === 8) out = await inflate(data, 'deflate-raw', max);
    if (out) ctx.inflated += out.length; return out;
  };
  const dec = b => b ? new TextDecoder('utf-8').decode(b) : '';
  const extra = []; // texto de partes relevantes para las reglas
  const ENC = entries.filter(e => e.encrypted);
  if (ENC.length) findings.push({ sev: 'med', cat: 'Contenido del contenedor', title: 'Archivo comprimido protegido con contraseña (' + ENC.length + ' entrada/s cifrada/s)', detail: 'El cifrado impide que las pasarelas de correo y el antivirus inspeccionen el contenido; técnica muy habitual en campañas de malware (la contraseña se envía en el propio correo).', evidence: ENC.slice(0, 10).map(e => e.name).join(', '), attack: ['T1027.013'] });
  const RISKY = /\.(exe|scr|com|pif|cpl|dll|msi|js|jse|vbs|vbe|wsf|wsh|hta|ps1|bat|cmd|lnk|jar|iso|img|vhdx?|one|chm|reg|url|scf|library-ms|search-ms|xll|appref-ms|application|msc|inf|sh|py|apk)$/i;
  const risky = entries.filter(e => RISKY.test(e.name) && !/\/$/.test(e.name));
  if (risky.length && kind === 'zip') findings.push({ sev: risky.some(e => /\.(exe|scr|js|jse|vbs|vbe|wsf|hta|ps1|bat|cmd|lnk|iso|img|vhdx?|one|chm|xll|msc)$/i.test(e.name)) ? 'high' : 'med', cat: 'Contenido del contenedor', title: 'Contiene ' + risky.length + ' archivo(s) ejecutable(s) o de script', detail: 'Un comprimido que entrega ejecutables, scripts o accesos directos es el formato más común de adjuntos maliciosos.', evidence: risky.slice(0, 15).map(e => e.name).join(', '), attack: ['T1204.002', 'T1566.001'] });
  const dbl = entries.filter(e => /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv|html?)[\s._-]*\.(exe|scr|js|vbs|hta|bat|cmd|lnk|ps1|com|pif|msi)$/i.test(e.name) || /\s{3,}\.\w{2,4}$/.test(e.name));
  if (dbl.length) findings.push({ sev: 'high', cat: 'Contenido del contenedor', title: 'Entradas con doble extensión o relleno de espacios', detail: 'Nombre diseñado para parecer un documento y ocultar que es ejecutable.', evidence: dbl.slice(0, 10).map(e => e.name).join(', '), attack: ['T1036.007'] });
  // CVE-2023-38831 (WinRAR): un archivo "doc.pdf " y una carpeta "doc.pdf /" con el mismo nombre
  const spaced = entries.filter(e => / $/.test(e.name));
  const cve38831 = spaced.filter(e => entries.some(o => o.name.startsWith(e.name + '/')));
  if (cve38831.length) findings.push({ sev: 'crit', cat: 'Contenido del contenedor', title: 'Estructura de explotación de WinRAR (CVE-2023-38831)', detail: 'Archivo y carpeta con el mismo nombre terminado en espacio: al abrir el "documento" WinRAR ejecuta el script de la carpeta.', evidence: cve38831.slice(0, 5).map(e => JSON.stringify(e.name)).join(', '), attack: ['T1203', 'T1204.002'], cve: ['CVE-2023-38831'] });
  const trav = entries.filter(e => /(^|[\\/])\.\.([\\/]|$)|^[\\/]|^[a-z]:/i.test(e.name));
  if (trav.length) findings.push({ sev: 'high', cat: 'Contenido del contenedor', title: 'Rutas con salto de directorio (Zip Slip)', detail: 'Al descomprimir se podrían sobrescribir archivos fuera de la carpeta de destino.', evidence: trav.slice(0, 5).map(e => e.name).join(', '), attack: ['T1105'] });
  const ratio = entries.reduce((a, e) => a + e.usize, 0) / Math.max(1, entries.reduce((a, e) => a + e.csize, 0));
  if (ratio > 200 && entries.reduce((a, e) => a + e.usize, 0) > 500 * 1024 * 1024) findings.push({ sev: 'med', cat: 'Contenido del contenedor', title: 'Posible bomba de descompresión (ratio ' + Math.round(ratio) + ':1)', detail: 'Al descomprimir ocupa una cantidad desproporcionada de espacio; puede tumbar antivirus o sistemas.', attack: ['T1499'] });
  const nested = entries.filter(e => /\.(zip|rar|7z|iso|img|vhdx?|cab|gz|tar)$/i.test(e.name));
  if (nested.length && kind === 'zip') findings.push({ sev: 'low', cat: 'Contenido del contenedor', title: 'Comprimidos anidados (' + nested.length + ')', detail: 'Varias capas de contenedores dificultan la inspección automática.', evidence: nested.slice(0, 10).map(e => e.name).join(', '), attack: ['T1027'] });

  // Office Open XML: macros, relaciones externas, OLE, ActiveX, DDE
  const vba = entries.filter(e => /vbaProject\.bin$/i.test(e.name));
  const macros = [];
  for (const e of vba) { const b = await readEntry(e); if (b) extractVBA(b).forEach(m => macros.push(m)); }
  if (vba.length) findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Documento con macros VBA (' + (macros.length ? macros.length + ' módulo/s extraído/s' : 'proyecto VBA presente') + ')', detail: 'Las macros pueden ejecutar código al habilitar el contenido. Microsoft las bloquea por defecto en archivos de Internet.', evidence: vba.map(e => e.name).join(', '), attack: ['T1204.002', 'T1059.005'] });
  if (/^(docx|xlsx|pptx)$/.test(kind) && vba.length && ctx.ext && !/m$|^xlsb$/.test(ctx.ext)) findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Documento con macros guardado con extensión sin macros (.' + ctx.ext + ')', detail: 'Office no ejecutaría macros en un .' + ctx.ext + '; la extensión engaña al usuario o a los filtros.', attack: ['T1036.008'] });
  const xlm = entries.filter(e => /^xl\/macrosheets\//i.test(e.name));
  if (xlm.length) { findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Hojas de macros de Excel 4.0 (XLM)', detail: 'Macros heredadas que ejecutan comandos y suelen pasar desapercibidas.', evidence: xlm.map(e => e.name).join(', '), attack: ['T1059', 'T1204.002'] }); for (const e of xlm.slice(0, 5)) extra.push(dec(await readEntry(e, 2 * 1024 * 1024))); }
  const rels = entries.filter(e => /\.rels$/i.test(e.name));
  const external = [];
  for (const e of rels.slice(0, 60)) {
    const x = dec(await readEntry(e, 1024 * 1024)); if (!x) continue;
    const re = /<Relationship\b[^>]*>/gi; let m;
    while ((m = re.exec(x))) {
      const tag = m[0]; if (!/TargetMode\s*=\s*["']External/i.test(tag)) continue;
      const target = (tag.match(/Target\s*=\s*["']([^"']+)/i) || [])[1] || ''; const type = ((tag.match(/Type\s*=\s*["']([^"']+)/i) || [])[1] || '').split('/').pop();
      if (/^mailto:/i.test(target) || type === 'hyperlink' && /^https?:\/\/(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}\/?[^\s]*$/i.test(target) && !/\.(?:dotm?|docm|xlsm|hta|exe|rtf|html?)(?:$|[?#])/i.test(target)) { external.push({ part: e.name, type, target, sev: 'info' }); continue; }
      external.push({ part: e.name, type, target, sev: /attachedTemplate|oleObject|frame|subDocument/i.test(type) ? 'high' : 'med' });
    }
    extra.push(x);
  }
  const extHi = external.filter(x => x.sev !== 'info');
  if (extHi.some(x => /attachedTemplate/i.test(x.type))) findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Inyección de plantilla remota', detail: 'El documento descarga una plantilla desde Internet al abrirse; la plantilla suele traer macros o exploits (el archivo original parece limpio).', evidence: extHi.filter(x => /attachedTemplate/i.test(x.type)).map(x => x.target).join(' · '), attack: ['T1221'] });
  if (extHi.some(x => !/attachedTemplate/i.test(x.type))) findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Objetos o marcos cargados desde una ubicación externa', detail: 'Relaciones externas (oleObject/frame) que el documento resuelve al abrirse: vector de exploits como CVE-2017-0199 y CVE-2021-40444.', evidence: extHi.filter(x => !/attachedTemplate/i.test(x.type)).map(x => x.type + ' → ' + x.target).slice(0, 8).join(' · '), attack: ['T1221', 'T1203'] });
  const embeds = entries.filter(e => /\/embeddings\/|oleObject\d*\.bin$/i.test(e.name));
  if (embeds.length) {
    findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Objetos OLE / archivos incrustados (' + embeds.length + ')', detail: 'Documentos o ejecutables empaquetados dentro del documento; la víctima los abre con doble clic.', evidence: embeds.slice(0, 10).map(e => e.name).join(', '), attack: ['T1027.009'] });
    for (const e of embeds.slice(0, 10)) { const b = await readEntry(e, 4 * 1024 * 1024); if (b) { extra.push(latin1(b, 0, Math.min(b.length, 1024 * 1024))); const s = extractStrings(b, 5); extra.push(s.ascii.join('\n'), s.wide.join('\n')); } }
  }
  const ax = entries.filter(e => /\/activeX\//i.test(e.name));
  if (ax.length) findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Controles ActiveX (' + ax.length + ')', detail: 'Controles que pueden ejecutar código al abrir el documento.', evidence: ax.slice(0, 6).map(e => e.name).join(', '), attack: ['T1559', 'T1204.002'] });
  // Hojas "veryHidden" en libros OOXML
  const wb = entries.find(e => /^xl\/workbook\.xml$/i.test(e.name));
  if (wb) { const x = dec(await readEntry(wb, 2 * 1024 * 1024)); const vh = (x.match(/<sheet\b[^>]*state="veryHidden"[^>]*>/gi) || []).map(t => (t.match(/name="([^"]*)"/) || [])[1] || '?');
    if (vh.length) findings.push({ sev: xlm.length ? 'high' : 'med', cat: 'Macros y contenido activo', title: 'Hojas "muy ocultas" en el libro (' + vh.length + ')', detail: 'Solo pueden mostrarse por código; se usan para esconder macros XLM, fórmulas o datos.', evidence: vh.slice(0, 10).join(', '), attack: ['T1564'] }); }
  const docXml = entries.filter(e => /^(word\/(document|settings|header\d*|footer\d*)\.xml|xl\/(workbook|sharedStrings)\.xml|xl\/worksheets\/sheet\d+\.xml|ppt\/slides\/slide\d+\.xml|content\.xml|customXml\/item\d+\.xml)$/i.test(e.name));
  for (const e of docXml.slice(0, 40)) extra.push(dec(await readEntry(e, 4 * 1024 * 1024)));
  // JAR/APK: nombres y manifiesto
  if (kind === 'jar' || kind === 'apk') {
    const man = entries.find(e => /^META-INF\/MANIFEST\.MF$/i.test(e.name)); if (man) extra.push(dec(await readEntry(man, 256 * 1024)));
    const sig = entries.some(e => /^META-INF\/[^/]+\.(RSA|DSA|EC|SF)$/i.test(e.name));
    if (!sig) findings.push({ sev: 'low', cat: 'Contenido del contenedor', title: 'Paquete ' + kind.toUpperCase() + ' sin firma v1 (META-INF)', detail: kind === 'apk' ? 'Puede usar firma v2/v3 (no visible aquí); verifica con apksigner.' : 'El JAR no está firmado.', attack: [] });
    if (kind === 'apk') { const mf = entries.find(e => e.name === 'AndroidManifest.xml'); if (mf) { const b = await readEntry(mf, 2 * 1024 * 1024); if (b) { const s = extractStrings(b, 4); extra.push(s.wide.join('\n')); ctx.apkPerms = uniq(s.wide.concat(s.ascii).filter(x => /^android\.permission\./.test(x))); } } }
  }
  // Scripts sueltos dentro del ZIP: leer su contenido para las reglas
  for (const e of risky.filter(e => /\.(js|jse|vbs|vbe|wsf|hta|ps1|bat|cmd|sh|py|url|scf|reg|inf)$/i.test(e.name)).slice(0, 20)) extra.push(dec(await readEntry(e, 2 * 1024 * 1024)));
  // Ejecutables/LNK dentro del ZIP: cadenas
  for (const e of risky.filter(e => /\.(exe|dll|scr|lnk)$/i.test(e.name)).slice(0, 5)) { const b = await readEntry(e, 16 * 1024 * 1024); if (b) { const s = extractStrings(b, 6); extra.push(s.ascii.slice(0, 4000).join('\n'), s.wide.slice(0, 4000).join('\n')); ctx.inner = ctx.inner || []; if (ctx.inner.length < 5) ctx.inner.push({ name: e.name, size: b.length, sha256: await digest('SHA-256', b) }); } }
  return { kind, kindLabel, entries: entries.slice(0, 500).map(e => ({ name: e.name, size: e.usize, csize: e.csize, encrypted: e.encrypted })), totalEntries: entries.length, macros: macros.map(m => ({ name: m.name, lines: m.code.split(/\r?\n/).length, code: m.code.slice(0, 60000) })), external, text: extra.join('\n') + '\n' + macros.map(m => m.code).join('\n') };
}

/* ============================================================ OLE2 (doc/xls/ppt/msi/msg) */
function parseOLE(u8, findings, ctx) {
  const s = extractStrings(u8, 4);
  const wide = s.wide;
  const streams = uniq(wide.filter(w => /^(WordDocument|Workbook|Book|PowerPoint Document|_VBA_PROJECT|VBA|PROJECT|PROJECTwm|Macros|dir|ThisDocument|ThisWorkbook|Module\d*|ObjectPool|Ole10Native|\u0001Ole10Native|Equation Native|EncryptedPackage|EncryptionInfo|__substg1\.0_[0-9A-F]{8}|_xmlsignatures|SummaryInformation|DocumentSummaryInformation|CompObj|\x01CompObj|Package|Contents|MsiPatchSequence)$/.test(w) || /^.{0,3}(CompObj|Ole|ObjInfo|Ole10Native)$/.test(w)).slice(0, 80));
  const kind = wide.includes('WordDocument') ? 'doc' : wide.some(w => w === 'Workbook' || w === 'Book') ? 'xls' : wide.includes('PowerPoint Document') ? 'ppt' : wide.some(w => /^__substg1\.0_/.test(w)) ? 'msg' : (/msi|Installer|MsiFile/i.test(s.ascii.slice(0, 3000).join(' ')) || ctx.ext === 'msi') ? 'msi' : 'ole';
  const kindLabel = { doc: 'Documento Word 97-2003', xls: 'Libro Excel 97-2003', ppt: 'Presentación PowerPoint 97-2003', msg: 'Mensaje de Outlook (.msg)', msi: 'Paquete de instalación Windows (MSI)', ole: 'Contenedor OLE2' }[kind];
  const hasVBA = wide.some(w => /^(_VBA_PROJECT|VBA|PROJECT)$/.test(w)) || /_VBA_PROJECT/.test(latin1(u8, 0, Math.min(u8.length, 4 * 1024 * 1024)));
  const macros = hasVBA ? extractVBA(u8) : [];
  if (hasVBA) findings.push({ sev: 'high', cat: 'Macros y contenido activo', title: 'Documento con macros VBA (' + (macros.length ? macros.length + ' módulo/s extraído/s' : 'proyecto VBA presente') + ')', detail: 'Las macros pueden ejecutar código al habilitar el contenido.', attack: ['T1204.002', 'T1059.005'] });
  if (wide.some(w => /EncryptedPackage/.test(w))) findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Documento Office cifrado con contraseña', detail: 'El contenido no puede inspeccionarse sin la contraseña; técnica usada para eludir filtros.', attack: ['T1027.013'] });
  if (wide.some(w => /Ole10Native|ObjectPool/.test(w))) findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Objetos OLE incrustados', detail: 'Archivos empaquetados dentro del documento (pueden ser ejecutables o scripts).', attack: ['T1027.009'] });
  // Excel 97-2003: registros BOUNDSHEET8 (0x0085) → hojas de macros XLM y hojas ocultas
  if (kind === 'xls') {
    const sheets = [];
    for (let i = 0; i + 12 < u8.length && sheets.length < 256; i++) {
      if (u8[i] !== 0x85 || u8[i + 1] !== 0x00) continue;
      const len = rd16(u8, i + 2); if (len < 8 || len > 300) continue;
      const hs = u8[i + 8] & 3, dt = u8[i + 9], cch = u8[i + 10], hi = u8[i + 11] & 1;
      if (u8[i + 8] > 2 || ![0, 1, 2, 6].includes(dt) || !cch || cch > 31 || len !== 8 + cch * (hi ? 2 : 1)) continue;
      const nm = hi ? new TextDecoder('utf-16le').decode(u8.subarray(i + 12, i + 12 + cch * 2)) : latin1(u8, i + 12, i + 12 + cch);
      sheets.push({ name: nm, hidden: hs, macro: dt === 1 });
    }
    const xlm = sheets.filter(s => s.macro), hid = sheets.filter(s => s.hidden);
    if (xlm.length) findings.push({ sev: xlm.some(s => s.hidden) ? 'crit' : 'high', cat: 'Macros y contenido activo', title: 'Hoja de macros Excel 4.0 (XLM)' + (xlm.some(s => s.hidden === 2) ? ' muy oculta' : xlm.some(s => s.hidden) ? ' oculta' : ''), detail: 'Las macros XLM ejecutan comandos y descargas al abrir el libro (Auto_Open) y escapan a muchas defensas; ocultarlas es una táctica de evasión.', evidence: xlm.map(s => s.name + (s.hidden === 2 ? ' (muy oculta)' : s.hidden ? ' (oculta)' : '')).join(', '), attack: ['T1059', 'T1204.002'].concat(xlm.some(s => s.hidden) ? ['T1564'] : []) });
    else if (hid.some(s => s.hidden === 2)) findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Hojas "muy ocultas" (solo visibles por código)', detail: 'Una hoja muy oculta no puede mostrarse desde Excel; se usa para esconder datos o fórmulas.', evidence: hid.filter(s => s.hidden === 2).map(s => s.name).join(', '), attack: ['T1564'] });
    if (sheets.length) ctx.sheets = sheets;
  }
  if (kind === 'msi') findings.push({ sev: 'info', cat: 'Estructura del archivo', title: 'Paquete MSI', detail: 'Los instaladores MSI se ejecutan con msiexec; las acciones personalizadas pueden lanzar scripts o binarios.', attack: [] });
  return { kind, kindLabel, streams, macros: macros.map(m => ({ name: m.name, lines: m.code.split(/\r?\n/).length, code: m.code.slice(0, 60000) })), text: macros.map(m => m.code).join('\n') + '\n' + s.ascii.join('\n') + '\n' + wide.join('\n') };
}

/* ============================================================ PDF (al estilo pdfid) */
const PDF_KEYS = ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', '/Page', '/Encrypt', '/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFile', '/EmbeddedFiles', '/XFA', '/URI', '/SubmitForm', '/GoToR', '/GoToE', '/ImportData', '/Colors'];
async function parsePDF(u8, findings, ctx) {
  const raw = latin1(u8, 0, Math.min(u8.length, SCAN_MAX));
  // Nombres con escapes hexadecimales (/J#61vaScript) — ofuscación clásica
  const hexNames = (raw.match(/\/[A-Za-z]*#[0-9a-fA-F]{2}[A-Za-z#0-9]*/g) || []).length;
  const norm = raw.replace(/\/([A-Za-z0-9#]+)/g, (m, n) => '/' + n.replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
  const counts = {};
  for (const k of PDF_KEYS) { const re = k.startsWith('/') ? new RegExp(k.replace('/', '\\/') + '(?![A-Za-z])', 'g') : new RegExp('\\b' + k + '\\b', 'g'); counts[k] = (norm.match(re) || []).length; }
  const version = (raw.match(/%PDF-(\d\.\d)/) || [])[1] || '?';
  // Descomprimir streams FlateDecode
  const decoded = []; let streams = 0, inflatedOk = 0;
  const re = /stream\r?\n/g; let m;
  while ((m = re.exec(raw)) && streams < 400 && ctx.inflated < INFLATE_MAX) {
    const s = m.index + m[0].length; const e = raw.indexOf('endstream', s); if (e < 0) break;
    const dict = raw.slice(Math.max(0, m.index - 400), m.index);
    streams++;
    if (/\/FlateDecode|\/Fl\b/.test(dict.slice(dict.lastIndexOf('<<')))) {
      const out = await inflate(u8.subarray(s, e), 'deflate', 4 * 1024 * 1024);
      if (out && out.length) { inflatedOk++; ctx.inflated += out.length; decoded.push(latin1(out)); }
    }
    re.lastIndex = e + 9;
  }
  const dtext = decoded.join('\n');
  const inner = norm + '\n' + dtext;
  // Recontar palabras clave dentro de flujos de objetos (/ObjStm) descomprimidos
  for (const k of ['/JS', '/JavaScript', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/URI', '/SubmitForm', '/XFA', '/RichMedia']) { const n = (dtext.match(new RegExp(k.replace('/', '\\/') + '(?![A-Za-z])', 'g')) || []).length; if (n) counts[k] += n; }
  const js = counts['/JS'] + counts['/JavaScript'];
  const auto = counts['/OpenAction'] + counts['/AA'];
  if (js && auto) findings.push({ sev: 'high', cat: 'Contenido activo del PDF', title: 'JavaScript que se ejecuta automáticamente al abrir el PDF', detail: 'Combinación /OpenAction o /AA + JavaScript: vector clásico de exploits de lectores PDF y de redirecciones.', evidence: '/JS+/JavaScript: ' + js + ' · /OpenAction+/AA: ' + auto, attack: ['T1204.002', 'T1059.007', 'T1203'] });
  else if (js) findings.push({ sev: 'med', cat: 'Contenido activo del PDF', title: 'El PDF contiene JavaScript', detail: 'Los PDF legítimos rara vez necesitan JavaScript (salvo formularios).', evidence: js + ' referencias', attack: ['T1059.007'] });
  else if (auto) findings.push({ sev: 'low', cat: 'Contenido activo del PDF', title: 'Acciones automáticas al abrir (/OpenAction o /AA)', detail: 'Suelen ser benignas (zoom, página inicial) pero pueden abrir URLs o lanzar acciones.', evidence: auto + ' acciones', attack: [] });
  if (counts['/Launch']) findings.push({ sev: 'high', cat: 'Contenido activo del PDF', title: 'Acción /Launch (ejecuta programas o archivos)', detail: 'Permite lanzar un ejecutable o comando desde el PDF.', evidence: counts['/Launch'] + ' acciones', attack: ['T1204.002', 'T1059'] });
  if (counts['/EmbeddedFile'] || counts['/EmbeddedFiles']) {
    const efn = uniq((inner.match(/\/(?:UF|F)\s*\(([^)]{1,120}\.[a-z0-9]{2,5})\)/gi) || []).map(x => x.replace(/^\/(?:UF|F)\s*\(/i, '').replace(/\)$/, ''))).slice(0, 10);
    const bad = efn.some(n => /\.(exe|scr|js|vbs|hta|bat|cmd|ps1|lnk|jar|msi|dll|iso|zip|docm|xlsm|one)$/i.test(n));
    findings.push({ sev: bad ? 'high' : 'med', cat: 'Contenido activo del PDF', title: 'Archivos incrustados en el PDF' + (efn.length ? ': ' + efn.join(', ') : ''), detail: 'El PDF transporta otros archivos; si son ejecutables o documentos con macros, es un dropper.', attack: ['T1027.009', 'T1204.002'] });
  }
  if (counts['/XFA']) findings.push({ sev: 'med', cat: 'Contenido activo del PDF', title: 'Formularios XFA', detail: 'Tecnología de formularios dinámicos explotada históricamente y capaz de ejecutar scripts.', attack: ['T1203'] });
  if (counts['/RichMedia']) findings.push({ sev: 'med', cat: 'Contenido activo del PDF', title: 'Contenido multimedia (/RichMedia, Flash)', detail: 'Flash embebido fue un vector de exploits frecuente.', attack: ['T1203'] });
  if (counts['/JBIG2Decode']) findings.push({ sev: 'low', cat: 'Contenido activo del PDF', title: 'Filtro JBIG2Decode', detail: 'Filtro asociado a exploits históricos (CVE-2009-0658, CVE-2021-30860); raro en PDF comunes.', attack: ['T1203'] });
  if (counts['/SubmitForm'] || counts['/ImportData']) findings.push({ sev: 'med', cat: 'Contenido activo del PDF', title: 'Formulario que envía datos a un servidor (/SubmitForm)', detail: 'Puede usarse en PDF de phishing para capturar credenciales o datos personales.', attack: ['T1566.001', 'T1056.003'] });
  if (counts['/GoToR'] || counts['/GoToE']) findings.push({ sev: 'low', cat: 'Contenido activo del PDF', title: 'Enlaces a documentos remotos o incrustados (/GoToR, /GoToE)', detail: 'Abren otros documentos; pueden forzar autenticación a recursos remotos (NTLM).', attack: ['T1187'] });
  if (counts['/URI'] > 0) { const n = counts['/URI']; findings.push({ sev: n > 20 ? 'low' : 'info', cat: 'Contenido activo del PDF', title: n + ' enlace(s) URI en el documento', detail: 'Revisa los dominios en la sección de IOCs: los PDF de phishing llevan a la víctima a páginas falsas.', attack: n ? ['T1204.001'] : [] }); }
  if (counts['/Encrypt']) findings.push({ sev: 'low', cat: 'Contenido activo del PDF', title: 'PDF cifrado', detail: 'Puede ser legítimo (restricción de permisos) o para impedir el análisis del contenido.', attack: ['T1027.013'] });
  if (hexNames > 0) findings.push({ sev: 'med', cat: 'Contenido activo del PDF', title: 'Nombres PDF ofuscados con escapes hexadecimales (' + hexNames + ')', detail: 'Técnica para esconder palabras clave como /JavaScript de los escáneres.', attack: ['T1027'] });
  if (counts.obj && Math.abs(counts.obj - counts.endobj) > 3) findings.push({ sev: 'low', cat: 'Estructura del archivo', title: 'Estructura PDF inconsistente (obj ≠ endobj)', detail: 'Puede indicar un documento malformado a propósito para confundir analizadores.', evidence: 'obj ' + counts.obj + ' · endobj ' + counts.endobj, attack: ['T1027'] });
  const eof = raw.lastIndexOf('%%EOF');
  if (eof > 0 && u8.length - eof > 2048) { const tail = u8.subarray(eof + 5); findings.push({ sev: startsWith(tail.subarray(tail.findIndex(b => b > 32)), [0x4D, 0x5A]) || startsWith(tail.subarray(tail.findIndex(b => b > 32)), [0x50, 0x4B]) ? 'high' : 'low', cat: 'Estructura del archivo', title: 'Datos tras el final del PDF (%%EOF): ' + ((u8.length - eof) / 1024).toFixed(0) + ' KB', detail: 'Puede ser una actualización incremental o una carga útil añadida (archivo políglota).', attack: ['T1027.009'] }); }
  // JavaScript extraído (para mostrarlo al analista)
  const jsSnips = uniq((inner.match(/\/JS\s*\((?:\\\)|[^)]){10,2000}\)/g) || []).concat(decoded.filter(d => /(app\.|this\.|getField|eval\s*\(|unescape|util\.|Collab|function\s*\()/.test(d) && d.length < 200000))).slice(0, 8).map(x => x.slice(0, 4000));
  return { version, counts, streams, inflated: inflatedOk, hexNames, javascript: jsSnips, text: inner.slice(0, TEXT_MAX) };
}

/* ============================================================ RTF */
function parseRTF(u8, findings) {
  const raw = latin1(u8, 0, Math.min(u8.length, SCAN_MAX));
  const objs = (raw.match(/\\object\b/g) || []).length, objdata = (raw.match(/\\objdata\b/g) || []).length;
  const classes = uniq((raw.match(/\\objclass\s+([^\\}\s]+)/g) || []).map(x => x.replace(/\\objclass\s+/, ''))).slice(0, 20);
  if (objdata) findings.push({ sev: 'med', cat: 'Macros y contenido activo', title: 'Objetos OLE incrustados en el RTF (' + objdata + ')', detail: 'Los RTF con objetos OLE son el vehículo habitual de exploits de Office (Editor de ecuaciones, OLE2Link).', evidence: classes.length ? 'Clases: ' + classes.join(', ') : '', attack: ['T1027.009', 'T1203'] });
  // Decodificar objdata hexadecimal para aplicar reglas
  let decoded = '';
  const re = /\\objdata\b([\s\S]{0,4000000}?)(?:\}|\\objalias|\\result)/g; let m; let n = 0;
  while ((m = re.exec(raw)) && n < 20) { n++; const h = m[1].replace(/[^0-9a-fA-F]/g, ''); const b = new Uint8Array(h.length >> 1); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); const s = extractStrings(b, 5); decoded += s.ascii.join('\n') + '\n' + s.wide.join('\n') + '\n'; }
  const junk = (raw.match(/\{\\\*\\[a-z]+[^}]{0,20}\}/gi) || []).length;
  if (/\\rt[^f]/.test(raw.slice(0, 8)) || (objs && raw.length > 50000 && junk > 200)) findings.push({ sev: 'med', cat: 'Estructura del archivo', title: 'RTF malformado u ofuscado', detail: 'Cabecera no estándar o grandes cantidades de grupos basura para confundir analizadores.', attack: ['T1027'] });
  return { objects: objs, objdata, classes, text: raw.slice(0, 2 * 1024 * 1024) + '\n' + decoded };
}

/* ============================================================ LNK (acceso directo) */
function parseLNK(u8, findings) {
  const flags = rd32(u8, 0x14); const unicode = !!(flags & 0x80);
  let o = 0x4C;
  if (flags & 0x01) o += 2 + rd16(u8, o);           // LinkTargetIDList
  let target = '';
  if (flags & 0x02) {                               // LinkInfo
    const size = rd32(u8, o); const lbpOff = rd32(u8, o + 16);
    if (lbpOff) target = cstr(u8, o + lbpOff, 260);
    o += size;
  }
  const readStr = () => { const n = rd16(u8, o); o += 2; let s = ''; if (unicode) { s = new TextDecoder('utf-16le').decode(u8.subarray(o, o + n * 2)); o += n * 2; } else { s = latin1(u8, o, o + n); o += n; } return s; };
  const out = { target };
  if (flags & 0x04) out.name = readStr();
  if (flags & 0x08) out.relativePath = readStr();
  if (flags & 0x10) out.workingDir = readStr();
  if (flags & 0x20) out.arguments = readStr();
  if (flags & 0x40) out.icon = readStr();
  const tgt = (out.target || out.relativePath || '').toLowerCase();
  const args = out.arguments || '';
  out.runsAs = /powershell|pwsh/.test(tgt) ? 'PowerShell' : /cmd\.exe/.test(tgt) ? 'cmd.exe' : /mshta/.test(tgt) ? 'mshta' : /wscript|cscript/.test(tgt) ? 'Windows Script Host' : /rundll32/.test(tgt) ? 'rundll32' : /regsvr32/.test(tgt) ? 'regsvr32' : /msiexec/.test(tgt) ? 'msiexec' : /conhost/.test(tgt) ? 'conhost' : /forfiles|pcalua|explorer\.exe|curl\.exe|bitsadmin|certutil|wmic|schtasks/.test(tgt) ? tgt.split(/[\\/]/).pop() : '';
  if (out.runsAs) findings.push({ sev: args.length ? 'high' : 'med', cat: 'Acceso directo (LNK)', title: 'El acceso directo ejecuta ' + out.runsAs + (args ? ' con argumentos' : ''), detail: 'Los LNK que lanzan intérpretes o LOLBins son uno de los adjuntos maliciosos más usados desde que Office bloquea macros.', evidence: ((out.target || out.relativePath || '') + ' ' + args).slice(0, 600), attack: ['T1204.002', 'T1059'] });
  if (args.length > 250 || /\s{40,}/.test(args)) findings.push({ sev: 'med', cat: 'Acceso directo (LNK)', title: 'Argumentos anormalmente largos o rellenos de espacios (' + args.length + ' caracteres)', detail: 'Se rellenan para que la ventana de propiedades de Windows no muestre el comando real.', attack: ['T1027'] });
  if (out.icon && /(?:shell32|imageres)\.dll|\.(?:pdf|docx?|xlsx?|jpg|png|txt)$/i.test(out.icon) && out.runsAs) findings.push({ sev: 'med', cat: 'Acceso directo (LNK)', title: 'Icono prestado para aparentar otro tipo de archivo', detail: 'El acceso directo usa el icono de un documento/carpeta para engañar al usuario.', evidence: out.icon, attack: ['T1036'] });
  return out;
}

/* ============================================================ OneNote, ISO, imágenes */
function parseOneNote(u8, findings) {
  const s = extractStrings(u8, 5); const all = s.wide.concat(s.ascii);
  const files = uniq(all.filter(x => /\.(hta|bat|cmd|vbs|vbe|wsf|js|jse|exe|scr|lnk|ps1|chm|msi|dll|iso)$/i.test(x.trim()))).slice(0, 20);
  if (files.length) findings.push({ sev: 'high', cat: 'Contenido del contenedor', title: 'OneNote con archivos ejecutables o scripts incrustados', detail: 'Táctica muy usada desde 2023: una imagen "haz doble clic para ver" oculta un script embebido.', evidence: files.join(', '), attack: ['T1204.002', 'T1566.001', 'T1027.009'] });
  return { embedded: files };
}
function parseISO(u8, findings) {
  const txt = latin1(u8, 0, Math.min(u8.length, SCAN_MAX));
  const names = uniq((txt.match(/[A-Z0-9_ ~$!#%&'()@^{}\-.]{1,64}\.[A-Z0-9]{1,5};1/g) || []).map(n => n.replace(/;1$/, ''))).slice(0, 200);
  const jol = uniq(extractStrings(u8.subarray(0, Math.min(u8.length, 8 * 1024 * 1024)), 4).wide.filter(x => /\.[a-z0-9]{2,5}$/i.test(x))).slice(0, 200);
  const all = uniq(names.concat(jol));
  const bad = all.filter(n => /\.(exe|scr|dll|lnk|js|vbs|hta|bat|cmd|ps1|msi|wsf|cpl)$/i.test(n));
  findings.push({ sev: bad.length ? 'high' : 'med', cat: 'Contenido del contenedor', title: 'Imagen de disco (ISO/IMG/VHD)' + (bad.length ? ' con ' + bad.length + ' ejecutable(s)/script(s)' : ''), detail: 'Los archivos dentro de una imagen montada no heredan la "Marca de la Web", por lo que Windows no muestra advertencias de SmartScreen al ejecutarlos.', evidence: (bad.length ? bad : all).slice(0, 15).join(', '), attack: ['T1553.005', 'T1204.002'] });
  return { files: all };
}
function trailingData(u8, type, findings) {
  let end = -1;
  if (type === 'png') { for (let i = u8.length - 12; i > 8; i--) if (u8[i] === 0x49 && u8[i + 1] === 0x45 && u8[i + 2] === 0x4E && u8[i + 3] === 0x44) { end = i + 8; break; } }
  else if (type === 'jpg') { for (let i = u8.length - 2; i > 2; i--) if (u8[i] === 0xFF && u8[i + 1] === 0xD9) { end = i + 2; break; } }
  else if (type === 'gif') { for (let i = u8.length - 1; i > 6; i--) if (u8[i] === 0x3B) { end = i + 1; break; } }
  if (end > 0 && u8.length - end > 512) {
    const t = u8.subarray(end); const k = t.findIndex(b => b !== 0 && b !== 0x20 && b !== 0x0A && b !== 0x0D); const h = k >= 0 ? t.subarray(k) : t;
    const what = startsWith(h, [0x4D, 0x5A]) ? 'un ejecutable (MZ)' : startsWith(h, [0x50, 0x4B]) ? 'un ZIP' : startsWith(h, [0x52, 0x61, 0x72, 0x21]) ? 'un RAR' : /^<\?php|<script/i.test(latin1(h, 0, 64)) ? 'código web' : 'datos';
    findings.push({ sev: what === 'datos' ? 'low' : 'high', cat: 'Estructura del archivo', title: 'Datos ocultos tras el final de la imagen: ' + ((u8.length - end) / 1024).toFixed(1) + ' KB de ' + what, detail: 'Imagen políglota: transporta otro archivo o código a continuación del contenido visible.', evidence: 'Desplazamiento ' + fmtHexOff(end), attack: ['T1027.009', 'T1027.003'] });
  }
}

/* ============================================================ manifiestos de dependencias (OSV) */
function parseManifest(name, text) {
  const n = name.toLowerCase(); const pk = [];
  const clean = v => (String(v || '').match(/\d+(?:\.\d+){0,3}(?:[-.][0-9A-Za-z.]+)?/) || [''])[0];
  try {
    if (n === 'package-lock.json' || n === 'npm-shrinkwrap.json') {
      const j = JSON.parse(text);
      if (j.packages) for (const [p, v] of Object.entries(j.packages)) { if (!p || !v || !v.version) continue; pk.push({ name: v.name || p.replace(/^.*node_modules\//, ''), version: v.version }); }
      else if (j.dependencies) { const walk = d => { for (const [k, v] of Object.entries(d || {})) { if (v && v.version) pk.push({ name: k, version: v.version }); if (v && v.dependencies) walk(v.dependencies); } }; walk(j.dependencies); }
      return { ecosystem: 'npm', packages: pk };
    }
    if (n === 'package.json') {
      const j = JSON.parse(text); if (!j.dependencies && !j.devDependencies) return null;
      for (const d of [j.dependencies, j.devDependencies, j.optionalDependencies]) for (const [k, v] of Object.entries(d || {})) { const ver = clean(v); if (ver && /^\d/.test(ver) && !/^(file|git|link|workspace|http)/.test(v)) pk.push({ name: k, version: ver }); }
      return { ecosystem: 'npm', packages: pk, approx: true };
    }
    if (/requirements.*\.txt$/.test(n) || n === 'constraints.txt') {
      for (const l of text.split(/\r?\n/)) { const m = l.replace(/#.*/, '').trim().match(/^([A-Za-z0-9_.\-\[\]]+)\s*===?\s*([0-9][^\s;,]*)/); if (m) pk.push({ name: m[1].replace(/\[.*\]/, ''), version: m[2] }); }
      return { ecosystem: 'PyPI', packages: pk };
    }
    if (n === 'poetry.lock' || n === 'uv.lock' || n === 'pdm.lock') {
      const re = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g; let m; while ((m = re.exec(text))) pk.push({ name: m[1], version: m[2] });
      return { ecosystem: 'PyPI', packages: pk };
    }
    if (n === 'composer.lock') { const j = JSON.parse(text); for (const p of (j.packages || []).concat(j['packages-dev'] || [])) pk.push({ name: p.name, version: String(p.version).replace(/^v/, '') }); return { ecosystem: 'Packagist', packages: pk }; }
    if (n === 'gemfile.lock') { const re = /^ {4}([A-Za-z0-9_.-]+) \(([0-9][^)]*)\)$/gm; let m; while ((m = re.exec(text))) pk.push({ name: m[1], version: m[2].split('-')[0] }); return { ecosystem: 'RubyGems', packages: pk }; }
    if (n === 'go.mod') { const re = /^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+(v[0-9][^\s]*)/gm; let m; while ((m = re.exec(text))) pk.push({ name: m[1], version: m[2] }); return { ecosystem: 'Go', packages: pk }; }
    if (n === 'cargo.lock') { const re = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g; let m; while ((m = re.exec(text))) pk.push({ name: m[1], version: m[2] }); return { ecosystem: 'crates.io', packages: pk }; }
    if (n === 'pom.xml') { const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([0-9][^<$]*)<\/version>/g; let m; while ((m = re.exec(text))) pk.push({ name: m[1].trim() + ':' + m[2].trim(), version: m[3].trim() }); return { ecosystem: 'Maven', packages: pk }; }
    if (/\.csproj$|^packages\.config$/.test(n)) { const re = /<Package(?:Reference)?\s+(?:Include|id)="([^"]+)"\s+[Vv]ersion="([0-9][^"]*)"/g; let m; while ((m = re.exec(text))) pk.push({ name: m[1], version: m[2] }); return { ecosystem: 'NuGet', packages: pk }; }
  } catch (e) { return null; }
  return null;
}

/* ============================================================ reglas sobre texto */
function applyRules(text, scope, findings, seen) {
  if (!text) return;
  for (const r of RULES) {
    const [id, re, sev, title, detail, attack, cves, sc] = r;
    if (seen.has(id)) continue;
    if (sc === 'script' && scope === 'bin') continue;
    if (sc === 'bin' && scope === 'script') continue;
    const m = re.exec(text);
    if (!m) continue;
    seen.add(id);
    const i = m.index; const ev = text.slice(Math.max(0, i - 60), Math.min(text.length, i + m[0].length + 100)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '·').replace(/\s+/g, ' ').trim();
    findings.push({ sev, cat: 'Comportamiento e indicadores', title, detail, evidence: ev.slice(0, 400), attack: attack.slice(), cve: cves.slice(), rule: id });
  }
}
function obfuscationStats(text, findings, isScript, isMarkup) {
  if (!isScript || !text) return {};
  const lines = text.split(/\r?\n/); const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  // En HTML/SVG, las imágenes y fuentes incrustadas (data:image/…;base64) son habituales y no cuentan como carga oculta
  const b64src = isMarkup ? text.replace(/data:(?:image|font|application\/(?:font|x-font)[\w.+-]*)\/?[\w.+-]*;base64,[A-Za-z0-9+/=\s]+/gi, '') : text;
  const b64 = (b64src.match(/[A-Za-z0-9+/]{200,}={0,2}/g) || []);
  const hexb = (text.match(/(?:\\x[0-9a-f]{2}|0x[0-9a-f]{2},?\s?){60,}/gi) || []);
  const nonAlnum = text.length ? (text.replace(/[A-Za-z0-9\s]/g, '').length / text.length) : 0;
  const stats = { lines: lines.length, longestLine: longest, base64Blobs: b64.length, largestBase64: b64.reduce((m, x) => Math.max(m, x.length), 0), hexBlobs: hexb.length, symbolRatio: Math.round(nonAlnum * 100) / 100 };
  if (b64.length && stats.largestBase64 > 2000) findings.push({ sev: stats.largestBase64 > 20000 ? 'high' : 'med', cat: 'Ofuscación', title: 'Bloques Base64 extensos (' + b64.length + ', el mayor de ' + (stats.largestBase64 / 1024).toFixed(1) + ' KB)', detail: 'Cargas útiles codificadas dentro del script (binarios o etapas siguientes).', attack: ['T1027', 'T1027.009'] });
  if (hexb.length) findings.push({ sev: 'med', cat: 'Ofuscación', title: 'Secuencias de bytes en hexadecimal (' + hexb.length + ')', detail: 'Típico de shellcode o binarios embebidos en scripts.', attack: ['T1027'] });
  if (longest > 8000 && !isMarkup) findings.push({ sev: 'low', cat: 'Ofuscación', title: 'Líneas extremadamente largas (' + longest.toLocaleString('es') + ' caracteres)', detail: 'Código minificado u ofuscado; en scripts de un solo uso es indicio de ofuscación.', attack: ['T1027'] });
  if (nonAlnum > 0.35 && text.length > 2000) findings.push({ sev: 'med', cat: 'Ofuscación', title: 'Proporción muy alta de símbolos (' + Math.round(nonAlnum * 100) + '%)', detail: 'Patrón de ofuscadores que sustituyen identificadores por símbolos.', attack: ['T1027'] });
  if (/(?:['"][a-zA-Z0-9]{1,3}['"]\s*\+\s*){12,}/.test(text)) findings.push({ sev: 'med', cat: 'Ofuscación', title: 'Concatenación masiva de fragmentos de texto', detail: 'Divide palabras clave en trozos para evadir firmas.', attack: ['T1027'] });
  if (/\^[a-z]\^[a-z]\^|%[a-z]+:~\d+,\d+%/i.test(text)) findings.push({ sev: 'med', cat: 'Ofuscación', title: 'Ofuscación de línea de comandos (carets o subcadenas de variables)', detail: 'Técnicas de ofuscación de cmd.exe (p.ej. p^o^w^e^r^s^h^e^l^l, %var:~3,1%).', attack: ['T1027.010'] });
  return stats;
}

/* ============================================================ análisis principal */
/* ============================================================ YARA (subconjunto)
   Reglas propias del usuario aplicadas a los bytes del archivo. Soporta:
   - meta: clave = "texto" | número | true/false (severity, description, attack, author…)
   - strings: texto con nocase/wide/ascii/fullword, hexadecimales con ?? / nibbles / saltos [n-m] / (A|B), regex /…/is
   - condition: any|all|N of them | of ($a*,$b) · $a · #a op N · $a at N · $a in (A..B) · filesize op N[KB|MB]
                uint8/16/32[be](off) op N · and / or / not · paréntesis · true/false
   Las reglas se compilan una vez y se evalúan sobre el archivo como texto latin1 (un carácter = un byte). */
const YARA_MAX_RULES = 300, YARA_MAX_HITS = 1000;
function yaraEsc(s) { return s.replace(/[\\^$.*+?()[\]{}|\/]/g, '\\$&'); }
function yaraUnescape(s) {
  return s.replace(/\\(x[0-9a-fA-F]{2}|n|r|t|\\|"|0)/g, (m, c) => c[0] === 'x' ? String.fromCharCode(parseInt(c.slice(1), 16)) : ({ n: '\n', r: '\r', t: '\t', '\\': '\\', '"': '"', '0': '\0' })[c]);
}
function yaraHexToRe(h) {
  const t = h.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s+/g, '');
  let out = '', i = 0;
  while (i < t.length) {
    const c = t[i];
    if (c === '[') { const j = t.indexOf(']', i); if (j < 0) throw new Error('salto sin cerrar en cadena hex'); const r = t.slice(i + 1, j); const m = r.match(/^(\d*)-(\d*)$/); out += m ? '[\\s\\S]{' + (m[1] || '0') + ',' + (m[2] || '') + '}' : /^\d+$/.test(r) ? '[\\s\\S]{' + r + '}' : (() => { throw new Error('salto no válido [' + r + ']'); })(); i = j + 1; continue; }
    if (c === '(') { out += '(?:'; i++; continue; }
    if (c === ')') { out += ')'; i++; continue; }
    if (c === '|') { out += '|'; i++; continue; }
    const b = t.substr(i, 2); if (b.length < 2) throw new Error('byte incompleto en cadena hex');
    if (b === '??') out += '[\\s\\S]';
    else if (/^[0-9a-fA-F]\?$/.test(b)) { const hi = parseInt(b[0], 16); out += '[\\x' + (hi * 16).toString(16).padStart(2, '0') + '-\\x' + (hi * 16 + 15).toString(16).padStart(2, '0') + ']'; }
    else if (/^\?[0-9a-fA-F]$/.test(b)) { const lo = parseInt(b[1], 16); out += '[' + Array.from({ length: 16 }, (_, k) => '\\x' + (k * 16 + lo).toString(16).padStart(2, '0')).join('') + ']'; }
    else if (/^[0-9a-fA-F]{2}$/.test(b)) out += '\\x' + b.toLowerCase();
    else throw new Error('carácter no válido en cadena hex: ' + b);
    i += 2;
  }
  return new RegExp(out, 'g');
}
function yaraCompile(src) {
  src = String(src || '').replace(/\r/g, '');
  // Quitar comentarios fuera de cadenas
  let clean = '', i = 0, inStr = false, inRe = false;
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (!inStr && !inRe && c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (!inStr && !inRe && c === '/' && n === '*') { const j = src.indexOf('*/', i + 2); i = j < 0 ? src.length : j + 2; continue; }
    if (c === '"' && !inRe && src[i - 1] !== '\\') inStr = !inStr;
    clean += c; i++;
  }
  const rules = []; const errors = [];
  const reRule = /(?:^|\n)\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][\w]*)\s*(?::\s*([\w\s]+?))?\s*\{/g;
  let m;
  while ((m = reRule.exec(clean)) && rules.length < YARA_MAX_RULES) {
    const name = m[1], tags = (m[2] || '').trim().split(/\s+/).filter(Boolean);
    // localizar la llave de cierre respetando cadenas y regex
    let depth = 1, k = reRule.lastIndex, s = false;
    for (; k < clean.length && depth; k++) { const ch = clean[k]; if (ch === '"' && clean[k - 1] !== '\\') s = !s; if (!s) { if (ch === '{') depth++; else if (ch === '}') depth--; } }
    const body = clean.slice(reRule.lastIndex, k - 1); reRule.lastIndex = k;
    try {
      // Secciones meta/strings/condition, también en reglas escritas en una sola línea
      const sec = name => { const r = new RegExp('(?:^|[\\s{}])' + name + '\\s*:([\\s\\S]*?)(?=[\\s{}](?:meta|strings|condition)\\s*:|$)'); const x = body.match(r); return x ? x[1] : ''; };
      const meta = {};
      // Pares clave = valor, uno por línea o varios en la misma línea
      const reM = /(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+)\b|(true|false)\b)/g; let x; const ms = sec('meta');
      while ((x = reM.exec(ms))) meta[x[1]] = x[2] !== undefined ? yaraUnescape(x[2]) : x[3] !== undefined ? +x[3] : x[4] === 'true';
      const strings = [];
      const sb = sec('strings'); const reS = /\$(\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"([^\n$]*)|\{([^}]*)\}([^\n$]*)|\/((?:[^\/\\\n]|\\.)+)\/([a-z]*)([^\n$]*))/g; let sm, anon = 0;
      while ((sm = reS.exec(sb))) {
        const id = sm[1] || ('_' + (anon++));
        let re;
        if (sm[2] !== undefined) {
          const mods = sm[3] || ''; const txt = yaraUnescape(sm[2]); const nocase = /\bnocase\b/.test(mods), wide = /\bwide\b/.test(mods), ascii = /\bascii\b/.test(mods) || !wide, full = /\bfullword\b/.test(mods);
          const alts = []; if (ascii) alts.push(yaraEsc(txt)); if (wide) alts.push(txt.split('').map(ch => yaraEsc(ch) + '\\x00').join(''));
          let p = '(?:' + alts.join('|') + ')'; if (full) p = '(?<![A-Za-z0-9])' + p + '(?![A-Za-z0-9])';
          re = new RegExp(p, 'g' + (nocase ? 'i' : ''));
        } else if (sm[4] !== undefined) re = yaraHexToRe(sm[4]);
        else { const fl = (sm[7] || '').replace(/[^is]/g, ''); re = new RegExp(sm[6], 'g' + fl); }
        strings.push({ id, re });
      }
      const cond = sec('condition').trim();
      if (!cond) throw new Error('falta condition');
      const ev = yaraParseCond(cond, strings);
      rules.push({ name, tags, meta, strings, ev });
    } catch (e) { errors.push('Regla ' + name + ': ' + e.message); }
  }
  if (!rules.length && !errors.length && clean.trim()) errors.push('No se encontró ninguna regla (rule nombre { … })');
  return { rules, errors };
}
function yaraParseCond(src, strings) {
  const toks = []; const re = /\s*(0x[0-9a-fA-F]+|\d+(?:\.\.)?|\.\.|\$\w*\*?|#\w*|@\w*|!\w*|[A-Za-z_]\w*|==|!=|<=|>=|[<>()\[\],*]|"(?:[^"\\]|\\.)*")/y;
  let p = 0; while (p < src.length) { re.lastIndex = p; const m = re.exec(src); if (!m) { if (/^\s*$/.test(src.slice(p))) break; throw new Error('condición no válida cerca de "' + src.slice(p, p + 15) + '"'); } let t = m[1]; if (/^\d+\.\.$/.test(t)) { toks.push(t.slice(0, -2)); toks.push('..'); } else toks.push(t); p = re.lastIndex; }
  let k = 0; const peek = () => toks[k], next = () => toks[k++], expect = t => { if (toks[k] !== t) throw new Error('se esperaba "' + t + '" y se encontró "' + (toks[k] || 'fin') + '"'); k++; };
  const ids = strings.map(s => s.id);
  const setOf = () => { // them | ($a, $b*)
    if (peek() === 'them') { next(); return ids; }
    expect('('); const out = [];
    while (peek() !== ')') { const t = next(); if (!t || t[0] !== '$') throw new Error('se esperaba una cadena $ en el conjunto'); if (t.endsWith('*')) { const pre = t.slice(1, -1); ids.filter(i => i.startsWith(pre)).forEach(i => out.push(i)); } else out.push(t.slice(1)); if (peek() === ',') next(); }
    next(); out.forEach(i => { if (!ids.includes(i)) throw new Error('cadena $' + i + ' no definida'); }); return out;
  };
  const num = () => { // número, filesize, uintXX(off), #a, (expr numérica)
    const t = next();
    if (t === undefined) throw new Error('condición incompleta');
    if (/^0x/i.test(t)) return () => parseInt(t, 16);
    if (/^\d+$/.test(t)) { let v = +t; if (peek() === 'KB') { next(); v *= 1024; } else if (peek() === 'MB') { next(); v *= 1048576; } return () => v; }
    if (t === 'filesize') return c => c.size;
    if (t[0] === '#') { const id = t.slice(1); if (!ids.includes(id)) throw new Error('cadena #' + id + ' no definida'); return c => c.count(id); }
    const u = t.match(/^uint(8|16|32)(be)?$/); if (u) { expect('('); const off = num(); expect(')'); const w = +u[1] / 8, be = !!u[2]; return c => { const o = off(c); let v = 0; for (let i = 0; i < w; i++) { const b = c.u8[o + i]; if (b === undefined) return NaN; v += be ? b * Math.pow(256, w - 1 - i) : b * Math.pow(256, i); } return v; }; }
    throw new Error('se esperaba un número y se encontró "' + t + '"');
  };
  const primary = () => {
    const t = peek();
    if (t === '(') { next(); const e = orE(); expect(')'); return e; }
    if (t === 'not') { next(); const e = primary(); return c => !e(c); }
    if (t === 'true') { next(); return () => true; } if (t === 'false') { next(); return () => false; }
    if (t === 'any' || t === 'all' || /^\d+$/.test(t) && toks[k + 1] === 'of') {
      next(); expect('of'); const set = setOf(); const need = t === 'any' ? 1 : t === 'all' ? set.length : +t;
      return c => set.filter(i => c.count(i) > 0).length >= need;
    }
    if (t && t[0] === '$') {
      next(); const id = t.slice(1); if (!ids.includes(id)) throw new Error('cadena $' + id + ' no definida');
      if (peek() === 'at') { next(); const n = num(); return c => c.offs(id).includes(n(c)); }
      if (peek() === 'in') { next(); expect('('); const a = num(); expect('..'); const b = num(); expect(')'); return c => { const lo = a(c), hi = b(c); return c.offs(id).some(o => o >= lo && o <= hi); }; }
      return c => c.count(id) > 0;
    }
    // comparación numérica
    const l = num(); const op = next(); if (!['==', '!=', '<', '>', '<=', '>='].includes(op)) throw new Error('se esperaba un comparador y se encontró "' + (op || 'fin') + '"'); const r = num();
    return c => { const x = l(c), y = r(c); return op === '==' ? x === y : op === '!=' ? x !== y : op === '<' ? x < y : op === '>' ? x > y : op === '<=' ? x <= y : x >= y; };
  };
  const andE = () => { let e = primary(); while (peek() === 'and') { next(); const a = e, b = primary(); e = c => a(c) && b(c); } return e; };
  const orE = () => { let e = andE(); while (peek() === 'or') { next(); const a = e, b = andE(); e = c => a(c) || b(c); } return e; };
  const e = orE(); if (k < toks.length) throw new Error('sobra "' + toks[k] + '" en la condición');
  return e;
}
let YARA_CACHE = { src: null, compiled: null };
function yaraRun(src, u8) {
  if (YARA_CACHE.src !== src) YARA_CACHE = { src, compiled: yaraCompile(src) };
  const { rules, errors } = YARA_CACHE.compiled;
  const text = latin1(u8, 0, Math.min(u8.length, SCAN_MAX));
  const hits = {};
  const scan = s => { if (hits[s.id + '@' + s.re.source]) return hits[s.id + '@' + s.re.source]; const offs = []; s.re.lastIndex = 0; let m; while ((m = s.re.exec(text)) && offs.length < YARA_MAX_HITS) { offs.push(m.index); if (m[0].length === 0) s.re.lastIndex++; } return (hits[s.id + '@' + s.re.source] = offs); };
  const matched = [];
  for (const r of rules) {
    const byId = {}; r.strings.forEach(s => byId[s.id] = s);
    const ctx = { size: u8.length, u8, count: id => scan(byId[id]).length, offs: id => scan(byId[id]) };
    let ok = false; try { ok = !!r.ev(ctx); } catch (e) { errors.push('Regla ' + r.name + ': ' + e.message); }
    if (ok) matched.push({ rule: r.name, tags: r.tags, meta: r.meta, strings: r.strings.map(s => ({ id: s.id, n: scan(s).length, first: scan(s).slice(0, 3) })).filter(x => x.n) });
  }
  return { matched, errors: uniq(errors), rules: rules.length };
}

const SEVW = { crit: 35, high: 20, med: 8, low: 3, info: 0 };
async function analyze(name, buf, opts) {
  opts = opts || {};
  const t0 = Date.now();
  const u8 = new Uint8Array(buf);
  const ext = (name.match(/\.([a-z0-9-]{1,20})$/i) || [, ''])[1].toLowerCase();
  const findings = []; const seen = new Set(); const ctx = { inflated: 0, ext };
  const report = { name, size: u8.length, ext, extClass: extClass(ext) };
  // hashes
  const [sha1, sha256, sha512] = await Promise.all([digest('SHA-1', u8), digest('SHA-256', u8), digest('SHA-512', u8)]);
  report.hashes = { md5: md5(u8), sha1, sha256, sha512 };
  report.entropy = entropy(u8); report.entropyBlocks = entropyBlocks(u8);
  const type = detectType(u8, ext, name); report.type = type;
  // nombre del archivo: enmascaramiento
  if (/\u202E|\u202D|\u200F|\u2066|\u2067|\u2068/.test(name)) findings.push({ sev: 'crit', cat: 'Nombre y tipo de archivo', title: 'El nombre contiene caracteres de control de dirección (RLO/LRO)', detail: 'Invierte visualmente parte del nombre para disfrazar la extensión real.', evidence: JSON.stringify(name), attack: ['T1036.002'] });
  if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|mp[34]|html?|zip)[\s._-]*\.(exe|scr|com|pif|cpl|js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1|lnk|msi|jar|iso|img|vhdx?|one|chm|url|reg)$/i.test(name)) findings.push({ sev: 'high', cat: 'Nombre y tipo de archivo', title: 'Doble extensión en el nombre', detail: 'Windows oculta por defecto la última extensión: "factura.pdf.exe" se muestra como "factura.pdf".', evidence: name, attack: ['T1036.007'] });
  if (/\s{4,}\.[a-z0-9]{2,5}$/i.test(name)) findings.push({ sev: 'high', cat: 'Nombre y tipo de archivo', title: 'Relleno de espacios antes de la extensión', detail: 'Empuja la extensión real fuera de la vista en el explorador de archivos.', evidence: JSON.stringify(name), attack: ['T1036.007'] });
  const okExts = TYPE_EXTS[type.id];
  if (okExts && ext && !okExts.includes(ext) && !(type.family === 'document' && ['txt', 'log', 'csv', 'json', 'md', 'xml'].includes(type.id))) {
    const dang = type.family === 'exec' || type.family === 'script';
    findings.push({ sev: dang ? 'crit' : (type.id === 'zip' && /^(pdf|jpg|png|txt|docx?)$/.test(ext)) ? 'high' : 'med', cat: 'Nombre y tipo de archivo', title: 'La extensión (.' + ext + ') no coincide con el contenido real: ' + type.label, detail: dang ? 'Un ejecutable/script disfrazado de otro tipo de archivo es un indicador fuerte de malicia.' : 'El tipo real del archivo difiere del declarado; puede ser un error o un intento de evadir filtros por extensión.', attack: ['T1036.008'] });
    report.mismatch = true;
  }
  else if (!okExts && ext && ['document', 'script'].includes(type.family) && ['media', 'exec', 'office_macro'].includes(report.extClass) && !['rtf', 'slk', 'mht', 'mhtml'].includes(ext)) {
    findings.push({ sev: type.family === 'script' ? 'high' : 'low', cat: 'Nombre y tipo de archivo', title: 'La extensión (.' + ext + ') no coincide con el contenido real: ' + type.label, detail: 'El archivo es texto aunque su nombre indica otro formato.', attack: ['T1036.008'] });
    report.mismatch = true;
  }
  if (!ext) findings.push({ sev: 'info', cat: 'Nombre y tipo de archivo', title: 'Archivo sin extensión', detail: 'El tipo se determinó por su contenido (firma).', attack: [] });
  const cls = report.extClass;
  if (cls === 'exec' || type.family === 'exec') findings.push({ sev: 'info', cat: 'Nombre y tipo de archivo', title: 'Tipo de archivo ejecutable', detail: 'Solo debe ejecutarse si procede de una fuente verificada y su firma es válida.', attack: [] });
  else if (cls === 'script' || type.family === 'script') findings.push({ sev: 'low', cat: 'Nombre y tipo de archivo', title: 'Tipo de archivo de script o acceso directo (.' + (ext || type.id) + ')', detail: 'Estos formatos ejecutan código al abrirse con doble clic; son de alto riesgo como adjunto de correo.', attack: ['T1204.002'] });

  // análisis según formato
  let text = ''; let scope = 'bin';
  const S = () => { const s = extractStrings(u8, 6); report.stringsCount = s.ascii.length + s.wide.length; return s; };
  try {
    if (type.id === 'pe-exe' || type.id === 'pe-dll') {
      report.pe = parsePE(u8, findings); report.imphash = report.pe.imphash;
      const s = S(); text = s.ascii.join('\n') + '\n' + s.wide.join('\n'); scope = 'bin';
      if (report.pe.dotnet) { const us = s.wide.filter(x => x.length > 6); text += '\n' + us.join('\n'); report.pe.dotnetHint = /ConfuserEx|Confused by|\.NETReactor|Eazfuscator|SmartAssembly|Babel Obfuscator|Dotfuscator/i.exec(text)?.[0] || ''; if (report.pe.dotnetHint) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Ofuscador .NET detectado: ' + report.pe.dotnetHint, detail: 'El código IL está protegido; común en malware .NET (AgentTesla, AsyncRAT…) y en software comercial.', attack: ['T1027'] }); }
    } else if (type.id === 'elf') { report.elf = parseELF(u8); const s = S(); text = s.ascii.join('\n'); if (report.elf.upx) findings.push({ sev: 'high', cat: 'Estructura del ejecutable', title: 'ELF empaquetado con UPX', detail: 'Muy común en botnets IoT (Mirai, Gafgyt) y mineros en Linux.', attack: ['T1027.002'] }); }
    else if (type.id === 'macho') { report.macho = parseMachO(u8); const s = S(); text = s.ascii.join('\n'); if (report.macho && report.macho.signed === false) findings.push({ sev: 'low', cat: 'Estructura del ejecutable', title: 'Mach-O sin firma de código', detail: 'Gatekeeper bloqueará su ejecución salvo que el usuario la fuerce.', attack: ['T1553.001'] }); }
    else if (type.id === 'pdf') { report.pdf = await parsePDF(u8, findings, ctx); text = report.pdf.text; delete report.pdf.text; scope = 'script'; }
    else if (type.id === 'zip') { report.zip = await parseZip(u8, findings, ctx); text = report.zip.text; delete report.zip.text; scope = 'script'; if (ctx.apkPerms) report.zip.permissions = ctx.apkPerms; if (ctx.inner) report.zip.inner = ctx.inner; report.type = Object.assign({}, type, { label: report.zip.kindLabel }); }
    else if (type.id === 'ole') { report.ole = parseOLE(u8, findings, ctx); text = report.ole.text; delete report.ole.text; scope = 'script'; report.type = Object.assign({}, type, { label: report.ole.kindLabel }); }
    else if (type.id === 'rtf') { report.rtf = parseRTF(u8, findings); text = report.rtf.text; delete report.rtf.text; scope = 'script'; }
    else if (type.id === 'lnk') { report.lnk = parseLNK(u8, findings); const s = S(); text = Object.values(report.lnk).join('\n') + '\n' + s.wide.join('\n') + '\n' + s.ascii.join('\n'); scope = 'script'; }
    else if (type.id === 'one') { report.onenote = parseOneNote(u8, findings); const s = S(); text = s.ascii.join('\n') + '\n' + s.wide.join('\n'); scope = 'script'; }
    else if (['iso', 'vhd', 'vhdx'].includes(type.id)) { report.iso = parseISO(u8, findings); const s = S(); text = s.ascii.slice(0, 5000).join('\n'); }
    else if (['png', 'jpg', 'gif', 'webp'].includes(type.id)) { trailingData(u8, type.id, findings); const s = S(); text = s.ascii.join('\n'); }
    else if (['rar', '7z', 'gz', 'cab', 'xz', 'bz2'].includes(type.id)) { findings.push({ sev: 'low', cat: 'Contenido del contenedor', title: 'Archivo comprimido ' + type.label.replace('Archivo ', '') + ' (contenido no inspeccionable en el navegador)', detail: 'Extráelo en un entorno aislado y analiza cada archivo por separado; revisa la reputación del hash.', attack: [] }); const s = S(); text = s.ascii.slice(0, 3000).join('\n'); }
    else if (type.family === 'script' || type.family === 'document' || isMostlyText(u8)) {
      text = decodeText(u8); scope = 'script';
      if (type.id === 'eml') { const b64parts = text.match(/Content-Transfer-Encoding:\s*base64[\s\S]{0,400}?\r?\n\r?\n([A-Za-z0-9+/=\r\n]{100,})/gi) || []; const att = uniq((text.match(/(?:file)?name\*?=\s*"?([^"\r\n;]+\.[a-z0-9]{2,5})"?/gi) || []).map(x => x.replace(/^(?:file)?name\*?=\s*"?/i, '').replace(/"$/, ''))); report.eml = { attachments: att }; const bad = att.filter(a => new RegExp('\\.(' + EXT_CLASS.exec.concat(EXT_CLASS.script, ['iso', 'img', 'vhd', 'vhdx', 'one', 'zip', 'rar', '7z', 'docm', 'xlsm', 'html', 'htm', 'svg']).join('|') + ')$', 'i').test(a)); if (bad.length) findings.push({ sev: 'high', cat: 'Correo electrónico', title: 'Adjuntos de alto riesgo: ' + bad.join(', '), detail: 'Tipos de adjunto usados habitualmente para entregar malware o páginas de phishing.', attack: ['T1566.001'] }); for (const p of b64parts.slice(0, 5)) { try { const b = p.replace(/^[\s\S]*?\r?\n\r?\n/, '').replace(/\s+/g, ''); const bin = atob(b.slice(0, 4 * 1024 * 1024)); if (/<html|<script|<svg/i.test(bin.slice(0, 5000))) text += '\n' + bin; } catch (e) {} } }
      report.script = obfuscationStats(text, findings, type.family === 'script' || ['html', 'svg', 'hta'].includes(type.id), ['html', 'svg'].includes(type.id));
      const man = parseManifest(name, text);
      if (man && man.packages.length) { const seenP = new Set(); man.packages = man.packages.filter(p => { const k = p.name + '@' + p.version; if (seenP.has(k)) return false; seenP.add(k); return true; }).slice(0, 1000); report.manifest = man; }
    } else { const s = S(); text = s.ascii.join('\n') + '\n' + s.wide.join('\n'); }
  } catch (e) { report.parseError = String(e && e.message || e); const s = S(); text = s.ascii.join('\n') + '\n' + s.wide.join('\n'); }

  // reglas de comportamiento
  if (text.length > TEXT_MAX) text = text.slice(0, TEXT_MAX);
  applyRules(text, scope, findings, seen);
  // En binarios, los nombres de API sospechosas en cadenas (resueltas dinámicamente) también cuentan
  if (report.pe && report.pe.importCount < 15) { const dyn = uniq((text.match(/\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookExA|SetWindowsHookExW|GetAsyncKeyState|URLDownloadToFileA|URLDownloadToFileW|IsDebuggerPresent|MiniDumpWriteDump|CryptUnprotectData|AdjustTokenPrivileges)\b/g) || [])); if (dyn.length >= 2) findings.push({ sev: 'med', cat: 'Capacidades (API importadas)', title: 'API sensibles referenciadas como texto (resolución dinámica)', detail: 'Nombres de funciones que no están en la tabla de importaciones pero sí como cadenas: se cargan en tiempo de ejecución para ocultarlas.', evidence: dyn.join(', '), attack: ['T1027.007', 'T1106'] }); }
  // IOCs
  report.iocs = extractIOCs(text + '\n' + (report.lnk ? Object.values(report.lnk).join('\n') : ''));
  if (report.iocs.urls.some(u => /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\//.test(u))) findings.push({ sev: 'med', cat: 'Comportamiento e indicadores', title: 'URL con dirección IP directa', detail: 'Los servicios legítimos casi siempre usan nombres de dominio; las IP directas son comunes en servidores de descarga y C2.', evidence: report.iocs.urls.filter(u => /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(u)).slice(0, 5).join(' · '), attack: ['T1071.001', 'T1105'] });
  {
    // En páginas web los enlaces a .js son los propios scripts del sitio y enlazar descargas es habitual
    const markup = ['html', 'svg'].includes(type.id);
    const payRe = markup ? /\.(exe|scr|dll|msi|ps1|vbs|hta|bat|jar|iso|img|lnk)(?:[?#]|$)/i : /\.(exe|scr|dll|msi|ps1|vbs|hta|bat|js|jar|zip|rar|iso|img|lnk|bin|dat)(?:[?#]|$)/i;
    const pay = report.iocs.urls.filter(u => payRe.test(u));
    if (pay.length) findings.push({ sev: markup ? 'low' : 'med', cat: 'Comportamiento e indicadores', title: 'URLs que apuntan a ejecutables o archivos de carga', detail: markup ? 'La página enlaza archivos ejecutables; es habitual en sitios de descarga, pero revisa su origen.' : 'Posibles descargas de etapas siguientes.', evidence: pay.slice(0, 6).join(' · '), attack: ['T1105'] });
  }
  if (report.iocs.crypto.length) findings.push({ sev: 'med', cat: 'Comportamiento e indicadores', title: 'Direcciones de criptomonedas (' + report.iocs.crypto.length + ')', detail: 'Presentes en notas de rescate, estafas y malware "clipper".', evidence: report.iocs.crypto.slice(0, 4).join(' · '), attack: ['T1486'] });
  // Entropía global en formatos que no deberían tenerla
  if (report.entropy > 7.6 && ['script', 'document'].includes(type.family) && !report.pdf) findings.push({ sev: 'med', cat: 'Ofuscación', title: 'Entropía global muy alta para un archivo de texto (' + report.entropy + ')', detail: 'El contenido parece cifrado o comprimido.', attack: ['T1027'] });
  if (report.pe && report.entropy > 7.4 && !findings.some(f => /Empaquetador|entropía/i.test(f.title))) findings.push({ sev: 'med', cat: 'Estructura del ejecutable', title: 'Entropía global muy alta (' + report.entropy + ')', detail: 'La mayor parte del archivo está comprimida o cifrada.', attack: ['T1027.002'] });
  // Macros extraídas: comprobar su texto también con reglas "script"
  report.cvesFromContent = uniq(findings.flatMap(f => f.cve || []).concat(report.iocs.cves));
  // Cadenas relevantes para el analista
  const INTEREST = /(https?:\/\/|\\\\|HKEY_|HKLM|HKCU|\.exe\b|\.dll\b|\.ps1\b|\.vbs\b|\.bat\b|cmd\b|powershell|WScript|CreateObject|http|\.onion|password|passwd|token|api[_-]?key|user-agent|Mozilla\/|\/bin\/|\/tmp\/|\/etc\/|schtasks|reg add|vssadmin|bitcoin|wallet|\.php\b|webhook|telegram|discord|\bcurl\b|\bwget\b)/i;
  report.interesting = uniq(text.split(/\n/).filter(l => l.length >= 6 && l.length <= 600 && INTEREST.test(l))).slice(0, 400);
  // Reglas YARA del usuario
  if (opts.yara && String(opts.yara).trim()) {
    try {
      const Y = yaraRun(String(opts.yara), u8);
      report.yara = { rules: Y.rules, matched: Y.matched, errors: Y.errors };
      const SEVMAP = { critical: 'crit', critica: 'crit', crítica: 'crit', crit: 'crit', high: 'high', alta: 'high', medium: 'med', media: 'med', med: 'med', low: 'low', baja: 'low', info: 'info', informativa: 'info' };
      for (const m of Y.matched) {
        const sev = SEVMAP[String(m.meta.severity || m.meta.severidad || '').toLowerCase()] || 'high';
        const att = uniq(String(m.meta.attack || m.meta.mitre || m.meta.mitre_attack || '').split(/[\s,;]+/).filter(t => /^T\d{4}(\.\d{3})?$/.test(t)));
        findings.push({ sev, cat: 'Reglas YARA', title: 'Regla YARA: ' + m.rule + (m.meta.description || m.meta.descripcion ? ' — ' + (m.meta.description || m.meta.descripcion) : ''),
          detail: 'El archivo cumple la condición de la regla' + (m.tags.length ? ' (etiquetas: ' + m.tags.join(', ') + ')' : '') + (m.meta.author ? '. Autor: ' + m.meta.author : '') + (m.meta.reference ? '. Referencia: ' + m.meta.reference : '') + '.',
          evidence: m.strings.map(x => '$' + x.id + ' ×' + x.n + ' @' + x.first.map(fmtHexOff).join(',')).join(' · ').slice(0, 400), attack: att, rule: 'yara:' + m.rule });
      }
    } catch (e) { report.yara = { rules: 0, matched: [], errors: ['Error al aplicar las reglas: ' + (e && e.message || e)] }; }
  }
  // Puntuación
  report.findings = findings.map(f => Object.assign({ attack: [], cve: [] }, f));
  const sum = report.findings.reduce((a, f) => a + (SEVW[f.sev] || 0), 0);
  report.score = Math.min(100, Math.round(100 * (1 - Math.exp(-sum / 55))));
  report.counts = { crit: 0, high: 0, med: 0, low: 0, info: 0 }; report.findings.forEach(f => report.counts[f.sev]++);
  report.attack = uniq(report.findings.flatMap(f => f.attack || []));
  report.elapsedMs = Date.now() - t0;
  return report;
}

return { analyze, md5, parseManifest, extractIOCs, ovbaDecompress, extractVBA, yaraCompile };
}

/* Conecta el motor con quien lo cargue */
function centinelaSandboxServe(scope, engine) {
  scope.addEventListener('message', async e => {
    const { id, name, buf, yara } = e.data || {};
    if (!id) return;
    try { const report = await engine.analyze(String(name || 'archivo'), buf, { yara }); scope.postMessage({ id, ok: true, report }); }
    catch (err) { scope.postMessage({ id, ok: false, error: String(err && err.message || err) }); }
  });
}
if (typeof WorkerGlobalScope !== 'undefined' && typeof self !== 'undefined' && self instanceof WorkerGlobalScope) centinelaSandboxServe(self, centinelaSandboxEngine());
else if (typeof module !== 'undefined' && module.exports) module.exports = centinelaSandboxEngine();
else if (typeof window !== 'undefined') { window.centinelaSandboxEngine = centinelaSandboxEngine; window.centinelaSandboxServe = centinelaSandboxServe; }
