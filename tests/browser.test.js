// Pruebas de la aplicación en Chrome/Edge headless: carga, CSP, módulos, idioma, accesibilidad (WCAG),
// sandbox en sus tres entornos, paleta de comandos, retención del historial y casos.
// No dependen de servicios externos: las opciones de red del sandbox se desactivan y no hay backend.
'use strict';
const fs = require('fs');
const { ok, section, summary, serve, browser, tinyPE } = require('./lib');
let AXE = null; try { AXE = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'); } catch (e) {}

(async () => {
  const srv = await serve(); const b = await browser(+process.env.CDP_PORT || 9400);
  const URL = srv.url + '/index.html';
  try {
    section('Carga y seguridad');
    await b.go(URL, 3000);
    ok(await b.ev(`typeof setMode==='function'&&!!document.querySelector('#homeGrid .homecard')`), 'la aplicación carga (app.js) y muestra el panel de inicio');
    ok(await b.ev(`/script-src 'self';/.test(document.querySelector('meta[http-equiv="Content-Security-Policy"]').content)`), "CSP sin 'unsafe-inline' en script-src");
    ok(await b.ev(`/style-src 'self';/.test(document.querySelector('meta[http-equiv="Content-Security-Policy"]').content)`), "CSP sin 'unsafe-inline' en style-src");
    const bg0 = await b.ev(`getComputedStyle(document.body).backgroundColor`);
    await b.ev(`const st=document.createElement('style');st.textContent='body{background:rgb(255,0,0)!important}';document.head.appendChild(st);document.querySelector('#homeOut').innerHTML='<p id="inj" style="color:rgb(0,255,0)">x</p>';1`); await b.sleep(300);
    ok(await b.ev(`getComputedStyle(document.body).backgroundColor`) === bg0 && await b.ev(`getComputedStyle(document.querySelector('#inj')).color`) !== 'rgb(0, 255, 0)', 'la CSP bloquea hojas <style> y atributos style inyectados');
    ok(await b.ev(`getComputedStyle(document.querySelector('#modeDomainWrap')).display`) === 'none' && await b.ev(`document.querySelector('#printHead').style.display`) === 'none', 'los estilos propios (data-s) se aplican por CSSOM');
    await b.ev(`window.__x=0;const s=document.createElement('script');s.textContent='window.__x=1';document.body.appendChild(s);document.querySelector('#homeOut').innerHTML='<img src="x:y" onerror="window.__x=2">';1`); await b.sleep(500);
    ok(await b.ev(`window.__x`) === 0, 'la CSP bloquea scripts y manejadores en línea inyectados');
    await b.ev(`document.querySelector('#homeOut').innerHTML='';1`);   // retirar la imagen inyectada para la prueba
    const cspErrs = b.errs.filter(e => /^CSP/.test(e)).length; b.errs.length = 0;
    ok(cspErrs >= 1, 'el navegador registra la violación de CSP provocada');

    section('Módulos');
    const modes = await b.ev(`[...document.querySelectorAll('aside.nav .modebtn')].map(x=>x.dataset.mode)`);
    const bad = await b.ev(`(()=>{const out=[];${JSON.stringify(modes)}.forEach(m=>{setMode(m);const w=document.querySelector('#mode'+m.charAt(0).toUpperCase()+m.slice(1)+'Wrap');if(!w||w.style.display==='none')out.push(m);});setMode('home');return out;})()`);
    ok(modes.length >= 18 && bad.length === 0, `los ${modes.length} módulos del menú se abren` + (bad.length ? ' (fallan: ' + bad.join(', ') + ')' : ''));
    ok(await b.ev(`document.querySelectorAll('#homeGrid .homecard').length`) === modes.length - 1, 'el inicio tiene una tarjeta por módulo');

    section('Idioma');
    const snap = `(()=>{const o=[];const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);while(w.nextNode()){const n=w.currentNode,p=n.parentNode;if(!p||/SCRIPT|STYLE|TEXTAREA/.test(p.nodeName)||p.closest('svg,#legalBody,.raw'))continue;const t=n.nodeValue.replace(/\\s+/g,' ').trim();if(t)o.push(t);}document.querySelectorAll('[placeholder],[title],[aria-label]').forEach(e=>['placeholder','title','aria-label'].forEach(a=>{const v=e.getAttribute(a);if(v)o.push('@'+a+':'+v);}));return o;})()`;
    const es1 = await b.ev(snap); await b.ev(`document.querySelector('#langBtn').click();1`); const en = await b.ev(snap);
    const left = en.filter(t => /[áéíóúñ¿¡]|\b(de|la|el|los|las|del|para|con|por|una|que|sin|tu|tus|se|es)\b/i.test(t) && !/^@title:Idioma/.test(t));
    ok(left.length === 0, 'interfaz completa en inglés' + (left.length ? ': ' + left.slice(0, 5).join(' | ') : ''));
    await b.ev(`document.querySelector('#langBtn').click();1`);
    ok(JSON.stringify(await b.ev(snap)) === JSON.stringify(es1), 'al volver a español se restaura todo exactamente');

    section('Accesibilidad (WCAG 2.1 A/AA, axe-core)');
    if (!AXE) ok(false, 'axe-core instalado (ejecuta npm install en tests/)');
    else {
      await b.send('Runtime.evaluate', { expression: AXE });
      const viol = {};
      for (const theme of ['dark', 'light']) for (const m of modes) {
        await b.ev(`setTheme('${theme}');setMode('${m}');1`); await b.sleep(700);
        (await b.ev(`(async()=>{const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}});return r.violations.map(v=>v.id+' ('+v.nodes.length+')');})()`)).forEach(v => (viol[v] = viol[v] || []).push(theme + ':' + m));
      }
      await b.ev(`setTheme('dark');setMode('home');1`);
      ok(Object.keys(viol).length === 0, 'sin incumplimientos en ' + modes.length + ' módulos × 2 temas' + (Object.keys(viol).length ? ': ' + Object.entries(viol).map(([k, v]) => k + ' en ' + v.slice(0, 4).join(',')).join(' · ') : ''));
    }

    section('Móvil (390 px)');
    await b.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    await b.go(URL, 2500);
    const overflow = await b.ev(`(async()=>{const out=[];for(const m of ${JSON.stringify(modes)}){setMode(m);await new Promise(r=>setTimeout(r,150));const d=document.documentElement.scrollWidth-document.documentElement.clientWidth;if(d>0)out.push(m+' ('+d+'px)');}setMode('home');return out;})()`);
    ok(overflow.length === 0, 'ningún módulo desborda horizontalmente' + (overflow.length ? ': ' + overflow.join(', ') : ''));
    const nav = await b.ev(`(()=>{const t=[...document.querySelectorAll('.mnav .mtab')];return {n:t.length,rows:new Set(t.map(x=>Math.round(x.getBoundingClientRect().top))).size};})()`);
    ok(nav.n >= 6 && nav.rows === 1, 'menú inferior: ' + nav.n + ' pestañas en una sola fila');
    await b.send('Emulation.clearDeviceMetricsOverride'); await b.go(URL, 2500);

    section('Sandbox en sus tres entornos');
    const pe = tinyPE().toString('base64');
    for (const [label, prep] of [['Web Worker', ''], ['Web Worker en memoria', `SBX.mode=null;SBX.worker&&SBX.worker.terminate();SBX.worker=null;const W=window.Worker;window.Worker=function(u,o){if(!String(u).startsWith('blob:'))throw new DOMException('x','SecurityError');return new W(u,o);};`], ['modo compatibilidad', `SBX.mode=null;SBX.worker&&SBX.worker.terminate();SBX.worker=null;window.Worker=undefined;`]]) {
      await b.ev(`${prep}setMode('sbx');['#sbxOptRep','#sbxOptCve','#sbxOptOsv'].forEach(s=>document.querySelector(s).checked=false);SBX.files=[];sbxAddFiles([new File([Uint8Array.from(atob('${pe}'),c=>c.charCodeAt(0))],'factura.pdf')]);1`);
      await b.ev(`runSbx()`);
      const r = await b.ev(`(()=>{const x=SBX.results[0];return x.r?{mode:x.r.engineMode,type:x.r.type.id,mis:x.r.mismatch,v:x.r.verdict.t,card:!!document.querySelector('.sbxcard')}:{err:x.error};})()`);
      ok(r.type === 'pe-exe' && r.mis && r.card, `${label} (${r.mode || r.err}): detecta el ejecutable disfrazado de PDF → ${r.v}`);
    }

    section('Paleta de comandos');
    await b.go(URL, 2500);
    for (const t of ['keyDown', 'keyUp']) await b.send('Input.dispatchKeyEvent', { type: t, key: 'k', code: 'KeyK', modifiers: 2, windowsVirtualKeyCode: 75 });
    await b.sleep(200); await b.send('Input.insertText', { text: 'ioc' }); await b.sleep(150);
    ok(await b.ev(`document.querySelector('#cmdkDlg').open&&/IOCs/.test(document.querySelector('#cmdkList li[aria-selected="true"]').textContent)`), 'Ctrl+K abre la paleta y filtra módulos');
    await b.ev(`document.querySelector('#cmdkDlg').close();1`);

    section('Retención del historial');
    await b.ev(`(()=>{const n=Date.now(),H=3600e3;localStorage.setItem('ctn-hist',JSON.stringify([{domain:'reciente.com',score:90,date:n-H},{domain:'viejo.com',score:50,date:n-48*H}]));localStorage.setItem('ctn-org','Mi Entidad');sessionStorage.clear();})();1`);
    await b.go(URL, 2500);
    ok(JSON.stringify(await b.ev(`JSON.parse(localStorage.getItem('ctn-hist')||'[]').map(x=>x.domain)`)) === '["reciente.com"]' && await b.ev(`localStorage.getItem('ctn-org')`) === 'Mi Entidad', 'sesión nueva: borra el historial de más de 24 h y conserva la configuración');
    await b.ev(`(()=>{const n=Date.now(),H=3600e3;sessionStorage.setItem('ctn-sess',String(n-30*H));sessionStorage.setItem('ctn-last-act',String(n-60e3));localStorage.setItem('ctn-hist',JSON.stringify([{domain:'en-sesion.com',score:1,date:n-26*H}]));})();1`);
    await b.go(URL, 2500);
    ok(await b.ev(`JSON.parse(localStorage.getItem('ctn-hist')||'[]').length`) === 1, 'lo hecho durante la sesión activa no se borra');

    section('Casos');
    await b.ev(`localStorage.removeItem('ctn-cases');setMode('cases');document.querySelector('#caseTitle').value='Caso de prueba';document.querySelector('#caseNew').click();document.querySelector('#caseNote').value='Nota';document.querySelector('#caseNoteAdd').click();1`);
    ok(await b.ev(`caseAll().length===1&&caseAll()[0].items[0].kind==='note'`), 'crea un caso y añade una nota');

    ok(b.errs.length === 0, 'sin excepciones de JavaScript' + (b.errs.length ? ': ' + b.errs.slice(0, 3).join(' | ') : ''));
  } catch (e) { ok(false, 'error inesperado: ' + e.message); }
  finally { await b.close(); srv.close(); summary('Pruebas de navegador'); process.exit(process.exitCode || 0); }
})();
