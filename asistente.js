/* Centinela — asistente de IA (panel lateral derecho "Preguntar")
   Habla con el backend (Cloudflare Worker, rutas /ai/* de worker-asistente.js), que usa Cloudflare Workers AI y,
   como respaldo, Groq. Las claves están en el Worker; aquí solo se envían la pregunta, el historial de esta
   conversación y, si el usuario lo permite, un extracto del resultado que está viendo. Nada se guarda.
   URL del backend: la de Ajustes (localStorage "ctn-backend") o, si está vacía, CENTINELA_BACKEND de config.js.
   Diseño: en pantallas anchas el panel queda acoplado a la derecha y la página se desplaza (no la tapa); en
   pantallas estrechas se abre por encima con un fondo atenuado. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const escH = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const lang = () => (document.documentElement.lang === 'en' ? 'en' : 'es');
  const DOCK = window.matchMedia('(min-width:1100px)');

  const T = {
    es: {
      ask: 'Preguntar', askLong: 'Pregúntale a Centinela', title: 'Asistente Centinela', sub: 'Ciberseguridad explicada en palabras sencillas',
      close: 'Cerrar el asistente', reset: 'Nueva conversación', send: 'Enviar', copy: 'Copiar', copied: 'Copiado',
      ph: 'Escribe tu pregunta…', keys: 'Enter para enviar · Mayús + Enter para salto de línea',
      ctx: 'Usar lo que tengo en pantalla', ctxOn: 'Viendo', ctxHint: 'Se envía un extracto del resultado del módulo abierto.',
      helloT: '¿En qué te ayudo?', hello: 'Puedo explicarte un resultado en palabras sencillas, decirte qué módulo usar o qué hacer después.',
      tryq: 'Sugerencias para este módulo', thinking: 'Escribiendo', bot: 'Centinela · IA', you: 'Tú',
      st: { ok: 'En línea', checking: 'Conectando…', nobackend: 'Sin configurar', off: 'No disponible', down: 'Sin conexión' },
      foot: 'Gratis con Cloudflare Workers AI. No se guarda nada. Verifica lo importante.',
      nobackend: 'El asistente necesita el backend de Centinela. Configúralo en Ajustes → URL del backend.',
      down: 'No se pudo conectar con el asistente. Revisa tu conexión o inténtalo más tarde.',
      off: 'El backend no tiene el asistente activado (falta el binding AI o la clave GROQ_KEY).',
      go: 'Abrir', via: { 'workers-ai': 'Workers AI', groq: 'Groq' }
    },
    en: {
      ask: 'Ask', askLong: 'Ask Centinela', title: 'Centinela Assistant', sub: 'Cybersecurity explained in plain words',
      close: 'Close the assistant', reset: 'New conversation', send: 'Send', copy: 'Copy', copied: 'Copied',
      ph: 'Type your question…', keys: 'Enter to send · Shift + Enter for a new line',
      ctx: 'Use what is on my screen', ctxOn: 'Viewing', ctxHint: 'An excerpt of the open module\'s result is sent.',
      helloT: 'How can I help?', hello: 'I can explain a result in plain words, tell you which module to use or what to do next.',
      tryq: 'Suggestions for this module', thinking: 'Typing', bot: 'Centinela · AI', you: 'You',
      st: { ok: 'Online', checking: 'Connecting…', nobackend: 'Not configured', off: 'Unavailable', down: 'Offline' },
      foot: 'Free with Cloudflare Workers AI. Nothing is stored. Double-check what matters.',
      nobackend: 'The assistant needs the Centinela backend. Set it in Settings → Backend URL.',
      down: 'Could not reach the assistant. Check your connection or try again later.',
      off: 'The backend does not have the assistant enabled (missing AI binding or GROQ_KEY).',
      go: 'Open', via: { 'workers-ai': 'Workers AI', groq: 'Groq' }
    }
  };
  const t = k => T[lang()][k];

  // Módulos: id → nombre en español (el inglés se toma de la traducción de la interfaz)
  const MODS = { home: 'Inicio', domain: 'Dominio & correo', cmp: 'Comparar dominios', gen: 'Generador DNS', phish: 'Phishing',
    eml: 'Analizar correo', sbx: 'Sandbox de archivos', leak: 'Filtraciones', mon: 'Monitoreo', recon: 'Reconocimiento OSINT',
    vuln: 'Análisis de vulnerabilidades', ioc: 'Consulta de IOCs', cases: 'Casos', report: 'Informe ejecutivo',
    geo: 'Geolocalización IP', tls: 'TLS y certificados', headers: 'Cabeceras HTTP', tools: 'Herramientas', colombia: 'Ataques en Colombia' };
  const modName = (id, l) => { const es = MODS[id] || id; if (l !== 'en') return es;
    try { return (typeof I18N_MAP !== 'undefined' && I18N_MAP.get(es)) || es; } catch (e) { return es; } };

  const SUGG = {
    es: {
      home: ['¿Por dónde empiezo para revisar la seguridad de mi dominio?', '¿Qué hace cada módulo?', '¿Cómo sé si un enlace es phishing?'],
      domain: ['Explícame este resultado en palabras sencillas', '¿Qué debo corregir primero?', '¿Qué es DMARC y por qué importa?'],
      phish: ['¿Este enlace es peligroso?', '¿Cómo denuncio un sitio de phishing?', '¿Qué hago si ya hice clic?'],
      eml: ['¿Este correo es legítimo?', '¿Qué significan SPF, DKIM y DMARC aquí?', '¿Dónde consigo los encabezados de un correo?'],
      sbx: ['¿Este archivo es peligroso?', '¿Qué significan las técnicas de MITRE ATT&CK?', '¿Qué hago si ya abrí el archivo?'],
      leak: ['¿Qué hago si mi correo aparece en una filtración?', '¿Cómo protejo las cuentas afectadas?'],
      vuln: ['¿Cuáles de estos riesgos son urgentes?', '¿Qué es un CVE y cómo lo corrijo?'],
      gen: ['¿Qué política DMARC me conviene?', '¿Cómo publico estos registros DNS?'],
      colombia: ['¿Qué grupos atacan más a Colombia?', '¿Qué diferencia hay entre confirmado y reclamado?', '¿Cómo protejo mi organización del ransomware?'],
      _: ['Explícame este resultado en palabras sencillas', '¿Qué debo hacer ahora?', '¿Qué módulo me sirve para esto?']
    },
    en: {
      home: ['Where do I start to check my domain\'s security?', 'What does each module do?', 'How can I tell if a link is phishing?'],
      domain: ['Explain this result in plain words', 'What should I fix first?', 'What is DMARC and why does it matter?'],
      phish: ['Is this link dangerous?', 'How do I report a phishing site?', 'What do I do if I already clicked?'],
      eml: ['Is this email legitimate?', 'What do SPF, DKIM and DMARC mean here?', 'Where do I get an email\'s headers?'],
      sbx: ['Is this file dangerous?', 'What do the MITRE ATT&CK techniques mean?', 'What do I do if I already opened the file?'],
      leak: ['What do I do if my email appears in a leak?', 'How do I protect the affected accounts?'],
      vuln: ['Which of these risks are urgent?', 'What is a CVE and how do I fix it?'],
      gen: ['Which DMARC policy suits me?', 'How do I publish these DNS records?'],
      colombia: ['Which groups attack Colombia the most?', 'What is the difference between confirmed and claimed?', 'How do I protect my organization from ransomware?'],
      _: ['Explain this result in plain words', 'What should I do now?', 'Which module helps with this?']
    }
  };

  const backend = () => {
    let b = ''; try { b = localStorage.getItem('ctn-backend') || ''; } catch (e) {}
    if (!b && typeof window.CENTINELA_BACKEND === 'string') b = window.CENTINELA_BACKEND;
    return b.trim().replace(/\/$/, '');
  };
  const curMode = () => { const b = $('.modebtn.active'); return (b && b.dataset.mode) || 'home'; };
  function screenSummary() {
    const m = curMode(); const w = $('#mode' + m.charAt(0).toUpperCase() + m.slice(1) + 'Wrap');
    if (!w) return '';
    const seen = new Set(); const out = [];
    for (const line of (w.innerText || '').split('\n')) { const l = line.replace(/\s+/g, ' ').trim(); if (l && !seen.has(l)) { seen.add(l); out.push(l); } }
    return out.join('\n').slice(0, 3000);
  }

  // ---------- Iconos (trazo fino, monocromo) ----------
  const svg = d => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
  const I = {
    mark: svg('<path d="M12 3l7 3v5c0 4.2-2.9 7.6-7 8.9C7.9 18.6 5 15.2 5 11V6z"/><path d="M12 8.2l.9 2.2 2.3.2-1.8 1.5.6 2.3-2-1.3-2 1.3.6-2.3-1.8-1.5 2.3-.2z"/>'),
    chat: svg('<path d="M4 5.5h16v10H9l-5 4z"/><path d="M8.5 10.5h.01M12 10.5h.01M15.5 10.5h.01"/>'),
    reset: svg('<path d="M4 12a8 8 0 1 0 2.4-5.7M4 4v4h4"/>'),
    close: svg('<path d="M6 6l12 12M18 6 6 18"/>'),
    send: svg('<path d="M5 12h14M13 6l6 6-6 6"/>'),
    arrow: svg('<path d="M9 6l6 6-6 6"/>'),
    copy: svg('<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>'),
    eye: svg('<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
  };

  // ---------- Estructura ----------
  const fab = document.createElement('button');
  fab.className = 'asst-fab'; fab.id = 'asstBtn'; fab.type = 'button'; fab.setAttribute('aria-controls', 'asstPanel'); fab.setAttribute('aria-expanded', 'false'); fab.dataset.noi18n = '';
  const scrim = document.createElement('div'); scrim.className = 'asst-scrim'; scrim.hidden = true;
  const panel = document.createElement('aside');
  panel.className = 'asst'; panel.id = 'asstPanel'; panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-labelledby', 'asstTitle'); panel.hidden = true; panel.dataset.noi18n = '';
  panel.innerHTML = `
    <header class="asst-head">
      <span class="asst-avatar">${I.mark}</span>
      <div class="asst-headtxt"><h2 id="asstTitle"></h2><p class="asst-status" id="asstStatus" data-st="checking"><span class="asst-dot"></span><span class="asst-stxt"></span></p></div>
      <button type="button" class="asst-icon" id="asstReset">${I.reset}</button>
      <button type="button" class="asst-icon" id="asstClose">${I.close}</button>
    </header>
    <div class="asst-ctxbar">
      <span class="asst-ctxmod">${I.eye}<span id="asstCtxMod"></span></span>
      <label class="asst-switch"><input type="checkbox" id="asstCtx" checked><span class="asst-track" aria-hidden="true"></span><span class="asst-swtxt"></span></label>
    </div>
    <div class="asst-log" id="asstLog" aria-live="polite"></div>
    <form class="asst-form" id="asstForm">
      <div class="asst-compose">
        <textarea id="asstQ" rows="1" maxlength="1500"></textarea>
        <button type="submit" class="asst-send" id="asstSend">${I.send}</button>
      </div>
      <p class="asst-keys"></p>
      <p class="asst-foot"></p>
    </form>`;
  // "Preguntar" va en la cabecera junto a la búsqueda (no flota sobre el contenido); en el teléfono el CSS lo fija sobre la barra inferior
  const anchor = document.querySelector('header.top #cmdkBtn');
  if (anchor) anchor.parentNode.insertBefore(fab, anchor); else document.body.appendChild(fab);
  document.body.appendChild(scrim); document.body.appendChild(panel);
  const log = $('#asstLog'), q = $('#asstQ'), form = $('#asstForm'), sendBtn = $('#asstSend'), stEl = $('#asstStatus');

  let history = [];       // [{role, content}]
  let busy = false, status = 'checking', statusChecked = false, ctrl = null;

  function setStatus(s) { status = s; stEl.dataset.st = s; stEl.querySelector('.asst-stxt').textContent = T[lang()].st[s] || ''; }
  function renderCtx() { $('#asstCtxMod').textContent = t('ctxOn') + ': ' + modName(curMode(), lang()); }

  function renderChrome() {
    fab.innerHTML = '<span class="asst-fab-ico">' + I.chat + '<i class="asst-fab-dot"></i></span><span>' + escH(t('ask')) + '</span>';
    fab.setAttribute('aria-label', t('askLong')); fab.title = t('askLong');
    $('#asstTitle').textContent = t('title');
    $('#asstReset').setAttribute('aria-label', t('reset')); $('#asstReset').title = t('reset');
    $('#asstClose').setAttribute('aria-label', t('close')); $('#asstClose').title = t('close');
    panel.querySelector('.asst-swtxt').textContent = t('ctx');
    panel.querySelector('.asst-switch').title = t('ctxHint');
    q.placeholder = t('ph'); q.setAttribute('aria-label', t('ph'));
    sendBtn.setAttribute('aria-label', t('send')); sendBtn.title = t('send');
    panel.querySelector('.asst-keys').textContent = t('keys');
    panel.querySelector('.asst-foot').textContent = t('foot');
    setStatus(status); renderCtx();
    log.querySelectorAll('.asst-copy').forEach(b => { b.setAttribute('aria-label', t('copy')); b.title = t('copy'); });
    if (!history.length) renderWelcome();
  }

  function renderWelcome() {
    const l = lang(), m = curMode();
    const list = (SUGG[l][m] || SUGG[l]._);
    log.innerHTML = `<div class="asst-welcome"><span class="asst-avatar asst-avatar-lg">${I.mark}</span><p class="asst-hello">${escH(t('helloT'))}</p><p class="asst-hello-sub">${escH(t('hello'))}</p></div>
      <div class="asst-sugg"><p class="asst-sugg-t">${escH(t('tryq'))}</p>${list.map(s => `<button type="button" class="asst-chip"><span>${escH(s)}</span>${I.arrow}</button>`).join('')}</div>`;
  }

  // Markdown mínimo y seguro: se escapa todo y luego se interpretan negritas, código, listas y títulos.
  function md(src) {
    const l = lang();
    const inline = s => {
      let h = escH(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
      // Nombres de módulos → botones que abren el módulo
      Object.keys(MODS).forEach(id => {
        if (id === 'home') return;
        [modName(id, l), MODS[id]].forEach(n => {
          const e = escH(n); if (!h.includes(e) || h.includes('data-mode="' + id + '"')) return;
          h = h.replace(e, `<button type="button" class="asst-go" data-mode="${id}" title="${escH(t('go'))}">${e}</button>`);
        });
      });
      return h;
    };
    const out = []; let list = null;
    const close = () => { if (list) { out.push('</' + list + '>'); list = null; } };
    for (const raw of String(src).split('\n')) {
      const line = raw.trimEnd();
      let m;
      if ((m = line.match(/^\s*[-*•]\s+(.*)$/))) { if (list !== 'ul') { close(); out.push('<ul>'); list = 'ul'; } out.push('<li>' + inline(m[1]) + '</li>'); }
      else if ((m = line.match(/^\s*\d+[.)]\s+(.*)$/))) { if (list !== 'ol') { close(); out.push('<ol>'); list = 'ol'; } out.push('<li>' + inline(m[1]) + '</li>'); }
      else if ((m = line.match(/^#{1,6}\s+(.*)$/))) { close(); out.push('<p class="asst-h">' + inline(m[1]) + '</p>'); }
      else if (!line.trim()) close();
      else { close(); out.push('<p>' + inline(line) + '</p>'); }
    }
    close();
    return out.join('');
  }

  // keepSugg: los avisos de estado se muestran sin quitar las sugerencias
  function addMsg(role, html, keepSugg) {
    const sugg = log.querySelector('.asst-sugg'), wel = log.querySelector('.asst-welcome');
    if (!keepSugg) { if (sugg) sugg.remove(); if (wel) wel.remove(); }
    const d = document.createElement('div');
    d.className = 'asst-msg ' + (role === 'user' ? 'user' : 'bot');
    d.innerHTML = role === 'user'
      ? `<div class="asst-txt">${html}</div>`
      : `<span class="asst-avatar asst-avatar-sm">${I.mark}</span><div class="asst-card"><div class="asst-who">${escH(t('bot'))}</div><div class="asst-txt">${html}</div></div>`;
    if (sugg && keepSugg) log.insertBefore(d, sugg); else log.appendChild(d);
    log.scrollTop = log.scrollHeight;
    return d.querySelector('.asst-txt');
  }

  async function checkStatus() {
    const b = backend();
    if (!b) return 'nobackend';
    try {
      const r = await fetch(b + '/ai/status', { cache: 'no-store' });
      const j = await r.json().catch(() => ({}));
      return j && j.ok ? 'ok' : 'off';
    } catch (e) { return 'down'; }
  }

  const grow = () => { q.style.height = 'auto'; q.style.height = Math.min(q.scrollHeight, 160) + 'px'; };

  async function ask(text) {
    text = String(text || '').trim();
    if (!text || busy) return;
    const b = backend();
    if (!b) { addMsg('user', '<p>' + escH(text) + '</p>'); addMsg('bot', '<p class="asst-err">' + escH(t('nobackend')) + '</p>'); setStatus('nobackend'); return; }
    busy = true; sendBtn.disabled = true; q.value = ''; grow();
    addMsg('user', '<p>' + escH(text) + '</p>');
    history.push({ role: 'user', content: text });
    const box = addMsg('bot', '<p class="asst-wait" aria-label="' + escH(t('thinking')) + '"><span></span><span></span><span></span></p>');
    const body = { messages: history.slice(-8), lang: lang(),
      context: { module: modName(curMode(), 'es'), summary: $('#asstCtx').checked ? screenSummary() : '' } };
    let answer = '', via = '', err = '';
    try {
      ctrl = new AbortController();
      // text/plain evita la petición previa CORS (preflight); el Worker lee el JSON igualmente
      const r = await fetch(b + '/ai/chat', { method: 'POST', headers: { 'content-type': 'text/plain;charset=UTF-8' }, body: JSON.stringify(body), signal: ctrl.signal });
      if (!r.ok || !r.body) { const j = await r.json().catch(() => ({})); err = (j && j.error) || t('down'); }
      else {
        if (status !== 'ok') setStatus('ok');
        const reader = r.body.getReader(), dec = new TextDecoder(); let buf = '', raf = 0;
        const paint = () => { raf = 0; box.innerHTML = md(answer); log.scrollTop = log.scrollHeight; };
        for (;;) {
          const { value, done } = await reader.read(); if (done) break;
          buf += dec.decode(value, { stream: true }); let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const ev = buf.slice(0, i); buf = buf.slice(i + 2);
            const d = ev.replace(/^data:\s*/, ''); let j = null; try { j = JSON.parse(d); } catch (e) { continue; }
            if (j.t) { answer += j.t; if (!raf) raf = requestAnimationFrame(paint); }
            else if (j.done) via = j.via || '';
            else if (j.error) err = j.error;
          }
        }
        if (raf) cancelAnimationFrame(raf);
        paint();
      }
    } catch (e) { if (e.name !== 'AbortError') { err = t('down'); setStatus('down'); } }
    ctrl = null;
    if (answer) {
      history.push({ role: 'assistant', content: answer });
      if (err) box.insertAdjacentHTML('beforeend', '<p class="asst-err">' + escH(err) + '</p>');
      box.insertAdjacentHTML('afterend', `<div class="asst-meta">${via ? `<span class="asst-via">${escH(T[lang()].via[via] || via)}</span>` : ''}<button type="button" class="asst-copy" aria-label="${escH(t('copy'))}" title="${escH(t('copy'))}">${I.copy}</button></div>`);
      box.closest('.asst-msg')._answer = answer;
    } else {
      history.pop();
      box.innerHTML = '<p class="asst-err">' + escH(err || t('down')) + '</p>';
    }
    busy = false; sendBtn.disabled = false; q.focus();
  }

  const docked = () => DOCK.matches;
  function layout() {
    const open = !panel.hidden;
    document.body.classList.toggle('asst-open', open);
    document.body.classList.toggle('asst-docked', open && docked());
    scrim.hidden = !open || docked();
    panel.setAttribute('aria-modal', open && !docked() ? 'true' : 'false');
  }
  function open() {
    panel.hidden = false; fab.setAttribute('aria-expanded', 'true'); layout();
    renderCtx();
    if (!history.length) renderWelcome();
    q.focus();
    if (!statusChecked) {
      statusChecked = true; setStatus('checking');
      checkStatus().then(s => {
        setStatus(s);
        if (s !== 'ok') { statusChecked = false; if (!history.length) addMsg('bot', '<p class="asst-err">' + escH(t(s)) + '</p>', true); }
      });
    }
  }
  function close() { panel.hidden = true; fab.setAttribute('aria-expanded', 'false'); layout(); fab.focus(); }

  fab.addEventListener('click', () => (panel.hidden ? open() : close()));
  scrim.addEventListener('click', close);
  $('#asstClose').addEventListener('click', close);
  $('#asstReset').addEventListener('click', () => { if (ctrl) ctrl.abort(); history = []; renderWelcome(); q.focus(); });
  panel.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); close(); } });
  form.addEventListener('submit', e => { e.preventDefault(); ask(q.value); });
  q.addEventListener('input', grow);
  q.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(q.value); } });
  log.addEventListener('click', e => {
    const chip = e.target.closest('.asst-chip'); if (chip) { ask(chip.textContent); return; }
    const cp = e.target.closest('.asst-copy');
    if (cp) {
      const msg = cp.closest('.asst-msg'); const txt = (msg && msg._answer) || '';
      const done = () => { cp.classList.add('ok'); cp.title = t('copied'); setTimeout(() => { cp.classList.remove('ok'); cp.title = t('copy'); }, 1500); };
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(done, () => {}); return;
    }
    const go = e.target.closest('.asst-go');
    if (go && typeof setMode === 'function') { setMode(go.dataset.mode); if (!docked()) close(); }
  });
  DOCK.addEventListener('change', layout);
  // El contexto y las sugerencias dependen del módulo abierto
  const nav = $('aside.nav');
  if (nav) new MutationObserver(() => { renderCtx(); if (!history.length) renderWelcome(); }).observe(nav, { subtree: true, attributes: true, attributeFilter: ['class'] });
  // Idioma: la interfaz se cambia en app.js modificando <html lang>
  new MutationObserver(renderChrome).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
  renderChrome();
  window.centinelaAsk = text => { if (panel.hidden) open(); ask(text); };
})();
