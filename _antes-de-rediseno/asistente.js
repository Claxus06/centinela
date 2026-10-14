/* Centinela — asistente de IA (panel lateral "Preguntar")
   Habla con el backend (Cloudflare Worker, rutas /ai/* de worker-asistente.js), que usa Cloudflare Workers AI y,
   como respaldo, Groq. Las claves están en el Worker; aquí solo se envían la pregunta, el historial de esta
   conversación y, si el usuario lo permite, un extracto del resultado que está viendo. Nada se guarda.
   URL del backend: la de Ajustes (localStorage "ctn-backend") o, si está vacía, CENTINELA_BACKEND de config.js. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const escH = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const lang = () => (document.documentElement.lang === 'en' ? 'en' : 'es');

  const T = {
    es: {
      ask: 'Preguntar', title: 'Asistente', sub: 'Respuestas orientativas generadas por IA',
      close: 'Cerrar el asistente', reset: 'Nueva conversación', send: 'Enviar',
      ph: 'Escribe tu pregunta… (Enter para enviar)', ctx: 'Incluir el resultado que tengo en pantalla',
      hello: 'Hola. Puedo explicarte un resultado en palabras sencillas, decirte qué módulo usar o qué hacer después.',
      tryq: 'Prueba con:', thinking: 'Pensando…', you: 'Tú', bot: 'Centinela · IA',
      foot: 'Gratis con Cloudflare Workers AI. No se guarda nada. Verifica lo importante.',
      nobackend: 'El asistente necesita el backend de Centinela. Configúralo en Ajustes → URL del backend.',
      down: 'No se pudo conectar con el asistente. Revisa tu conexión o inténtalo más tarde.',
      off: 'El backend no tiene el asistente activado (falta el binding AI o la clave GROQ_KEY).',
      go: 'Abrir', via: { 'workers-ai': 'Workers AI', groq: 'Groq' }
    },
    en: {
      ask: 'Ask', title: 'Assistant', sub: 'AI-generated guidance',
      close: 'Close the assistant', reset: 'New conversation', send: 'Send',
      ph: 'Type your question… (Enter to send)', ctx: 'Include the result on my screen',
      hello: 'Hi. I can explain a result in plain words, tell you which module to use or what to do next.',
      tryq: 'Try:', thinking: 'Thinking…', you: 'You', bot: 'Centinela · AI',
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

  // ---------- Interfaz ----------
  const ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5.5h16v10H9l-5 4z"/><path d="M8.5 10.5h.01M12 10.5h.01M15.5 10.5h.01"/></svg>';
  const fab = document.createElement('button');
  fab.className = 'asst-fab'; fab.id = 'asstBtn'; fab.type = 'button'; fab.setAttribute('aria-controls', 'asstPanel'); fab.setAttribute('aria-expanded', 'false'); fab.dataset.noi18n = '';
  const panel = document.createElement('section');
  panel.className = 'asst'; panel.id = 'asstPanel'; panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-labelledby', 'asstTitle'); panel.hidden = true; panel.dataset.noi18n = '';
  panel.innerHTML = `
    <header class="asst-head">
      <div><h2 id="asstTitle"></h2><p class="asst-sub"></p></div>
      <button type="button" class="asst-icon" id="asstReset"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12a8 8 0 1 0 2.4-5.7M4 4v4h4"/></svg></button>
      <button type="button" class="asst-icon" id="asstClose"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
    </header>
    <div class="asst-log" id="asstLog" aria-live="polite"></div>
    <form class="asst-form" id="asstForm">
      <label class="asst-ctx"><input type="checkbox" id="asstCtx" checked> <span></span></label>
      <div class="asst-row">
        <textarea id="asstQ" rows="2" maxlength="1500"></textarea>
        <button type="submit" class="asst-send" id="asstSend"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button>
      </div>
      <p class="asst-foot"></p>
    </form>`;
  document.body.appendChild(fab); document.body.appendChild(panel);
  const log = $('#asstLog'), q = $('#asstQ'), form = $('#asstForm'), sendBtn = $('#asstSend');

  let history = [];       // [{role, content}]
  let busy = false, statusChecked = false, ctrl = null;

  function renderChrome() {
    fab.innerHTML = ICON + '<span>' + escH(t('ask')) + '</span>';
    fab.setAttribute('aria-label', t('ask'));
    $('#asstTitle').textContent = t('title');
    panel.querySelector('.asst-sub').textContent = t('sub');
    $('#asstReset').setAttribute('aria-label', t('reset')); $('#asstReset').title = t('reset');
    $('#asstClose').setAttribute('aria-label', t('close')); $('#asstClose').title = t('close');
    panel.querySelector('.asst-ctx span').textContent = t('ctx');
    q.placeholder = t('ph'); q.setAttribute('aria-label', t('ph'));
    sendBtn.setAttribute('aria-label', t('send')); sendBtn.title = t('send');
    panel.querySelector('.asst-foot').textContent = t('foot');
    if (!history.length) renderWelcome();
  }

  function renderWelcome() {
    const l = lang(), m = curMode();
    const list = (SUGG[l][m] || SUGG[l]._);
    log.innerHTML = `<div class="asst-msg bot"><div class="asst-who">${escH(t('bot'))}</div><div class="asst-txt"><p>${escH(t('hello'))}</p></div></div>
      <div class="asst-sugg"><span>${escH(t('tryq'))}</span>${list.map(s => `<button type="button" class="asst-chip">${escH(s)}</button>`).join('')}</div>`;
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

  // keepSugg: los avisos de estado se muestran sin quitar las preguntas sugeridas
  function addMsg(role, html, keepSugg) {
    const sugg = log.querySelector('.asst-sugg'); if (sugg && !keepSugg) sugg.remove();
    const d = document.createElement('div');
    d.className = 'asst-msg ' + (role === 'user' ? 'user' : 'bot');
    d.innerHTML = (role === 'user' ? '' : `<div class="asst-who">${escH(t('bot'))}</div>`) + `<div class="asst-txt">${html}</div>`;
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

  async function ask(text) {
    text = String(text || '').trim();
    if (!text || busy) return;
    const b = backend();
    if (!b) { addMsg('user', '<p>' + escH(text) + '</p>'); addMsg('bot', '<p class="asst-err">' + escH(t('nobackend')) + '</p>'); return; }
    busy = true; sendBtn.disabled = true; q.value = '';
    addMsg('user', '<p>' + escH(text) + '</p>');
    history.push({ role: 'user', content: text });
    const box = addMsg('bot', '<p class="asst-wait">' + escH(t('thinking')) + '</p>');
    const body = { messages: history.slice(-8), lang: lang(),
      context: { module: modName(curMode(), 'es'), summary: $('#asstCtx').checked ? screenSummary() : '' } };
    let answer = '', via = '', err = '';
    try {
      ctrl = new AbortController();
      // text/plain evita la petición previa CORS (preflight); el Worker lee el JSON igualmente
      const r = await fetch(b + '/ai/chat', { method: 'POST', headers: { 'content-type': 'text/plain;charset=UTF-8' }, body: JSON.stringify(body), signal: ctrl.signal });
      if (!r.ok || !r.body) { const j = await r.json().catch(() => ({})); err = (j && j.error) || t('down'); }
      else {
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
    } catch (e) { if (e.name !== 'AbortError') err = t('down'); }
    ctrl = null;
    if (answer) {
      history.push({ role: 'assistant', content: answer });
      if (err) box.insertAdjacentHTML('beforeend', '<p class="asst-err">' + escH(err) + '</p>');
      if (via) box.insertAdjacentHTML('beforeend', '<p class="asst-via">' + escH(T[lang()].via[via] || via) + '</p>');
    } else {
      history.pop();
      box.innerHTML = '<p class="asst-err">' + escH(err || t('down')) + '</p>';
    }
    busy = false; sendBtn.disabled = false; q.focus();
  }

  function open() {
    panel.hidden = false; fab.setAttribute('aria-expanded', 'true'); document.body.classList.add('asst-open');
    if (!history.length) renderWelcome();
    q.focus();
    if (!statusChecked) {
      statusChecked = true;
      checkStatus().then(s => { if (s !== 'ok' && !history.length) addMsg('bot', '<p class="asst-err">' + escH(t(s)) + '</p>', true); if (s !== 'ok') statusChecked = false; });
    }
  }
  function close() { panel.hidden = true; fab.setAttribute('aria-expanded', 'false'); document.body.classList.remove('asst-open'); fab.focus(); }

  fab.addEventListener('click', () => (panel.hidden ? open() : close()));
  $('#asstClose').addEventListener('click', close);
  $('#asstReset').addEventListener('click', () => { if (ctrl) ctrl.abort(); history = []; renderWelcome(); q.focus(); });
  panel.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); close(); } });
  form.addEventListener('submit', e => { e.preventDefault(); ask(q.value); });
  q.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(q.value); } });
  log.addEventListener('click', e => {
    const chip = e.target.closest('.asst-chip'); if (chip) { ask(chip.textContent); return; }
    const go = e.target.closest('.asst-go');
    if (go && typeof setMode === 'function') { setMode(go.dataset.mode); if (window.matchMedia('(max-width:700px)').matches) close(); }
  });
  // Las sugerencias dependen del módulo abierto
  const nav = $('aside.nav');
  if (nav) new MutationObserver(() => { if (!history.length) renderWelcome(); }).observe(nav, { subtree: true, attributes: true, attributeFilter: ['class'] });
  // Idioma: la interfaz se cambia en app.js modificando <html lang>
  new MutationObserver(renderChrome).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
  renderChrome();
  window.centinelaAsk = text => { if (panel.hidden) open(); ask(text); };
})();
