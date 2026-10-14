/* Centinela — módulo "Ataques en Colombia"
   Lee data/colombia.json (lo genera scripts/actualizar-colombia.mjs desde GitHub Actions cada 6 horas a partir de
   ransomware.live) y muestra los ciberataques conocidos en Colombia:
     · Confirmado: la víctima o la prensa informaron el incidente (con la noticia).
     · Reclamado: un grupo de ransomware publicó a la víctima en su sitio de filtraciones (sin confirmar).
     · Confirmado y reclamado: ambas cosas.
   Por incidente: qué se filtró (según el actor o la noticia), actor, sector, credenciales robadas por infostealers,
   noticia y fuentes. Nunca enlaza a sitios de filtración ni muestra datos filtrados. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const escH = s => (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const lang = () => (document.documentElement.lang === 'en' ? 'en' : 'es');
  const PAGE = 20;

  const T = {
    es: {
      title: 'Ataques en Colombia', lede: 'Ciberataques conocidos contra organizaciones colombianas: los confirmados por la víctima o la prensa y los que reclaman grupos de ransomware. Cada incidente detalla qué se filtró, quién se lo adjudica y qué hacer.',
      updated: 'Actualizado', source: 'Fuente', loading: 'Cargando incidentes…', err: 'No se pudieron cargar los datos (data/colombia.json). Si acabas de publicar el sitio, ejecuta la acción "Actualizar ataques en Colombia" en GitHub.',
      t_conf: 'Confirmado', t_recl: 'Reclamado', t_ambos: 'Confirmado y reclamado',
      d_conf: 'La víctima o la prensa informaron el incidente.', d_recl: 'Un grupo de ransomware lo publicó en su sitio de filtraciones. No está confirmado.', d_ambos: 'Hay confirmación pública y un grupo se lo adjudica.',
      k_inc: 'Incidentes', k_conf: 'Confirmados', k_act: 'Grupos activos', k_sec: 'Sector más afectado', k_12: 'últimos 12 meses', none: '—',
      ch_month: 'Incidentes por mes · últimos 24 meses', ch_act: 'Grupos con más víctimas · últimos 12 meses', ch_sec: 'Sectores más afectados · últimos 12 meses', ch_hint: 'Pulsa una barra para filtrar.',
      f_q: 'Buscar víctima o dominio', f_type: 'Tipo', f_per: 'Periodo', f_act: 'Actor', f_sec: 'Sector', all: 'Todos', allf: 'Todas', clear: 'Limpiar filtros',
      p30: 'Últimos 30 días', p90: 'Últimos 90 días', p365: 'Últimos 12 meses', pall: 'Todo el histórico',
      results: n => n === 1 ? '1 incidente' : n + ' incidentes', more: 'Ver más', empty: 'No hay incidentes con estos filtros.',
      leak: '¿Qué se filtró?', leakTypes: 'Tipos de datos mencionados', leakNone: 'No se ha detallado públicamente qué datos se vieron afectados.', vol: 'Volumen que dice tener el actor', ransom: 'Rescate pedido', actorSays: 'Lo que publica el actor (sin verificar)',
      actor: 'Quién se lo adjudica', pubs: 'Publicaciones en sitios de filtración', repub: 'republicó una filtración anterior', newsN: n => n + ' noticias', noActor: 'Ningún grupo se lo ha adjudicado públicamente.', actorN: n => n + (n === 1 ? ' víctima' : ' víctimas') + ' en Colombia en estos datos',
      stealer: 'Credenciales robadas por infostealers', st_emp: 'Empleados', st_usr: 'Usuarios', st_3p: 'Terceros', st_fam: 'Programas espía detectados', st_last: 'Último empleado afectado', st_hint: 'Equipos infectados con programas que roban contraseñas y cuyas credenciales de este dominio circulan en el mercado criminal.',
      news: 'Noticia', newsSum: 'Resumen de la fuente (puede estar en otro idioma)', sources: 'Fuentes',
      a_ai: 'Explicar con IA', a_case: 'Añadir a un caso', a_dom: 'Revisar el dominio', a_leak: 'Buscar filtraciones', a_open: 'Ver detalle', date: 'Fecha', detected: 'Detectado',
      exp_csv: 'Exportar CSV', exp_json: 'Exportar JSON',
      note: 'Las reclamaciones de grupos criminales no están confirmadas y pueden ser falsas o exageradas. Centinela no enlaza a sitios de filtración ni muestra datos filtrados. Los tipos de datos se detectan por palabras clave en la descripción del actor o la noticia: son orientativos.',
      aiQ: it => `Explícame en palabras sencillas este incidente de ciberseguridad en Colombia y qué deberían hacer la organización afectada y sus clientes:\n- Víctima: ${it.victima}${it.dominio ? ' (' + it.dominio + ')' : ''}\n- Sector: ${it.sector}\n- Fecha: ${it.fecha || 'desconocida'}\n- Estado: ${it.tipo === 'reclamado' ? 'reclamado por un grupo de ransomware, sin confirmar' : it.tipo === 'ambos' ? 'confirmado y reclamado por un grupo' : 'confirmado por la víctima o la prensa'}\n- Actores: ${actoresDe(it).join(', ') || 'ninguno conocido'}\n- Datos mencionados: ${it.filtracion.tipos.join(', ') || 'sin detallar'}${it.filtracion.volumen ? '\n- Volumen reclamado: ' + it.filtracion.volumen : ''}${it.infostealer ? '\n- Credenciales en infostealers: ' + it.infostealer.empleados + ' empleados, ' + it.infostealer.usuarios + ' usuarios' : ''}${it.noticia && it.noticia.resumen ? '\n- Resumen de la noticia: ' + it.noticia.resumen : ''}`,
    },
    en: {
      title: 'Attacks in Colombia', lede: 'Known cyberattacks against Colombian organizations: those confirmed by the victim or the press, and those claimed by ransomware groups. Each incident details what leaked, who claims it and what to do.',
      updated: 'Updated', source: 'Source', loading: 'Loading incidents…', err: 'Could not load the data (data/colombia.json). If you just published the site, run the "Actualizar ataques en Colombia" action on GitHub.',
      t_conf: 'Confirmed', t_recl: 'Claimed', t_ambos: 'Confirmed and claimed',
      d_conf: 'The victim or the press reported the incident.', d_recl: 'A ransomware group posted it on its leak site. Not confirmed.', d_ambos: 'There is public confirmation and a group claims it.',
      k_inc: 'Incidents', k_conf: 'Confirmed', k_act: 'Active groups', k_sec: 'Most affected sector', k_12: 'last 12 months', none: '—',
      ch_month: 'Incidents per month · last 24 months', ch_act: 'Groups with most victims · last 12 months', ch_sec: 'Most affected sectors · last 12 months', ch_hint: 'Click a bar to filter.',
      f_q: 'Search victim or domain', f_type: 'Type', f_per: 'Period', f_act: 'Actor', f_sec: 'Sector', all: 'All', allf: 'All', clear: 'Clear filters',
      p30: 'Last 30 days', p90: 'Last 90 days', p365: 'Last 12 months', pall: 'All time',
      results: n => n === 1 ? '1 incident' : n + ' incidents', more: 'Show more', empty: 'No incidents match these filters.',
      leak: 'What leaked?', leakTypes: 'Data types mentioned', leakNone: 'What data was affected has not been publicly detailed.', vol: 'Volume the actor claims', ransom: 'Ransom demanded', actorSays: 'What the actor posts (unverified)',
      actor: 'Who claims it', pubs: 'Leak-site posts', repub: 're-posted an earlier leak', newsN: n => n + ' news reports', noActor: 'No group has publicly claimed it.', actorN: n => n + (n === 1 ? ' victim' : ' victims') + ' in Colombia in this data',
      stealer: 'Credentials stolen by infostealers', st_emp: 'Employees', st_usr: 'Users', st_3p: 'Third parties', st_fam: 'Infostealer families detected', st_last: 'Last employee affected', st_hint: 'Computers infected with password-stealing malware whose credentials for this domain circulate on criminal markets.',
      news: 'News', newsSum: 'Source summary (may be in another language)', sources: 'Sources',
      a_ai: 'Explain with AI', a_case: 'Add to a case', a_dom: 'Check the domain', a_leak: 'Search leaks', a_open: 'See details', date: 'Date', detected: 'Detected',
      exp_csv: 'Export CSV', exp_json: 'Export JSON',
      note: 'Claims by criminal groups are unconfirmed and may be false or exaggerated. Centinela does not link to leak sites or show leaked data. Data types are detected from keywords in the actor\'s description or the news: they are indicative.',
      aiQ: it => `Explain in plain words this cybersecurity incident in Colombia and what the affected organization and its customers should do:\n- Victim: ${it.victima}${it.dominio ? ' (' + it.dominio + ')' : ''}\n- Sector: ${it.sector}\n- Date: ${it.fecha || 'unknown'}\n- Status: ${it.tipo === 'reclamado' ? 'claimed by a ransomware group, unconfirmed' : it.tipo === 'ambos' ? 'confirmed and claimed by a group' : 'confirmed by the victim or the press'}\n- Actors: ${actoresDe(it).join(', ') || 'none known'}\n- Data mentioned: ${it.filtracion.tipos.join(', ') || 'not detailed'}${it.filtracion.volumen ? '\n- Claimed volume: ' + it.filtracion.volumen : ''}${it.infostealer ? '\n- Infostealer credentials: ' + it.infostealer.empleados + ' employees, ' + it.infostealer.usuarios + ' users' : ''}${it.noticia && it.noticia.resumen ? '\n- News summary: ' + it.noticia.resumen : ''}`,
    },
  };
  const t = k => T[lang()][k];
  const EN_TERMS = { 'Servicios profesionales': 'Professional services', 'Manufactura': 'Manufacturing', 'Tecnología': 'Technology', 'Agro y alimentos': 'Agriculture & food',
    'Servicios financieros': 'Financial services', 'Transporte': 'Transportation', 'Energía y servicios públicos': 'Energy & utilities', 'Salud': 'Healthcare',
    'Gobierno y defensa': 'Government & defense', 'Comercio': 'Retail', 'Educación': 'Education', 'Turismo y hotelería': 'Hospitality', 'Telecomunicaciones': 'Telecommunications',
    'Construcción': 'Construction', 'Servicios empresariales': 'Business services', 'Servicios al consumidor': 'Consumer services', 'Sector público': 'Public sector', 'Medios': 'Media',
    'Legal': 'Legal', 'Sin clasificar': 'Unclassified', 'Otro': 'Other', 'Datos personales': 'Personal data', 'Datos de empleados': 'Employee data',
    'Datos de clientes o usuarios': 'Customer or user data', 'Documentos de identidad': 'ID documents', 'Datos financieros o tributarios': 'Financial or tax data',
    'Datos médicos': 'Medical data', 'Contratos y documentos legales': 'Contracts and legal documents', 'Bases de datos': 'Databases', 'Correos electrónicos': 'Emails',
    'Credenciales': 'Credentials', 'Planos y propiedad intelectual': 'Blueprints and intellectual property', 'Noticia': 'News', 'Ficha en ransomware.live': 'ransomware.live entry',
    'Reclamación en ransomware.live': 'Claim on ransomware.live', 'Perfil del grupo en ransomware.live': 'Group profile on ransomware.live', 'Desconocida': 'Unknown' };
  const tr = s => (lang() === 'en' && EN_TERMS[s]) || s;
  const typeLabel = ty => t(ty === 'confirmado' ? 't_conf' : ty === 'reclamado' ? 't_recl' : 't_ambos');
  const fmtDate = d => { if (!d) return '—'; try { return new Date(d + 'T12:00:00Z').toLocaleDateString(lang() === 'en' ? 'en-US' : 'es-CO', { day: 'numeric', month: 'short', year: 'numeric' }); } catch (e) { return d; } };
  const fmtN = n => Number(n || 0).toLocaleString(lang() === 'en' ? 'en-US' : 'es-CO');
  const daysAgo = d => d ? (Date.now() - new Date(d + 'T12:00:00Z')) / 864e5 : Infinity;

  const actoresDe = it => (Array.isArray(it.actores) && it.actores.length ? it.actores : it.actor ? [it.actor] : []);
  const S = { data: null, err: false, loading: false, f: { q: '', type: 'all', per: '365', actor: '', sector: '' }, shown: PAGE };
  const out = () => $('#coOut');

  async function load() {
    if (S.data || S.loading) return;
    S.loading = true; render();
    try {
      const r = await fetch('./data/colombia.json', { cache: 'no-cache' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const j = await r.json();
      if (!j || !Array.isArray(j.incidentes)) throw new Error('formato');
      S.data = j; S.err = false;
    } catch (e) { S.err = true; }
    S.loading = false; render();
  }

  function filtered() {
    const f = S.f, q = f.q.trim().toLowerCase();
    return S.data.incidentes.filter(it =>
      (f.type === 'all' || (f.type === 'confirmado' ? it.tipo !== 'reclamado' : it.tipo !== 'confirmado')) &&
      (f.per === 'all' || daysAgo(it.fecha) <= +f.per) &&
      (!f.actor || actoresDe(it).includes(f.actor)) && (!f.sector || it.sector === f.sector) &&
      (!q || (it.victima + ' ' + (it.dominio || '')).toLowerCase().includes(q)));
  }
  // key puede devolver varios valores (un incidente con varios actores cuenta una vez para cada uno)
  const countBy = (arr, key) => { const m = new Map(); arr.forEach(it => { [].concat(key(it) || []).forEach(k => { if (k) m.set(k, (m.get(k) || 0) + 1); }); }); return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])); };

  // ---------- Gráficos (una sola serie: un tono, sin leyenda; tooltip al pasar o enfocar) ----------
  function monthChart(all) {
    const now = new Date(); const months = [];
    for (let i = 23; i >= 0; i--) { const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1)); months.push(d.toISOString().slice(0, 7)); }
    const cnt = new Map(months.map(m => [m, 0]));
    all.forEach(it => { const m = (it.fecha || '').slice(0, 7); if (cnt.has(m)) cnt.set(m, cnt.get(m) + 1); });
    const max = Math.max(1, ...cnt.values());
    const fmtM = m => new Date(m + '-15T12:00:00Z').toLocaleDateString(lang() === 'en' ? 'en-US' : 'es-CO', { month: 'short', year: '2-digit' });
    const peak = [...cnt.entries()].reduce((a, b) => (b[1] > a[1] ? b : a));
    return `<figure class="co-fig"><figcaption>${escH(t('ch_month'))}</figcaption>
      <div class="co-cols" role="list">${months.map(m => { const v = cnt.get(m); const lbl = fmtM(m) + ': ' + t('results')(v);
        return `<div class="co-col" role="listitem" tabindex="0" data-tip="${escH(lbl)}" aria-label="${escH(lbl)}"><span data-s="--h:${(v / max * 100).toFixed(1)}%"></span></div>`; }).join('')}</div>
      <div class="co-axis"><span>${escH(fmtM(months[0]))}</span><span>${escH(t('k_12').replace(/^./, c => c.toUpperCase()))}: ${fmtN([...cnt.entries()].slice(-12).reduce((s, x) => s + x[1], 0))} · ${escH('max ' + fmtM(peak[0]) + ' (' + peak[1] + ')')}</span><span>${escH(fmtM(months[23]))}</span></div></figure>`;
  }
  function barList(title, rows, kind) {
    if (!rows.length) return '';
    const max = rows[0][1];
    return `<figure class="co-fig"><figcaption>${escH(title)}</figcaption><div class="co-bars">${rows.map(([k, v]) => {
      const lbl = tr(k) + ': ' + t('results')(v);
      return `<button type="button" class="co-bar" data-f="${kind}" data-v="${escH(k)}" data-tip="${escH(lbl)}" aria-label="${escH(lbl)}" aria-pressed="${S.f[kind] === k}">
        <span class="co-bar-l">${escH(tr(k))}</span><span class="co-bar-t"><span data-s="--w:${(v / max * 100).toFixed(1)}%"></span></span><span class="co-bar-v">${v}</span></button>`; }).join('')}</div>
      <p class="co-hint">${escH(t('ch_hint'))}</p></figure>`;
  }

  // ---------- Incidente ----------
  function badge(ty) { return `<span class="co-badge co-${ty}">${escH(typeLabel(ty))}</span>`; }
  function incident(it, actorCounts) {
    const L = lang(), fl = it.filtracion || {}, st = it.infostealer, nw = it.noticia;
    const leakBlock = `<section><h4>${escH(t('leak'))}</h4>
      ${fl.tipos && fl.tipos.length ? `<p class="co-lbl">${escH(t('leakTypes'))}</p><div class="co-tags">${fl.tipos.map(x => `<span class="co-tag">${escH(tr(x))}</span>`).join('')}</div>` : `<p class="co-muted">${escH(t('leakNone'))}</p>`}
      ${fl.volumen || fl.rescate ? `<dl class="co-dl">${fl.volumen ? `<div><dt>${escH(t('vol'))}</dt><dd class="co-data">${escH(fl.volumen)}</dd></div>` : ''}${fl.rescate ? `<div><dt>${escH(t('ransom'))}</dt><dd class="co-data">${escH(fl.rescate)}</dd></div>` : ''}</dl>` : ''}
      ${fl.descripcion ? `<p class="co-lbl">${escH(t('actorSays'))}</p><blockquote class="co-data">${escH(fl.descripcion)}</blockquote>` : ''}</section>`;
    const acts = actoresDe(it), pubs = Array.isArray(it.publicaciones) ? it.publicaciones : [];
    const actorBlock = `<section><h4>${escH(t('actor'))}</h4>${acts.length
      ? acts.map(a => `<p><span class="co-actor co-data">${escH(a)}</span> <span class="co-muted">${escH(t('actorN')(actorCounts.get(a) || 1))}</span></p>`).join('')
        + (pubs.length > 1 ? `<p class="co-lbl">${escH(t('pubs'))}</p><ol class="co-timeline">${pubs.map(p => `<li><span class="co-mono">${escH(fmtDate(p.fecha))}</span> <span class="co-data">${escH(p.actor || '—')}</span>${p.republicacion ? ` <span class="co-muted">· ${escH(t('repub'))}</span>` : ''}</li>`).join('')}</ol>` : '')
      : `<p class="co-muted">${escH(t('noActor'))}</p>`}</section>`;
    const stBlock = st ? `<section><h4>${escH(t('stealer'))}</h4><p class="co-muted">${escH(t('st_hint'))}</p>
      <dl class="co-dl co-nums"><div><dt>${escH(t('st_emp'))}</dt><dd>${fmtN(st.empleados)}</dd></div><div><dt>${escH(t('st_usr'))}</dt><dd>${fmtN(st.usuarios)}</dd></div><div><dt>${escH(t('st_3p'))}</dt><dd>${fmtN(st.terceros)}</dd></div>${st.ultimoEmpleado ? `<div class="co-dl-date"><dt>${escH(t('st_last'))}</dt><dd>${escH(fmtDate(st.ultimoEmpleado))}</dd></div>` : ''}</dl>
      ${st.familias && st.familias.length ? `<p class="co-lbl">${escH(t('st_fam'))}</p><div class="co-tags">${st.familias.slice(0, 6).map(f => `<span class="co-tag co-mono">${escH(tr(f.familia))} · ${fmtN(f.equipos)}</span>`).join('')}</div>` : ''}</section>` : '';
    const nws = Array.isArray(it.noticias) && it.noticias.length ? it.noticias : nw ? [nw] : [];
    const newsBlock = nw && (nw.titulo || nw.resumen) ? `<section><h4>${escH(nws.length > 1 ? t('newsN')(nws.length) : t('news'))}</h4>${nws.filter(n => n.titulo).map(n => `<p class="co-news co-data">${n.url ? `<a href="${escH(n.url)}" target="_blank" rel="noopener noreferrer">${escH(n.titulo)}</a>` : escH(n.titulo)}</p>`).join('')}
      ${nw.resumen ? `<p class="co-lbl">${escH(t('newsSum'))}</p><blockquote class="co-data">${escH(nw.resumen)}</blockquote>` : ''}</section>` : '';
    const src = (it.fuentes || []).filter(s => /^https:\/\//.test(s.url));
    const srcBlock = src.length ? `<section><h4>${escH(t('sources'))}</h4><ul class="co-src">${src.map(s => `<li><a href="${escH(s.url)}" target="_blank" rel="noopener noreferrer">${escH(tr(s.nombre))}</a></li>`).join('')}</ul></section>` : '';
    return `<details class="co-inc" data-id="${escH(it.id)}">
      <summary>
        <span class="co-date"><span class="co-mono">${escH(fmtDate(it.fecha))}</span></span>
        <span class="co-main"><b class="co-data">${escH(it.victima)}</b>${it.dominio ? ` <span class="co-dom co-mono co-data">${escH(it.dominio)}</span>` : ''}
          <span class="co-meta">${badge(it.tipo)}<span>${escH(tr(it.sector))}</span>${acts.slice(0, 2).map(a => `<span class="co-actor co-data">${escH(a)}</span>`).join('')}${acts.length > 2 ? `<span class="co-muted">+${acts.length - 2}</span>` : ''}${fl.tipos && fl.tipos.length ? `<span class="co-muted">${escH(fl.tipos.slice(0, 2).map(tr).join(' · '))}${fl.tipos.length > 2 ? ' +' + (fl.tipos.length - 2) : ''}</span>` : ''}</span></span>
        <span class="co-chev" aria-hidden="true"></span>
      </summary>
      <div class="co-body">
        <div class="co-grid">${leakBlock}${actorBlock}${stBlock}${newsBlock}${srcBlock}</div>
        <div class="co-actions">
          <button type="button" class="btn ghost" data-act="ai">${escH(t('a_ai'))}</button>
          <button type="button" class="btn ghost" data-act="case">${escH(t('a_case'))}</button>
          ${it.dominio ? `<button type="button" class="btn ghost" data-act="dom">${escH(t('a_dom'))}</button><button type="button" class="btn ghost" data-act="leak">${escH(t('a_leak'))}</button>` : ''}
        </div>
      </div></details>`;
  }

  function render() {
    const o = out(); if (!o) return;
    const L = lang();
    const head = `<div class="glass co-head"><h2>${escH(t('title'))}</h2><p class="co-lede">${escH(t('lede'))}</p>
      ${S.data ? `<p class="co-src-line co-mono">${escH(t('updated'))}: ${escH(new Date(S.data.generado).toLocaleString(L === 'en' ? 'en-US' : 'es-CO', { dateStyle: 'medium', timeStyle: 'short' }))} · ${escH(t('source'))}: <a href="${escH(S.data.fuente.url)}" target="_blank" rel="noopener noreferrer">${escH(S.data.fuente.nombre)}</a></p>` : ''}
      <ul class="co-legend">${['confirmado', 'reclamado', 'ambos'].map(ty => `<li>${badge(ty)}<span>${escH(t(ty === 'confirmado' ? 'd_conf' : ty === 'reclamado' ? 'd_recl' : 'd_ambos'))}</span></li>`).join('')}</ul></div>`;
    if (!S.data) { o.innerHTML = head + `<div class="glass co-state" role="status">${S.err ? `<p class="co-err">${escH(t('err'))}</p>` : `<span class="spinner"></span><span>${escH(t('loading'))}</span>`}</div>`; return; }

    const all = S.data.incidentes, y1 = all.filter(it => daysAgo(it.fecha) <= 365);
    const actorsY = countBy(y1, actoresDe), sectorsY = countBy(y1, it => it.sector !== 'Sin clasificar' ? it.sector : null);
    const actorCounts = new Map(countBy(all, actoresDe));
    // Las cifras cuentan hasta su valor solo la primera vez (app.js); al redibujar se muestran ya fijas
    const fixed = S.kpiShown ? ' data-counted="1"' : ''; S.kpiShown = true;
    const kpis = `<div class="co-kpis">
      <div class="kpi"><b${fixed}>${fmtN(y1.length)}</b><span>${escH(t('k_inc'))} · ${escH(t('k_12'))}</span></div>
      <div class="kpi"><b${fixed}>${fmtN(y1.filter(i => i.tipo !== 'reclamado').length)}</b><span>${escH(t('k_conf'))} · ${escH(t('k_12'))}</span></div>
      <div class="kpi"><b${fixed}>${fmtN(actorsY.length)}</b><span>${escH(t('k_act'))} · ${escH(t('k_12'))}</span></div>
      <div class="kpi co-kpi-txt"><b${fixed}>${escH(sectorsY[0] ? tr(sectorsY[0][0]) : t('none'))}</b><span>${escH(t('k_sec'))}${sectorsY[0] ? ' · ' + t('results')(sectorsY[0][1]) : ''}</span></div></div>`;
    const charts = `<div class="glass co-charts">${monthChart(all)}<div class="co-two">${barList(t('ch_act'), actorsY.slice(0, 8), 'actor')}${barList(t('ch_sec'), sectorsY.slice(0, 8), 'sector')}</div></div>`;

    const f = S.f;
    const opt = (v, label, cur) => `<option value="${escH(v)}"${v === cur ? ' selected' : ''}>${escH(label)}</option>`;
    const actorsAll = countBy(all, actoresDe).map(x => x[0]).sort((a, b) => a.localeCompare(b));
    const sectorsAll = countBy(all, it => it.sector).map(x => x[0]).sort((a, b) => tr(a).localeCompare(tr(b)));
    const filters = `<div class="glass co-filters" role="search">
      <div class="field grow"><label for="coQ">${escH(t('f_q'))}</label><input type="text" id="coQ" value="${escH(f.q)}" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="coType">${escH(t('f_type'))}</label><select id="coType">${opt('all', t('all'), f.type)}${opt('confirmado', t('t_conf'), f.type)}${opt('reclamado', t('t_recl'), f.type)}</select></div>
      <div class="field"><label for="coPer">${escH(t('f_per'))}</label><select id="coPer">${opt('30', t('p30'), f.per)}${opt('90', t('p90'), f.per)}${opt('365', t('p365'), f.per)}${opt('all', t('pall'), f.per)}</select></div>
      <div class="field"><label for="coActor">${escH(t('f_act'))}</label><select id="coActor">${opt('', t('all'), f.actor)}${actorsAll.map(a => opt(a, a, f.actor)).join('')}</select></div>
      <div class="field"><label for="coSector">${escH(t('f_sec'))}</label><select id="coSector">${opt('', t('allf'), f.sector)}${sectorsAll.map(s => opt(s, tr(s), f.sector)).join('')}</select></div>
    </div>`;
    const list = filtered();
    const rows = list.slice(0, S.shown).map(it => incident(it, actorCounts)).join('');
    const listHtml = `<div class="co-listhead"><p class="co-count" role="status" aria-live="polite">${escH(t('results')(list.length))}</p>
        <div class="co-tools"><button type="button" class="btn ghost" data-act="clear">${escH(t('clear'))}</button><button type="button" class="btn ghost" data-act="csv">${escH(t('exp_csv'))}</button><button type="button" class="btn ghost" data-act="json">${escH(t('exp_json'))}</button></div></div>
      <div class="co-list">${rows || `<p class="glass co-state">${escH(t('empty'))}</p>`}</div>
      ${list.length > S.shown ? `<div class="co-morewrap"><button type="button" class="btn ghost" data-act="more">${escH(t('more'))} (${fmtN(list.length - S.shown)})</button></div>` : ''}
      <p class="hint co-note">${escH(t('note'))}</p>`;
    // Conservar foco y posición del cursor si se está escribiendo en el buscador
    const ae = document.activeElement, keep = ae && ae.id === 'coQ' ? ae.selectionStart : null;
    o.innerHTML = head + kpis + charts + filters + listHtml;
    if (keep !== null) { const q = $('#coQ'); q.focus(); try { q.setSelectionRange(keep, keep); } catch (e) {} }
  }

  function itemById(id) { return S.data && S.data.incidentes.find(x => x.id === id); }
  function csvCell(v) { v = v == null ? '' : String(v); return /[",\n;]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function exportData(kind) {
    const list = filtered(), stamp = new Date().toISOString().slice(0, 10);
    const save = (name, text, type) => { if (typeof downloadFile === 'function') downloadFile(name, text, type); };
    if (kind === 'json') { save('centinela-ataques-colombia-' + stamp + '.json', JSON.stringify({ tool: 'Centinela', type: 'colombia-incidents', generated: new Date().toISOString(), source: S.data.fuente, filters: S.f, incidents: list }, null, 2), 'application/json'); return; }
    const head = ['fecha', 'tipo', 'victima', 'dominio', 'sector', 'actores', 'tipos_de_datos', 'volumen', 'rescate', 'infostealer_empleados', 'infostealer_usuarios', 'noticia', 'url_noticia'];
    const lines = [head.join(',')].concat(list.map(it => [it.fecha, it.tipo, it.victima, it.dominio, it.sector, actoresDe(it).join(' | '), it.filtracion.tipos.join(' | '), it.filtracion.volumen, it.filtracion.rescate,
      it.infostealer ? it.infostealer.empleados : '', it.infostealer ? it.infostealer.usuarios : '', it.noticia ? it.noticia.titulo : '', it.noticia ? it.noticia.url : ''].map(csvCell).join(',')));
    save('centinela-ataques-colombia-' + stamp + '.csv', '﻿' + lines.join('\n'), 'text/csv');
  }

  // ---------- Eventos (delegación sobre el contenedor) ----------
  let qTimer = null;
  function bind() {
    const o = out(); if (!o || o._bound) return; o._bound = true;
    o.addEventListener('input', e => {
      if (e.target.id !== 'coQ') return;
      clearTimeout(qTimer); const v = e.target.value; qTimer = setTimeout(() => { S.f.q = v; S.shown = PAGE; render(); }, 200);
    });
    o.addEventListener('change', e => {
      const map = { coType: 'type', coPer: 'per', coActor: 'actor', coSector: 'sector' }; const k = map[e.target.id]; if (!k) return;
      S.f[k] = e.target.value; S.shown = PAGE; render();
    });
    o.addEventListener('click', e => {
      const bar = e.target.closest('.co-bar');
      if (bar) { const k = bar.dataset.f, v = bar.dataset.v; S.f[k] = S.f[k] === v ? '' : v; if (S.f.per !== 'all' && S.f.per !== '365') S.f.per = '365'; S.shown = PAGE; render(); const l = $('#coOut .co-listhead'); if (l) l.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
      const b = e.target.closest('[data-act]'); if (!b) return;
      const act = b.dataset.act;
      if (act === 'more') { S.shown += PAGE; render(); return; }
      if (act === 'clear') { S.f = { q: '', type: 'all', per: 'all', actor: '', sector: '' }; S.shown = PAGE; render(); return; }
      if (act === 'csv' || act === 'json') { exportData(act); return; }
      const det = b.closest('.co-inc'); const it = det && itemById(det.dataset.id); if (!it) return;
      if (act === 'ai') { if (typeof window.centinelaAsk === 'function') { const c = $('#asstCtx'); if (c) c.checked = false; window.centinelaAsk(t('aiQ')(it)); } return; }
      if (act === 'case' && typeof caseAddDialog === 'function') {
        caseAddDialog({ kind: 'incident', title: it.victima + (it.dominio ? ' (' + it.dominio + ')' : ''),
          summary: [typeLabel(it.tipo), it.fecha, actoresDe(it).join(', '), it.filtracion.tipos.join(', ')].filter(Boolean).join(' · '),
          data: { fecha: it.fecha, tipo: it.tipo, victima: it.victima, dominio: it.dominio, sector: it.sector, actores: actoresDe(it), publicaciones: it.publicaciones, filtracion: it.filtracion, infostealer: it.infostealer, noticia: it.noticia, fuentes: it.fuentes } });
        return;
      }
      if (act === 'dom' && typeof setMode === 'function') { setMode('domain'); const d = $('#domain'); if (d) { d.value = it.dominio; const g = $('#go'); if (g) g.click(); } window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
      if (act === 'leak' && typeof setMode === 'function') { setMode('leak'); if (typeof leakTab === 'function') leakTab('entity'); const d = $('#leakEntity'); if (d) d.value = it.dominio; window.scrollTo({ top: 0, behavior: 'smooth' }); }
    });
    // Tooltip de los gráficos (ratón y teclado)
    const tip = document.createElement('div'); tip.className = 'co-tip'; tip.setAttribute('role', 'tooltip'); tip.hidden = true; document.body.appendChild(tip);
    const show = el => { const r = el.getBoundingClientRect(); tip.textContent = el.dataset.tip; tip.hidden = false;
      const w = tip.offsetWidth; tip.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2)) + 'px'; tip.style.top = Math.max(8, r.top - tip.offsetHeight - 8) + 'px'; };
    o.addEventListener('mouseover', e => { const el = e.target.closest('[data-tip]'); if (el) show(el); });
    o.addEventListener('mouseout', e => { if (e.target.closest('[data-tip]')) tip.hidden = true; });
    o.addEventListener('focusin', e => { const el = e.target.closest('[data-tip]'); if (el) show(el); else tip.hidden = true; });
    o.addEventListener('focusout', () => { tip.hidden = true; });
    window.addEventListener('scroll', () => { tip.hidden = true; }, { passive: true });
  }

  window.renderColombia = function () { bind(); if (!S.data) load(); else render(); };
  const btn = $('#mbColombia'); if (btn && typeof setMode === 'function') btn.addEventListener('click', () => setMode('colombia'));
  new MutationObserver(() => { const o = out(); if (o && o._bound) render(); })
    .observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
})();
