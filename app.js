/* Centinela — lógica de la aplicación.
   Se carga al final de index.html (tras el marcado) y funciona con una CSP sin 'unsafe-inline'. */
"use strict";
/* Iconos: referencia al sprite SVG del inicio del <body> */
const ico=(n,cls='i')=>`<svg class="${cls}" aria-hidden="true"><use href="#i-${n}"/></svg>`;
const SECTION_ICON={'SPF':'mail','DKIM':'key','DMARC':'shield-check','MX':'inbox','Listas negras':'ban','WHOIS / RDAP':'book','CAA':'file','MTA-STS':'lock','TLS-RPT':'chart','BIMI':'image','DNSSEC':'shield','DNS inverso (PTR)':'undo','Registros TXT':'note','Certificados TLS (CT)':'file','Geolocalización & ASN':'globe','DANE / TLSA':'link','Riesgo de suplantación':'user-x','DNS base':'server'};
/* ============================================================
   Núcleo DNS: consultas DNS-over-HTTPS con respaldo entre resolutores (todo en el navegador)
   ============================================================ */
const TYPES={A:1,NS:2,CNAME:5,SOA:6,PTR:12,MX:15,TXT:16,AAAA:28,DS:43,DNSKEY:48,TLSA:52,CAA:257};
const cache=new Map();
const RESOLVERS={
  google:{name:'Google',u:(n,t)=>`https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}&do=1`},
  cloudflare:{name:'Cloudflare',u:(n,t)=>`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}&do=1`},
  // Quad9 no envía de forma consistente la cabecera CORS y el navegador bloquea sus respuestas; DNS.SB (sin registros) sí
  dnssb:{name:'DNS.SB',u:(n,t)=>`https://doh.dns.sb/dns-query?name=${encodeURIComponent(n)}&type=${t}&do=1`},
};
let RESOLVER='auto', USED_RESOLVERS=new Set();

async function doh(key,name,type){
  const r=await fetch(RESOLVERS[key].u(name,type),{headers:{'Accept':'application/dns-json'}});
  if(!r.ok) throw new Error(RESOLVERS[key].name+' '+r.status);
  USED_RESOLVERS.add(RESOLVERS[key].name);
  return r.json();
}
async function rawQuery(name,type){
  if(RESOLVER!=='auto') return doh(RESOLVER,name,type);
  const chain=['google','cloudflare','dnssb'];
  let lastErr;
  for(const k of chain){ try{ return await doh(k,name,type); }catch(e){ lastErr=e; } }
  throw lastErr||new Error('todos los resolutores fallaron');
}
async function query(name,typeName){
  const key=typeName+':'+name.toLowerCase();
  if(cache.has(key)) return cache.get(key);
  const type=TYPES[typeName]; let res;
  try{
    const j=await rawQuery(name,type);
    const ans=j.Answer||[];
    const answers=ans.filter(a=>a.type===type).map(a=>({data:clean(a.data,type),ttl:a.TTL}));
    const cnames=ans.filter(a=>a.type===TYPES.CNAME).map(a=>a.data.replace(/\.$/,''));
    res={status:j.Status,ad:!!j.AD,answers,cnames,ok:true,name};
  }catch(err){ res={status:-1,ad:false,answers:[],cnames:[],ok:false,error:String(err.message||err),name}; }
  cache.set(key,res); return res;
}
function clean(data,type){
  if(type===TYPES.TXT||type===TYPES.CAA){
    let s=data.trim(); if(s.includes('" "'))s=s.replace(/" "/g,''); return s.replace(/^"|"$/g,'');
  }
  return data.replace(/\.$/,'');
}
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
const F=(sev,title,why)=>({sev,title,why});
const tag=(t,c)=>`<span class="tag ${c||''}">${esc(t)}</span>`;
function raw(txt){return `<div class="raw"><span class="copy" data-copy="${esc(txt)}">copiar</span>${esc(txt)}</div>`;}

let ITEMS=[], REPORT={};
function finalize(name,status,subtitle,cat,findings,kv,record,noScore){
  const icon=ico(SECTION_ICON[name]||'shield');
  const it={name,status,icon,subtitle,cat,findings,kv,record,noScore};
  ITEMS.push(it);
  REPORT[name]={status,record,findings:findings.map(f=>({sev:f.sev,title:f.title}))};
  return it;
}
function deriveStatus(findings,fallback){
  if(findings.some(f=>f.sev==='fail'))return'fail';
  if(findings.some(f=>f.sev==='warn'))return'warn';
  if(findings.some(f=>f.sev==='ok'))return'ok';
  return fallback||'neutral';
}

/* ============================================================ SPF */
async function checkSPF(d){
  const q=await query(d,'TXT');
  const recs=q.answers.map(a=>a.data).filter(x=>/^v=spf1\b/i.test(x));
  const f=[];
  if(!recs.length){f.push(F('fail','No se encontró registro SPF','Sin SPF cualquier servidor puede enviar correo en nombre del dominio.'));return finalize('SPF','fail','Marco de políticas de envío (RFC 7208)','correo',f,{},null);}
  if(recs.length>1)f.push(F('fail','Hay '+recs.length+' registros SPF','El estándar permite solo uno; con varios se produce PermError.'));
  const rec=recs[0], mechs=rec.trim().split(/\s+/).slice(1);
  const allM=mechs.find(m=>/all$/i.test(m))||'', qual=allM.charAt(0);
  const map={'-':['ok','-all (hardfail): el correo no autorizado se rechaza. Óptimo.'],'~':['warn','~all (softfail): se marca pero puede entregarse. Endurece a -all.'],'?':['warn','?all (neutral): no ofrece protección real.'],'+':['fail','+all: autoriza a CUALQUIER servidor. Elimínalo de inmediato.']};
  if(allM){const[s,m]=map[qual]||map['+'];f.push(F(s,'Mecanismo final: '+allM,m));}
  else f.push(F('warn','Falta el mecanismo "all"','Añade -all o ~all al final del registro.'));
  const tree=[],seen=new Set(),acc={n:0,void:0};
  await countLk(d,rec,0,tree,seen,acc);
  if(acc.n>10)f.push(F('fail','Consultas DNS: '+acc.n+' de 10 (LÍMITE EXCEDIDO)','Supera el máximo del RFC → PermError → el SPF se ignora. Reduce includes o aplana IPs.'));
  else if(acc.n>=8)f.push(F('warn','Consultas DNS: '+acc.n+' de 10','Cerca del límite; considera aplanar registros.'));
  else f.push(F('ok','Consultas DNS: '+acc.n+' de 10','Dentro del límite permitido.'));
  if(acc.void>=1)f.push(F('warn','Void lookups: '+acc.void,'Includes que no resuelven; más de 2 provoca PermError.'));
  if(mechs.some(m=>/^ptr(:|$)/i.test(m)))f.push(F('warn','Uso de "ptr"','Mecanismo obsoleto y lento (RFC 7208 §5.5); elimínalo.'));
  const incs=mechs.filter(m=>/^include:/i.test(m)).map(m=>m.slice(8));
  const ips=mechs.filter(m=>/^ip[46]:/i.test(m));
  const status=deriveStatus(f);
  const kv={'Registro SPF':raw(rec),'Mecanismo final':allM?tag(allM,qual==='-'?'g':(qual==='+'?'r':'y')):tag('(ninguno)','r'),
    'Consultas DNS':`<b>${acc.n}</b> / 10${acc.void?` · ${tag(acc.void+' void','y')}`:''}`,
    ['Includes ('+incs.length+')']:incs.length?incs.map(i=>tag(i)).join(''):'—',
    'Rangos IP directos':(ips.length||0)+' entradas ip4/ip6',
    'Árbol de resolución':`<div class="lookup-tree">${esc(tree.join('\n'))}</div>`};
  return finalize('SPF',status,'Marco de políticas de envío (RFC 7208)','correo',f,kv,rec);
}
async function countLk(d,rec,depth,tree,seen,acc){
  if(depth>10)return;
  for(const m of rec.trim().split(/\s+/)){
    const l=m.toLowerCase();let tgt=null,kind=null;
    if(l.startsWith('include:')){kind='include';tgt=m.slice(8);}
    else if(l.startsWith('redirect=')){kind='redirect';tgt=m.slice(9);}
    else if(l==='a'||l.startsWith('a:')||l==='mx'||l.startsWith('mx:')||l.startsWith('ptr')||l.startsWith('exists:')){acc.n++;tree.push('  '.repeat(depth)+'• '+l.split(/[:=]/)[0]+(m.includes(':')?' '+m.split(':')[1]:'')+'  (+1)');continue;}
    else continue;
    if(tgt){acc.n++;const ind='  '.repeat(depth);
      if(seen.has(tgt.toLowerCase())){tree.push(ind+'• '+kind+':'+tgt+'  (+1, ya visto)');continue;}
      seen.add(tgt.toLowerCase());
      const q=await query(tgt,'TXT');const sub=q.answers.map(a=>a.data).find(x=>/^v=spf1/i.test(x));
      if(!sub){acc.void++;tree.push(ind+'• '+kind+':'+tgt+'  (+1) · sin SPF');}
      else{tree.push(ind+'• '+kind+':'+tgt+'  (+1)');await countLk(tgt,sub,depth+1,tree,seen,acc);}
    }
  }
}

/* ============================================================ DKIM */
const DKSEL=['selector1','selector2','google','default','k1','k2','k3','s1','s2','s1024','dkim','mail','smtp','mandrill','mailjet','mxvault','zoho','zohomail','everlytickey1','everlytickey2','protonmail','protonmail2','protonmail3','sig1','scph0819','scph1018','scph1220','fm1','fm2','fm3','pic','key1','key2','cm','dkim1','sm1','sm2','ctct1','ctct2','sib','sendgrid','sendinblue','turbo-smtp','hs1','hs2','amazonses','200608','20230601','mesmtp','em','sel1','sel2'];
async function checkDKIM(d,extra){
  const sels=[...new Set([...DKSEL,...extra])];const found=[],f=[];const B=8;
  for(let i=0;i<sels.length;i+=B){
    const sl=sels.slice(i,i+B);
    const res=await Promise.all(sl.map(async s=>{
      const nm=s+'._domainkey.'+d;let q=await query(nm,'TXT');let via=null;
      if(!q.answers.length&&q.cnames.length){via=q.cnames[0];const q2=await query(via,'TXT');if(q2.answers.length)q={...q2,cnames:q.cnames};}
      const rec=q.answers.map(a=>a.data).find(x=>/(^|;)\s*(v=DKIM1|k=|p=)/i.test(x));
      return rec?{selector:s,record:rec,via}:null;
    }));
    res.forEach(r=>r&&found.push(r));
    setStatus(`Escaneando selectores DKIM… (${Math.min(i+B,sels.length)}/${sels.length}) — ${found.length} hallados`);
  }
  if(!found.length){f.push(F('fail','No se encontró ninguna clave DKIM','Se probaron '+sels.length+' selectores. Puede usar un selector personalizado; agrégalo en opciones avanzadas.'));return finalize('DKIM','fail','Firma criptográfica del correo (RFC 6376)','correo',f,{},null);}
  const kv={};f.push(F('ok',found.length+' selector(es) DKIM activos','El dominio firma criptográficamente su correo saliente.'));
  found.forEach(x=>{
    const p=parseDKIM(x.record),b=p.bits;let sev='ok',note='';
    if(p.revoked){sev='warn';note='clave vacía (revocada)';}
    else if(p.keytype==='rsa'&&b&&b<1024){sev='fail';note=b+' bits — inseguro';}
    else if(p.keytype==='rsa'&&b&&b<2048){sev='warn';note=b+' bits — débil, rota a 2048';}
    else if(p.keytype==='rsa'&&b>=2048){note=b+' bits — fuerte';}
    else if(p.keytype==='ed25519')note='Ed25519 — moderno';
    f.push(F(sev,'Selector "'+x.selector+'"'+(x.via?' (CNAME delegado)':''),
      p.keytype==='rsa'?(b>=2048?`Clave RSA de ${b} bits — cumple recomendación.`:b>=1024?`Clave RSA de ${b} bits — funcional pero rota a 2048.`:`Clave RSA de ${b} bits — insegura.`):p.keytype==='ed25519'?'Clave Ed25519 moderna.':p.revoked?'Clave publicada pero vacía.':'Clave DKIM publicada.'));
    kv[`Selector ${x.selector}${x.via?' <span class="hint">(→'+esc(x.via)+')</span>':''}`]=tag(p.keytype||'?',b&&b<2048?'y':'g')+(b?tag(b+' bits',b>=2048?'g':(b>=1024?'y':'r')):'')+(note?` <span class="hint">${esc(note)}</span>`:'')+raw(x.record);
  });
  return finalize('DKIM',deriveStatus(f),'Firma criptográfica del correo (RFC 6376)','correo',f,kv,found.map(x=>x.selector+': '+x.record).join('\n\n'));
}
function parseDKIM(rec){const o={keytype:'rsa',bits:null,revoked:false};rec.split(';').forEach(p=>{const[k,...v]=p.split('=');if(k)o[k.trim().toLowerCase()==='k'?'keytype':k.trim().toLowerCase()]=v.join('=').trim();});const p=(o.p||'').replace(/\s+/g,'');if(o.k)o.keytype=o.k.toLowerCase();if(!p){o.revoked=true;return o;}if(o.keytype==='rsa'){try{o.bits=rsaBits(p);}catch(e){o.bits=estBits(p);}}return o;}
function rsaBits(b64){const der=b64b(b64);let i=0;function len(){let l=der[i++];if(l&0x80){let n=l&0x7f;l=0;while(n--)l=(l<<8)|der[i++];}return l;}if(der[i++]!==0x30)throw 0;len();if(der[i++]!==0x30)throw 0;const a=len();i+=a;if(der[i++]!==0x03)throw 0;len();i++;if(der[i++]!==0x30)throw 0;len();if(der[i++]!==0x02)throw 0;let m=len();if(der[i]===0x00){m--;i++;}return m*8;}
function estBits(b64){const n=Math.floor(b64.replace(/=+$/,'').length*3/4);return n<200?1024:n<400?2048:n<700?4096:null;}
function b64b(b64){const s=atob(b64),a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a;}

/* ============================================================ DMARC */
async function checkDMARC(d){
  const q=await query('_dmarc.'+d,'TXT');const recs=q.answers.map(a=>a.data).filter(x=>/^v=DMARC1\b/i.test(x));const f=[];
  if(!recs.length){f.push(F('fail','No hay registro DMARC','Sin DMARC no defines qué hacer con el correo que falla SPF/DKIM ni recibes reportes.'));return finalize('DMARC','fail','Política y alineación (RFC 7489)','correo',f,{},null);}
  if(recs.length>1)f.push(F('fail','Hay '+recs.length+' registros DMARC','Solo se permite uno.'));
  const rec=recs[0],t={};rec.split(';').forEach(p=>{const[k,...v]=p.split('=');if(k&&k.trim())t[k.trim().toLowerCase()]=v.join('=').trim();});
  const p=(t.p||'').toLowerCase();
  const map={reject:['ok','p=reject — máxima protección: el correo suplantado se rechaza.'],quarantine:['warn','p=quarantine — el correo que falla va a spam. Buen paso; el objetivo es reject.'],none:['fail','p=none — solo monitoreo. NO protege contra suplantación. Es lo más importante a corregir.']};
  if(map[p]){const[s,m]=map[p];f.push(F(s,'Política: p='+p,m));}else f.push(F('fail','Política ausente o inválida','El tag p= debe ser none, quarantine o reject.'));
  const pct=t.pct?parseInt(t.pct):100;
  if(t.pct&&pct<100)f.push(F('warn','pct='+pct,'Solo se aplica al '+pct+'% del correo; súbelo a 100 tras el despliegue.'));
  if(t.rua)f.push(F('ok','Reportes agregados (rua) configurados','Recibirás informes de quién envía como tu dominio.'));else f.push(F('warn','Sin rua','Sin reportes no sabrás quién suplanta tu dominio.'));
  if(t.ruf)f.push(F('info','Reportes forenses (ruf) configurados','Muestras de correos que fallan; pocos proveedores los envían.'));
  const adk=(t.adkim||'r').toLowerCase(),asp=(t.aspf||'r').toLowerCase();
  f.push(F('info','Alineación DKIM '+(adk==='s'?'estricta':'relajada')+' · SPF '+(asp==='s'?'estricta':'relajada'),'La relajada permite subdominios; la estricta exige coincidencia exacta.'));
  if(!t.sp&&(p==='reject'||p==='quarantine'))f.push(F('info','Sin sp explícito','Los subdominios heredan p='+p+'. Añade sp=reject para blindarlos.'));
  const kv={'Registro DMARC':raw(rec),'Política (p)':tag('p='+(p||'?'),p==='reject'?'g':(p==='quarantine'?'y':'r')),'Subdominios (sp)':t.sp?tag('sp='+t.sp,t.sp==='reject'?'g':'y'):'<span class="hint">hereda p</span>','Cobertura (pct)':tag(pct+'%',pct===100?'g':'y'),'Alineación':tag('adkim='+adk)+tag('aspf='+asp),'rua':t.rua?esc(t.rua):tag('no','y'),'ruf':t.ruf?esc(t.ruf):'—','fo':t.fo?esc(t.fo):'0'};
  return finalize('DMARC',deriveStatus(f),'Política y alineación (RFC 7489)','correo',f,kv,rec);
}

/* ============================================================ MX + provider */
const MXP=[[/google|googlemail|aspmx/i,'Google Workspace'],[/outlook|protection\.outlook|office365/i,'Microsoft 365'],[/iphmx|ironport|cisco/i,'Cisco IronPort'],[/proofpoint|pphosted/i,'Proofpoint'],[/mimecast/i,'Mimecast'],[/zoho/i,'Zoho Mail'],[/amazonaws|amazonses/i,'Amazon SES/WorkMail'],[/protonmail|proton\.me/i,'Proton Mail'],[/mailgun/i,'Mailgun'],[/barracuda|cudasvc/i,'Barracuda'],[/messagelabs|symantec/i,'Symantec'],[/secureserver|godaddy/i,'GoDaddy'],[/yandex/i,'Yandex'],[/email-messaging|netcore/i,'Netcore'],[/hostinger/i,'Hostinger']];
let MX_IPS=[], SITE_IPS=[], BL_LISTED=[];
/* Windows no dibuja las banderas emoji (muestra las letras del país), así que allí se omiten */
const FLAGS_OK=!/Windows/i.test(navigator.userAgent);
function flagOf(cc){if(!FLAGS_OK||!cc||cc.length!==2)return'';try{return String.fromCodePoint(...[...cc.toUpperCase()].map(c=>127397+c.charCodeAt(0)));}catch(e){return'';}}
async function geoLookup(ip){
  try{const r=await fetch('https://ipwho.is/'+ip);if(r.ok){const j=await r.json();if(j.success!==false)return{ip:j.ip,country:j.country,cc:j.country_code,flag:FLAGS_OK&&j.flag?j.flag.emoji:'',region:j.region,city:j.city,lat:j.latitude,lon:j.longitude,asn:j.connection&&j.connection.asn?('AS'+j.connection.asn):'',org:j.connection&&(j.connection.org||j.connection.isp),isp:j.connection&&j.connection.isp,tz:j.timezone&&j.timezone.id,type:j.type,postal:j.postal};}}catch(e){}
  try{const r=await fetch('https://ipapi.co/'+ip+'/json/');if(r.ok){const j=await r.json();if(!j.error)return{ip:j.ip,country:j.country_name,cc:j.country_code,flag:flagOf(j.country_code),region:j.region,city:j.city,lat:j.latitude,lon:j.longitude,asn:j.asn,org:j.org,isp:j.org,tz:j.timezone,type:j.version,postal:j.postal};}}catch(e){}
  return null;
}
async function checkMX(d){
  const q=await query(d,'MX');const f=[];
  if(!q.answers.length){f.push(F('warn','Sin registros MX','El dominio no recibe correo.'));return finalize('MX','warn','Servidores de correo entrante','correo',f,{},null);}
  const rows=q.answers.map(a=>{const[pr,...h]=a.data.split(' ');return{prio:parseInt(pr),host:h.join(' ').replace(/\.$/,'')};}).sort((a,b)=>a.prio-b.prio);
  const prov=new Set();rows.forEach(r=>{for(const[re,n]of MXP){if(re.test(r.host)){prov.add(n);break;}}});
  // resolve IPs of top MX hosts (for blacklist + PTR)
  for(const r of rows.slice(0,3)){const a=await query(r.host,'A');a.answers.forEach(x=>MX_IPS.push({ip:x.data,host:r.host}));}
  f.push(F('ok',rows.length+' registro(s) MX','El correo entrante se enruta correctamente.'));
  if(prov.size)f.push(F('info','Proveedor: '+[...prov].join(', '),'Identificado por los hosts MX.'));
  const kv={'Servidores MX':'<table class="mini"><tr><th>Prio</th><th>Host</th><th>IP</th></tr>'+rows.map(r=>{const ip=MX_IPS.find(x=>x.host===r.host);return `<tr><td>${r.prio}</td><td>${esc(r.host)}</td><td>${ip?esc(ip.ip):'—'}</td></tr>`;}).join('')+'</table>','Proveedor':prov.size?[...prov].map(p=>tag(p,'g')).join(''):'<span class="hint">no identificado</span>'};
  return finalize('MX','ok','Servidores de correo entrante','correo',f,kv,rows.map(r=>r.prio+' '+r.host).join('\n'));
}

/* ============================================================ Blacklist / RBL */
const RBLS=['zen.spamhaus.org','b.barracudacentral.org','bl.spamcop.net','dnsbl.sorbs.net','cbl.abuseat.org','psbl.surriel.com','dnsbl-1.uceprotect.net','all.s5h.net'];
async function checkRBL(d){
  const f=[];
  if(!MX_IPS.length){f.push(F('info','No hay IPs de MX para verificar','Sin registros MX resolubles no se puede consultar listas negras.'));return finalize('Listas negras','neutral','Reputación IP (DNSBL / RBL)','seguridad',f,{},null);}
  const ips=[...new Map(MX_IPS.map(x=>[x.ip,x])).values()].filter(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x.ip)).slice(0,3);
  const rows=[];let listed=0,indet=0,checked=0;
  for(const {ip,host} of ips){
    const rev=ip.split('.').reverse().join('.');
    const res=await Promise.all(RBLS.map(async bl=>{
      const q=await query(rev+'.'+bl,'A');checked++;
      if(q.status===3)return{bl,st:'clean'};
      if(q.answers.length){const code=q.answers[0].data;if(/^127\.255\.255\./.test(code))return{bl,st:'indet',code};return{bl,st:'listed',code};}
      return{bl,st:'indet'};
    }));
    res.forEach(r=>{if(r.st==='listed')listed++;if(r.st==='indet')indet++;rows.push({ip,host,...r});});
  }
  const listedRows=rows.filter(r=>r.st==='listed');
  BL_LISTED=listedRows.map(r=>({ip:r.ip,host:r.host,bl:r.bl,code:r.code}));
  const kv={};
  if(listed>0){
    const byIp={};listedRows.forEach(r=>{(byIp[r.ip]=byIp[r.ip]||[]).push(r.bl);});
    const listNames=[...new Set(listedRows.map(r=>r.bl))];
    f.push(F('fail','REPORTADA en '+listNames.length+' lista(s) negra(s)','El dominio SÍ está reportado. Listas: '+listNames.join(', ')+'. Esto bloquea o degrada gravemente la entrega de tu correo; solicita el delisting en cada operador.'));
    // prominent detail block per affected IP
    kv['IPs reportadas']='<table class="mini"><tr><th>IP</th><th>Host MX</th><th>Reportada en</th></tr>'+
      Object.entries(byIp).map(([ip,bls])=>{const host=(listedRows.find(r=>r.ip===ip)||{}).host||'';return `<tr><td data-s="color:var(--fail);font-weight:700">${esc(ip)}</td><td>${esc(host)}</td><td>${bls.map(b=>`<span class="tag r">${esc(b)}</span>`).join('')}</td></tr>`;}).join('')+'</table>';
  }
  else f.push(F('ok','NO reportada — ninguna IP en listas negras','Las IPs verificadas de tus servidores de correo tienen buena reputación.'));
  if(indet>0)f.push(F('info',indet+' consulta(s) no concluyentes','Algunos operadores de RBL (p. ej. Spamhaus) limitan las consultas desde resolutores públicos; ese resultado no significa que esté listada.'));
  const dot=s=>`<span class="st-dot" data-s="background:${s==='listed'?'var(--fail)':s==='clean'?'var(--ok)':'var(--muted2)'}"></span>`;
  ips.forEach(({ip,host})=>{
    const st=rows.filter(r=>r.ip===ip).some(r=>r.st==='listed')?'<svg class="i ifail"><use href="#i-alert"/></svg> ':'';
    kv[`${st}IP ${ip} <span class="hint">(${esc(host)})</span>`]='<table class="mini">'+rows.filter(r=>r.ip===ip).map(r=>`<tr><td>${dot(r.st)}${esc(r.bl)}</td><td>${r.st==='listed'?'<span data-s="color:var(--fail);font-weight:700">LISTADA'+(r.code?' ('+esc(r.code)+')':'')+'</span>':r.st==='clean'?'<span data-s="color:var(--ok)">limpia</span>':'<span data-s="color:var(--muted)">no concluyente</span>'}</td></tr>`).join('')+'</table>';
  });
  return finalize('Listas negras',deriveStatus(f,'ok'),'Reputación IP · '+ips.length+' IP × '+RBLS.length+' listas','seguridad',f,kv,null);
}

/* ============================================================ WHOIS / RDAP */
async function checkRDAP(d){
  const f=[];let data=null;
  try{
    const r=await fetch('https://rdap.org/domain/'+encodeURIComponent(d),{headers:{'Accept':'application/rdap+json'}});
    if(r.ok)data=await r.json();
  }catch(e){}
  if(!data){f.push(F('info','WHOIS/RDAP no disponible','No se obtuvo información de registro (el TLD puede no ofrecer RDAP público, p. ej. algunos .gov.co, o CORS restringido).'));return finalize('WHOIS / RDAP','neutral','Datos de registro del dominio','dominio',f,{},null);}
  const ev={};(data.events||[]).forEach(e=>ev[e.eventAction]=e.eventDate);
  const reg=(data.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
  let regName='—';if(reg){const vc=reg.vcardArray?.[1];const fn=vc?.find(x=>x[0]==='fn');regName=fn?fn[3]:(reg.handle||'—');}
  const created=ev.registration,expires=ev.expiration,updated=ev.lastChanged||ev['last changed'];
  const status=(data.status||[]).join(', ');
  const ns=(data.nameservers||[]).map(n=>n.ldhName).filter(Boolean);
  f.push(F('ok','Dominio registrado','Información de registro obtenida vía RDAP.'));
  if(regName!=='—')f.push(F('info','Registrador: '+regName,'Entidad donde está registrado el dominio.'));
  if(expires){const days=Math.round((new Date(expires)-new Date())/864e5);
    if(days<0)f.push(F('fail','Dominio EXPIRADO','La fecha de expiración ya pasó ('+expires.slice(0,10)+'). Renuévalo con urgencia.'));
    else if(days<30)f.push(F('warn','Expira en '+days+' días','El dominio vence pronto ('+expires.slice(0,10)+'); renuévalo para evitar caída de servicios.'));
    else f.push(F('ok','Vigente — expira en '+days+' días','Fecha de expiración: '+expires.slice(0,10)+'.'));}
  if(/clienttransferprohibited|clientdeleteprohibited/i.test(status))f.push(F('ok','Bloqueos de protección activos','El dominio tiene locks contra transferencias/borrados no autorizados.'));
  const kv={'Registrador':esc(regName),'Creado':created?esc(created.slice(0,10)):'—','Última modificación':updated?esc(updated.slice(0,10)):'—','Expira':expires?esc(expires.slice(0,10)):'—','Estado (EPP)':status?esc(status):'—','Nameservers':ns.length?ns.map(n=>tag(n)).join(''):'—'};
  return finalize('WHOIS / RDAP',deriveStatus(f,'ok'),'Datos de registro del dominio','dominio',f,kv,null);
}

/* ============================================================ CAA */
async function checkCAA(d){
  const q=await query(d,'CAA');const f=[];
  if(!q.answers.length){f.push(F('warn','Sin registros CAA','Sin CAA, cualquier autoridad certificadora puede emitir certificados TLS para tu dominio. Añade registros CAA para limitarlo a tus CAs autorizadas.'));return finalize('CAA','warn','Autorización de emisión de certificados','seguridad',f,{},null);}
  const issuers=new Set();q.answers.forEach(a=>{const m=a.data.match(/issue"?\s*"?([^"]+)"?/i);if(m)issuers.add(m[1].trim());});
  f.push(F('ok',q.answers.length+' registro(s) CAA','Solo las CAs autorizadas pueden emitir certificados para este dominio, reduciendo el riesgo de emisión fraudulenta.'));
  if(q.answers.some(a=>/iodef/i.test(a.data)))f.push(F('ok','Contacto iodef configurado','Recibirás aviso de intentos de emisión no autorizados.'));
  const kv={'Registros CAA':raw(q.answers.map(a=>a.data).join('\n')),'CAs autorizadas':[...issuers].map(i=>tag(i,'g')).join('')||'—'};
  return finalize('CAA',deriveStatus(f,'ok'),'Autorización de emisión de certificados (RFC 8659)','seguridad',f,kv,q.answers.map(a=>a.data).join('\n'));
}

/* ============================================================ MTA-STS / TLS-RPT / BIMI */
async function checkMTASTS(d){
  const q=await query('_mta-sts.'+d,'TXT');const rec=q.answers.map(a=>a.data).find(x=>/^v=STSv1/i.test(x));const f=[];
  if(!rec){f.push(F('warn','MTA-STS no configurado','Sin MTA-STS un atacante podría degradar el cifrado TLS del correo entrante (downgrade). Muy recomendado.'));return finalize('MTA-STS','warn','Cifrado TLS obligatorio (RFC 8461)','correo',f,{},null);}
  const host='mta-sts.'+d,a=await query(host,'A');
  f.push(F('ok','Registro _mta-sts publicado','El dominio anuncia política MTA-STS.'));
  f.push(a.answers.length?F('ok','Host de política resuelve','Debe servir https://'+host+'/.well-known/mta-sts.txt.'):F('warn','El host '+host+' no resuelve','La política no será accesible.'));
  return finalize('MTA-STS',deriveStatus(f,'ok'),'Cifrado TLS obligatorio (RFC 8461)','correo',f,{'Registro TXT':raw(rec),'Política':`<a href="https://${host}/.well-known/mta-sts.txt" target="_blank" rel="noopener">ver archivo ↗</a>`},rec);
}
async function checkTLSRPT(d){
  const q=await query('_smtp._tls.'+d,'TXT');const rec=q.answers.map(a=>a.data).find(x=>/^v=TLSRPTv1/i.test(x));const f=[];
  if(!rec){f.push(F('info','TLS-RPT no configurado','Complementa a MTA-STS enviando reportes de fallos de cifrado. Opcional.'));return finalize('TLS-RPT','neutral','Reportes de cifrado TLS (RFC 8460)','correo',f,{},null);}
  f.push(F('ok','TLS-RPT publicado','Recibirás reportes de problemas de cifrado en la entrega.'));
  return finalize('TLS-RPT','ok','Reportes de cifrado TLS (RFC 8460)','correo',f,{'Registro':raw(rec)},rec);
}
async function checkBIMI(d){
  const q=await query('default._bimi.'+d,'TXT');const rec=q.answers.map(a=>a.data).find(x=>/^v=BIMI1/i.test(x));const f=[];
  if(!rec){f.push(F('info','BIMI no configurado','Muestra tu logo verificado junto al correo (requiere DMARC en quarantine/reject). Opcional.'));return finalize('BIMI','neutral','Logo verificado de marca','correo',f,{},null);}
  const t={};rec.split(';').forEach(p=>{const[k,...v]=p.split('=');if(k&&k.trim())t[k.trim().toLowerCase()]=v.join('=').trim();});
  f.push(F('ok','BIMI publicado','El dominio anuncia un logo de marca.'));
  f.push(t.a?F('ok','Certificado VMC presente','El logo se mostrará en más clientes (Gmail).'):F('warn','Sin VMC (a=)','Sin certificado VMC, Gmail no mostrará el logo.'));
  return finalize('BIMI',deriveStatus(f,'ok'),'Logo verificado de marca','correo',f,{'Registro':raw(rec),'Logo':t.l?esc(t.l):'—','VMC':t.a?esc(t.a):'—'},rec);
}

/* ============================================================ DNSSEC */
async function checkDNSSEC(d){
  const [ds,dk]=await Promise.all([query(d,'DS'),query(d,'DNSKEY')]);const f=[];
  if(ds.answers.length){
    f.push(F('ok','DNSSEC habilitado (registro DS)','La zona está firmada criptográficamente; protege contra envenenamiento de caché y respuestas falsificadas.'));
    if(dk.answers.length)f.push(F('ok',dk.answers.length+' clave(s) DNSKEY publicadas','Claves de firma de zona presentes.'));
    if(ds.ad)f.push(F('ok','Cadena de validación correcta (AD=1)','El resolutor validó la firma de extremo a extremo.'));
    return finalize('DNSSEC',deriveStatus(f,'ok'),'Firmado de la zona DNS','seguridad',f,{'Registros DS':raw(ds.answers.map(a=>a.data).join('\n')),'DNSKEY':dk.answers.length+' clave(s)'},ds.answers.map(a=>a.data).join('\n'));
  }
  f.push(F('warn','DNSSEC no habilitado','Sin registro DS la zona no está firmada; un atacante podría falsificar respuestas DNS (incluidos tus propios SPF/DMARC). Recomendado para gobierno/banca.'));
  return finalize('DNSSEC','warn','Firmado de la zona DNS','seguridad',f,{},null);
}

/* ============================================================ PTR inverso */
async function checkPTR(d){
  const f=[];
  if(!MX_IPS.length){f.push(F('info','Sin IPs de MX','No hay servidores de correo para verificar el DNS inverso.'));return finalize('DNS inverso (PTR)','neutral','Resolución inversa de los MX','dominio',f,{},null);}
  const ips=[...new Map(MX_IPS.map(x=>[x.ip,x])).values()].filter(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x.ip)).slice(0,4);
  const kv={};let missing=0;
  for(const {ip,host} of ips){
    const rev=ip.split('.').reverse().join('.')+'.in-addr.arpa';
    const q=await query(rev,'PTR');
    const ptr=q.answers.map(a=>a.data)[0];
    if(!ptr)missing++;
    kv[`${ip} <span class="hint">(${esc(host)})</span>`]=ptr?tag(ptr,'g'):tag('sin PTR','y');
  }
  f.push(missing?F('warn',missing+' IP(s) sin PTR','La falta de DNS inverso (PTR) en un servidor de correo hace que muchos receptores rechacen o marquen como spam sus envíos.'):F('ok','Todas las IPs tienen PTR','El DNS inverso está configurado, requisito básico para buena entregabilidad.'));
  return finalize('DNS inverso (PTR)',deriveStatus(f,'ok'),'Resolución inversa de los MX','dominio',f,kv,null);
}

/* ============================================================ TXT catalog */
async function checkTXT(d){
  const q=await query(d,'TXT');const f=[];const rows=q.answers.map(a=>a.data);
  if(!rows.length){f.push(F('info','Sin registros TXT','El dominio no publica registros TXT.'));return finalize('Registros TXT','neutral','Verificaciones y otros TXT','dominio',f,{},null);}
  const known=[[/^v=spf1/i,'SPF'],[/google-site-verification/i,'Google Search Console'],[/^MS=/i,'Microsoft 365'],[/facebook-domain-verification/i,'Meta/Facebook'],[/^apple-domain-verification/i,'Apple'],[/^atlassian-/i,'Atlassian'],[/^stripe-verification/i,'Stripe'],[/^adobe-idp-site-verification/i,'Adobe'],[/^docusign=/i,'DocuSign'],[/^zoom-/i,'Zoom'],[/sendinblue|brevo/i,'Brevo/Sendinblue'],[/^amazonses:/i,'Amazon SES'],[/^onetrust-/i,'OneTrust']];
  const cat=[];rows.forEach(r=>{const m=known.find(k=>k[0].test(r));cat.push({r,svc:m?m[1]:'genérico/otro'});});
  const svcs=[...new Set(cat.filter(c=>c.svc!=='genérico/otro').map(c=>c.svc))];
  f.push(F('ok',rows.length+' registro(s) TXT','Incluyen SPF y verificaciones de servicios de terceros.'));
  if(svcs.length)f.push(F('info','Servicios verificados: '+svcs.join(', '),'Detectados por el patrón del registro TXT.'));
  const kv={'Registros TXT':'<table class="mini"><tr><th>Servicio</th><th>Registro</th></tr>'+cat.map(c=>`<tr><td>${esc(c.svc)}</td><td data-s="font-family:var(--mono);font-size:11.5px;word-break:break-all">${esc(c.r.length>90?c.r.slice(0,90)+'…':c.r)}</td></tr>`).join('')+'</table>'};
  return finalize('Registros TXT','ok','Verificaciones y otros TXT','dominio',f,kv,null);
}

/* ============================================================ Certificate Transparency (crt.sh) */
async function checkCT(d){
  const f=[];let data=null;
  try{const r=await fetch('https://crt.sh/?q='+encodeURIComponent(d)+'&output=json&exclude=expired');if(r.ok)data=await r.json();}catch(e){}
  if(!data){try{const r=await fetch('https://crt.sh/?q='+encodeURIComponent(d)+'&output=json');if(r.ok)data=await r.json();}catch(e){}}
  if(!data||!Array.isArray(data)){
    f.push(F('info','Certificate Transparency no disponible','No se pudo consultar crt.sh (puede estar limitado por CORS o el servicio saturado). Ábrelo manualmente para ver los certificados emitidos.'));
    return finalize('Certificados TLS (CT)','neutral','Transparencia de certificados · crt.sh','seguridad',f,{'Consulta manual':`<a href="https://crt.sh/?q=${encodeURIComponent(d)}" target="_blank" rel="noopener">crt.sh/?q=${esc(d)} ↗</a>`},null);
  }
  const names=new Set(),issuers={};let latest=null;
  data.slice(0,600).forEach(c=>{
    (c.name_value||'').split(/\n/).forEach(n=>{n=n.trim().toLowerCase();if(n)names.add(n);});
    const iss=(c.issuer_name||'').match(/O="?([^",]+)"?/);const io=iss?iss[1]:'otro';issuers[io]=(issuers[io]||0)+1;
    if(c.not_before&&(!latest||c.not_before>latest))latest=c.not_before;
  });
  const subs=[...names].filter(n=>!n.startsWith('*')).filter(n=>n.endsWith(d)).sort();
  const wild=[...names].filter(n=>n.startsWith('*'));
  f.push(F('ok',data.length+' certificado(s) en registros CT','Los certificados TLS emitidos para tu dominio son públicos (Certificate Transparency). Revísalos para detectar emisiones no autorizadas.'));
  f.push(F('info',subs.length+' subdominio(s) expuestos en certificados','Cada certificado revela nombres de host; atacantes los usan para reconocimiento. Verifica que todos sean tuyos.'));
  if(latest)f.push(F('info','Último certificado emitido: '+latest.slice(0,10),'Fecha del certificado más reciente registrado.'));
  const topIss=Object.entries(issuers).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const kv={
    'Autoridades emisoras':topIss.map(([k,v])=>tag(k+' ('+v+')','g')).join('')||'—',
    ['Subdominios detectados ('+subs.length+')']:subs.length?('<div class="lookup-tree">'+subs.slice(0,60).map(esc).join('\n')+(subs.length>60?'\n… +'+(subs.length-60)+' más':'')+'</div>'):'—',
    'Comodines (wildcard)':wild.length?wild.map(esc).map(w=>tag(w)).join(''):'—',
    'Ver todo':`<a href="https://crt.sh/?q=${encodeURIComponent(d)}" target="_blank" rel="noopener">crt.sh ↗</a>`
  };
  return finalize('Certificados TLS (CT)','ok','Transparencia de certificados · crt.sh','seguridad',f,kv,null);
}

/* ============================================================ Geolocalización & ASN */
async function checkGeo(d){
  const f=[];let targets=[];
  SITE_IPS.slice(0,2).forEach(ip=>targets.push({ip,label:'Sitio web (A)'}));
  const seen=new Set(targets.map(t=>t.ip));
  MX_IPS.forEach(x=>{if(!seen.has(x.ip)&&/^\d+\.\d+\.\d+\.\d+$/.test(x.ip)){seen.add(x.ip);targets.push({ip:x.ip,label:'MX '+x.host});}});
  targets=targets.slice(0,6);
  if(!targets.length){f.push(F('info','Sin IPs para geolocalizar','No se resolvieron IPs del sitio ni de los MX.'));return finalize('Geolocalización & ASN','neutral','Ubicación e infraestructura de las IPs','infra',f,{},null);}
  const kv={};const countries=new Set(),asns=new Set();let okc=0;
  for(const t of targets){
    setStatus('Geolocalizando '+t.ip+'…');
    const g=await geoLookup(t.ip);
    if(!g){kv[`${t.label} — ${esc(t.ip)}`]=tag('geolocalización no disponible','y');continue;}
    okc++;const flag=g.flag||flagOf(g.cc)||'';
    if(g.country)countries.add((flag?flag+' ':'')+g.country);
    if(g.asn)asns.add(g.asn+(g.org?' · '+g.org:''));
    const mapl=g.lat?`<a href="https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=9/${g.lat}/${g.lon}" target="_blank" rel="noopener">ver mapa ↗</a>`:'';
    kv[`${t.label} — ${esc(t.ip)}`]=`<table class="mini">`+
      `<tr><td>País</td><td>${flag} ${esc(g.country||'—')} ${g.cc?'('+esc(g.cc)+')':''}</td></tr>`+
      `<tr><td>Ciudad / Región</td><td>${esc([g.city,g.region].filter(Boolean).join(', ')||'—')}${g.postal?' · CP '+esc(g.postal):''}</td></tr>`+
      `<tr><td>ASN / Red</td><td>${g.asn?tag(g.asn,'g'):'—'}</td></tr>`+
      `<tr><td>Organización / ISP</td><td>${esc(g.org||g.isp||'—')}</td></tr>`+
      `<tr><td>Zona horaria</td><td>${esc(g.tz||'—')}</td></tr>`+
      `<tr><td>Coordenadas</td><td>${g.lat?esc(g.lat+', '+g.lon):'—'} ${mapl}</td></tr>`+
    `</table>`;
  }
  if(okc)f.push(F('ok',okc+' IP(s) geolocalizada(s)','Ubicación física aproximada, red (ASN) y proveedor de hosting de la infraestructura del dominio.'));
  else f.push(F('warn','Geolocalización no disponible','No se pudo obtener la ubicación (el proveedor de geo-IP puede estar limitado o bloqueado por CORS).'));
  if(countries.size)f.push(F('info','País(es) de alojamiento: '+[...countries].join('  ·  '),'Dónde están físicamente los servidores.'));
  if(asns.size)f.push(F('info','Red(es) / ASN: '+[...asns].join('  ·  '),'Sistema autónomo y proveedor de conectividad.'));
  return finalize('Geolocalización & ASN',okc?'ok':'neutral','Ubicación e infraestructura de las IPs','infra',f,kv,null);
}

/* ============================================================ DANE / TLSA */
async function checkDANE(d){
  const f=[];const mx=[...new Map(MX_IPS.map(x=>[x.host,x])).values()].slice(0,3);
  if(!mx.length){f.push(F('info','Sin MX para verificar DANE','No hay servidores de correo.'));return finalize('DANE / TLSA','neutral','Anclaje de certificados TLS del correo','seguridad',f,{},null);}
  const kv={};let has=0;
  for(const m of mx){const q=await query('_25._tcp.'+m.host,'TLSA');if(q.answers.length){has++;kv[esc(m.host)]=raw(q.answers.map(a=>a.data).join('\n'));}else kv[esc(m.host)]=tag('sin TLSA','y');}
  f.push(has?F('ok',has+' host(s) MX con DANE/TLSA','Los servidores anclan su certificado TLS vía DNSSEC, impidiendo la suplantación del certificado en la entrega de correo.'):F('info','DANE/TLSA no configurado','Registro avanzado que ata el certificado TLS del correo a DNSSEC. Opcional; requiere DNSSEC activo.'));
  return finalize('DANE / TLSA',deriveStatus(f,'neutral'),'Anclaje de certificados TLS del correo (RFC 7672)','seguridad',f,kv,null);
}

/* ============================================================ Riesgo de suplantación (síntesis) */
function checkSpoof(){
  const f=[];const spf=REPORT['SPF'],dkim=REPORT['DKIM'],dmarc=REPORT['DMARC'];
  const p=((dmarc&&dmarc.record||'').match(/p=(\w+)/i)||[])[1];const pl=p?p.toLowerCase():'';
  const spfHard=!!(spf&&spf.record&&/-all\b/.test(spf.record));
  const spfSoft=!!(spf&&spf.record&&/~all\b/.test(spf.record));
  const dkimOk=!!(dkim&&dkim.status!=='fail');
  let level,sev,msg;
  if(pl==='reject'&&(spfHard||spfSoft)&&dkimOk){level='ALTA';sev='ok';msg='Con DMARC en reject más SPF y DKIM activos, un tercero no puede suplantar tu dominio: los receptores rechazan el correo falsificado.';}
  else if(pl==='quarantine'){level='MEDIA';sev='warn';msg='DMARC en quarantine desvía el correo suplantado a spam pero no lo rechaza. Sube a p=reject para protección total.';}
  else if(pl==='none'||!pl){level='BAJA';sev='fail';msg='Sin DMARC en enforcement (quarantine/reject), cualquiera puede enviar correo falsificando tu dominio y llegará a la bandeja de entrada. Es el riesgo más crítico.';}
  else{level='MEDIA';sev='warn';msg='Configuración parcial; revisa SPF, DKIM y DMARC.';}
  f.push(F(sev,'Protección anti-suplantación: '+level,msg));
  f.push(F(spfHard?'ok':spfSoft?'warn':'fail','SPF: '+(spfHard?'hardfail (-all)':spfSoft?'softfail (~all)':'ausente o permisivo'),''));
  f.push(F(dkimOk?'ok':'fail','DKIM: '+(dkimOk?'firma activa':'ausente'),''));
  f.push(F(pl==='reject'?'ok':pl==='quarantine'?'warn':'fail','DMARC: '+(pl?'p='+pl:'ausente'),''));
  const kv={'Nivel de protección':tag(level,level==='ALTA'?'g':level==='MEDIA'?'y':'r'),'SPF':spfHard?tag('-all','g'):spfSoft?tag('~all','y'):tag('débil','r'),'DKIM':dkimOk?tag('activo','g'):tag('ausente','r'),'DMARC':pl?tag('p='+pl,pl==='reject'?'g':pl==='quarantine'?'y':'r'):tag('ausente','r')};
  return finalize('Riesgo de suplantación',sev,'Síntesis de protección del correo','seguridad',f,kv,null);
}

/* ============================================================ DNS base */
async function checkBase(d){
  const [a,aaaa,ns,soa]=await Promise.all([query(d,'A'),query(d,'AAAA'),query(d,'NS'),query(d,'SOA')]);const f=[];
  SITE_IPS=a.answers.map(x=>x.data).filter(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x));
  if(soa.status===3){f.push(F('fail','El dominio no existe (NXDOMAIN)','No hay zona DNS. Verifica la ortografía y el registro.'));return finalize('DNS base','fail','Registros fundamentales','dominio',f,{},null,true);}
  f.push(F('ok','Dominio activo con zona DNS','SOA y nameservers resueltos.'));
  if(a.answers.length)f.push(F('info','A (IPv4): '+a.answers.map(x=>x.data).join(', '),'Direcciones del sitio web.'));
  f.push(aaaa.answers.length?F('ok','AAAA (IPv6) presente','Accesible por IPv6.'):F('info','Sin AAAA (IPv6)','El sitio no publica IPv6. No es un error.'));
  const kv={'Nameservers':ns.answers.length?ns.answers.map(x=>tag(x.data)).join(''):'—','A (IPv4)':a.answers.length?a.answers.map(x=>x.data).join(', '):'—','AAAA (IPv6)':aaaa.answers.length?aaaa.answers.map(x=>x.data).join(', '):tag('ninguno','y'),'SOA':soa.answers.length?raw(soa.answers[0].data):'—'};
  return finalize('DNS base','ok','Registros fundamentales','dominio',f,kv,null,true);
}

/* ============================================================ Orchestration */
const $=s=>document.querySelector(s);
const setStatus=t=>{$('#statusTxt').textContent=t;};
const setBar=p=>{$('#bar').style.width=p+'%';};
const ORDER=['Riesgo de suplantación','SPF','DKIM','DMARC','MX','MTA-STS','TLS-RPT','BIMI','Listas negras','DNSSEC','DANE / TLSA','CAA','Certificados TLS (CT)','DNS inverso (PTR)','Geolocalización & ASN','WHOIS / RDAP','Registros TXT','DNS base'];

async function run(){
  let d=$('#domain').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Ingresa un dominio válido, p. ej. ejemplo.com');return;}
  RESOLVER=$('#resolver').value;
  const extra=$('#selectors').value.split(',').map(s=>s.trim()).filter(Boolean);
  const doRBL=$('#rbltoggle').value==='1';
  cache.clear();ITEMS=[];REPORT={};MX_IPS=[];SITE_IPS=[];BL_LISTED=[];USED_RESOLVERS=new Set();
  $('#results').innerHTML='';$('#dash').style.display='none';$('#tabs').style.display='none';const _ba=$('#blAlert');if(_ba){_ba.style.display='none';_ba.innerHTML='';}const _ap=$('#actionPlan');if(_ap)_ap.innerHTML='';
  $('#status').style.display='flex';$('#barwrap').style.display='block';setBar(3);$('#go').disabled=true;
  const t0=performance.now();
  try{
    setStatus('Consultando registros base…');
    const base=await checkBase(d);setBar(10);
    if(base.status==='fail'){renderAll(d,(performance.now()-t0)/1000);finishUI();return;}
    const steps=[
      ['Analizando SPF…',()=>checkSPF(d),18],
      ['Escaneando selectores DKIM…',()=>checkDKIM(d,extra),42],
      ['Evaluando DMARC…',()=>checkDMARC(d),50],
      ['Consultando servidores MX…',()=>checkMX(d),58],
      ...(doRBL?[['Verificando listas negras (RBL)…',()=>checkRBL(d),68]]:[]),
      ['Verificando MTA-STS…',()=>checkMTASTS(d),72],
      ['Verificando TLS-RPT…',()=>checkTLSRPT(d),75],
      ['Verificando BIMI…',()=>checkBIMI(d),78],
      ['Comprobando DNSSEC…',()=>checkDNSSEC(d),80],
      ['Comprobando DANE/TLSA…',()=>checkDANE(d),83],
      ['Comprobando CAA…',()=>checkCAA(d),84],
      ['Consultando certificados (crt.sh)…',()=>checkCT(d),86],
      ['Resolviendo DNS inverso (PTR)…',()=>checkPTR(d),88],
      ['Geolocalizando IPs…',()=>checkGeo(d),91],
      ['Consultando WHOIS / RDAP…',()=>checkRDAP(d),95],
      ['Catalogando registros TXT…',()=>checkTXT(d),97],
      ['Evaluando riesgo de suplantación…',()=>Promise.resolve(checkSpoof()),99],
    ];
    for(const [msg,fn,pct] of steps){setStatus(msg);await fn();setBar(pct);}
    renderAll(d,(performance.now()-t0)/1000);setBar(100);
  }catch(err){
    alert('Error consultando DNS: '+err.message+'\n\nSi abriste el archivo con file:// y falla, súbelo a un hosting estático (GitHub Pages, Netlify) o ábrelo con un servidor local.');
    console.error(err);
  }finally{finishUI();}
}
function finishUI(){$('#go').disabled=false;setTimeout(()=>{$('#status').style.display='none';$('#barwrap').style.display='none';},700);}

const BADGE={ok:['b-ok','Correcto'],warn:['b-warn','Atención'],fail:['b-fail','Crítico'],info:['b-info','Info'],neutral:['b-neutral','N/D']};
const WEIGHTS={SPF:18,DKIM:18,DMARC:24,MX:6,'MTA-STS':4,DNSSEC:5,CAA:3,'Listas negras':7,'DANE / TLSA':1,'WHOIS / RDAP':1,'DNS inverso (PTR)':4,BIMI:1,'TLS-RPT':2,'Certificados TLS (CT)':2};
const SCOREVAL={ok:1,info:1,warn:0.5,neutral:0.65,fail:0};

function renderAll(d,secs){
  ITEMS.sort((a,b)=>ORDER.indexOf(a.name)-ORDER.indexOf(b.name));
  // sections
  $('#results').innerHTML='';
  ITEMS.forEach(it=>$('#results').appendChild(renderSection(it,['SPF','DKIM','DMARC'].includes(it.name))));
  // score
  let total=0,max=0,c={ok:0,warn:0,fail:0,neut:0};
  ITEMS.forEach(it=>{const w=WEIGHTS[it.name]||0;if(w){max+=w;total+=w*(SCOREVAL[it.status]??0);}
    if(it.status==='ok'||it.status==='info')c.ok++;else if(it.status==='warn')c.warn++;else if(it.status==='fail')c.fail++;else c.neut++;});
  const score=max?Math.round(total/max*100):0;
  animateScore(score);
  const grade=score>=90?'A':score>=80?'B':score>=65?'C':score>=45?'D':'F';
  $('#scoreGrade').textContent='NOTA '+grade;
  const col=score>=85?'var(--ok)':score>=60?'var(--warn)':'var(--fail)';
  $('#scoreGrade').style.color=col;
  $('#verdict').textContent=score>=90?'Excelente — configuración robusta':score>=75?'Buena — con mejoras recomendadas':score>=55?'Regular — hay riesgos importantes':score>=30?'Deficiente — expuesto a suplantación':'Crítico — sin protección efectiva';
  $('#vdom').textContent=d;
  $('#kpis').innerHTML=`<div class="kpi ok"><b>${c.ok}</b><span>Correctos</span></div><div class="kpi warn"><b>${c.warn}</b><span>Atención</span></div><div class="kpi fail"><b>${c.fail}</b><span>Críticos</span></div><div class="kpi neut"><b>${c.neut}</b><span>N/D</span></div>`;
  $('#meta').innerHTML=`<span><b>Analizado:</b> ${new Date().toLocaleString('es-CO')}</span><span><b>Resolutor:</b> ${[...USED_RESOLVERS].join(', ')||RESOLVER}</span><span><b>Tiempo:</b> ${secs.toFixed(1)}s</span><span><b>Pruebas:</b> ${ITEMS.length}</span>`;
  // Blacklist alert banner
  const ba=$('#blAlert');
  if(BL_LISTED.length){
    const lists=[...new Set(BL_LISTED.map(x=>x.bl))];
    const ipsL=[...new Set(BL_LISTED.map(x=>x.ip))];
    ba.className='blalert';
    ba.innerHTML=`<div class="blalert-in"><span class="blbig"><svg class="i"><use href="#i-ban"/></svg></span><div><b>Dominio REPORTADO en listas negras</b><span>IP(s) afectada(s): ${ipsL.map(i=>esc(i)).join(', ')} · Listas: ${lists.map(l=>esc(l)).join(', ')}. Afecta gravemente la entrega de tu correo — solicita el delisting.</span></div></div>`;
    ba.style.display='block';
  } else { ba.style.display='none'; ba.innerHTML=''; }
  $('#dash').style.display='block';
  renderActionPlan(d);
  saveHistory(d,score);
  renderTabs();
  $('#dash').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function animateScore(target){
  const el=$('#scoreNum'),arc=$('#ringArc'),circ=2*Math.PI*80;
  const col=target>=85?'var(--ok)':target>=60?'var(--warn)':'var(--fail)';
  arc.style.stroke=col;el.style.color=col;
  arc.setAttribute('stroke-dasharray',circ.toFixed(0));
  requestAnimationFrame(()=>arc.setAttribute('stroke-dashoffset',(circ*(1-target/100)).toFixed(0)));
  let cur=0;const step=Math.max(1,Math.round(target/40));
  const iv=setInterval(()=>{cur+=step;if(cur>=target){cur=target;clearInterval(iv);}el.textContent=cur;},22);
}
/* ============================================================ Plan de acción / remediación */
function buildActionPlan(d){
  const A=[];const rec=n=>(REPORT[n]&&REPORT[n].record)||'';const st=n=>(REPORT[n]&&REPORT[n].status)||'neutral';
  const spf=rec('SPF');
  if(st('SPF')==='fail'&&!spf)A.push({sev:'fail',title:'Publicar registro SPF',why:'No existe SPF; cualquiera puede enviar correo en nombre del dominio.',impact:'Alto',effort:'Bajo',host:d,record:'v=spf1 include:_spf.google.com -all',note:'Reemplaza el include por los de tus proveedores reales de correo.'});
  else if(spf&&/[~?]all/.test(spf))A.push({sev:'warn',title:'Endurecer SPF a -all',why:'Tu SPF termina en softfail/neutral; el correo no autorizado no se rechaza.',impact:'Medio',effort:'Bajo',host:d,record:spf.replace(/[~?]all/,'-all'),note:'Confirma primero que todos tus emisores legítimos estén incluidos.'});
  const dm=rec('DMARC');const p=(dm.match(/p=(\w+)/i)||[])[1];const pl=p?p.toLowerCase():'';
  if(st('DMARC')==='fail'&&!dm)A.push({sev:'fail',title:'Publicar DMARC (fase de monitoreo)',why:'Sin DMARC no controlas la suplantación ni recibes reportes.',impact:'Alto',effort:'Bajo',host:'_dmarc.'+d,record:'v=DMARC1; p=none; rua=mailto:dmarc@'+d+'; ruf=mailto:dmarc@'+d+'; fo=1; adkim=r; aspf=r',note:'Tras 2–4 semanas revisando reportes, sube a p=quarantine y luego a p=reject.'});
  else if(pl==='none')A.push({sev:'fail',title:'Subir DMARC a quarantine → reject',why:'p=none solo monitorea; no protege contra suplantación.',impact:'Alto',effort:'Medio',host:'_dmarc.'+d,record:dm.replace(/p=none/i,'p=quarantine'),note:'Fase 1: p=quarantine con pct=25, sube a 100; Fase 2: p=reject.'});
  else if(pl==='quarantine')A.push({sev:'warn',title:'Elevar DMARC a reject',why:'quarantine desvía a spam pero no rechaza el correo falso.',impact:'Medio',effort:'Bajo',host:'_dmarc.'+d,record:dm.replace(/p=quarantine/i,'p=reject')});
  if(st('DKIM')==='fail')A.push({sev:'fail',title:'Activar firma DKIM (2048 bits)',why:'Sin DKIM el correo no puede verificarse criptográficamente.',impact:'Alto',effort:'Medio',note:'Actívalo en tu proveedor (Microsoft 365 / Google Workspace) y publica los CNAME/TXT que indique. Usa claves de 2048 bits.'});
  if(st('MTA-STS')!=='ok')A.push({sev:'warn',title:'Implementar MTA-STS',why:'Evita la degradación del cifrado TLS del correo entrante (downgrade).',impact:'Medio',effort:'Medio',host:'_mta-sts.'+d,record:'v=STSv1; id='+new Date().toISOString().slice(0,10).replace(/-/g,'')+'01',note:'Publica ese TXT y sirve https://mta-sts.'+d+'/.well-known/mta-sts.txt con: version: STSv1 · mode: enforce · mx: <tus MX> · max_age: 604800'});
  if(st('TLS-RPT')!=='ok')A.push({sev:'info',title:'Añadir TLS-RPT',why:'Recibe reportes de fallos de cifrado en la entrega.',impact:'Bajo',effort:'Bajo',host:'_smtp._tls.'+d,record:'v=TLSRPTv1; rua=mailto:tlsrpt@'+d});
  if(st('CAA')!=='ok')A.push({sev:'warn',title:'Publicar registros CAA',why:'Limita qué autoridades pueden emitir certificados TLS para tu dominio.',impact:'Medio',effort:'Bajo',host:d,record:'0 issue "letsencrypt.org"\n0 issue "digicert.com"\n0 iodef "mailto:security@'+d+'"',note:'Ajusta las CAs a las que realmente utilizas.'});
  if(st('DNSSEC')!=='ok')A.push({sev:'warn',title:'Habilitar DNSSEC',why:'Firma la zona DNS y evita respuestas falsificadas (incluidos tus SPF/DMARC).',impact:'Medio',effort:'Medio',note:'Actívalo en tu proveedor DNS/registrador y publica el registro DS en el TLD.'});
  if(st('Listas negras')==='fail')A.push({sev:'fail',title:'Solicitar delisting (IP en lista negra)',why:'Una IP de tus MX está reportada; afecta gravemente la entrega.',impact:'Alto',effort:'Medio',note:'Corrige la causa (relay abierto, equipo comprometido, spam saliente) y solicita la remoción en cada operador de RBL.'});
  if(st('DNS inverso (PTR)')==='warn')A.push({sev:'warn',title:'Configurar DNS inverso (PTR)',why:'Sin PTR muchos receptores rechazan o marcan como spam tu correo.',impact:'Medio',effort:'Bajo',note:'Pide a tu proveedor de hosting configurar el PTR de la IP hacia el hostname del servidor de correo.'});
  const rank={fail:0,warn:1,info:2};A.sort((a,b)=>rank[a.sev]-rank[b.sev]);
  return A;
}
function planText(d,A){return 'PLAN DE ACCIÓN DE SEGURIDAD — '+d+'\n'+new Date().toLocaleString('es-CO')+'\n'+'═'.repeat(50)+'\n\n'+A.map((a,i)=>`${i+1}. [${a.sev.toUpperCase()}] ${a.title}\n   Motivo: ${a.why}\n   Impacto: ${a.impact} · Esfuerzo: ${a.effort}${a.host?'\n   Publicar en: '+a.host:''}${a.record?'\n   Registro: '+a.record.replace(/\n/g,' | '):''}${a.note?'\n   Nota: '+a.note:''}`).join('\n\n')+'\n\nGenerado con Centinela.';}
function renderActionPlan(d){
  const w=$('#actionPlan');if(!w)return;const A=buildActionPlan(d);
  if(!A.length){w.innerHTML='<div class="glass phishcard"><div class="phverdict" data-s="color:var(--ok);margin:0"><svg class="i"><use href="#i-check-circle"/></svg> Sin acciones pendientes — la configuración es sólida</div></div>';return;}
  const chip=s=>s==='fail'?'<span class="badge b-fail"><span class="dot"></span>Crítico</span>':s==='warn'?'<span class="badge b-warn"><span class="dot"></span>Importante</span>':'<span class="badge b-info"><span class="dot"></span>Opcional</span>';
  const items=A.map((a,i)=>`<div class="apitem ${a.sev}"><div class="aphead"><span class="apnum">${i+1}</span><div data-s="flex:1;min-width:0"><b>${esc(a.title)}</b><div class="hint">${esc(a.why)}</div></div>${chip(a.sev)}</div><div class="apmeta">Impacto: <b>${a.impact}</b> · Esfuerzo: <b>${a.effort}</b>${a.host?' · Publicar en: <code>'+esc(a.host)+'</code>':''}</div>${a.record?`<div class="raw"><span class="copy" data-copy="${esc(a.record)}">copiar</span>${esc(a.record)}</div>`:''}${a.note?`<div class="hint" data-s="margin-top:6px"><svg class="i"><use href="#i-bulb"/></svg> ${esc(a.note)}</div>`:''}</div>`).join('');
  const nF=A.filter(a=>a.sev==='fail').length,nW=A.filter(a=>a.sev==='warn').length;
  w.innerHTML=`<div class="glass phishcard"><div data-s="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><div class="phverdict" data-s="margin:0"><svg class="i"><use href="#i-wrench"/></svg> Plan de acción — ${A.length} mejora(s)</div><span class="hint">${nF} crítica(s) · ${nW} importante(s)</span><button class="btn ghost" id="apDl" data-s="margin-left:auto"><svg class="i"><use href="#i-download"/></svg>Descargar plan (.txt)</button></div><div class="applist">${items}</div></div>`;
  const apDl=$('#apDl');if(apDl)apDl.addEventListener('click',()=>downloadFile('plan-accion-'+d+'.txt',planText(d,A)));
}

function renderSection(it,open){
  const[bc,bt]=BADGE[it.status]||BADGE.neutral;
  const sec=E('div','section glass'+(open?' open':''));sec.dataset.cat=it.cat;sec.dataset.status=it.status;
  const fh=it.findings.map(f=>{const ic={ok:'✓',warn:'!',fail:'✕',info:'i'}[f.sev]||'•';return `<li class="f-${f.sev}"><span class="ic">${ic}</span><div><b>${esc(f.title)}</b>${f.why?`<span class="why">${f.why}</span>`:''}</div></li>`;}).join('');
  const kvh=it.kv&&Object.keys(it.kv).length?'<div class="subh">Detalle técnico</div><table class="kv">'+Object.entries(it.kv).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')+'</table>':'';
  sec.innerHTML=`<div class="shead"><div class="sicon">${it.icon}</div><div class="stitle"><b>${esc(it.name)}</b><small>${esc(it.subtitle)}</small></div><div class="sledge"><span class="badge ${bc}"><span class="dot"></span>${bt}</span><span class="chev">▼</span></div></div><div class="sbody"><div class="sbodyin"><ul class="findings">${fh}</ul>${kvh}</div></div>`;
  sec.querySelector('.shead').addEventListener('click',()=>sec.classList.toggle('open'));
  return sec;
}
const CATS=[['todo','Todo','note'],['correo','Correo','mail'],['seguridad','Seguridad','shield'],['infra','Infraestructura','server'],['dominio','Dominio & DNS','globe']];
function renderTabs(){
  const tabs=$('#tabs');tabs.innerHTML='';
  CATS.forEach(([id,label,ic])=>{
    const n=id==='todo'?ITEMS.length:ITEMS.filter(i=>i.cat===id).length;
    if(!n&&id!=='todo')return;
    const t=E('button','tab'+(id==='todo'?' active':''),`${ico(ic)} ${label} <span class="cnt">${n}</span>`);
    t.dataset.cat=id;t.addEventListener('click',()=>filterCat(id,t));tabs.appendChild(t);
  });
  tabs.style.display='flex';
}
function filterCat(cat,btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.section').forEach(s=>s.classList.toggle('hide',cat!=='todo'&&s.dataset.cat!==cat));
}

/* Export */
function summaryText(){
  let o=`DNS GUARDIAN — ${$('#vdom').textContent}\nPuntaje: ${$('#scoreNum').textContent}/100 (${$('#scoreGrade').textContent}) — ${$('#verdict').textContent}\nFecha: ${new Date().toLocaleString('es-CO')}\n\n`;
  ITEMS.sort((a,b)=>ORDER.indexOf(a.name)-ORDER.indexOf(b.name)).forEach(it=>{
    o+=`■ ${it.name}: ${(BADGE[it.status]||BADGE.neutral)[1]}\n`;
    it.findings.forEach(f=>o+=`   ${({ok:'✓',warn:'!',fail:'✕',info:'·'}[f.sev]||'·')} ${f.title}\n`);
    if(it.record)o+=`   → ${it.record.split('\n')[0].slice(0,120)}\n`;o+='\n';
  });
  return o;
}
document.addEventListener('click',e=>{
  const c=e.target.closest('.copy');if(c){navigator.clipboard.writeText(c.dataset.copy);c.textContent='✓';setTimeout(()=>c.textContent='copiar',1000);}
  const ch=e.target.closest('.chip');if(ch&&ch.dataset.d){$('#domain').value=ch.dataset.d;run();}
});
$('#go').addEventListener('click',run);
$('#domain').addEventListener('keydown',e=>{if(e.key==='Enter')run();});
$('#advToggle').addEventListener('click',()=>$('#adv').classList.toggle('open'));
$('#advToggle').addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('#adv').classList.toggle('open');}});
/* Cambia solo el texto de un botón con icono (conserva el <svg>) */
function btnTxt(sel,txt){const e=typeof sel==='string'?$(sel):sel;if(!e)return;(e.querySelector(':scope > .t')||e).textContent=txt;}
$('#btnPrint').addEventListener('click',()=>window.print());
$('#btnCopy').addEventListener('click',()=>{navigator.clipboard.writeText(summaryText());btnTxt('#btnCopy','Copiado');setTimeout(()=>btnTxt('#btnCopy','Copiar resumen'),1400);});
$('#btnShare').addEventListener('click',()=>{const u=location.origin+location.pathname+'?d='+encodeURIComponent($('#vdom').textContent);navigator.clipboard.writeText(u);btnTxt('#btnShare','Copiado');setTimeout(()=>btnTxt('#btnShare','Enlace'),1400);});
$('#btnJson').addEventListener('click',()=>downloadFile('centinela-'+$('#vdom').textContent+'.json',JSON.stringify({domain:$('#vdom').textContent,score:+$('#scoreNum').textContent,date:new Date().toISOString(),resolvers:[...USED_RESOLVERS],report:REPORT},null,2),'application/json'));
/* ============================================================
   Módulo Phishing / Sitios maliciosos
   ============================================================ */
const MULTI_SUFFIX=['com.co','gov.co','edu.co','org.co','net.co','mil.co','co.uk','org.uk','gov.uk','com.mx','gob.mx','com.br','com.ar','gob.ar','co.in','com.au','co.jp','com.tr','com.ec','com.pe','com.ve','com.es'];
function registrable(host){host=host.toLowerCase().replace(/\.$/,'');const p=host.split('.');if(p.length<=2)return host;const l2=p.slice(-2).join('.');return MULTI_SUFFIX.includes(l2)?p.slice(-3).join('.'):p.slice(-2).join('.');}
function lev(a,b){const m=a.length,n=b.length,d=Array.from({length:m+1},(_,i)=>[i,...Array(n).fill(0)]);for(let j=0;j<=n;j++)d[0][j]=j;for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return d[m][n];}
function similar(a,b){if(!a||!b)return 0;const L=Math.max(a.length,b.length);return L?1-lev(a,b)/L:0;}
const SUSP_TLD=['tk','ml','ga','cf','gq','top','xyz','zip','mov','click','link','country','work','support','rest','fit','icu','buzz','live','shop','online','site','host','cam','sbs','cyou','quest','autos'];
const SUSP_TOK=['login','signin','sign-in','verify','verificar','secure','seguro','account','cuenta','update','actualizar','confirm','confirmar','banco','bank','wallet','clave','password','contrasena','pagar','payment','pago','soporte','webscr','recover','recuperar','unlock','desbloquear','suspend','premio','sorteo','factura'];
function setPhishStatus(t){const s=$('#phishStatus');if(s){s.style.display='flex';$('#phishStatusTxt').textContent=t;}}
function hidePhishStatus(){const s=$('#phishStatus');if(s)s.style.display='none';}

async function analyzePhish(){
  const raw=$('#phishUrl').value.trim();
  if(!raw){alert('Ingresa la URL o dominio sospechoso');return;}
  let url;try{url=new URL(/^https?:\/\//i.test(raw)?raw:'http://'+raw);}catch(e){alert('URL inválida. Ejemplo: https://sitio-sospechoso.co/login');return;}
  const host=url.hostname.toLowerCase();
  const brandRaw=$('#phishBrand').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'');
  const brand=brandRaw?registrable(brandRaw):'';
  const reg=registrable(host);
  const signals=[];let score=0;
  const add=(w,sev,title,why)=>{score+=w;signals.push({sev,title,why});};
  $('#goPhish').disabled=true;$('#phishOut').innerHTML='';
  try{
    if(/(^|\.)xn--/.test(host))add(30,'fail','Dominio con punycode/IDN (posibles homógrafos)','El host usa "xn--": letras de otros alfabetos que imitan visualmente una marca (p. ej. а cirílica por a latina).');
    if(/^\d+\.\d+\.\d+\.\d+$/.test(host))add(25,'fail','El host es una dirección IP','Los sitios legítimos usan nombres de dominio, no IPs directas.');
    const tld=host.split('.').pop();
    if(SUSP_TLD.includes(tld))add(15,'warn','TLD de alto riesgo: .'+tld,'Dominio de nivel superior frecuente en campañas de phishing por su bajo costo.');
    if(url.href.includes('@'))add(20,'fail','La URL contiene "@"','Todo lo anterior a "@" se ignora en el navegador; se usa para ocultar el destino real.');
    const labels=host.split('.').length;
    if(labels>=5)add(12,'warn','Muchos subdominios ('+labels+' niveles)','Los atacantes anidan subdominios para incrustar el nombre de la marca.');
    const hay=(host+url.pathname+url.search).toLowerCase();
    const toks=[...new Set(SUSP_TOK.filter(t=>hay.includes(t)))];
    if(toks.length)add(Math.min(18,toks.length*6),'warn','Palabras sensibles en la URL: '+toks.slice(0,5).join(', '),'Términos típicos de páginas que piden credenciales o datos financieros.');
    if(url.protocol==='http:')add(8,'warn','Sin HTTPS','No cifra la conexión; inusual en sitios legítimos que solicitan datos.');
    if((reg.match(/-/g)||[]).length>=2)add(8,'warn','Múltiples guiones en el dominio','p. ej. "portal-seguro-banco": patrón frecuente en dominios fraudulentos.');
    if(brand){
      const core=brand.split('.')[0], sim=similar(reg.split('.')[0],core);
      if(reg===brand)add(-45,'ok','Coincide con el dominio real','El dominio es exactamente el legítimo; no es suplantación por nombre.');
      else if(host.includes(core)&&reg!==brand)add(35,'fail','La marca "'+core+'" aparece pero el dominio NO es el real','El nombre está en un subdominio/ruta, pero el dominio registrable ('+reg+') no es '+brand+'. Suplantación muy probable.');
      else if(sim>=0.7)add(30,'fail','Dominio muy parecido al real ('+Math.round(sim*100)+'% de similitud)','"'+reg+'" se asemeja a "'+brand+'": typosquatting / lookalike.');
      else if(sim>=0.5)add(15,'warn','Cierto parecido con el real ('+Math.round(sim*100)+'%)','Podría ser un lookalike; revísalo manualmente.');
    }
    // DNS + reputación + geo + edad
    RESOLVER='auto';cache.clear();USED_RESOLVERS=new Set();
    let ip=null,geo=null,created=null,ageDays=null,listedOn=[];
    if(!/^\d+\.\d+\.\d+\.\d+$/.test(host)){
      setPhishStatus('Resolviendo DNS…');
      const a=await query(host,'A');ip=a.answers.map(x=>x.data).find(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x));
      if(!ip)add(10,'warn','El dominio no resuelve a una IP','Puede estar recién creado, dado de baja o mal escrito.');
    }else ip=host;
    if(ip){
      setPhishStatus('Consultando reputación de la IP…');
      const rev=ip.split('.').reverse().join('.');
      for(const bl of ['zen.spamhaus.org','bl.spamcop.net','dnsbl.sorbs.net','b.barracudacentral.org']){
        const q=await query(rev+'.'+bl,'A');
        if(q.answers.length&&!/^127\.255\.255\./.test(q.answers[0].data))listedOn.push(bl);
      }
      if(listedOn.length)add(20,'fail','IP en listas negras: '+listedOn.join(', '),'La IP que aloja el sitio ya está reportada por abuso/spam.');
      setPhishStatus('Geolocalizando…');geo=await geoLookup(ip);
    }
    setPhishStatus('Consultando registro (RDAP)…');
    let registrar=null,nservers=[],rstatus=[],ptr=null;
    try{const r=await fetch('https://rdap.org/domain/'+encodeURIComponent(reg),{headers:{'Accept':'application/rdap+json'}});
      if(r.ok){const j=await r.json();const ev=(j.events||[]).find(e=>e.eventAction==='registration');
        if(ev){created=ev.eventDate;ageDays=Math.round((Date.now()-new Date(created))/864e5);
          if(ageDays<30)add(25,'fail','Dominio MUY reciente ('+ageDays+' días)','Los dominios de phishing suelen tener pocos días de creados. Indicador fuerte.');
          else if(ageDays<180)add(12,'warn','Dominio reciente ('+ageDays+' días)','Antigüedad baja; combínalo con las demás señales.');
          else add(-5,'ok','Dominio con antigüedad (~'+Math.max(1,Math.round(ageDays/365))+' año/s)','Menos común en campañas de phishing, aunque no lo descarta.');
        }
        const rg=(j.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
        if(rg){const vc=rg.vcardArray&&rg.vcardArray[1];const fn=vc&&vc.find(x=>x[0]==='fn');registrar=fn?fn[3]:(rg.handle||null);}
        nservers=(j.nameservers||[]).map(n=>n.ldhName).filter(Boolean);
        rstatus=j.status||[];
      }}
    catch(e){}
    if(ip){try{const rev=ip.split('.').reverse().join('.')+'.in-addr.arpa';const q=await query(rev,'PTR');ptr=q.answers.map(x=>x.data)[0]||null;}catch(e){}}
    // Verificación automática: backend (Worker) si existe, o Google Safe Browsing con clave local
    const backend=(function(){try{return localStorage.getItem('ctn-backend')||'';}catch(e){return'';}})();
    const gsbKey=(function(){try{return localStorage.getItem('ctn-gsb')||'';}catch(e){return'';}})();
    if(backend){setPhishStatus('Verificando con el backend (VirusTotal / Safe Browsing)…');
      try{const rr=await fetch(backend+'/verify?url='+encodeURIComponent(url.href));if(rr.ok){const v=await rr.json();
        if(v.gsb==='listed')add(40,'fail','CATALOGADO por Google Safe Browsing','El backend confirma que la URL está en la base de amenazas de Google.');
        else if(v.gsb==='clean')add(0,'ok','Google Safe Browsing: sin coincidencias','No figura (aún) en la base de Google.');
        if(v.vt&&typeof v.vt.malicious==='number'){if(v.vt.malicious>0)add(Math.min(40,10+v.vt.malicious*5),'fail','VirusTotal: '+v.vt.malicious+' motor(es) lo marcan como malicioso','Verificación con 70+ motores antivirus vía el backend.');else add(0,'ok','VirusTotal: limpio','Ningún motor lo marca (según VirusTotal).');}
      }}catch(e){}
    } else if(gsbKey){setPhishStatus('Consultando Google Safe Browsing…');
      try{const gr=await safeBrowsingCheck(url.href,gsbKey);
        if(gr==='listed')add(40,'fail','CATALOGADO como malicioso por Google Safe Browsing','Verificación automática: Google confirma que esta URL está en su base de amenazas (phishing/malware).');
        else if(gr==='clean')add(0,'ok','Google Safe Browsing: sin coincidencias','La URL no figura (aún) en la base de Google. No descarta un sitio nuevo.');
      }catch(e){}
    }
    score=Math.max(0,Math.min(100,Math.round(score)));
    renderPhish({url,host,reg,brand,ip,geo,created,ageDays,listedOn,signals,score,registrar,nservers,rstatus,ptr});
  }catch(err){alert('Error en el análisis: '+err.message);console.error(err);}
  finally{$('#goPhish').disabled=false;hidePhishStatus();}
}

function buildReportText(r){
  const now=new Date();
  const refId='CTN-'+now.getFullYear()+(''+(now.getMonth()+1)).padStart(2,'0')+(''+now.getDate()).padStart(2,'0')+'-'+Math.random().toString(36).slice(2,7).toUpperCase();
  const lvl=r.score>=60?'ALTO':r.score>=30?'MEDIO':'BAJO';
  const org=(function(){try{return localStorage.getItem('ctn-org')||'';}catch(e){return'';}})();
  const iocs=r.signals.filter(s=>s.sev!=='ok');
  const geoStr=r.geo?[r.geo.city,r.geo.region,r.geo.country].filter(Boolean).join(', '):'—';
  const coord=r.geo&&r.geo.lat!=null?`${r.geo.lat}, ${r.geo.lon}`:'—';
  const L=[];
  L.push('═══════════════════════════════════════════════════════════');
  L.push('  REPORTE TÉCNICO DE SITIO MALICIOSO / SUPLANTACIÓN (PHISHING)');
  L.push('═══════════════════════════════════════════════════════════');
  L.push('Referencia: '+refId);
  L.push('Fecha y hora: '+now.toLocaleString('es-CO')+' (America/Bogota)');
  if(org) L.push('Entidad que reporta: '+org);
  L.push('Clasificación del incidente: Suplantación de identidad / Phishing');
  L.push('Nivel de riesgo (evaluación heurística): '+r.score+'/100 — '+lvl);
  L.push('');
  L.push('1. SITIO REPORTADO');
  L.push('   • URL completa......: '+r.url.href);
  L.push('   • Esquema/protocolo.: '+r.url.protocol.replace(':','')+(r.url.protocol==='http:'?' (SIN cifrado TLS)':' (TLS)'));
  L.push('   • Host..............: '+r.host);
  L.push('   • Dominio registrable: '+r.reg);
  L.push('   • TLD...............: .'+r.reg.split('.').pop());
  if(r.brand) L.push('   • Marca/dominio suplantado: '+r.brand);
  L.push('');
  L.push('2. INFRAESTRUCTURA (hosting)');
  L.push('   • Dirección IP......: '+(r.ip||'no resuelve'));
  L.push('   • DNS inverso (PTR).: '+(r.ptr||'sin PTR'));
  L.push('   • ASN / Red.........: '+((r.geo&&r.geo.asn)||'—'));
  L.push('   • Proveedor / ISP...: '+((r.geo&&(r.geo.org||r.geo.isp))||'—'));
  L.push('   • Ubicación.........: '+geoStr);
  L.push('   • Coordenadas.......: '+coord);
  L.push('   • Reputación IP.....: '+(r.listedOn&&r.listedOn.length?('LISTADA en '+r.listedOn.join(', ')):'sin reportes en las RBL consultadas'));
  L.push('');
  L.push('3. REGISTRO DEL DOMINIO (WHOIS/RDAP)');
  L.push('   • Fecha de creación.: '+(r.created?r.created.slice(0,10)+(r.ageDays!=null?' ('+r.ageDays+' días de antigüedad)':''):'desconocida'));
  L.push('   • Registrador.......: '+(r.registrar||'—'));
  L.push('   • Nameservers.......: '+((r.nservers&&r.nservers.length)?r.nservers.join(', '):'—'));
  if(r.rstatus&&r.rstatus.length) L.push('   • Estado (EPP)......: '+r.rstatus.join(', '));
  L.push('');
  L.push('4. INDICADORES DE COMPROMISO (IOCs) DETECTADOS');
  if(iocs.length) iocs.forEach((s,i)=>{L.push('   '+(i+1)+'. ['+(s.sev==='fail'?'ALTO':'MEDIO')+'] '+s.title);if(s.why)L.push('      → '+s.why);});
  else L.push('   (sin indicadores negativos automáticos; reportado por criterio del usuario)');
  L.push('');
  L.push('5. IMPACTO POTENCIAL');
  L.push('   Captura fraudulenta de credenciales y/o datos personales y financieros');
  L.push('   de las víctimas mediante la imitación de un sitio legítimo'+(r.brand?' ('+r.brand+')':'')+'.');
  L.push('');
  L.push('6. SOLICITUD');
  L.push('   Se solicita la verificación, bloqueo y/o baja (takedown) del sitio, la');
  L.push('   inclusión en listas de navegación segura y, si procede, el inicio de las');
  L.push('   actuaciones legales correspondientes.');
  L.push('');
  L.push('7. MARCO LEGAL (Colombia)');
  L.push('   • Ley 1273 de 2009 — "De la protección de la información y de los datos".');
  L.push('   • Art. 269G — Suplantación de sitios web para capturar datos personales.');
  L.push('   • Art. 269A/269F — Acceso abusivo y violación de datos personales.');
  L.push('   • Ley 1581 de 2012 — Protección de datos personales.');
  L.push('');
  L.push('8. RECOMENDACIONES / EVIDENCIA');
  L.push('   • No ingrese credenciales ni datos en el sitio reportado.');
  L.push('   • Conserve capturas de pantalla, encabezados de correo y la URL original.');
  L.push('   • Adjunte este reporte a la denuncia en los canales oficiales.');
  L.push('');
  L.push('───────────────────────────────────────────────────────────');
  L.push('Generado con Centinela · Análisis heurístico automatizado (orientativo,');
  L.push('no constituye determinación legal ni pericial). Verifique los datos.');
  return L.join('\n');
}

function renderPhish(r){
  const lv=r.score>=60?['ALTO','var(--fail)','<svg class="i"><use href="#i-stop"/></svg>','Alta probabilidad de sitio malicioso / suplantación']
        :r.score>=30?['MEDIO','var(--warn)','<svg class="i"><use href="#i-alert"/></svg>','Señales sospechosas — revísalo con cuidado antes de confiar']
        :['BAJO','var(--ok)','<svg class="i"><use href="#i-check-circle"/></svg>','Pocos indicadores de phishing detectados'];
  const encU=encodeURIComponent(r.url.href),rt=buildReportText(r),encT=encodeURIComponent(rt);
  const circ=2*Math.PI*70, off=(circ*(1-r.score/100)).toFixed(0);
  const sig=r.signals.slice().sort((a,b)=>({fail:0,warn:1,ok:2,info:1}[a.sev]-{fail:0,warn:1,ok:2,info:1}[b.sev]));
  const sigH=sig.map(s=>{const ic={ok:'✓',warn:'!',fail:'✕',info:'i'}[s.sev]||'•';return `<li class="f-${s.sev}"><span class="ic">${ic}</span><div><b>${esc(s.title)}</b>${s.why?`<span class="why">${esc(s.why)}</span>`:''}</div></li>`;}).join('');
  const flag=r.geo?(r.geo.flag||flagOf(r.geo.cc)||''):'';
  const siteKv={
    'URL':`<span data-s="font-family:var(--mono);font-size:12px;word-break:break-all">${esc(r.url.href)}</span>`,
    'Dominio registrable':tag(r.reg,r.score>=60?'r':''),
    'IP':r.ip?esc(r.ip):tag('no resuelve','y'),
    'Alojamiento':r.geo?`${flag} ${esc(r.geo.country||'—')} · ${esc(r.geo.org||r.geo.isp||'—')} ${r.geo.asn?tag(r.geo.asn):''}`:'—',
    'Registrado':r.created?esc(r.created.slice(0,10))+(r.ageDays!=null?` <span class="hint">(${r.ageDays} días)</span>`:''):'—',
    'Reputación IP':r.listedOn&&r.listedOn.length?`<span data-s="color:var(--fail)"><svg class="i"><use href="#i-alert"/></svg> ${r.listedOn.map(esc).join(', ')}</span>`:tag('sin reportes','g')
  };
  const kvH='<table class="kv">'+Object.entries(siteKv).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')+'</table>';
  const inv=investigateCards(r.host,r.reg,r.ip,r.url.href);
  const rep=reportCards(r.host,r.url.href,encT);
  $('#phishOut').innerHTML=`
    <div class="glass phishcard">
      <div class="phrow">
        <div class="gauge">
          <svg width="160" height="160" viewBox="0 0 160 160" data-s="transform:rotate(-90deg)">
            <circle cx="80" cy="80" r="70" fill="none" stroke="var(--line2)" stroke-width="12"/>
            <circle cx="80" cy="80" r="70" fill="none" stroke="${lv[1]}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${circ.toFixed(0)}" stroke-dashoffset="${circ.toFixed(0)}" data-s="transition:stroke-dashoffset 1s ease" id="phArc"/>
          </svg>
          <div class="num"><div data-s="text-align:center"><b data-s="color:${lv[1]}">${r.score}</b><small>riesgo /100</small><div data-s="font-weight:800;letter-spacing:1px;color:${lv[1]};margin-top:4px">${lv[2]} ${lv[0]}</div></div></div>
        </div>
        <div>
          <div class="phverdict" data-s="color:${lv[1]}">${esc(lv[3])}</div>
          <div class="phurl">${esc(r.url.href)}</div>
          <ul class="findings">${sigH}</ul>
        </div>
      </div>
      <div class="subh">Datos del sitio</div>${kvH}
      <div class="subh"><svg class="i"><use href="#i-search"/></svg>Investigar / analizar (MXToolbox, VirusTotal y más)</div>
      <div class="repgrid">${inv.map(cardHtml).join('')}</div>
      <div class="subh"><svg class="i"><use href="#i-shield-alert"/></svg>Reportar gratis — canales oficiales</div>
      <div class="repgrid">${rep.global.map(cardHtml).join('')}</div>
      <div class="subh"><svg class="i"><use href="#i-building"/></svg>Colombia</div>
      <div class="repgrid">${rep.co.map(cardHtml).join('')}</div>
      <div class="subh">Texto de denuncia técnico (cópialo y pégalo en el formulario o correo)</div>
      <div class="reptext"><span class="copy" data-copy="${esc(rt)}" data-s="position:absolute;top:8px;right:8px;font-size:11px;padding:3px 9px;background:var(--panel);border:1px solid var(--line);border-radius:7px;color:var(--muted);cursor:pointer">copiar</span>${esc(rt)}</div>
      <div class="dashbtns" data-s="justify-content:flex-start;margin-top:10px">
        <button class="btn ghost" id="phTxt"><svg class="i"><use href="#i-download"/></svg>Descargar denuncia (.txt)</button>
        <button class="btn ghost" id="phPrint"><svg class="i"><use href="#i-printer"/></svg>Imprimir / PDF</button>
        <button class="btn ghost" id="phSbx"><svg class="i"><use href="#i-bug"/></svg>Analizar el contenido en el sandbox</button>
      </div>
      <p class="hint" data-s="margin-top:12px">Este análisis es heurístico (orientativo), no una determinación legal ni una prueba definitiva. No ingreses tus credenciales en el sitio sospechoso. Para suplantación de un dominio oficial, reporta también a su administrador de dominio.</p>
    </div>`;
  requestAnimationFrame(()=>{const a=document.getElementById('phArc');if(a)a.setAttribute('stroke-dashoffset',off);});
  const phTxt=$('#phTxt');{const sb=$('#phSbx');if(sb)sb.addEventListener('click',()=>{setMode('sbx');sbxTab('url');$('#sbxUrl').value=r.url.href;runSbxUrl();window.scrollTo({top:0,behavior:'smooth'});});}if(phTxt)phTxt.addEventListener('click',()=>downloadFile('denuncia-'+r.reg+'.txt',rt));
  const pr=$('#phPrint');if(pr)pr.addEventListener('click',()=>window.print());
  $('#phishOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ---- Shared investigate / report link builders ---- */
function investigateCards(host,reg,ip,urlHref){
  const encH=encodeURIComponent(reg||host),encU=urlHref?encodeURIComponent(urlHref):encodeURIComponent('http://'+(reg||host)),encIP=ip?encodeURIComponent(ip):'';
  return [
    ['MXToolbox', ip?'Blacklist de la IP':'MX / DNS del dominio','sliders', ip?('https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a'+encIP+'&run=toolpage'):('https://mxtoolbox.com/SuperTool.aspx?action=mx%3a'+encH+'&run=toolpage')],
    ['VirusTotal','Reputación (70+ motores)','bug', ip?('https://www.virustotal.com/gui/ip-address/'+encIP):('https://www.virustotal.com/gui/domain/'+encH)],
    ['urlscan.io','Escaneo del sitio','search','https://urlscan.io/search/#'+encH],
    ['AbuseIPDB', ip?'Reputación de la IP':'Reputación','shield-alert', ip?('https://www.abuseipdb.com/check/'+encIP):('https://www.abuseipdb.com/check/'+encH)],
    ['Cisco Talos','Centro de reputación','radar','https://talosintelligence.com/reputation_center/lookup?search='+encodeURIComponent(ip||reg||host)],
    ['Netcraft Site Report','Perfil e infraestructura','chart','https://sitereport.netcraft.com/?url='+encU],
    ['Sucuri SiteCheck','Malware & listas negras','shield','https://sitecheck.sucuri.net/results/'+encH],
    ['Safe Browsing (Google)','Estado de navegación segura','search','https://transparencyreport.google.com/safe-browsing/search?url='+encU],
    ['WHOIS (who.is)','Datos de registro','book','https://who.is/whois/'+encH],
  ];
}
function reportCards(host,urlHref,encT){
  const encU=urlHref?encodeURIComponent(urlHref):'';
  return {global:[
    ['Google Safe Browsing','Reportar página de phishing','search','https://safebrowsing.google.com/safebrowsing/report_phish/?url='+encU],
    ['Microsoft SmartScreen','Reportar sitio inseguro','shield','https://www.microsoft.com/wdsi/support/report-unsafe-site'],
    ['Cloudflare Abuse','Phishing alojado en Cloudflare','globe','https://abuse.cloudflare.com/phishing'],
    ['Netcraft','Reportar phishing','radar','https://report.netcraft.com/report'],
    ['APWG','Correo a Anti-Phishing WG','mail','mailto:reportphishing@apwg.org?subject='+encodeURIComponent('Phishing report: '+host)+'&body='+encT],
    ['PhishTank','Base comunitaria de phishing','hook','https://phishtank.org/'],
    ['Spamhaus','Reportar abuso / spam','ban','https://www.spamhaus.org/report/'],
  ],co:[
    ['CAI Virtual — Policía Nacional','Denuncia de delito informático','shield-alert','https://caivirtual.policia.gov.co/'],
    ['colCERT / CSIRT Gobierno','Incidente en dominios .gov.co','building','https://www.colcert.gov.co/'],
    ['Fiscalía General','Denuncia virtual','scale','https://www.fiscalia.gov.co/colombia/servicios-de-informacion-al-ciudadano/'],
    ['Te Protejo (MinTIC · Red PaPaz)','Reportar estafa / contenido','shield','https://teprotejo.org/'],
  ]};
}
const cardHtml=c=>`<a class="repcard" href="${c[3]}" target="_blank" rel="noopener"><div class="ri">${ico(c[2])}</div><div><b>${esc(c[0])}</b><span>${esc(c[1])}</span></div></a>`;

/* ============================================================
   Módulo Geolocalización IP + mapa
   ============================================================ */
function setGeoStatus(t){const s=$('#geoStatus');if(s){s.style.display='flex';$('#geoStatusTxt').textContent=t;}}
function hideGeoStatus(){const s=$('#geoStatus');if(s)s.style.display='none';}
async function myPublicIP(){
  for(const u of ['https://api.ipify.org?format=json','https://ipwho.is/']){
    try{const r=await fetch(u);if(r.ok){const j=await r.json();if(j.ip)return j.ip;}}catch(e){}
  }
  return null;
}
async function runGeo(){
  let inp=$('#geoInput').value.trim();
  if(!inp){alert('Ingresa una IP o dominio');return;}
  $('#goGeo').disabled=true;$('#geoOut').innerHTML='';
  try{
    RESOLVER='auto';cache.clear();USED_RESOLVERS=new Set();
    let ip=null,host=null;
    if(inp==='mi-ip'){setGeoStatus('Obteniendo tu IP pública…');ip=await myPublicIP();if(!ip){alert('No se pudo obtener tu IP pública');return;}}
    else if(/^\d+\.\d+\.\d+\.\d+$/.test(inp)) ip=inp;
    else{host=inp.toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'');setGeoStatus('Resolviendo dominio…');const a=await query(host,'A');ip=a.answers.map(x=>x.data).find(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x));if(!ip){alert('El dominio no resuelve a una IP');return;}}
    setGeoStatus('Geolocalizando IP…');
    const g=await geoLookup(ip);
    if(!g){$('#geoOut').innerHTML='<div class="glass phishcard"><p>No se pudo geolocalizar la IP (el proveedor de geo-IP puede estar limitado o bloqueado por CORS). Ábrela desde un navegador o un hosting.</p></div>';return;}
    setGeoStatus('Consultando DNS inverso y reputación…');
    let ptr=null;try{const rev=ip.split('.').reverse().join('.')+'.in-addr.arpa';const q=await query(rev,'PTR');ptr=q.answers.map(x=>x.data)[0]||null;}catch(e){}
    let listedOn=[];for(const bl of ['zen.spamhaus.org','bl.spamcop.net','dnsbl.sorbs.net','b.barracudacentral.org']){const q=await query(ip.split('.').reverse().join('.')+'.'+bl,'A');if(q.answers.length&&!/^127\.255\.255\./.test(q.answers[0].data))listedOn.push(bl);}
    renderGeo({ip,host,g,ptr,listedOn});
  }catch(err){alert('Error: '+err.message);console.error(err);}
  finally{$('#goGeo').disabled=false;hideGeoStatus();}
}
function renderGeo(r){
  const g=r.g, flag=g.flag||flagOf(g.cc)||'<svg class="i"><use href="#i-globe"/></svg>';
  const lat=g.lat,lon=g.lon;
  let localTime='—';try{if(g.tz)localTime=new Date().toLocaleString('es-CO',{timeZone:g.tz,hour:'2-digit',minute:'2-digit',hour12:false})+' h';}catch(e){}
  const mapHtml = (lat!=null&&lon!=null) ? (()=>{
    const d=0.6, bbox=[lon-d,lat-d,lon+d,lat+d].join('%2C');
    return `<iframe class="geomap" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}"></iframe>`;
  })() : '<div class="geomap" data-s="display:grid;place-items:center;color:var(--muted)">Sin coordenadas para el mapa</div>';
  const tile=(l,v)=>`<div class="geotile"><div class="lbl">${l}</div><div class="val">${v}</div></div>`;
  const inv=investigateCards(r.host||r.ip, r.host||r.ip, r.ip, r.host?('http://'+r.host):('http://'+r.ip));
  $('#geoOut').innerHTML=`
    <div class="glass geocard">
      ${mapHtml}
      <div class="geohead">
        <div class="geoflag">${flag}</div>
        <div class="gh"><b>${esc([g.city,g.region,g.country].filter(Boolean).join(', ')||g.country||'Ubicación desconocida')}</b>
          <span>${esc(r.ip)}${r.host?' · '+esc(r.host):''}${g.cc?' · '+esc(g.cc):''}</span></div>
      </div>
      <div class="geobody">
        <div class="geogrid">
          ${tile('País', (flag)+' '+esc(g.country||'—')+(g.cc?' <small>('+esc(g.cc)+')</small>':''))}
          ${tile('Ciudad / Región', esc([g.city,g.region].filter(Boolean).join(', ')||'—')+(g.postal?' <small>CP '+esc(g.postal)+'</small>':''))}
          ${tile('Coordenadas', (lat!=null?esc(lat+', '+lon):'—'))}
          ${tile('Hora local', esc(localTime)+(g.tz?' <small>'+esc(g.tz)+'</small>':''))}
          ${tile('ASN / Red', g.asn?tag(g.asn,'g'):'—')}
          ${tile('Organización / ISP', esc(g.org||g.isp||'—'))}
          ${tile('DNS inverso (PTR)', r.ptr?tag(r.ptr,'g'):tag('sin PTR','y'))}
          ${tile('Reputación IP', r.listedOn.length?'<span data-s="color:var(--fail);font-weight:700"><svg class="i"><use href="#i-alert"/></svg> '+r.listedOn.map(esc).join(', ')+'</span>':tag('sin reportes','g'))}
        </div>
        <div class="dashbtns" data-s="justify-content:flex-start;margin-top:6px">
          <a class="btn ghost" href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" rel="noopener"><svg class="i"><use href="#i-map"/></svg>Google Maps</a>
          <a class="btn ghost" href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=11/${lat}/${lon}" target="_blank" rel="noopener"><svg class="i"><use href="#i-globe"/></svg>OpenStreetMap</a>
          <button class="btn ghost" id="geoCopy"><svg class="i"><use href="#i-copy"/></svg><span class="t">Copiar datos</span></button>
        </div>
        <div class="subh"><svg class="i"><use href="#i-search"/></svg>Investigar esta IP / dominio</div>
        <div class="lookgrid">${inv.map(cardHtml).join('')}</div>
      </div>
    </div>`;
  const gc=$('#geoCopy');if(gc)gc.addEventListener('click',()=>{const t=`IP: ${r.ip}\nUbicación: ${[g.city,g.region,g.country].filter(Boolean).join(', ')}\nCoordenadas: ${lat}, ${lon}\nASN: ${g.asn||'-'} (${g.org||g.isp||'-'})\nPTR: ${r.ptr||'-'}\nZona horaria: ${g.tz||'-'}`;navigator.clipboard.writeText(t);btnTxt(gc,'Copiado');setTimeout(()=>btnTxt(gc,'Copiar datos'),1400);});
  $('#geoOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ============================================================ Comparar dominios */
async function snapshotChecks(d){
  d=d.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))return{domain:d,fail:'inválido'};
  cache.clear();ITEMS=[];REPORT={};MX_IPS=[];SITE_IPS=[];BL_LISTED=[];
  const base=await checkBase(d);if(base.status==='fail')return{domain:d,fail:'no existe'};
  await checkSPF(d);await checkDKIM(d,[]);await checkDMARC(d);await checkMX(d);await checkDNSSEC(d);await checkCAA(d);await checkMTASTS(d);
  const snap={};ITEMS.forEach(it=>snap[it.name]=it.status);
  let total=0,max=0;ITEMS.forEach(it=>{const w=WEIGHTS[it.name]||0;if(w){max+=w;total+=w*(SCOREVAL[it.status]??0);}});
  return{domain:d,score:max?Math.round(total/max*100):0,snap};
}
async function runCompare(){
  const a=$('#cmpA').value.trim(),b=$('#cmpB').value.trim();
  if(!a||!b){alert('Ingresa los dos dominios a comparar');return;}
  $('#goCmp').disabled=true;$('#cmpOut').innerHTML='';const st=$('#cmpStatus');st.style.display='flex';
  try{
    RESOLVER='auto';
    $('#cmpStatusTxt').textContent='Analizando '+a+'…';const RA=await snapshotChecks(a);
    $('#cmpStatusTxt').textContent='Analizando '+b+'…';const RB=await snapshotChecks(b);
    renderCompare(RA,RB);
  }catch(err){alert('Error: '+err.message);console.error(err);}
  finally{$('#goCmp').disabled=false;st.style.display='none';}
}
function renderCompare(A,B){
  const rows=['SPF','DKIM','DMARC','MX','MTA-STS','DNSSEC','CAA'];
  const bcol=s=>s==='ok'?'var(--ok)':s==='warn'?'var(--warn)':s==='fail'?'var(--fail)':'var(--muted2)';
  const btxt=s=>({ok:'✓ OK',warn:'! Atención',fail:'✕ Crítico',neutral:'– N/D',info:'✓ OK'}[s]||'–');
  const cell=s=>`<td data-s="text-align:center"><span data-s="color:${bcol(s)};font-weight:700">${btxt(s)}</span></td>`;
  const scol=s=>s>=85?'var(--ok)':s>=60?'var(--warn)':'var(--fail)';
  const head=(R)=>R.fail?`<div data-s="text-align:center"><div data-s="font-size:13px;color:var(--fail)">${esc(R.domain||'—')}</div><div class="hint">${esc(R.fail)}</div></div>`
    :`<div data-s="text-align:center"><div data-s="font-family:var(--mono);font-size:12.5px;color:var(--muted);margin-bottom:4px">${esc(R.domain)}</div><div data-s="font-size:30px;font-weight:800;color:${scol(R.score)}">${R.score}<span data-s="font-size:13px;color:var(--muted)">/100</span></div></div>`;
  const body=(A.fail||B.fail)?'':rows.map(r=>`<tr><td data-s="font-weight:600">${r}</td>${cell(A.snap[r]||'neutral')}${cell(B.snap[r]||'neutral')}</tr>`).join('');
  const winner=(!A.fail&&!B.fail)?(A.score===B.score?'Empate técnico':(A.score>B.score?A.domain+' tiene mejor postura':B.domain+' tiene mejor postura')):'';
  $('#cmpOut').innerHTML=`<div class="glass phishcard">
    <table class="kv" data-s="table-layout:fixed"><tr><td data-s="width:34%"></td><td>${head(A)}</td><td>${head(B)}</td></tr></table>
    ${winner?`<div data-s="text-align:center;font-weight:700;margin:6px 0 14px;color:var(--accent)"><svg class="i"><use href="#i-check-circle"/></svg> ${esc(winner)}</div>`:''}
    <table class="mini"><tr><th>Control</th><th data-s="text-align:center">A</th><th data-s="text-align:center">B</th></tr>${body}</table>
    <p class="hint" data-s="margin-top:12px">Comparativa de controles clave. Para el detalle completo de cada dominio usa el módulo "Dominio & correo".</p>
  </div>`;
  $('#cmpOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* Sustituciones de caracteres parecidos (homóglifos), usadas para generar variantes de dominio */
const HOMO={o:['0'],'0':['o'],l:['1','i'],i:['1','l'],e:['3'],a:['4'],s:['5'],b:['8'],g:['9'],c:['('],m:['nn'],n:['m']};

/* ============================================================ Helpers de postura DNS/correo (compartidos por recon y vuln) */
async function posSPF(dom){const q=await query(dom,'TXT');const rec=q.answers.map(x=>x.data).find(x=>/^v=spf1/i.test(x))||'';const all=(rec.match(/([-~?+])all\b/i)||[])[1]||'';return{present:!!rec,record:rec,all};}
async function posDMARC(dom){const q=await query('_dmarc.'+dom,'TXT');const rec=q.answers.map(x=>x.data).find(x=>/^v=DMARC1/i.test(x))||'';const p=(rec.match(/\bp=(\w+)/i)||[])[1]||'';return{present:!!rec,record:rec,policy:p};}
async function posDNSSEC(dom){const q=await query(dom,'DS');return{present:!!q.answers.length};}
async function posCAA(dom){const q=await query(dom,'CAA');return{present:!!q.answers.length,records:q.answers.map(a=>a.data)};}
async function posMTASTS(dom){const q=await query('_mta-sts.'+dom,'TXT');return{present:q.answers.some(x=>/v=STSv1/i.test(x.data))};}

/* ============================================================ Ciberinteligencia OSINT (recon) */
const RECON_TLDS=['com','net','org','co','info','online','site','top','xyz','app','io','me','biz','live','click','link','pro','gov.co','edu.co','com.co','org.co','net.co','com.mx','com.ar','pe','cl','es'];
const RECON_KW=['seguro','online','portal','oficial','pagos','pago','acceso','soporte','ayuda','login','cuenta','cuentas','verificar','verificacion','tramite','tramites','sistema','virtual','sso','gob','gov','info','app','net'];
function reconVariants(reg,depth){
  const parts=reg.split('.');const sld=parts[0];const tld=parts.slice(1).join('.');
  const V=new Set();
  for(let i=0;i<sld.length;i++){const su=HOMO[sld[i]];if(su)su.forEach(s=>V.add(sld.slice(0,i)+s+sld.slice(i+1)));}
  if(sld.includes('m'))V.add(sld.replace('m','rn'));
  if(sld.includes('rn'))V.add(sld.replace('rn','m'));
  if(sld.includes('w'))V.add(sld.replace('w','vv'));
  if(sld.includes('cl'))V.add(sld.replace('cl','d'));
  for(let i=0;i<sld.length;i++)V.add(sld.slice(0,i)+sld.slice(i+1));                        // omisión
  for(let i=0;i<sld.length;i++)V.add(sld.slice(0,i)+sld[i]+sld[i]+sld.slice(i+1));           // duplicación
  for(let i=0;i<sld.length-1;i++)V.add(sld.slice(0,i)+sld[i+1]+sld[i]+sld.slice(i+2));       // transposición
  if(depth!=='fast'){
    const KB={a:'qsz',e:'wrd',i:'ou',o:'ip',s:'ad',n:'mb',r:'et',l:'k',c:'xv',m:'n',t:'ry',u:'yi',d:'sf',g:'fh',b:'vn',p:'ol'};
    for(let i=0;i<sld.length;i++){const adj=KB[sld[i]];if(adj)for(const k of adj){V.add(sld.slice(0,i)+k+sld.slice(i+1));if(depth==='max')V.add(sld.slice(0,i)+sld[i]+k+sld.slice(i+1));}}
    for(let i=0;i<sld.length;i++)if('aeiou'.includes(sld[i]))for(const v of 'aeiou')if(v!==sld[i])V.add(sld.slice(0,i)+v+sld.slice(i+1)); // permuta vocal
  }
  V.delete(sld);
  const doms=new Set();
  V.forEach(v=>{if(v&&v.length>1)doms.add(v+'.'+tld);});
  RECON_TLDS.forEach(t=>{if(t!==tld)doms.add(sld+'.'+t);});
  const combTlds=depth==='max'?['com','co','net','online','site','xyz','top','info','com.co','gov.co']:depth==='deep'?['com','co','net','online','info']:['com','co'];
  RECON_KW.forEach(kw=>{combTlds.forEach(t=>{doms.add(sld+'-'+kw+'.'+t);doms.add(kw+'-'+sld+'.'+t);if(depth==='max')doms.add(sld+kw+'.'+t);});});
  doms.delete(reg);
  const cap=depth==='fast'?60:depth==='deep'?150:280;
  return [...doms].slice(0,cap);
}
async function ctSearch(sld){
  const out=new Set();
  try{
    const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),15000);
    const r=await fetch('https://crt.sh/?q=%25'+encodeURIComponent(sld)+'%25&output=json',{signal:ctrl.signal});
    clearTimeout(to);
    if(r.ok){const j=await r.json();(j||[]).forEach(row=>{String(row.name_value||'').split(/\n/).forEach(n=>{n=n.trim().toLowerCase().replace(/^\*\./,'');if(/^[a-z0-9.-]+\.[a-z]{2,}$/.test(n))out.add(registrable(n));});});}
  }catch(e){}
  return [...out];
}
async function shodanIDB(ip){
  try{const r=await fetch('https://internetdb.shodan.io/'+ip);if(r.ok){const j=await r.json();return{ports:j.ports||[],hostnames:j.hostnames||[],cpes:j.cpes||[],vulns:j.vulns||[],tags:j.tags||[]};}}catch(e){}
  return null;
}
async function reconEnrich(dom){
  const d={dom,ips:[],ns:[],mx:[],mxprov:''};
  const a=await query(dom,'A');d.ips=a.answers.map(x=>x.data).filter(ip=>/^\d+\.\d+\.\d+\.\d+$/.test(ip));
  const ns=await query(dom,'NS');d.ns=ns.answers.map(x=>x.data.replace(/\.$/,''));
  const mx=await query(dom,'MX');d.mx=mx.answers.map(x=>{const p=x.data.split(' ');return p.slice(1).join(' ').replace(/\.$/,'');}).filter(Boolean);
  for(const h of d.mx){for(const[re,n]of MXP){if(re.test(h)){d.mxprov=n;break;}}if(d.mxprov)break;}
  const _spf=await posSPF(dom);d.spf=_spf.record;
  const _dm=await posDMARC(dom);d.dmarc=_dm.record;d.dmarcP=_dm.policy;
  d.idn=/(^|\.)xn--/i.test(dom);                       // IDN / homóglifo Punycode
  if(d.ips.length){
    d.geo=await geoLookup(d.ips[0]);
    d.shodan=await shodanIDB(d.ips[0]);
    const rev=d.ips[0].split('.').reverse().join('.');const bl=await query(rev+'.zen.spamhaus.org','A');d.listed=!!(bl.answers.length&&!/^127\.255\.255\./.test(bl.answers[0].data));
  }
  try{const r=await fetch('https://archive.org/wayback/available?url='+encodeURIComponent(dom));if(r.ok){const j=await r.json();const s=j&&j.archived_snapshots&&j.archived_snapshots.closest;if(s&&s.available)d.wayback={ts:s.timestamp,url:s.url};}}catch(e){}
  try{
    const r=await fetch('https://rdap.org/domain/'+encodeURIComponent(dom),{headers:{'Accept':'application/rdap+json'}});
    if(r.ok){const j=await r.json();const ev={};(j.events||[]).forEach(e=>ev[e.eventAction]=e.eventDate);
      d.created=ev.registration;d.expires=ev.expiration;
      const reg=(j.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
      if(reg){const vc=reg.vcardArray&&reg.vcardArray[1];const fn=vc&&vc.find(x=>x[0]==='fn');d.registrar=fn?fn[3]:(reg.handle||'');}
      let abuse='';const scan=en=>{if((en.roles||[]).includes('abuse')){const vc=en.vcardArray&&en.vcardArray[1];const em=vc&&vc.find(x=>x[0]==='email');if(em&&!abuse)abuse=em[3];}};
      (j.entities||[]).forEach(e=>{scan(e);(e.entities||[]).forEach(scan);});d.abuse=abuse;
    }
  }catch(e){}
  return d;
}
function reconScore(d){
  let s=0;const reasons=[];
  if(d.ips&&d.ips.length){s+=26;reasons.push('IP activa (aloja contenido)');}
  if(d.mx.length){s+=20;reasons.push('correo configurado (puede enviar phishing)');}
  if(d.mx.length&&!d.dmarcP)  {s+=8;reasons.push('correo sin DMARC (spoofeable)');}
  if(d.spf)s+=3;
  if(d.idn){s+=15;reasons.push('dominio IDN/Punycode (homóglifo)');}
  if(typeof d.sim==='number'&&d.sim>=80){s+=10;reasons.push('nombre casi idéntico ('+d.sim+'%)');}
  if(d.listed){s+=22;reasons.push('en lista negra Spamhaus');}
  if(d.created){const days=(Date.now()-new Date(d.created).getTime())/864e5;if(days>=0&&days<90){s+=18;reasons.push('registrado hace <90 días');}else if(days<180){s+=9;reasons.push('registrado hace <6 meses');}}
  if(d.wayback){s+=4;reasons.push('con historial en Wayback');}
  if(d.shodan&&d.shodan.ports&&d.shodan.ports.some(p=>[80,443,8080,8443].includes(p))){s+=9;reasons.push('servidor web expuesto');}
  if(d.shodan&&d.shodan.vulns&&d.shodan.vulns.length){s+=8;reasons.push(d.shodan.vulns.length+' CVE(s) reportadas');}
  return {score:Math.min(100,s),reasons};
}
function reconPivots(dom,brand){
  const q=encodeURIComponent(dom),b=encodeURIComponent(brand);
  return {
    surface:[['urlscan.io','https://urlscan.io/search/#'+q],['VirusTotal','https://www.virustotal.com/gui/domain/'+q],['Shodan','https://www.shodan.io/search?query='+q],['Censys','https://search.censys.io/search?resource=hosts&q='+q],['crt.sh','https://crt.sh/?q='+q],['SecurityTrails','https://securitytrails.com/domain/'+dom+'/dns'],['DNSlytics','https://dnslytics.com/domain/'+dom],['ViewDNS','https://viewdns.info/whois/?domain='+dom],['Robtex','https://www.robtex.com/dns-lookup/'+dom],['BuiltWith','https://builtwith.com/'+dom],['Netcraft','https://sitereport.netcraft.com/?url='+q],['Sucuri','https://sitecheck.sucuri.net/results/'+dom],['Talos','https://talosintelligence.com/reputation_center/lookup?search='+dom],['who.is','https://who.is/whois/'+dom],['MXToolbox','https://mxtoolbox.com/SuperTool.aspx?action=mx%3a'+dom],['Google dork','https://www.google.com/search?q='+encodeURIComponent('site:'+dom+' OR "'+brand+'"')],['Bing','https://www.bing.com/search?q='+q],['Wayback','https://web.archive.org/web/*/'+dom+'/*']],
    deep:[['Intelligence X','https://intelx.io/?s='+q],['GreyNoise','https://viz.greynoise.io/query/?gnql='+q],['Pulsedive','https://pulsedive.com/indicator/?ioc='+q],['AlienVault OTX','https://otx.alienvault.com/indicator/domain/'+dom],['ThreatMiner','https://www.threatminer.org/domain.php?q='+dom],['ThreatFox','https://threatfox.abuse.ch/browse.php?search=ioc%3A'+q],['MalwareBazaar','https://bazaar.abuse.ch/browse.php?search='+q],['URLhaus','https://urlhaus.abuse.ch/browse.php?search='+q],['Maltiverse','https://maltiverse.com/search;query='+q],['LeakIX','https://leakix.net/search?scope=leak&q='+q],['ZoomEye','https://www.zoomeye.org/searchResult?q='+q],['PublicWWW','https://publicwww.com/websites/'+q+'/'],['grep.app','https://grep.app/search?q='+q],['PhishTank','https://phishtank.org/'],['OpenPhish','https://openphish.com/'],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query='+q],['ANY.RUN','https://any.run/submissions#filter='+q]],
    dark:[['Ahmia (Tor)','https://ahmia.fi/search/?q='+b],['IntelX (leaks)','https://intelx.io/?s='+b],['HIBP (dominio)','https://haveibeenpwned.com/DomainSearch'],['Onionland','https://onionlandsearchengine.net/search?q='+b],['Tor66','http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/'],['Ransomlook','https://www.ransomlook.io/search?query='+b],['RansomWatch','https://ransomwatch.telemetry.ltd/'],['DeHashed','https://dehashed.com/search?query='+b],['BreachDirectory','https://breachdirectory.org/'],['Dark.fail','https://dark.fail/']]
  };
}
function ipPivots(ip){
  const q=encodeURIComponent(ip);
  return [['Shodan','https://www.shodan.io/host/'+ip],['Censys','https://search.censys.io/hosts/'+ip],['ViewDNS rev','https://viewdns.info/reverseip/?host='+ip+'&t=1'],['GreyNoise','https://viz.greynoise.io/ip/'+ip],['AbuseIPDB','https://www.abuseipdb.com/check/'+ip],['VirusTotal','https://www.virustotal.com/gui/ip-address/'+ip],['IPinfo','https://ipinfo.io/'+ip],['Onyphe','https://www.onyphe.io/search/?q='+q],['BinaryEdge','https://app.binaryedge.io/services/query?query='+q]];
}
let RECON_DATA=null;
async function runRecon(){
  let d=$('#reconInput').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Ingresa un dominio válido, p. ej. mineducacion.gov.co');return;}
  const reg=registrable(d);const sld=reg.split('.')[0];const depth=$('#reconDepth').value;
  $('#goRecon').disabled=true;$('#reconOut').innerHTML='';
  const st=$('#reconStatus');st.style.display='flex';$('#reconBarwrap').style.display='block';
  RESOLVER='auto';cache.clear();
  const setP=(p,t)=>{$('#reconBar').style.width=p+'%';$('#reconStatusTxt').textContent=t;};
  try{
    setP(5,'Generando variantes de suplantación…');
    const cand=new Set(reconVariants(reg,depth));const gen=cand.size;
    setP(12,'Barriendo Certificate Transparency (crt.sh)…');
    const ct=await ctSearch(sld);ct.forEach(c=>{if(c&&c!==reg)cand.add(c);});
    const list=[...cand];
    const found=[];let done=0;const B=12;
    for(let i=0;i<list.length;i+=B){
      const slice=list.slice(i,i+B);
      const res=await Promise.all(slice.map(async v=>{const ns=await query(v,'NS');return ns.answers.length?v:null;}));
      res.forEach(v=>v&&found.push(v));
      done=Math.min(i+B,list.length);setP(12+Math.round(done/list.length*46),`Verificando registro DNS… (${done}/${list.length}) — ${found.length} registrados`);
    }
    const cap=depth==='max'?42:depth==='deep'?26:16;
    const toEnrich=found.slice(0,cap);const dossiers=[];
    for(let i=0;i<toEnrich.length;i++){setP(58+Math.round(i/Math.max(1,toEnrich.length)*40),`Levantando expediente… (${i+1}/${toEnrich.length}) ${toEnrich[i]}`);const e=await reconEnrich(toEnrich[i]);e.sim=Math.round(similar(sld,e.dom.split('.')[0])*100);const sc=reconScore(e);e.score=sc.score;e.reasons=sc.reasons;dossiers.push(e);}
    dossiers.sort((a,b)=>b.score-a.score);
    RECON_DATA={reg,sld,depth,gen,ctCount:ct.length,scanned:list.length,registered:found,dossiers,when:new Date()};
    setP(100,'Listo');renderRecon(RECON_DATA);
  }catch(e){alert('Error: '+e.message);}
  finally{$('#goRecon').disabled=false;st.style.display='none';$('#reconBarwrap').style.display='none';}
}
function reconBadge(s){const c=s>=60?'r':s>=30?'y':'g';const t=s>=60?'ALTO':s>=30?'MEDIO':'BAJO';return `<span class="tag ${c}">Riesgo ${t} · ${s}</span>`;}
function pivGrid(arr){return `<div class="pivgrid">${arr.map(p=>`<a target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${ico('link')}${esc(p[0])}</a>`).join('')}</div>`;}
function pivotRow(title,arr){return `<div class="pivcat">${esc(title)}</div>${pivGrid(arr)}`;}
function pivotBlock(piv,ip){return `${pivotRow('Superficie',piv.surface)}${pivotRow('Deep web / feeds',piv.deep)}${pivotRow('Dark web',piv.dark)}${ip?pivotRow('Infraestructura (IP '+esc(ip)+')',ipPivots(ip)):''}`;}
function reconDossierCard(e,brand){
  const g=e.geo||{};const sh=e.shodan;
  const sev=e.score>=60?'fail':e.score>=30?'warn':'ok';
  const kv=[];
  kv.push(['URL del sitio',`<a class="urlopen" target="_blank" rel="noopener noreferrer nofollow" href="https://${esc(e.dom)}/"><svg class="i"><use href="#i-link"/></svg> https://${esc(e.dom)}</a> · <a class="urlopen" target="_blank" rel="noopener noreferrer nofollow" href="http://${esc(e.dom)}/">http</a> · <a target="_blank" rel="noopener noreferrer" href="https://urlscan.io/search/#${encodeURIComponent(e.dom)}"><svg class="i"><use href="#i-shield"/></svg> vista previa segura</a><div class="hint" data-s="margin-top:3px">Puede ser una página maliciosa que suplanta la tuya. Ábrela solo en un entorno seguro; para verla sin riesgo usa la vista previa (urlscan).</div>`]);
  kv.push(['IP(s)',e.ips.length?e.ips.map(ip=>esc(ip)).join(', '):'<span class="hint">sin registro A (parqueado)</span>']);
  if(g.country)kv.push(['Ubicación',`${g.flag||''} ${esc([g.city,g.region,g.country].filter(Boolean).join(', '))}`]);
  if(g.lat!=null&&g.lon!=null)kv.push(['Coordenadas',`${esc(g.lat)}, ${esc(g.lon)} · <a target="_blank" rel="noopener" href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(g.lat)}&mlon=${encodeURIComponent(g.lon)}#map=13/${encodeURIComponent(g.lat)}/${encodeURIComponent(g.lon)}">ver mapa ↗</a>`]);
  if(g.asn||g.org)kv.push(['Hosting / ASN',esc([g.asn,g.org||g.isp].filter(Boolean).join(' · '))]);
  kv.push(['Correo (MX)',e.mx.length?esc(e.mx.join(', '))+(e.mxprov?' '+tag(e.mxprov,'g'):''):'<span class="hint">sin MX</span>']);
  if(e.mx.length)kv.push(['DMARC',e.dmarcP?tag('p='+e.dmarcP,e.dmarcP==='reject'?'g':e.dmarcP==='quarantine'?'y':'r'):tag('sin DMARC — spoofeable','r')]);
  if(e.spf)kv.push(['SPF',raw(e.spf)]);
  kv.push(['Nameservers',e.ns.length?esc(e.ns.slice(0,4).join(', ')):'—']);
  if(e.registrar)kv.push(['Registrador',esc(e.registrar)]);
  if(e.created)kv.push(['Registrado',esc((''+e.created).slice(0,10))+(e.expires?' → expira '+esc((''+e.expires).slice(0,10)):'')]);
  if(e.abuse)kv.push(['Contacto abuse',esc(e.abuse)]);
  if(e.wayback)kv.push(['Wayback',`archivado ${esc((''+e.wayback.ts).slice(0,8))}`+(/^https?:\/\//i.test(e.wayback.url||'')?` · <a target="_blank" rel="noopener noreferrer" href="${esc(e.wayback.url)}">ver copia ↗</a>`:'')]);
  if(sh&&(sh.ports.length||sh.vulns.length||sh.tags.length)){
    if(sh.ports.length)kv.push(['Puertos abiertos (Shodan)',sh.ports.map(p=>tag(String(p))).join('')]);
    if(sh.hostnames&&sh.hostnames.length)kv.push(['Hostnames',esc(sh.hostnames.slice(0,4).join(', '))]);
    if(sh.tags&&sh.tags.length)kv.push(['Etiquetas',sh.tags.map(t=>tag(esc(t),'y')).join('')]);
    if(sh.vulns&&sh.vulns.length)kv.push(['CVEs',sh.vulns.slice(0,8).map(v=>tag(esc(v),'r')).join('')]);
  }
  if(e.listed)kv.push(['Reputación','<span data-s="color:var(--fail);font-weight:700"><svg class="i"><use href="#i-alert"/></svg> en lista negra Spamhaus</span>']);
  const piv=reconPivots(e.dom,brand);
  const rows=kv.map(([k,v])=>`<tr><td data-s="white-space:nowrap;color:var(--muted);vertical-align:top">${esc(k)}</td><td>${v}</td></tr>`).join('');
  const badges=[reconBadge(e.score)];
  if(typeof e.sim==='number')badges.push(tag('similitud '+e.sim+'%',e.sim>=80?'r':e.sim>=60?'y':''));
  if(e.idn)badges.push(tag('IDN/Punycode','r'));
  if(e.ips.length)badges.push(tag('activo','y'));else badges.push(tag('parqueado',''));
  return `<div class="glass phishcard rcard sev-${sev}" data-s="margin-top:12px" data-dom="${esc(e.dom)}" data-score="${e.score}" data-sim="${e.sim||0}" data-active="${e.ips.length?1:0}">
    <div data-s="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
      <div class="phverdict" data-s="font-size:16px;margin:0;font-family:var(--mono)">${esc(e.dom)}</div>
      <div class="rbadges">${badges.join('')}</div>
    </div>
    ${e.reasons&&e.reasons.length?`<p class="hint" data-s="margin:6px 0 4px">Señales: ${e.reasons.map(r=>esc(r)).join(' · ')}</p>`:''}
    <table class="mini" data-s="margin-top:8px">${rows}</table>
    <details data-s="margin-top:8px"><summary data-s="cursor:pointer;color:var(--accent);font-size:13px"><svg class="i"><use href="#i-search"/></svg> Pivotes OSINT para investigar este dominio</summary>
      ${pivotBlock(piv,e.ips[0])}
    </details>
    <div class="dashbtns" data-s="justify-content:flex-start;margin-top:10px;gap:8px">
      <button class="btn ghost reconToPhish" data-dom="${esc(e.dom)}" data-s="padding:5px 12px;font-size:12.5px"><svg class="i"><use href="#i-hook"/></svg>Analizar como phishing</button>
      <button class="btn ghost reconToDomain" data-dom="${esc(e.dom)}" data-s="padding:5px 12px;font-size:12.5px"><svg class="i"><use href="#i-shield-check"/></svg>Validación DNS completa</button>
    </div>
  </div>`;
}
function reconInfraPanel(D){
  const act=D.dossiers.filter(e=>e.geo);
  if(!act.length)return '';
  const agg=(keyfn)=>{const m={};act.forEach(e=>{const k=keyfn(e)||'—';m[k]=(m[k]||0)+1;});return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,6);};
  const byCountry=agg(e=>((e.geo.flag||'')+' '+(e.geo.country||'')).trim());
  const byAsn=agg(e=>(e.geo.org||e.geo.isp||e.geo.asn||''));
  const byReg=agg(e=>e.registrar||'');
  const max=arr=>Math.max(1,...arr.map(x=>x[1]));
  const block=(title,arr)=>arr.length?`<div><div class="pivcat" data-s="margin-top:0">${title}</div>${arr.map(([k,n])=>`<div data-s="margin-top:7px"><div data-s="display:flex;justify-content:space-between;font-size:12.5px"><span>${esc(k)}</span><b>${n}</b></div><div class="rminibar"><span data-s="width:${Math.round(n/max(arr)*100)}%"></span></div></div>`).join('')}</div>`:'';
  return `<div class="glass phishcard" data-s="margin-top:14px"><div class="subh"><svg class="i"><use href="#i-map"/></svg>Panorama de infraestructura</div><p class="hint" data-s="margin-top:0">Concentración de los dominios suplantadores por hosting, país y registrador — útil para detectar campañas montadas sobre la misma infraestructura.</p><div class="infragrid">${block('Por país',byCountry)}${block('Por hosting / ASN',byAsn)}${block('Por registrador',byReg)}</div></div>`;
}
function renderRecon(D){
  const active=D.dossiers.filter(e=>e.ips.length);
  const withMail=D.dossiers.filter(e=>e.mx.length);
  const listed=D.dossiers.filter(e=>e.listed);
  const high=D.dossiers.filter(e=>e.score>=60);
  const idn=D.dossiers.filter(e=>e.idn);
  const sev=high.length?'fail':active.length?'warn':'ok';
  const col=sev==='fail'?'var(--fail)':sev==='warn'?'var(--warn)':'var(--ok)';
  const gp=reconPivots(D.reg,D.sld);
  const head=`<div class="glass phishcard">
    <div class="phverdict" data-s="color:${col}">${D.registered.length?(''+D.registered.length+' dominio(s) parecidos registrados — '+active.length+' activos, '+high.length+' de riesgo alto'):'No se hallaron dominios parecidos registrados'}</div>
    <div class="phurl">Objetivo: ${esc(D.reg)} · ${D.scanned} candidatos analizados (${D.gen} algorítmicos + ${D.ctCount} vía crt.sh) · ${D.dossiers.length} expedientes levantados</div>
    <div class="kpis" data-s="margin-top:12px;margin-bottom:0">
      <div class="kpi fail"><b>${D.registered.length}</b><span>registrados</span></div>
      <div class="kpi warn"><b>${active.length}</b><span>con IP activa</span></div>
      <div class="kpi neut"><b>${withMail.length}</b><span>con correo (MX)</span></div>
      <div class="kpi fail"><b>${listed.length}</b><span>en lista negra</span></div>
      <div class="kpi ${idn.length?'fail':'neut'}"><b>${idn.length}</b><span>IDN/homóglifo</span></div>
      <div class="kpi ${high.length?'fail':'ok'}"><b>${high.length}</b><span>riesgo alto</span></div>
    </div>
    <div class="rtoolbar">
      <button class="btn" id="reconExportBtn"><svg class="i"><use href="#i-download"/></svg>Informe (.txt)</button>
      <button class="btn ghost" id="reconCsvBtn"><svg class="i"><use href="#i-chart"/></svg>IOCs (.csv)</button>
      <button class="btn ghost" id="reconJsonBtn"><svg class="i"><use href="#i-download"/></svg>IOCs (.json)</button>
      <button class="btn ghost" id="reconCopyBtn"><svg class="i"><use href="#i-copy"/></svg>Copiar IOCs</button>
    </div>
    <details data-s="margin-top:14px" open><summary data-s="cursor:pointer;color:var(--accent);font-size:13px"><svg class="i"><use href="#i-globe"/></svg> Pivotes OSINT globales de la marca "${esc(D.sld)}"</summary>
      ${pivotRow('Superficie',gp.surface)}
      ${pivotRow('Deep web / feeds',gp.deep)}
      ${pivotRow('Dark web',gp.dark)}
      <p class="hint" data-s="margin-top:8px"><b>Sobre la dark web:</b> una app 100% en el navegador no puede rastrear la red Tor (.onion) directamente. Estos son <b>pivotes asistidos</b> hacia buscadores e índices que sí indexan contenido .onion y filtraciones (Ahmia, IntelligenceX, HIBP, Ransomlook). Para un rastreo dark web automatizado 24/7 se requiere el backend (Cloudflare Worker) o un servicio especializado; te puedo guiar para conectarlo.</p>
    </details>
  </div>`;
  const infra=reconInfraPanel(D);
  const controls=D.dossiers.length?`<div class="glass phishcard" data-s="margin-top:14px;padding-top:14px;padding-bottom:14px"><div class="rtoolbar" data-s="margin-top:0">
      <div class="rsearch"><span><svg class="i"><use href="#i-search"/></svg></span><input id="reconFilter" type="text" placeholder="Filtrar por dominio…" autocomplete="off" spellcheck="false"></div>
      <select class="rselect" id="reconFilterSev"><option value="all">Todos los riesgos</option><option value="fail">Solo riesgo ALTO</option><option value="warn">Medio o superior</option><option value="active">Solo con IP activa</option></select>
      <select class="rselect" id="reconSort"><option value="score">Ordenar: riesgo</option><option value="sim">Ordenar: similitud</option><option value="dom">Ordenar: alfabético</option></select>
      <span class="hint" id="reconCount"></span>
    </div></div>`:'';
  $('#reconOut').innerHTML=head+infra+(D.dossiers.length?'<div class="subh" data-s="margin-top:16px">Expedientes de los dominios detectados</div>'+controls+'<div id="reconCards" class="stg"></div>':'<div class="glass phishcard" data-s="margin-top:14px"><p class="hint">No se levantaron expedientes detallados. Usa los pivotes OSINT de arriba para investigar manualmente.</p></div>');
  const bind=(id,fn)=>{const el=$('#'+id);if(el)el.addEventListener('click',fn);};
  bind('reconExportBtn',reconExport);bind('reconCsvBtn',reconExportCSV);bind('reconJsonBtn',reconExportJSON);bind('reconCopyBtn',reconCopyIOCs);
  ['reconFilter','reconFilterSev','reconSort'].forEach(id=>{const el=$('#'+id);if(el)el.addEventListener(el.tagName==='SELECT'?'change':'input',reconApplyView);});
  reconApplyView();
  $('#reconOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function reconApplyView(){
  if(!RECON_DATA)return;const D=RECON_DATA;const cont=$('#reconCards');if(!cont)return;
  const term=(($('#reconFilter')||{}).value||'').toLowerCase().trim();
  const fsev=(($('#reconFilterSev')||{}).value)||'all';
  const sort=(($('#reconSort')||{}).value)||'score';
  let list=D.dossiers.slice();
  if(term)list=list.filter(e=>e.dom.includes(term));
  if(fsev==='fail')list=list.filter(e=>e.score>=60);
  else if(fsev==='warn')list=list.filter(e=>e.score>=30);
  else if(fsev==='active')list=list.filter(e=>e.ips.length);
  list.sort((a,b)=>sort==='dom'?a.dom.localeCompare(b.dom):sort==='sim'?(b.sim||0)-(a.sim||0):b.score-a.score);
  cont.innerHTML=list.length?list.map(e=>reconDossierCard(e,D.sld)).join(''):'<div class="glass phishcard"><p class="hint">Ningún expediente coincide con el filtro.</p></div>';
  const cc=$('#reconCount');if(cc)cc.textContent=list.length+' de '+D.dossiers.length+' expedientes';
  cont.querySelectorAll('.reconToPhish').forEach(b=>b.addEventListener('click',()=>{setMode('phish');$('#phishUrl').value='http://'+b.dataset.dom;$('#phishBrand').value=D.reg;analyzePhish();}));
  cont.querySelectorAll('.reconToDomain').forEach(b=>b.addEventListener('click',()=>{setMode('domain');$('#domain').value=b.dataset.dom;if(typeof run==='function')run();}));
  cont.querySelectorAll('a.urlopen').forEach(a=>a.addEventListener('click',ev=>{if(!confirm('Vas a abrir un sitio potencialmente malicioso que podría suplantar tu página:\n\n'+a.href+'\n\nÁbrelo solo en un entorno seguro. ¿Continuar?')){ev.preventDefault();}}));
}
function reconIOCs(){const D=RECON_DATA;const ipset=new Set();D.dossiers.forEach(e=>e.ips.forEach(ip=>ipset.add(ip)));return{domains:D.dossiers.map(e=>e.dom),ips:[...ipset]};}
/* Descarga un texto como archivo (única utilidad de descarga del programa) */
function downloadFile(name,text,type){const blob=new Blob([text],{type:(type||'text/plain')+';charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000);}
function reconExportCSV(){
  if(!RECON_DATA)return;const D=RECON_DATA;
  const cols=['dominio','url','riesgo','similitud','ips','pais','ciudad','asn_hosting','mx','proveedor_correo','dmarc','registrador','creado','abuse','puertos','cves','listado','idn','wayback'];
  const q=v=>'"'+String(v==null?'':v).replace(/"/g,'""')+'"';
  const rows=[cols.join(',')];
  D.dossiers.forEach(e=>{const g=e.geo||{};const sh=e.shodan||{};rows.push([e.dom,'https://'+e.dom+'/',e.score,(e.sim||'')+'',e.ips.join(' '),g.country||'',g.city||'',[g.asn,g.org||g.isp].filter(Boolean).join(' '),e.mx.join(' '),e.mxprov||'',e.dmarcP||'',e.registrar||'',(''+(e.created||'')).slice(0,10),e.abuse||'',(sh.ports||[]).join(' '),(sh.vulns||[]).join(' '),e.listed?'si':'no',e.idn?'si':'no',e.wayback?(''+e.wayback.ts).slice(0,8):''].map(q).join(','));});
  downloadFile('centinela-iocs-'+D.reg+'.csv',rows.join('\n'),'text/csv');
}
function reconExportJSON(){
  if(!RECON_DATA)return;const D=RECON_DATA;const io=reconIOCs();
  const out={tool:'Centinela',type:'cyber-intelligence-recon',target:D.reg,generated:D.when.toISOString(),depth:D.depth,stats:{scanned:D.scanned,generated:D.gen,ct:D.ctCount,registered:D.registered.length},iocs:io,dossiers:D.dossiers.map(e=>({domain:e.dom,url:'https://'+e.dom+'/',risk:e.score,similarity:e.sim,idn:!!e.idn,ips:e.ips,geo:e.geo||null,mx:e.mx,mail_provider:e.mxprov||null,spf:e.spf||null,dmarc:e.dmarcP||null,ns:e.ns,registrar:e.registrar||null,created:e.created||null,expires:e.expires||null,abuse:e.abuse||null,shodan:e.shodan||null,wayback:e.wayback||null,blacklisted:!!e.listed,signals:e.reasons||[]}))};
  downloadFile('centinela-iocs-'+D.reg+'.json',JSON.stringify(out,null,2),'application/json');
}
function reconCopyIOCs(){
  if(!RECON_DATA)return;const io=reconIOCs();const txt=['# Dominios',...io.domains,'','# IPs',...io.ips].join('\n');
  const done=()=>{const b=$('#reconCopyBtn');if(b){const o=b.textContent;b.textContent='✓ Copiado';setTimeout(()=>b.textContent=o,1200);}};
  if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(txt).then(done).catch(()=>{downloadFile('centinela-iocs.txt',txt);});
  else downloadFile('centinela-iocs.txt',txt);
}
function reconExport(){
  if(!RECON_DATA)return;const D=RECON_DATA;const L=[];
  L.push('EXPEDIENTE DE CIBERINTELIGENCIA — CENTINELA');
  L.push('='.repeat(60));
  L.push('Objetivo protegido : '+D.reg);
  L.push('Fecha              : '+D.when.toLocaleString('es-CO'));
  L.push('Profundidad        : '+D.depth);
  L.push('Candidatos analizados: '+D.scanned+' ('+D.gen+' algorítmicos + '+D.ctCount+' vía Certificate Transparency)');
  L.push('Dominios registrados : '+D.registered.length);
  L.push('Expedientes         : '+D.dossiers.length);
  L.push('');
  D.dossiers.forEach((e,i)=>{
    const g=e.geo||{};
    L.push('-'.repeat(60));
    L.push('#'+(i+1)+'  '+e.dom+'   [Riesgo '+(e.score>=60?'ALTO':e.score>=30?'MEDIO':'BAJO')+' · '+e.score+']'+(typeof e.sim==='number'?'  (similitud '+e.sim+'%)':'')+(e.idn?'  [IDN/Punycode]':''));
    if(e.reasons&&e.reasons.length)L.push('  Señales      : '+e.reasons.join(' · '));
    L.push('  URL          : https://'+e.dom+'/  (vista previa segura: https://urlscan.io/search/#'+encodeURIComponent(e.dom)+')');
    L.push('  IP(s)        : '+(e.ips.join(', ')||'sin A (parqueado)'));
    if(g.country)L.push('  Ubicación    : '+[g.city,g.region,g.country].filter(Boolean).join(', '));
    if(g.lat!=null)L.push('  Coordenadas  : '+g.lat+', '+g.lon);
    if(g.asn||g.org)L.push('  Hosting/ASN  : '+[g.asn,g.org||g.isp].filter(Boolean).join(' · '));
    L.push('  Correo (MX)  : '+(e.mx.join(', ')||'sin MX')+(e.mxprov?' ['+e.mxprov+']':''));
    if(e.mx.length)L.push('  DMARC        : '+(e.dmarcP?'p='+e.dmarcP:'AUSENTE (spoofeable)'));
    if(e.spf)L.push('  SPF          : '+e.spf);
    L.push('  Nameservers  : '+(e.ns.slice(0,4).join(', ')||'—'));
    if(e.registrar)L.push('  Registrador  : '+e.registrar);
    if(e.created)L.push('  Registrado   : '+(''+e.created).slice(0,10)+(e.expires?' → expira '+(''+e.expires).slice(0,10):''));
    if(e.abuse)L.push('  Abuse        : '+e.abuse);
    if(e.wayback)L.push('  Wayback      : '+(''+e.wayback.ts).slice(0,8)+' '+e.wayback.url);
    if(e.shodan){if(e.shodan.ports.length)L.push('  Puertos      : '+e.shodan.ports.join(', '));if(e.shodan.vulns&&e.shodan.vulns.length)L.push('  CVEs         : '+e.shodan.vulns.join(', '));if(e.shodan.hostnames&&e.shodan.hostnames.length)L.push('  Hostnames    : '+e.shodan.hostnames.join(', '));}
    if(e.listed)L.push('  Reputación   : EN LISTA NEGRA (Spamhaus)');
  });
  L.push('');L.push('='.repeat(60));
  L.push('Pivotes OSINT (marca: '+D.sld+'):');
  const gp=reconPivots(D.reg,D.sld);
  ['surface','deep','dark'].forEach(k=>{L.push('  ['+(k==='surface'?'SUPERFICIE':k==='deep'?'DEEP WEB':'DARK WEB')+']');gp[k].forEach(p=>L.push('    - '+p[0]+': '+p[1]));});
  L.push('');L.push('Generado por Centinela — Suite de Ciberseguridad. Uso defensivo y de investigación autorizada.');
  downloadFile('centinela-expediente-'+D.reg+'.txt',L.join('\n'));
}

/* ============================================================ Análisis de vulnerabilidades (vuln) */
const VULN_SEV={crit:{w:25,label:'Crítica',cls:'crit'},high:{w:15,label:'Alta',cls:'high'},med:{w:7,label:'Media',cls:'med'},low:{w:3,label:'Baja',cls:'low'},info:{w:0,label:'Informativa',cls:'info'}};
function sevFromCvss(s){s=parseFloat(s);if(!(s>=0))return null;if(s>=9)return'crit';if(s>=7)return'high';if(s>=4)return'med';if(s>0)return'low';return'info';}
const PORT_RISK={
 21:['high','FTP','Transferencia de archivos sin cifrar; credenciales viajan en texto plano.'],
 23:['crit','Telnet','Acceso remoto SIN cifrar; credenciales expuestas. Debe deshabilitarse.'],
 25:['low','SMTP','Servidor de correo; verifica que no sea un open relay.'],
 110:['low','POP3','Correo sin cifrar si no usa TLS.'],
 143:['low','IMAP','Correo sin cifrar si no usa TLS.'],
 135:['high','MSRPC','RPC de Windows expuesto a internet.'],
 139:['high','NetBIOS','NetBIOS expuesto — fuga de información/SMB.'],
 445:['crit','SMB','Compartición de archivos Windows — vector de EternalBlue y ransomware.'],
 1433:['high','MSSQL','Base de datos SQL Server expuesta a internet.'],
 1521:['high','Oracle DB','Base de datos Oracle expuesta.'],
 3306:['high','MySQL','Base de datos expuesta a internet.'],
 5432:['high','PostgreSQL','Base de datos expuesta a internet.'],
 27017:['high','MongoDB','Base de datos NoSQL expuesta — históricamente sin autenticación.'],
 6379:['crit','Redis','Redis expuesto — con frecuencia sin autenticación → RCE.'],
 9200:['high','Elasticsearch','Índice expuesto — fugas masivas de datos son comunes.'],
 5601:['med','Kibana','Panel de Kibana expuesto.'],
 11211:['high','Memcached','Expuesto — amplificación DDoS y fuga de datos.'],
 2375:['crit','Docker API','API de Docker sin TLS — control total del host.'],
 6443:['med','Kubernetes API','API de K8s expuesta.'],
 3389:['crit','RDP','Escritorio remoto expuesto — objetivo #1 de ransomware y fuerza bruta.'],
 5900:['high','VNC','Escritorio remoto — a menudo sin contraseña.'],
 161:['med','SNMP','Puede filtrar información de red y credenciales por defecto.'],
 22:['low','SSH','Acceso remoto — asegura con llaves, sin root y con fail2ban.'],
 80:['info','HTTP','Servicio web sin cifrar; debe redirigir a HTTPS.'],
 443:['info','HTTPS','Servicio web cifrado.'],
 8080:['low','HTTP-alt','Servicio web alternativo — revisa paneles de administración.'],
 8443:['low','HTTPS-alt','Servicio web alternativo cifrado.'],
 53:['info','DNS','Servicio DNS.']
};
let KEV_MAP=null;
/* Catálogo CISA KEV. El sitio de CISA no envía cabeceras CORS, así que se intenta, por orden: el backend
   (si está configurado), el espejo oficial de CISA en GitHub (cisagov/kev-data, con CORS) y el feed original. */
let KEV_P=null;
async function loadKEV(){
  if(KEV_MAP&&KEV_MAP.size)return KEV_MAP;
  if(KEV_P)return KEV_P;
  KEV_P=(async()=>{
    const b=leakBackend();
    const urls=[b&&b+'/kev','https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'].filter(Boolean);
    const m=new Map();
    for(const u of urls){
      try{const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),25000);
        const r=await fetch(u,{signal:ctrl.signal});clearTimeout(to);
        if(r.ok){const j=await r.json();(j.vulnerabilities||[]).forEach(v=>m.set(v.cveID,{name:v.vulnerabilityName||'',due:v.dueDate||'',ransom:/known/i.test(v.knownRansomwareCampaignUse||'')}));if(m.size)break;}
      }catch(e){}
    }
    KEV_MAP=m;KEV_P=null;return m;
  })();
  return KEV_P;
}
let CIRCL_LIMITED=false; /* CIRCL respondió 429: evita seguir consultando en la misma tanda */
async function circlCve(id){
  try{const r=await fetch('https://cve.circl.lu/api/cve/'+encodeURIComponent(id));if(r.status===429)CIRCL_LIMITED=true;if(r.ok){const j=await r.json();if(j&&typeof j==='object'){
    let cvss=(typeof j.cvss==='number')?j.cvss:null;
    if(cvss==null&&j.cvss3&&j.cvss3.baseScore!=null)cvss=+j.cvss3.baseScore;
    if(cvss==null&&j.metrics&&j.metrics.cvssMetricV31&&j.metrics.cvssMetricV31[0])cvss=+j.metrics.cvssMetricV31[0].cvssData.baseScore;
    if(cvss==null&&j.containers&&j.containers.cna&&j.containers.cna.metrics){const m=j.containers.cna.metrics.find(x=>x.cvssV3_1||x.cvssV3_0);if(m){const c=m.cvssV3_1||m.cvssV3_0;if(c&&c.baseScore!=null)cvss=+c.baseScore;}}
    // Registros CVE 5: si la CNA no puntuó, CISA-ADP suele aportar el CVSS
    if(cvss==null&&j.containers&&Array.isArray(j.containers.adp))for(const a of j.containers.adp){const m=(a.metrics||[]).find(x=>x.cvssV3_1||x.cvssV3_0||x.cvssV4_0);if(m){const c=m.cvssV3_1||m.cvssV3_0||m.cvssV4_0;if(c&&c.baseScore!=null){cvss=+c.baseScore;break;}}}
    let summary=j.summary||'';
    if(!summary&&j.containers&&j.containers.cna&&j.containers.cna.descriptions&&j.containers.cna.descriptions[0])summary=j.containers.cna.descriptions[0].value;
    if(cvss!=null||summary)return {cvss:cvss!=null?cvss:null,summary:summary,src:'CIRCL'};
  }}}catch(e){}
  return null;
}
async function ctSubdomains(dom){
  const out=new Set();
  try{const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),15000);
    const r=await fetch('https://crt.sh/?q='+encodeURIComponent(dom)+'&output=json',{signal:ctrl.signal});clearTimeout(to);
    if(r.ok){const j=await r.json();(j||[]).forEach(row=>String(row.name_value||'').split(/\n/).forEach(n=>{n=n.trim().toLowerCase().replace(/^\*\./,'');if((n===dom||n.endsWith('.'+dom))&&/^[a-z0-9.-]+$/.test(n))out.add(n);}));}
  }catch(e){}
  return [...out];
}
/* Fingerprints de servicios propensos a subdomain takeover (CNAME colgante) */
const TAKEOVER_FP=[
 [/\.github\.io$/,'GitHub Pages','high'],[/\.gitlab\.io$/,'GitLab Pages','high'],[/\.bitbucket\.io$/,'Bitbucket','high'],
 [/\.herokudns\.com$|\.herokuapp\.com$|\.herokussl\.com$/,'Heroku','high'],
 [/\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$|s3-website/,'AWS S3','high'],
 [/\.cloudfront\.net$/,'AWS CloudFront','med'],
 [/\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$|\.azurefd\.net$/,'Microsoft Azure','high'],
 [/\.netlify\.app$|\.netlify\.com$/,'Netlify','high'],[/\.pages\.dev$/,'Cloudflare Pages','med'],
 [/\.web\.app$|\.firebaseapp\.com$/,'Firebase','med'],[/\.fly\.dev$/,'Fly.io','med'],
 [/\.ghost\.io$/,'Ghost','high'],[/\.wpengine\.com$/,'WP Engine','high'],[/\.wordpress\.com$/,'WordPress','med'],
 [/\.pantheonsite\.io$/,'Pantheon','high'],[/\.readthedocs\.io$/,'Read the Docs','high'],[/\.surge\.sh$/,'Surge.sh','high'],
 [/\.fastly\.net$/,'Fastly','med'],[/\.zendesk\.com$/,'Zendesk','med'],[/\.desk\.com$/,'Desk','high'],
 [/\.statuspage\.io$/,'Statuspage','med'],[/\.uservoice\.com$/,'UserVoice','high'],[/\.helpscoutdocs\.com$/,'Help Scout','high'],
 [/\.tumblr\.com$/,'Tumblr','high'],[/\.myshopify\.com$/,'Shopify','med'],[/\.cargocollective\.com$/,'Cargo','high'],
 [/\.launchrock\.com$/,'LaunchRock','high'],[/\.unbouncepages\.com$/,'Unbounce','high'],[/\.bcvp0rtal\.com$|\.brightcove/,'Brightcove','high']
];
async function scanTakeover(subs,cap,setP){
  const list=subs.filter(s=>s.split('.').length>2).slice(0,cap);
  const out=[];let done=0;const B=10;
  for(let i=0;i<list.length;i+=B){
    const slice=list.slice(i,i+B);
    const res=await Promise.all(slice.map(async sub=>{
      const c=await query(sub,'CNAME');
      const cname=(c.answers&&c.answers[0]&&c.answers[0].data)||(c.cnames&&c.cnames[0])||'';
      if(!cname)return null;
      const fp=TAKEOVER_FP.find(f=>f[0].test(cname));
      if(!fp)return null;
      const a=await query(sub,'A');
      const dangling=(a.status===3)||(!a.answers.length&&a.status!==0);
      const sev=dangling?(fp[2]==='high'?'crit':'high'):'low';
      return {sub,cname,service:fp[1],sev,dangling,detail:dangling?('El subdominio apunta a '+fp[1]+' pero el recurso NO resuelve — fuerte indicio de recurso liberado y reclamable por un atacante (takeover).'):('El subdominio apunta a un recurso de '+fp[1]+'; verifica que siga reclamado por ti (riesgo si se libera).')};
    }));
    res.forEach(r=>r&&out.push(r));
    done=Math.min(i+B,list.length);if(setP)setP(90+Math.round(done/list.length*8),'Buscando subdomain takeover… ('+done+'/'+list.length+')');
  }
  return out;
}
let VULN_DATA=null;
async function runVuln(){
  let input=$('#vulnInput').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  const isIP=/^\d{1,3}(\.\d{1,3}){3}$/.test(input);
  if(!isIP&&!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(input)){alert('Ingresa un dominio o IP válidos');return;}
  const depth=$('#vulnDepth').value;
  $('#goVuln').disabled=true;$('#vulnOut').innerHTML='';
  const st=$('#vulnStatus');st.style.display='flex';$('#vulnBarwrap').style.display='block';
  RESOLVER='auto';cache.clear();
  const setP=(p,t)=>{$('#vulnBar').style.width=p+'%';$('#vulnStatusTxt').textContent=t;};
  const F=[];const sources={shodan:false,circl:false,crtsh:false,doh:false,geo:false};
  const add=(sev,cat,title,detail,opt)=>{F.push(Object.assign({sev,cat,title,detail},opt||{}));};
  try{
    let ips=[];const dom=isIP?null:input;
    if(isIP)ips=[input];
    else{setP(6,'Resolviendo DNS…');const a=await query(input,'A');ips=a.answers.map(x=>x.data).filter(ip=>/^\d+\.\d+\.\d+\.\d+$/.test(ip));sources.doh=true;
      if(!ips.length)add('info','Infraestructura DNS','El dominio no resuelve a una IP (sin registro A)','No hay host público que analizar por puertos/CVEs; se evalúa solo la postura DNS/correo.',{});}
    let geo=null;if(ips.length){setP(14,'Identificando hosting/ASN…');geo=await geoLookup(ips[0]);if(geo)sources.geo=true;}
    const allPorts=new Set(),cveSet=new Set(),cpes=new Set(),tags=new Set(),hostnames=new Set();
    for(let i=0;i<Math.min(ips.length,3);i++){setP(20+i*7,'Consultando Shodan InternetDB… ('+(i+1)+'/'+Math.min(ips.length,3)+')');const sh=await shodanIDB(ips[i]);if(sh){sources.shodan=true;(sh.ports||[]).forEach(p=>allPorts.add(p));(sh.vulns||[]).forEach(v=>cveSet.add(v));(sh.cpes||[]).forEach(c=>cpes.add(c));(sh.tags||[]).forEach(t=>tags.add(t));(sh.hostnames||[]).forEach(h=>hostnames.add(h));}}
    const ports=[...allPorts].sort((a,b)=>a-b);
    ports.forEach(p=>{const r=PORT_RISK[p];if(r)add(r[0],'Exposición de servicios','Puerto '+p+' abierto — '+r[1],r[2],{evidence:'Abierto en '+(ips[0]||''),remediation:(r[0]==='crit'||r[0]==='high')?'Restringe el acceso por firewall/VPN, cierra el puerto si no es necesario y exige autenticación fuerte.':'Verifica que el servicio esté actualizado y con acceso restringido.'});else add('info','Exposición de servicios','Puerto '+p+' abierto','Servicio no catalogado; revísalo manualmente.',{});});
    if(tags.size)add((tags.has('self-signed')||tags.has('expired'))?'med':'info','Configuración TLS/servicio','Señales Shodan: '+[...tags].join(', '),'Etiquetas de configuración detectadas en el host.',{remediation:tags.has('self-signed')?'Sustituye certificados autofirmados por certificados de una CA de confianza.':''});
    let cves=[...cveSet];cves=depth==='std'?cves.slice(0,25):cves.slice(0,60);
    const cveDetails=[];
    let kev=new Map();if(cves.length){setP(38,'Cargando catálogo CISA KEV (explotadas activamente)…');kev=await loadKEV();if(kev.size)sources.kev=true;}
    for(let i=0;i<cves.length;i++){setP(42+Math.round(i/Math.max(1,cves.length)*33),'Enriqueciendo CVE '+(i+1)+'/'+cves.length+'…');const info=await circlCve(cves[i]);if(info)sources.circl=true;const sev=(info&&info.cvss!=null)?sevFromCvss(info.cvss):'high';cveDetails.push({id:cves[i],cvss:info?info.cvss:null,summary:info?info.summary:'',sev,kev:kev.get(cves[i])||null});}
    cveDetails.sort((a,b)=>(b.kev?1:0)-(a.kev?1:0)||(b.cvss||0)-(a.cvss||0));
    let kevCount=0;
    cveDetails.forEach(c=>{
      const k=c.kev;let sev=c.sev||'high';
      let title=c.id+(c.cvss!=null?' · CVSS '+c.cvss:' · CVSS n/d');
      let detail=c.summary||'Vulnerabilidad reportada en un servicio expuesto (sin descripción disponible en la fuente).';
      const opt={cvss:c.cvss,cve:c.id,remediation:'Aplica el parche del proveedor para '+c.id+' o actualiza el software afectado a la última versión.',refs:[['NVD','https://nvd.nist.gov/vuln/detail/'+c.id],['CIRCL','https://cve.circl.lu/cve/'+c.id]]};
      if(k){kevCount++;sev='crit';title=title+' · EXPLOTADA ACTIVAMENTE (CISA KEV)'+(k.ransom?' · RANSOMWARE':'');detail=(k.name?k.name+'. ':'')+detail+' Figura en el catálogo KEV de CISA: se explota activamente en ataques reales'+(k.ransom?', incluidos campañas de ransomware':'')+'. Máxima prioridad de parcheo.';opt.remediation='PRIORIDAD MÁXIMA: parchea '+c.id+' de inmediato'+(k.due?' (CISA fijó fecha límite '+k.due+')':'')+'. Está siendo explotada activamente.';opt.refs.push(['CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog']);}
      add(sev,'Vulnerabilidades conocidas (CVE)',title,detail,opt);
    });
    if(dom){
      setP(78,'Evaluando postura DNS / correo…');
      const spf=await posSPF(dom),dmarc=await posDMARC(dom),mx=await query(dom,'MX');
      if(!spf.present)add('high','Seguridad del correo','Sin registro SPF','El dominio no declara qué servidores pueden enviar en su nombre; facilita la suplantación de correo.',{remediation:'Publica un registro SPF (v=spf1 …) terminando en -all.'});
      else if(spf.all==='~'||spf.all==='?')add('low','Seguridad del correo','SPF con política débil (~all/?all)','El SPF no aplica una política estricta de rechazo.',{evidence:spf.record,remediation:'Endurece a -all cuando el inventario de remitentes esté completo.'});
      else if(spf.all==='+')add('high','Seguridad del correo','SPF permite a cualquier servidor (+all)','El SPF autoriza a CUALQUIER servidor a enviar como el dominio.',{evidence:spf.record,remediation:'Elimina +all de inmediato y usa -all.'});
      if(!dmarc.present)add('high','Seguridad del correo','Sin registro DMARC','Sin DMARC no hay política contra suplantación ni informes de abuso.',{remediation:'Publica _dmarc con v=DMARC1; p=quarantine (luego reject); rua=mailto:…'});
      else if(dmarc.policy==='none')add('med','Seguridad del correo','DMARC en modo monitor (p=none)','DMARC presente pero no bloquea el correo suplantado.',{evidence:dmarc.record,remediation:'Sube a p=quarantine y después a p=reject.'});
      if(!(await posDNSSEC(dom)).present)add('low','Infraestructura DNS','DNSSEC no habilitado','El dominio no está firmado; habilita el envenenamiento de caché y el spoofing DNS.',{remediation:'Activa DNSSEC con tu registrador/operador DNS.'});
      if(!(await posCAA(dom)).present)add('low','TLS / Certificados','Sin registro CAA','Cualquier autoridad certificadora puede emitir certificados para el dominio.',{remediation:'Publica un registro CAA restringiendo las CAs autorizadas.'});
      if(mx.answers.length&&!(await posMTASTS(dom)).present)add('low','Seguridad del correo','Sin MTA-STS','No se fuerza TLS en la entrega de correo entrante (posible downgrade).',{remediation:'Implementa MTA-STS (política HTTPS + registro _mta-sts).'});
      setP(85,'Midiendo superficie de ataque (crt.sh)…');
      const subs=await ctSubdomains(dom);
      if(subs.length){sources.crtsh=true;const sev=subs.length>80?'med':subs.length>25?'low':'info';add(sev,'Superficie de ataque',subs.length+' subdominios en Certificate Transparency','Cada subdominio/servicio es un punto de entrada potencial; una superficie amplia amplía el riesgo y puede incluir servicios olvidados.',{evidence:subs.slice(0,20).join(', ')+(subs.length>20?' …':''),remediation:'Inventaría y retira subdominios y servicios en desuso; monitoréalos.'});
        setP(90,'Buscando subdomain takeover…');
        const tk=await scanTakeover(subs,depth==='deep'?80:40,setP);
        tk.forEach(t=>add(t.sev,'Subdomain takeover',t.sub+' → '+t.service+(t.dangling?' (destino sin resolver)':''),t.detail,{evidence:'CNAME → '+t.cname,remediation:'Reclama o libera el recurso en '+t.service+', o elimina el registro CNAME colgante de '+t.sub+'. Un atacante podría registrar ese recurso y servir contenido bajo tu subdominio.',refs:[['can-i-take-over-xyz','https://github.com/EdOverflow/can-i-take-over-xyz']]}));
      }
    }
    const counts={crit:0,high:0,med:0,low:0,info:0};let penalty=0;
    F.forEach(f=>{counts[f.sev]=(counts[f.sev]||0)+1;penalty+=VULN_SEV[f.sev].w;});
    const score=Math.max(0,100-penalty);
    const order=['A','B','C','D','E','F'];let gi=score>=90?0:score>=80?1:score>=70?2:score>=55?3:score>=35?4:5;
    if(counts.crit>0)gi=Math.max(gi,3);if(counts.high>0)gi=Math.max(gi,2);
    const grade=order[gi];
    VULN_DATA={target:input,isIP,ips,geo,ports,tags:[...tags],hostnames:[...hostnames],cpes:[...cpes],findings:F,counts,score,grade,sources,kevCount,when:new Date(),depth};
    setP(100,'Listo');renderVuln(VULN_DATA);
  }catch(e){alert('Error: '+e.message);}
  finally{$('#goVuln').disabled=false;st.style.display='none';$('#vulnBarwrap').style.display='none';}
}
function vSevChip(sev){const s=VULN_SEV[sev];return `<span class="vsev ${s.cls}">${s.label}</span>`;}
function gradeColor(g){return {A:'var(--oktx)',B:'var(--oktx)',C:'var(--wartx)',D:'var(--sev-high)',E:'var(--failtx)',F:'var(--sev-crit)'}[g]||'var(--muted)';}
function renderVuln(D){
  const sevOrder={crit:0,high:1,med:2,low:3,info:4};
  const catOrder=['Vulnerabilidades conocidas (CVE)','Subdomain takeover','Exposición de servicios','Seguridad del correo','TLS / Certificados','Configuración TLS/servicio','Infraestructura DNS','Superficie de ataque'];
  const cats=[...new Set(D.findings.map(f=>f.cat))].sort((a,b)=>{const ia=catOrder.indexOf(a),ib=catOrder.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);});
  const gc=gradeColor(D.grade);
  const srcRow=[['Shodan InternetDB',D.sources.shodan],['CIRCL / NVD (CVE)',D.sources.circl],['CISA KEV',D.sources.kev],['crt.sh',D.sources.crtsh],['DNS-over-HTTPS',D.sources.doh],['Geo/ASN',D.sources.geo]].map(([n,on])=>`<span class="vsrc ${on?'on':''}">${on?'✓':'○'} ${esc(n)}</span>`).join(' ');
  const head=`<div class="glass phishcard">
    <div class="vgrade">
      <div class="vgbadge" data-s="color:${gc}">${D.grade}</div>
      <div data-s="flex:1 1 220px">
        <div class="phverdict" data-s="margin:0;color:${gc}">Puntaje de seguridad: ${D.score}/100</div>
        <div class="phurl">Objetivo: ${esc(D.target)}${D.ips.length?' · '+esc(D.ips.join(', ')):''}${D.geo&&(D.geo.asn||D.geo.org)?' · '+esc([D.geo.asn,D.geo.org||D.geo.isp].filter(Boolean).join(' · ')):''}</div>
      </div>
    </div>
    <div class="kpis" data-s="margin-top:14px;margin-bottom:0">
      <div class="kpi ${D.counts.crit?'fail':'neut'}"><b>${D.counts.crit}</b><span>Críticas</span></div>
      <div class="kpi ${D.counts.high?'fail':'neut'}"><b>${D.counts.high}</b><span>Altas</span></div>
      <div class="kpi ${D.counts.med?'warn':'neut'}"><b>${D.counts.med}</b><span>Medias</span></div>
      <div class="kpi neut"><b>${D.counts.low}</b><span>Bajas</span></div>
      ${D.kevCount?`<div class="kpi fail"><b>${D.kevCount}</b><span>explotadas</span></div>`:''}
      <div class="kpi neut"><b>${D.ports.length}</b><span>puertos</span></div>
    </div>
    ${D.kevCount?`<div class="vmeta" data-s="margin-top:10px;color:var(--failtx)"><b><svg class="i"><use href="#i-alert"/></svg> ${D.kevCount} vulnerabilidad(es) en el catálogo CISA KEV</b> — se explotan activamente en ataques reales. Parchéalas antes que nada.</div>`:''}
    <div data-s="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;align-items:center"><span class="hint">Fuentes:</span> ${srcRow}</div>
    <div class="rtoolbar"><button class="btn" id="vulnTxtBtn"><svg class="i"><use href="#i-download"/></svg>Informe (.txt)</button><button class="btn ghost" id="vulnJsonBtn"><svg class="i"><use href="#i-download"/></svg>Datos (.json)</button></div>
  </div>`;
  let body='';
  cats.forEach(cat=>{
    const items=D.findings.filter(f=>f.cat===cat).sort((a,b)=>sevOrder[a.sev]-sevOrder[b.sev]);
    body+=`<div class="glass phishcard" data-s="margin-top:14px"><div class="subh">${esc(cat)} <span class="hint">(${items.length})</span></div>`;
    items.forEach(f=>{body+=`<div class="vfind ${VULN_SEV[f.sev].cls}"><h4>${vSevChip(f.sev)} ${esc(f.title)} ${(f.cvss!=null&&f.cvss!==undefined)?'<span class="vcvss">CVSS '+esc(f.cvss)+'</span>':''}</h4>
      <div class="vmeta">${esc(f.detail)}</div>
      ${f.evidence?`<div class="vmeta">Evidencia: <span data-s="font-family:var(--mono);color:var(--txt)">${esc(f.evidence)}</span></div>`:''}
      ${f.remediation?`<div class="vrem"><svg class="i"><use href="#i-wrench"/></svg> <b>Remediación:</b> ${esc(f.remediation)}</div>`:''}
      ${f.refs&&f.refs.length?`<div data-s="margin-top:6px">${f.refs.map(r=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(r[1])}">${esc(r[0])} ↗</a>`).join(' ')}</div>`:''}
    </div>`;});
    body+='</div>';
  });
  if(!D.findings.length)body='<div class="glass phishcard" data-s="margin-top:14px"><p class="hint">No se detectaron hallazgos con las fuentes consultadas. El host puede no exponer servicios públicos, o las fuentes no tienen datos sobre él. Recuerda que esta evaluación es pasiva.</p></div>';
  $('#vulnOut').innerHTML=head+body;
  const b1=$('#vulnTxtBtn');if(b1)b1.addEventListener('click',vulnExportTxt);
  const b2=$('#vulnJsonBtn');if(b2)b2.addEventListener('click',vulnExportJson);
  $('#vulnOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function vulnExportTxt(){
  if(!VULN_DATA)return;const D=VULN_DATA;const L=[];
  L.push('INFORME DE ANÁLISIS DE VULNERABILIDADES — CENTINELA');
  L.push('='.repeat(62));
  L.push('Objetivo   : '+D.target+(D.ips.length?'  ('+D.ips.join(', ')+')':''));
  if(D.geo&&(D.geo.asn||D.geo.org))L.push('Hosting/ASN: '+[D.geo.asn,D.geo.org||D.geo.isp].filter(Boolean).join(' · '));
  L.push('Fecha      : '+D.when.toLocaleString('es-CO'));
  L.push('Calificación: '+D.grade+'   Puntaje: '+D.score+'/100');
  L.push('Hallazgos  : '+D.counts.crit+' críticas · '+D.counts.high+' altas · '+D.counts.med+' medias · '+D.counts.low+' bajas');
  if(D.kevCount)L.push('CISA KEV   : '+D.kevCount+' vulnerabilidad(es) EXPLOTADAS ACTIVAMENTE — prioridad máxima');
  L.push('Puertos    : '+(D.ports.join(', ')||'—'));
  L.push('Fuentes    : '+Object.entries(D.sources).filter(([k,v])=>v).map(([k])=>k).join(', '));
  L.push('');
  const sevOrder={crit:0,high:1,med:2,low:3,info:4};
  D.findings.slice().sort((a,b)=>sevOrder[a.sev]-sevOrder[b.sev]).forEach((f,i)=>{
    L.push('-'.repeat(62));
    L.push('['+VULN_SEV[f.sev].label.toUpperCase()+'] '+f.title+(f.cvss!=null&&f.cvss!==undefined?'  (CVSS '+f.cvss+')':''));
    L.push('  Categoría   : '+f.cat);
    L.push('  Detalle     : '+f.detail);
    if(f.evidence)L.push('  Evidencia   : '+f.evidence);
    if(f.remediation)L.push('  Remediación : '+f.remediation);
    if(f.refs)f.refs.forEach(r=>L.push('  Ref         : '+r[0]+' '+r[1]));
  });
  L.push('');L.push('Evaluación pasiva (sin pruebas intrusivas). Uso autorizado sobre infraestructura propia.');
  L.push('Generado por Centinela — Suite de Ciberseguridad.');
  downloadFile('centinela-vulnerabilidades-'+D.target+'.txt',L.join('\n'));
}
function vulnExportJson(){
  if(!VULN_DATA)return;const D=VULN_DATA;
  const out={tool:'Centinela',type:'vulnerability-assessment',target:D.target,generated:D.when.toISOString(),grade:D.grade,score:D.score,counts:D.counts,ips:D.ips,geo:D.geo||null,ports:D.ports,tags:D.tags,cpes:D.cpes,sources:D.sources,findings:D.findings.map(f=>({severity:f.sev,category:f.cat,title:f.title,detail:f.detail,cvss:f.cvss==null?null:f.cvss,cve:f.cve||null,evidence:f.evidence||null,remediation:f.remediation||null,references:(f.refs||[]).map(r=>r[1])}))};
  downloadFile('centinela-vulnerabilidades-'+D.target+'.json',JSON.stringify(out,null,2),'application/json');
}

/* ============================================================ Informe ejecutivo unificado */
async function runReport(){
  let d=$('#reportInput').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Ingresa un dominio válido');return;}
  const doDom=$('#rptDomain').checked,doVuln=$('#rptVuln').checked,doRecon=$('#rptRecon').checked,doLeak=$('#rptLeak').checked,doSbx=$('#rptSbx').checked;
  if(!doDom&&!doVuln&&!doRecon&&!doLeak&&!doSbx){alert('Selecciona al menos un módulo');return;}
  $('#goReport').disabled=true;$('#reportOut').innerHTML='';
  const st=$('#reportStatus');st.style.display='flex';$('#reportBarwrap').style.display='block';
  const setP=(p,t)=>{$('#reportBar').style.width=p+'%';$('#reportStatusTxt').textContent=t;};
  const data={target:d,when:new Date(),domain:null,vuln:null,recon:null,leak:null,files:null,mon:null};
  try{
    if(doDom){setP(8,'Analizando dominio y correo…');$('#domain').value=d;const rt=$('#rbltoggle');if(rt)rt.value='1';await run();data.domain={items:ITEMS.slice(),report:Object.assign({},REPORT)};}
    if(doVuln){setP(45,'Analizando vulnerabilidades…');$('#vulnInput').value=d;$('#vulnDepth').value='std';await runVuln();data.vuln=VULN_DATA;}
    if(doRecon){setP(62,'Buscando dominios suplantadores…');$('#reconInput').value=d;$('#reconDepth').value='fast';await runRecon();data.recon=RECON_DATA;}
    if(doLeak){setP(82,'Consultando filtraciones de la entidad…');$('#leakEntity').value=d;LEAK.last=null;await runLeakEntity();data.leak=LEAK.last&&LEAK.last.type==='entity'?LEAK.last.results:null;}
    if(doSbx){const f=sbxOk().map(x=>x.r);if(f.length)data.files=f;}
    try{const watched=monList().includes(d);let snap=null;try{snap=JSON.parse(localStorage.getItem('ctn-mon-'+d)||'null');}catch(e){}data.mon={watched,snap};}catch(e){}
    setP(100,'Listo');REPORT_DATA=data;renderReportDoc(data);
  }catch(e){alert('Error generando informe: '+e.message);}
  finally{$('#goReport').disabled=false;st.style.display='none';$('#reportBarwrap').style.display='none';setMode('report');}
}
let REPORT_DATA=null;
/* Barras horizontales accesibles. rows: [{label, value, max, color, icon}] · el valor siempre va escrito */
function rptBars(title,rows,unit,note){
  const sum=rows.map(r=>r.label+': '+r.value+(unit||'')).join(', ');
  return `<figure class="rchart" role="group" aria-label="${esc(title)}"><figcaption>${esc(title)}</figcaption>
    <div role="img" aria-label="${esc(title+'. '+sum)}">
    ${rows.map(r=>{const pct=r.max?Math.max(0,Math.min(100,r.value/r.max*100)):0;return `<div class="rbar"><span class="lb">${r.icon||''}${esc(r.label)}</span><span class="tr" title="${esc(r.label+': '+r.value+(unit||''))}"><span class="fl" data-s="width:${pct.toFixed(1)}%;background:${r.color}"></span></span><span class="vl">${esc(String(r.value))}${esc(unit||'')}</span></div>`;}).join('')}
    </div>${note?`<div class="hint">${esc(note)}</div>`:''}
    <details><summary>Ver datos en tabla</summary><table class="mini"><tr><th>Categoría</th><th>Valor</th></tr>${rows.map(r=>`<tr><td>${esc(r.label)}</td><td>${esc(String(r.value))}${esc(unit||'')}</td></tr>`).join('')}</table></details></figure>`;
}
/* ---- Cumplimiento: hallazgos → controles de ISO/IEC 27001:2022 (Anexo A), NIST CSF 2.0 y CIS Controls v8.
   Mapeo orientativo para priorizar; no sustituye una auditoría de certificación. Estados:
   ok = conforme · gap = con brechas · bad = no conforme · na = no evaluado */
const COMP_ST={ok:['Conforme','g',1],gap:['Con brechas','y',0.5],bad:['No conforme','r',0],na:['No evaluado','',null]};
function rptCompliance(D){
  const it=n=>D.domain?D.domain.items.find(x=>x.name===n):null;
  const st=n=>{const x=it(n);return x?x.status:null;};
  const V=D.vuln,L=D.leak,R=D.recon,F=D.files;
  const C=[];const add=(area,iso,nist,cis,s,ev)=>C.push({area,iso,nist,cis,s,ev});
  // Autenticación del correo (anti-suplantación)
  if(D.domain){const ss=['SPF','DKIM','DMARC'].map(st).filter(Boolean);
    add('Autenticación del correo (SPF, DKIM, DMARC)','A.5.14 · A.8.21','PR.DS-02','9.5',ss.includes('fail')?'bad':ss.every(x=>x==='ok')?'ok':'gap','SPF '+(st('SPF')||'—')+' · DKIM '+(st('DKIM')||'—')+' · DMARC '+(st('DMARC')||'—'));
    const tl=['MTA-STS','TLS-RPT'].map(st).filter(Boolean);
    add('Cifrado del correo en tránsito (MTA-STS, TLS-RPT)','A.8.24','PR.DS-02','3.10',!tl.length?'na':tl.every(x=>x==='ok')?'ok':tl.includes('fail')?'bad':'gap','MTA-STS '+(st('MTA-STS')||'—')+' · TLS-RPT '+(st('TLS-RPT')||'—'));
    const ds=st('DNSSEC');add('Integridad del DNS (DNSSEC)','A.8.20','PR.IR-01','—',!ds?'na':ds==='ok'?'ok':ds==='fail'?'bad':'gap','DNSSEC '+(ds||'—'));
    const caa=st('CAA');if(caa)add('Control de emisión de certificados (CAA)','A.8.24','PR.DS-02','3.10',caa==='ok'?'ok':caa==='fail'?'bad':'gap','CAA '+caa);
  } else ['Autenticación del correo (SPF, DKIM, DMARC)','Integridad del DNS (DNSSEC)'].forEach(x=>add(x,'—','—','—','na','Módulo no ejecutado'));
  // Vulnerabilidades y exposición
  if(V){
    add('Gestión de vulnerabilidades técnicas','A.8.8','ID.RA-01 · PR.PS-02','7.1 · 7.7',(V.kevCount||V.counts.crit)?'bad':V.counts.high?'gap':'ok',V.counts.crit+' críticas · '+V.counts.high+' altas'+(V.kevCount?' · '+V.kevCount+' explotadas activamente (CISA KEV)':''));
    const ex=V.findings.filter(f=>f.cat==='Exposición de servicios');
    const pr=(V.ports||[]).map(p=>(PORT_RISK[p]||[])[0]).filter(Boolean);   // también por el riesgo de cada puerto expuesto
    const riskyP=(V.ports||[]).filter(p=>PORT_RISK[p]&&(PORT_RISK[p][0]==='crit'||PORT_RISK[p][0]==='high'));
    add('Exposición de servicios a Internet','A.8.20 · A.8.22','PR.IR-01','4.4 · 12.1',(ex.some(f=>f.sev==='crit')||pr.includes('crit'))?'bad':(ex.some(f=>f.sev==='high'||f.sev==='med')||pr.includes('high')||pr.includes('med'))?'gap':'ok',(V.ports.length?'Puertos: '+V.ports.join(', '):'Sin puertos expuestos detectados')+(riskyP.length?' · de alto riesgo: '+riskyP.map(p=>p+' ('+PORT_RISK[p][1]+')').join(', '):''));
    const tk=V.findings.filter(f=>f.cat==='Subdomain takeover'&&(f.sev==='crit'||f.sev==='high'));
    const sub=V.findings.find(f=>f.cat==='Superficie de ataque');
    add('Inventario de activos y configuración segura','A.5.9 · A.8.9','ID.AM-01 · ID.AM-02','1.1 · 4.1',tk.length?'bad':sub&&sub.sev!=='info'?'gap':'ok',tk.length?tk.length+' subdominio(s) con riesgo de takeover':sub?sub.title:'Superficie de ataque acotada');
  } else add('Gestión de vulnerabilidades técnicas','A.8.8','ID.RA-01','7.1','na','Módulo no ejecutado');
  // Inteligencia de amenazas: suplantación
  if(R){const hi=R.dossiers.filter(e=>e.score>=60).length;add('Inteligencia de amenazas: dominios suplantadores','A.5.7','ID.RA-02','—',hi?'gap':'ok',R.registered.length+' registrados · '+hi+' de riesgo alto');}
  // Credenciales y filtraciones
  if(L){const emp=L.infostealer.employees||0,br=L.breaches.length,vic=(L.ransomware.victims||[]).length;
    add('Gestión de credenciales y autenticación','A.5.17 · A.8.5','PR.AA-01','5.2 · 6.3',emp?'bad':br?'gap':'ok',emp+' empleado(s) con infostealer · '+br+' filtración(es)');
    add('Gestión de incidentes de seguridad','A.5.24 · A.5.26','RS.MA-01','17.4',vic?'bad':'ok',vic?'La entidad aparece en '+vic+' publicación(es) de ransomware':'Sin publicaciones de ransomware');}
  // Protección contra malware
  if(F){const bad=F.filter(r=>r.verdict.c==='crit').length,sus=F.filter(r=>r.verdict.c==='high').length;
    add('Protección contra malware','A.8.7','DE.CM-09','10.1',bad?'bad':sus?'gap':'ok',F.length+' archivo(s) analizados · '+bad+' maliciosos · '+sus+' sospechosos');}
  // Monitoreo continuo
  if(D.mon)add('Monitoreo continuo','A.8.16','DE.CM-01','13.1',D.mon.watched?'ok':'gap',D.mon.watched?'Dominio bajo monitoreo':'El dominio no está bajo monitoreo');
  const ev=C.filter(c=>COMP_ST[c.s][2]!==null);
  const pct=ev.length?Math.round(ev.reduce((s,c)=>s+COMP_ST[c.s][2],0)/ev.length*100):null;
  return {controls:C,pct,counts:{ok:C.filter(c=>c.s==='ok').length,gap:C.filter(c=>c.s==='gap').length,bad:C.filter(c=>c.s==='bad').length,na:C.filter(c=>c.s==='na').length}};
}
function renderReportDoc(D){
  const org=(function(){try{return localStorage.getItem('ctn-org')||'';}catch(e){return'';}})();
  // ---- resúmenes ----
  let grade='—',gcol='var(--muted)',vsum='';
  if(D.vuln){grade=D.vuln.grade;gcol=gradeColor(grade);}
  // domain posture counts
  let dFail=0,dWarn=0,dOk=0;
  if(D.domain){D.domain.items.forEach(it=>{if(it.status==='fail')dFail++;else if(it.status==='warn')dWarn++;else if(it.status==='ok')dOk++;});}
  const recImp=D.recon?D.recon.registered.length:0;const recAct=D.recon?D.recon.dossiers.filter(e=>e.ips.length).length:0;
  // overall one-line verdict
  const crit=(D.vuln?D.vuln.counts.crit:0)+(D.recon?D.recon.dossiers.filter(e=>e.score>=60).length:0);
  const kev=D.vuln?(D.vuln.kevCount||0):0;
  const L=D.leak,lVic=L?(L.ransomware.victims||[]).length:0,lEmp=L?(L.infostealer.employees||0):0,lBr=L?L.breaches.length:0,lUsr=L?(L.infostealer.users||0):0;
  const fBad=D.files?D.files.filter(r=>r.verdict.c==='crit').length:0,fSus=D.files?D.files.filter(r=>r.verdict.c==='high').length:0;
  let verdict,vcol;
  if(kev>0||crit>0||dFail>2||lVic||lEmp||fBad){verdict='Riesgo ALTO — requiere acción inmediata';vcol='var(--fail)';}
  else if(dFail>0||(D.vuln&&D.vuln.counts.high)||recImp>0||lBr||lUsr||fSus){verdict='Riesgo MEDIO — hay hallazgos a corregir';vcol='var(--warn)';}
  else{verdict='Riesgo BAJO — postura aceptable';vcol='var(--ok)';}
  // ---- cover + resumen ----
  let html=`<div class="glass phishcard">
    <div class="rptcover">
      ${D.vuln?`<div class="vgbadge" data-s="color:${gcol}">${grade}</div>`:''}
      <div data-s="flex:1 1 240px">
        <div data-s="font-family:var(--display);font-size:22px;font-weight:700">Informe ejecutivo de ciberseguridad</div>
        <div class="phurl" data-s="margin-top:2px">${org?esc(org)+' · ':''}Objetivo: <b>${esc(D.target)}</b> · ${esc(D.when.toLocaleString('es-CO'))}</div>
        <div data-s="margin-top:6px;font-weight:700;color:${vcol}">${verdict}</div>
      </div>
    </div>
    <div class="kpis" data-s="margin-top:14px;margin-bottom:0">
      ${D.vuln?`<div class="kpi ${D.vuln.counts.crit?'fail':'ok'}"><b>${D.vuln.counts.crit}</b><span>vuln. críticas</span></div>
      <div class="kpi ${D.vuln.counts.high?'warn':'neut'}"><b>${D.vuln.counts.high}</b><span>vuln. altas</span></div>
      ${kev?`<div class="kpi fail"><b>${kev}</b><span>explotadas</span></div>`:''}`:''}
      ${D.domain?`<div class="kpi ${dFail?'fail':'ok'}"><b>${dFail}</b><span>fallos correo/DNS</span></div>`:''}
      ${D.recon?`<div class="kpi ${recImp?'warn':'ok'}"><b>${recImp}</b><span>suplantadores</span></div>`:''}
      ${L?`<div class="kpi ${lEmp||lVic?'fail':lBr?'warn':'ok'}"><b>${lBr+lVic}</b><span>filtraciones</span></div><div class="kpi ${lEmp?'fail':'ok'}"><b>${lEmp}</b><span>empleados con infostealer</span></div>`:''}
      ${D.files?`<div class="kpi ${fBad?'fail':fSus?'warn':'ok'}"><b>${fBad+fSus}</b><span>archivos de riesgo</span></div>`:''}
    </div>
    <!--POSTURA-->
    <div class="dashbtns" data-s="justify-content:flex-start;margin-top:14px;gap:8px">
      <button class="btn" id="rptPrintBtn"><svg class="i"><use href="#i-printer"/></svg>Guardar como PDF</button>
      <button class="btn ghost" id="rptJsonBtn"><svg class="i"><use href="#i-download"/></svg>Datos (.json)</button>
      <button class="btn ghost" data-caseadd="report"><svg class="i"><use href="#i-note"/></svg>Añadir a un caso</button>
    </div>
  </div>`;
  // ---- Postura por área (0–100, más alto = mejor) ----
  const areas=[];
  if(D.domain){const n=D.domain.items.filter(it=>['ok','warn','fail'].includes(it.status)).length||1;areas.push(['Correo y DNS',Math.round((dOk+dWarn*0.5)/n*100)]);}
  if(D.vuln)areas.push(['Vulnerabilidades',D.vuln.score]);
  if(D.recon){const hi=D.recon.dossiers.filter(e=>e.score>=60).length;areas.push(['Suplantación',Math.max(0,100-Math.min(100,hi*25+Math.max(0,recImp-hi)*3))]);}
  if(L)areas.push(['Filtraciones',Math.max(0,100-Math.min(100,lVic*60+lEmp*15+lBr*10+Math.min(20,lUsr*2)))]);
  if(D.files)areas.push(['Archivos analizados',Math.max(0,100-Math.max(0,...D.files.map(r=>r.score)))]);
  const postura=areas.length>1?rptBars('Postura de seguridad por área (0–100, más alto es mejor)',areas.map(([l,v])=>({label:l,value:v,max:100,color:'var(--accent)'})),'',
    'Índices orientativos calculados a partir de los hallazgos de cada módulo; consulta las secciones para el detalle.'):'';
  if(postura)html=html.replace('<!--POSTURA-->',postura);
  // ---- Prioridades de actuación (lo más urgente de todos los módulos) ----
  const P=[];const pr=(sev,txt,src)=>P.push({sev,txt,src});
  if(D.vuln)D.vuln.findings.filter(f=>f.sev==='crit'||f.sev==='high').sort((a,b)=>SEV_RANK[b.sev]-SEV_RANK[a.sev]).slice(0,4).forEach(f=>pr(f.sev,(f.remediation||f.title),'Vulnerabilidades'));
  if(lVic)pr('crit','La entidad aparece publicada por un grupo de ransomware: activa el plan de respuesta a incidentes, confirma el alcance y notifica a las autoridades (colCERT) y a los titulares afectados.','Filtraciones');
  if(lEmp)pr('crit','Hay '+lEmp+' empleado(s) con credenciales robadas por malware infostealer: restablece sus contraseñas, revoca sesiones y tokens, y revisa sus equipos.','Filtraciones');
  if(D.files)D.files.filter(r=>r.verdict.c==='crit'||r.verdict.c==='high').slice(0,3).forEach(r=>pr(r.verdict.c,'Archivo "'+r.name+'" ('+r.verdict.t.toLowerCase()+'): '+(r.recs[0]||'aíslalo y bloquea su hash.'),'Sandbox'));
  if(D.domain)D.domain.items.filter(it=>it.status==='fail').slice(0,3).forEach(it=>{const f=(it.findings||[]).find(x=>x.sev==='fail');pr('high',it.name+': '+(f?f.title:'control fallido')+'.','Correo y DNS');});
  if(D.recon)D.recon.dossiers.filter(e=>e.score>=60).slice(0,2).forEach(e=>pr('high','Dominio suplantador activo '+e.dom+': solicita su retirada al registrador/hosting y bloquéalo en correo y proxy.','OSINT'));
  if(lBr)pr('med','El dominio figura en '+lBr+' filtración(es): fuerza el cambio de contraseñas de las cuentas afectadas y activa MFA.','Filtraciones');
  if(P.length)html+=`<div class="glass phishcard rptsec"><h3>Prioridades de actuación</h3>${P.sort((a,b)=>SEV_RANK[b.sev]-SEV_RANK[a.sev]).slice(0,10).map((x,i)=>`<div class="vfind ${VULN_SEV[x.sev].cls}" data-s="margin-top:8px"><h4>${i+1}. ${vSevChip(x.sev)} <span class="tag">${esc(x.src)}</span></h4><div class="vmeta" data-s="color:var(--txt)">${esc(x.txt)}</div></div>`).join('')}</div>`;
  let secN=0;const secT=t=>`${++secN} · ${t}`;
  // ---- Sección Vulnerabilidades ----
  if(D.vuln){
    const V=D.vuln;const sevOrder={crit:0,high:1,med:2,low:3,info:4};
    const top=V.findings.filter(f=>f.sev!=='info').sort((a,b)=>sevOrder[a.sev]-sevOrder[b.sev]).slice(0,12);
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Vulnerabilidades e infraestructura')}</h3>
      <div class="rptrow"><span>Calificación de seguridad</span><b data-s="color:${gcol}">${grade} (${V.score}/100)</b></div>
      <div class="rptrow"><span>Puertos expuestos</span><b>${V.ports.join(', ')||'—'}</b></div>
      <div class="rptrow"><span>Hallazgos</span><b>${V.counts.crit} críticas · ${V.counts.high} altas · ${V.counts.med} medias · ${V.counts.low} bajas</b></div>
      ${kev?`<div class="rptrow"><span data-s="color:var(--fail)"><svg class="i"><use href="#i-alert"/></svg> Explotadas activamente (CISA KEV)</span><b data-s="color:var(--fail)">${kev}</b></div>`:''}
      ${rptBars('Hallazgos por severidad',[['crit','Crítica','stop'],['high','Alta','alert'],['med','Media','alert'],['low','Baja','bell']].map(([k,l,i])=>({label:l,value:V.counts[k]||0,max:Math.max(1,V.counts.crit,V.counts.high,V.counts.med,V.counts.low),color:'var(--sev-'+k+')',icon:ico(i)})),'')}
      <div data-s="margin-top:10px;font-weight:600;font-size:13px">Hallazgos principales</div>
      ${top.map(f=>`<div class="vfind ${VULN_SEV[f.sev].cls}" data-s="margin-top:8px"><h4>${vSevChip(f.sev)} ${esc(f.title)}</h4><div class="vmeta">${esc(f.detail)}</div>${f.remediation?`<div class="vrem"><svg class="i"><use href="#i-wrench"/></svg> ${esc(f.remediation)}</div>`:''}</div>`).join('')}
    </div>`;
  }
  // ---- Sección Correo & DNS ----
  if(D.domain){
    const items=D.domain.items;
    const icon=s=>s==='ok'?'<svg class="i iok"><use href="#i-check-circle"/></svg>':s==='warn'?'<svg class="i iwarn"><use href="#i-alert"/></svg>':s==='fail'?'<svg class="i ifail"><use href="#i-stop"/></svg>':'•';
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Postura de correo y DNS')}</h3>
      <div class="rptrow"><span>Controles evaluados</span><b>${items.length} · ${dOk} correctos, ${dWarn} advertencias, ${dFail} fallos</b></div>
      ${items.map(it=>{const f=(it.findings||[]).find(x=>x.sev===it.status)||(it.findings||[])[0];return `<div class="rptrow"><span>${icon(it.status)} ${esc(it.name)}</span><span data-s="color:var(--muted);max-width:60%;text-align:right">${esc(f?f.title:(it.subtitle||''))}</span></div>`;}).join('')}
    </div>`;
  }
  // ---- Sección OSINT / Suplantación ----
  if(D.recon){
    const R=D.recon;const ds=R.dossiers.slice().sort((a,b)=>b.score-a.score).slice(0,10);
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Dominios suplantadores (OSINT)')}</h3>
      <div class="rptrow"><span>Candidatos analizados</span><b>${R.scanned}</b></div>
      <div class="rptrow"><span>Registrados / activos</span><b>${R.registered.length} / ${recAct}</b></div>
      ${ds.length?`<div data-s="margin-top:10px;font-weight:600;font-size:13px">Dominios de mayor riesgo</div>
      <table class="mini" data-s="margin-top:6px"><tr><th>Dominio</th><th>Riesgo</th><th>IP</th><th>País</th></tr>
      ${ds.map(e=>`<tr><td data-s="font-family:var(--mono)">${esc(e.dom)}</td><td>${e.score>=60?'<b data-s="color:var(--fail)">ALTO':e.score>=30?'<b data-s="color:var(--warn)">MEDIO':'<b>BAJO'} ${e.score}</b></td><td>${esc((e.ips&&e.ips[0])||'—')}</td><td>${esc((e.geo&&e.geo.country)||'—')}</td></tr>`).join('')}</table>`:'<p class="hint" data-s="margin-top:8px">No se hallaron dominios suplantadores registrados con el barrido rápido.</p>'}
    </div>`;
  }
  // ---- Sección Filtraciones ----
  if(L){
    const hr=L.infostealer,rw=L.ransomware;
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Filtraciones de datos de la entidad')}</h3>
      <div class="rptrow"><span>Filtraciones conocidas del dominio</span><b data-s="color:${lBr?'var(--warn)':'inherit'}">${lBr}</b></div>
      <div class="rptrow"><span>Empleados con credenciales robadas (infostealer)</span><b data-s="color:${lEmp?'var(--fail)':'inherit'}">${hr.state==='error'?'no consultado':leakNum(lEmp)}</b></div>
      <div class="rptrow"><span>Usuarios externos / terceros afectados</span><b>${hr.state==='error'?'—':leakNum(lUsr)+' / '+leakNum(hr.thirdParties||0)}</b></div>
      <div class="rptrow"><span>Publicaciones en sitios de ransomware</span><b data-s="color:${lVic?'var(--fail)':'inherit'}">${rw.state==='skip'||rw.state==='error'?'no consultado':lVic}</b></div>
      ${lBr?`<div data-s="margin-top:10px;font-weight:600;font-size:13px">Filtraciones</div><table class="mini" data-s="margin-top:6px"><tr><th>Filtración</th><th>Fecha</th><th>Datos expuestos</th></tr>${L.breaches.slice(0,10).map(b=>`<tr><td>${esc(b.title||b.name||'')}</td><td>${esc(String(b.date||'').slice(0,10))}</td><td>${esc((b.classes||b.data||[]).slice(0,5).join(', '))}</td></tr>`).join('')}</table>`:''}
      ${lVic?`<div data-s="margin-top:10px;font-weight:600;font-size:13px">Publicaciones de ransomware</div><table class="mini" data-s="margin-top:6px"><tr><th>Víctima</th><th>Grupo</th><th>Fecha</th></tr>${rw.victims.slice(0,10).map(v=>`<tr><td>${esc(v.name)}</td><td>${esc(v.group)}</td><td>${esc(v.date)}</td></tr>`).join('')}</table>`:''}
      ${hr.state==='error'||rw.state==='error'?'<p class="hint" data-s="margin-top:8px">Algunas fuentes requieren el backend (Ajustes → URL del backend).</p>':''}
    </div>`;
  }
  // ---- Sección Archivos del sandbox ----
  if(D.files){
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Archivos analizados en el sandbox')}</h3>
      <table class="mini" data-s="margin-top:6px"><tr><th>Archivo</th><th>Veredicto</th><th>Puntaje</th><th>Técnicas ATT&amp;CK</th><th>CVE</th><th>SHA-256</th></tr>
      ${D.files.map(r=>`<tr><td>${esc(r.name)}</td><td data-s="color:${r.verdict.col}">${esc(r.verdict.t)}</td><td>${r.score}</td><td>${Object.entries(sbxTechSev(r)).filter(([,v])=>v!=='info').map(([k])=>esc(k)).join(', ')||'—'}</td><td>${(r.cveInfo||[]).map(c=>esc(c.id)).join(', ')||'—'}</td><td data-s="font-family:var(--mono);word-break:break-all">${esc(r.hashes.sha256.slice(0,16))}…</td></tr>`).join('')}</table>
      <p class="hint" data-s="margin-top:8px">Análisis estático en entorno aislado; el detalle completo de cada archivo se exporta desde el módulo Sandbox (TXT, JSON, STIX, capa ATT&amp;CK Navigator).</p></div>`;
  }
  // ---- Monitoreo ----
  if(D.mon){
    const sn=D.mon.snap;
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Monitoreo continuo')}</h3>
      <div class="rptrow"><span>Dominio bajo monitoreo en este navegador</span><b data-s="color:${D.mon.watched?'var(--ok)':'var(--warn)'}">${D.mon.watched?'sí':'no'}</b></div>
      ${sn?`<div class="rptrow"><span>Listas negras (última revisión)</span><b data-s="color:${sn.listed?'var(--fail)':'var(--ok)'}">${esc(sn.listed||'ninguna')}</b></div>`:''}
      ${D.mon.watched?'':'<p class="hint" data-s="margin-top:8px">Recomendación: añade el dominio en el módulo Monitoreo para detectar cambios en SPF/DMARC/MX/NS e inclusiones en listas negras.</p>'}
    </div>`;
  }
  // ---- Cumplimiento normativo ----
  const CP=rptCompliance(D);D.compliance=CP;
  if(CP.controls.length){
    html+=`<div class="glass phishcard rptsec"><h3>${secT('Cumplimiento normativo (ISO/IEC 27001 · NIST CSF 2.0 · CIS v8)')}</h3>
      <div class="kpis" data-s="margin-bottom:6px">
        ${CP.pct!=null?`<div class="kpi ${CP.pct>=80?'ok':CP.pct>=50?'warn':'fail'}"><b>${CP.pct}%</b><span>cumplimiento estimado</span></div>`:''}
        <div class="kpi ok"><b>${CP.counts.ok}</b><span>conformes</span></div><div class="kpi ${CP.counts.gap?'warn':'neut'}"><b>${CP.counts.gap}</b><span>con brechas</span></div>
        <div class="kpi ${CP.counts.bad?'fail':'neut'}"><b>${CP.counts.bad}</b><span>no conformes</span></div><div class="kpi neut"><b>${CP.counts.na}</b><span>no evaluados</span></div></div>
      <div class="sbxscroll"><table class="mini"><tr><th>Área de control</th><th>ISO/IEC 27001:2022</th><th>NIST CSF 2.0</th><th>CIS v8</th><th>Estado</th><th>Evidencia</th></tr>
      ${CP.controls.map(c=>`<tr><td>${esc(c.area)}</td><td data-s="font-family:var(--mono);white-space:nowrap">${esc(c.iso)}</td><td data-s="font-family:var(--mono);white-space:nowrap">${esc(c.nist)}</td><td data-s="font-family:var(--mono);white-space:nowrap">${esc(c.cis)}</td><td>${tag(COMP_ST[c.s][0],COMP_ST[c.s][1])}</td><td>${esc(c.ev)}</td></tr>`).join('')}</table></div>
      <p class="hint" data-s="margin-top:8px">Mapeo orientativo de los hallazgos técnicos observables desde Internet a controles de referencia (ISO/IEC 27001:2022 Anexo A, NIST Cybersecurity Framework 2.0 y CIS Critical Security Controls v8). Sirve para priorizar y documentar brechas; no sustituye una auditoría de certificación, que además evalúa políticas, procesos y evidencias internas.</p></div>`;
  }
  html+=`<div class="glass phishcard rptsec"><h3>Metodología y alcance</h3>
    <p class="hint" data-s="margin-top:0">Informe generado por <b>Centinela</b> mediante evaluación <b>pasiva</b> (sin pruebas intrusivas) correlacionando fuentes públicas: DNS-over-HTTPS, Shodan InternetDB, CIRCL/NVD, CISA KEV, FIRST EPSS, crt.sh, RDAP, IP-geo, Have I Been Pwned, XposedOrNot, Hudson Rock, ransomware.live y OSV.dev, además del análisis estático de archivos en entorno aislado (MITRE ATT&amp;CK). Los resultados reflejan el estado observable en la fecha del informe y deben validarse antes de tomar acciones. Uso autorizado sobre infraestructura propia.</p></div>`;
  const toc=[...html.matchAll(/<h3>(?:\d+ · )?([^<]+)<\/h3>/g)].map(m=>m[1]);
  const cover=`<div class="rptprint rptcoverpage"><div class="cl">Uso interno · Confidencial</div>
    <h1>Informe ejecutivo de ciberseguridad</h1>
    <div class="cvmeta">${org?'<b>'+esc(org)+'</b><br>':''}Objetivo evaluado: <b>${esc(D.target)}</b><br>Fecha: ${esc(D.when.toLocaleString('es-CO'))}${D.vuln?'<br>Calificación de seguridad: <b>'+esc(grade)+'</b> ('+D.vuln.score+'/100)':''}</div>
    <div class="verd" data-s="color:${vcol}">${esc(verdict)}</div>
    <div class="foot">Generado con Centinela mediante evaluación pasiva de fuentes públicas. Contiene información sensible sobre la postura de seguridad de la entidad: distribúyalo solo a personas autorizadas.</div></div>
    <div class="rptprint rpttoc"><h2>Contenido</h2><ol>${toc.map(t=>'<li>'+esc(t)+'</li>').join('')}</ol></div>`;
  $('#reportOut').innerHTML=cover+html;
  const pb=$('#rptPrintBtn');if(pb)pb.addEventListener('click',()=>{document.body.classList.add('printing-report');try{window.print();}catch(e){}});
  const jb=$('#rptJsonBtn');if(jb)jb.addEventListener('click',reportExportJson);
  $('#reportOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function reportExportJson(){
  if(!REPORT_DATA)return;const D=REPORT_DATA;
  const out={tool:'Centinela',type:'executive-report',target:D.target,generated:D.when.toISOString(),
    vulnerabilities:D.vuln?{grade:D.vuln.grade,score:D.vuln.score,counts:D.vuln.counts,kev:D.vuln.kevCount||0,ports:D.vuln.ports,findings:D.vuln.findings.map(f=>({severity:f.sev,category:f.cat,title:f.title}))}:null,
    mail_dns:D.domain?D.domain.items.map(it=>({control:it.name,status:it.status})):null,
    impersonation:D.recon?{scanned:D.recon.scanned,registered:D.recon.registered.length,domains:D.recon.dossiers.map(e=>({domain:e.dom,risk:e.score,ip:(e.ips&&e.ips[0])||null,country:(e.geo&&e.geo.country)||null}))}:null,
    data_leaks:D.leak?{breaches:D.leak.breaches.map(b=>({name:b.title||b.name||'',date:b.date||null,data:b.classes||b.data||[]})),infostealer:{employees:D.leak.infostealer.employees||0,users:D.leak.infostealer.users||0,third_parties:D.leak.infostealer.thirdParties||0},ransomware_posts:(D.leak.ransomware.victims||[]).map(v=>({victim:v.name,group:v.group,date:v.date}))}:null,
    files:D.files?D.files.map(r=>({name:r.name,sha256:r.hashes.sha256,verdict:r.verdict.t,score:r.score,attack:Object.keys(sbxTechSev(r)),cves:(r.cveInfo||[]).map(c=>c.id)})):null,
    monitoring:D.mon||null,
    compliance:D.compliance?{estimated_percent:D.compliance.pct,counts:D.compliance.counts,controls:D.compliance.controls.map(c=>({area:c.area,iso27001_2022:c.iso,nist_csf_2:c.nist,cis_v8:c.cis,status:{ok:'compliant',gap:'gaps',bad:'non-compliant',na:'not-assessed'}[c.s],evidence:c.ev}))}:null};
  downloadFile('centinela-informe-'+D.target+'.json',JSON.stringify(out,null,2),'application/json');
}

/* ============================================================ Analizador de correo (.eml) */
function analyzeEml(){
  const raw=$('#emlInput').value;
  if(!raw.trim()){alert('Pega el contenido del correo');return;}
  const headerBlock=raw.split(/\r?\n\r?\n/)[0];
  const H=[];headerBlock.split(/\r?\n/).forEach(l=>{if(/^\s/.test(l)&&H.length)H[H.length-1].v+=' '+l.trim();else{const i=l.indexOf(':');if(i>0)H.push({k:l.slice(0,i).trim(),v:l.slice(i+1).trim()});}});
  const get=k=>H.filter(x=>x.k.toLowerCase()===k.toLowerCase()).map(x=>x.v);
  const from=get('From')[0]||'',returnPath=get('Return-Path')[0]||'',replyTo=get('Reply-To')[0]||'',subject=get('Subject')[0]||'',date=get('Date')[0]||'';
  const authRes=get('Authentication-Results').concat(get('ARC-Authentication-Results')).join('  ;  ');
  const received=get('Received');
  const emailDom=s=>{const m=(s||'').match(/@([a-z0-9.-]+\.[a-z]{2,})/i);return m?m[1].toLowerCase().replace(/[>)."']+$/,''):'';};
  const dispName=s=>{const m=(s||'').match(/^\s*"?([^"<]*?)"?\s*</);return m?m[1].trim():'';};
  const fromDom=emailDom(from),rpDom=emailDom(returnPath),replyDom=emailDom(replyTo);
  const spf=(authRes.match(/spf=(\w+)/i)||[])[1];
  const dkim=(authRes.match(/dkim=(\w+)/i)||[])[1];
  const dmarc=(authRes.match(/dmarc=(\w+)/i)||[])[1];
  const ipm=received.join(' ').match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)||[];
  const pubIp=ipm.filter(ip=>!/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip));
  const originIp=pubIp[pubIp.length-1]||null;
  const f=[];let score=0;const add=(w,sev,t,why)=>{score+=w;f.push({sev,t,why});};
  const pf=(res,name,wFail)=>{if(!res){f.push({sev:'info',t:name+': no informado',why:'El correo no trae resultado de '+name+' en Authentication-Results.'});return;}
    if(/pass/i.test(res))f.push({sev:'ok',t:name+'=pass',why:name+' verificado correctamente.'});
    else{add(wFail,'fail',name+'='+res,name+' NO pasó — señal de posible suplantación.');}};
  pf(spf,'SPF',20);pf(dkim,'DKIM',20);pf(dmarc,'DMARC',30);
  if(fromDom&&rpDom&&fromDom!==rpDom){add(15,'warn','Return-Path distinto del From','From: @'+fromDom+' vs Return-Path: @'+rpDom+' — común en correos legítimos masivos, pero también en spoofing. Revísalo junto a SPF/DKIM.');}
  if(fromDom&&replyDom&&replyDom!==fromDom){add(20,'fail','Reply-To apunta a otro dominio','Las respuestas irían a @'+replyDom+' en vez de @'+fromDom+'. Truco frecuente de fraude (BEC).');}
  const dn=dispName(from);
  if(dn){const brandInName=dn.toLowerCase().match(/[a-z0-9.-]+\.[a-z]{2,}/);if(brandInName&&fromDom&&!fromDom.includes(brandInName[0].split('.')[0])&&brandInName[0]!==fromDom){add(18,'warn','Nombre visible engañoso','El remitente se muestra como "'+dn+'" pero envía desde @'+fromDom+'.');}}
  if(dmarc&&/fail/i.test(dmarc)){/*already counted*/}
  score=Math.min(100,score);
  renderEml({from,fromDom,returnPath,rpDom,replyTo,replyDom,subject,date,spf,dkim,dmarc,originIp,hops:received.length,findings:f,score});
}
async function renderEml(r){
  const lv=r.score>=50?['ALTO','var(--fail)','<svg class="i"><use href="#i-stop"/></svg>']:r.score>=20?['MEDIO','var(--warn)','<svg class="i"><use href="#i-alert"/></svg>']:['BAJO','var(--ok)','<svg class="i"><use href="#i-check-circle"/></svg>'];
  const sigH=r.findings.map(x=>{const ic={ok:'✓',warn:'!',fail:'✕',info:'i'}[x.sev]||'•';return `<li class="f-${x.sev}"><span class="ic">${ic}</span><div><b>${esc(x.t)}</b>${x.why?`<span class="why">${esc(x.why)}</span>`:''}</div></li>`;}).join('');
  const badge=v=>v?(/pass/i.test(v)?tag(v,'g'):tag(v,'r')):tag('n/d','y');
  const kv={
    'Asunto':esc(r.subject||'—'),'Fecha':esc(r.date||'—'),
    'De (From)':esc(r.from||'—')+(r.fromDom?' <span class="hint">@'+esc(r.fromDom)+'</span>':''),
    'Return-Path':r.returnPath?esc(r.returnPath):'—','Reply-To':r.replyTo?esc(r.replyTo):'—',
    'SPF':badge(r.spf),'DKIM':badge(r.dkim),'DMARC':badge(r.dmarc),
    'Saltos (Received)':r.hops,'IP de origen':r.originIp?esc(r.originIp):'no detectada'
  };
  let geoRow='';
  if(r.originIp){try{const g=await geoLookup(r.originIp);if(g)geoRow=`${g.flag||flagOf(g.cc)||''} ${esc([g.city,g.country].filter(Boolean).join(', '))} · ${esc(g.org||g.isp||'')} ${g.asn?tag(g.asn):''}`;}catch(e){}}
  if(geoRow)kv['Origen (geo)']=geoRow;
  $('#emlOut').innerHTML=`<div class="glass phishcard">
    <div class="phverdict" data-s="color:${lv[1]}">${lv[2]} Riesgo de suplantación del correo: ${lv[0]} (${r.score}/100)</div>
    <ul class="findings">${sigH}</ul>
    <div class="subh">Detalle del correo</div>
    <table class="kv">${Object.entries(kv).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')}</table>
    <p class="hint" data-s="margin-top:10px">Análisis basado en los encabezados que pegaste. Si SPF/DKIM/DMARC no aparecen, tu proveedor no los añadió: reenvía el correo como adjunto o usa "Mostrar original".</p>
  </div>`;
  $('#emlOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ============================================================ Sandbox de archivos
   Análisis de bytes: sandbox-worker.js (Web Worker aislado; el archivo nunca se ejecuta).
   Aquí: orquestación, enriquecimiento (MITRE ATT&CK, CVE, EPSS, KEV, OSV, reputación), informe y exportaciones. */
const ATT_TACTICS=[['TA0001','Acceso inicial'],['TA0002','Ejecución'],['TA0003','Persistencia'],['TA0004','Escalada de privilegios'],['TA0005','Evasión de defensas'],['TA0006','Acceso a credenciales'],['TA0007','Descubrimiento'],['TA0008','Movimiento lateral'],['TA0009','Recolección'],['TA0011','Comando y control'],['TA0010','Exfiltración'],['TA0040','Impacto']];
/* Técnicas que el motor puede reportar: nombre oficial y tácticas (MITRE ATT&CK Enterprise) */
const ATT_TECH=(()=>{const T={},add=(tac,list)=>list.split('|').forEach(x=>{const [id,name]=x.split('=');(T[id]=T[id]||[name,[]])[1].push(tac);});
add('TA0001','T1566.001=Spearphishing Attachment|T1566.002=Spearphishing Link');
add('TA0002','T1204.001=Malicious Link|T1204.002=Malicious File|T1203=Exploitation for Client Execution|T1059=Command and Scripting Interpreter|T1059.001=PowerShell|T1059.003=Windows Command Shell|T1059.004=Unix Shell|T1059.005=Visual Basic|T1059.006=Python|T1059.007=JavaScript|T1047=Windows Management Instrumentation|T1106=Native API|T1129=Shared Modules|T1559=Inter-Process Communication|T1559.002=Dynamic Data Exchange|T1053.003=Cron|T1053.005=Scheduled Task');
add('TA0003','T1053.003=Cron|T1053.005=Scheduled Task|T1547.001=Registry Run Keys / Startup Folder|T1543.002=Systemd Service|T1543.003=Windows Service|T1546.004=Unix Shell Configuration Modification|T1098.004=SSH Authorized Keys|T1574.006=Dynamic Linker Hijacking|T1197=BITS Jobs');
add('TA0004','T1053.005=Scheduled Task|T1547.001=Registry Run Keys / Startup Folder|T1543.003=Windows Service|T1543.002=Systemd Service|T1055=Process Injection|T1134=Access Token Manipulation|T1548.002=Bypass User Account Control|T1574.006=Dynamic Linker Hijacking|T1098.004=SSH Authorized Keys|T1546.004=Unix Shell Configuration Modification');
add('TA0005','T1027=Obfuscated Files or Information|T1027.002=Software Packing|T1027.003=Steganography|T1027.006=HTML Smuggling|T1027.007=Dynamic API Resolution|T1027.009=Embedded Payloads|T1027.010=Command Obfuscation|T1027.013=Encrypted/Encoded File|T1140=Deobfuscate/Decode Files or Information|T1036=Masquerading|T1036.002=Right-to-Left Override|T1036.007=Double File Extension|T1036.008=Masquerade File Type|T1218.005=Mshta|T1218.007=Msiexec|T1218.010=Regsvr32|T1218.011=Rundll32|T1197=BITS Jobs|T1221=Template Injection|T1553.001=Gatekeeper Bypass|T1553.005=Mark-of-the-Web Bypass|T1562.001=Disable or Modify Tools|T1564.003=Hidden Window|T1070.001=Clear Windows Event Logs|T1070.003=Clear Command History|T1070.004=File Deletion|T1070.006=Timestomp|T1112=Modify Registry|T1497=Virtualization/Sandbox Evasion|T1497.003=Time Based Evasion|T1622=Debugger Evasion|T1620=Reflective Code Loading|T1222.002=Linux and Mac File and Directory Permissions Modification|T1055=Process Injection|T1134=Access Token Manipulation|T1548.002=Bypass User Account Control|T1574.006=Dynamic Linker Hijacking');
add('TA0006','T1003.001=LSASS Memory|T1003.008=/etc/passwd and /etc/shadow|T1555=Credentials from Password Stores|T1555.003=Credentials from Web Browsers|T1056.001=Keylogging|T1056.003=Web Portal Capture|T1187=Forced Authentication');
add('TA0007','T1082=System Information Discovery|T1016=System Network Configuration Discovery|T1033=System Owner/User Discovery|T1057=Process Discovery|T1083=File and Directory Discovery|T1087=Account Discovery|T1518.001=Security Software Discovery|T1497=Virtualization/Sandbox Evasion|T1622=Debugger Evasion');
add('TA0009','T1005=Data from Local System|T1056.001=Keylogging|T1056.003=Web Portal Capture|T1113=Screen Capture|T1115=Clipboard Data');
add('TA0011','T1071=Application Layer Protocol|T1071.001=Web Protocols|T1105=Ingress Tool Transfer|T1102=Web Service|T1568=Dynamic Resolution|T1219=Remote Access Tools|T1090.003=Multi-hop Proxy');
add('TA0010','T1041=Exfiltration Over C2 Channel|T1567=Exfiltration Over Web Service');
add('TA0003','T1546.003=Windows Management Instrumentation Event Subscription|T1546.008=Accessibility Features|T1546.012=Image File Execution Options Injection|T1546.015=Component Object Model Hijacking|T1137=Office Application Startup|T1136.001=Local Account|T1098=Account Manipulation');
add('TA0004','T1546.003=Windows Management Instrumentation Event Subscription|T1546.008=Accessibility Features|T1546.012=Image File Execution Options Injection|T1546.015=Component Object Model Hijacking|T1098=Account Manipulation');
add('TA0005','T1127.001=MSBuild|T1218.003=CMSTP|T1218.004=InstallUtil|T1218.008=Odbcconf|T1218.009=Regsvcs/Regasm|T1202=Indirect Command Execution|T1562.004=Disable or Modify System Firewall|T1564=Hide Artifacts');
add('TA0006','T1003.002=Security Account Manager|T1003.003=NTDS|T1558.003=Kerberoasting');
add('TA0008','T1021.001=Remote Desktop Protocol');
add('TA0009','T1560.001=Archive via Utility');
add('TA0040','T1486=Data Encrypted for Impact|T1490=Inhibit System Recovery|T1496=Resource Hijacking|T1499=Endpoint Denial of Service');
return T;})();
const attName=id=>(ATT_TECH[id]||[])[0]||id;
const attUrl=id=>'https://attack.mitre.org/techniques/'+String(id).replace('.','/')+'/';
const SBX={files:[],results:[],worker:null,workerMode:null,mode:null,inline:null,busy:false,seq:0};
const SBX_MAX_FILES=20,SBX_MAX_SIZE=128*1024*1024,SBX_TIMEOUT=120000;
const SEV_RANK={crit:4,high:3,med:2,low:1,info:0};
const fmtBytes=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(2)+' MB';

/* ---- Entorno de análisis. Se prueba, en orden:
   1) 'file'   Web Worker cargado desde sandbox-worker.js (modo normal publicado en GitHub Pages u otro hosting);
   2) 'blob'   Web Worker creado en memoria con el código del motor (funciona aunque index.html se abra como
               archivo local file://, donde el navegador prohíbe cargar workers desde archivo);
   3) 'inline' el motor en la propia página (modo compatibilidad, si el navegador no admite workers).
   En los tres modos el archivo solo se lee como bytes: nunca se ejecuta ni se renderiza. */
const SBX_MODE_LABEL={file:'entorno aislado (Web Worker)',blob:'entorno aislado (Web Worker en memoria)',inline:'modo compatibilidad (en la página, sin ejecutar el archivo)'};
const sbxEnvErr=(msg)=>{const e=new Error(msg);e.env=true;return e;};
let SBX_ENGINE_P=null;
function sbxLoadEngine(){
  if(typeof window.centinelaSandboxEngine==='function')return Promise.resolve();
  if(SBX_ENGINE_P)return SBX_ENGINE_P;
  SBX_ENGINE_P=new Promise((res,rej)=>{const sc=document.createElement('script');sc.src='./sandbox-worker.js';
    sc.onload=()=>typeof window.centinelaSandboxEngine==='function'?res():rej(sbxEnvErr('sandbox-worker.js no contiene el motor esperado (versión antigua en caché)'));
    sc.onerror=()=>{SBX_ENGINE_P=null;sc.remove();rej(sbxEnvErr('No se encontró sandbox-worker.js junto a index.html'));};
    document.head.appendChild(sc);});
  return SBX_ENGINE_P;
}
function sbxKill(){if(SBX.worker){try{SBX.worker.terminate();}catch(e){}SBX.worker=null;}}
async function sbxGetWorker(mode){
  if(SBX.worker&&SBX.workerMode===mode)return SBX.worker;
  sbxKill();let w;
  if(mode==='file'){try{w=new Worker('./sandbox-worker.js');}catch(e){throw sbxEnvErr('el navegador no permite cargar el worker desde archivo');}}
  else{await sbxLoadEngine();
    const src='('+window.centinelaSandboxServe.toString()+')(self,('+window.centinelaSandboxEngine.toString()+')());';
    try{w=new Worker(URL.createObjectURL(new Blob([src],{type:'text/javascript'})));}catch(e){throw sbxEnvErr('el navegador no permite crear workers en memoria');}}
  SBX.worker=w;SBX.workerMode=mode;return w;
}
function sbxJob(w,name,buf){
  return new Promise((resolve,reject)=>{
    const id=++SBX.seq;
    const to=setTimeout(()=>{cleanup();sbxKill();const e=new Error('Tiempo máximo de análisis superado ('+SBX_TIMEOUT/1000+' s); el entorno aislado se reinició.');e.timeout=true;reject(e);},SBX_TIMEOUT);
    const onMsg=e=>{if(!e.data||e.data.id!==id)return;cleanup();if(e.data.ok)resolve(e.data.report);else{const x=new Error(e.data.error||'Error en el análisis');x.analysis=true;reject(x);}};
    const onErr=e=>{if(e&&e.preventDefault)e.preventDefault();cleanup();sbxKill();reject(sbxEnvErr((e&&e.message)||'el entorno aislado no pudo iniciarse'));};
    function cleanup(){clearTimeout(to);w.removeEventListener('message',onMsg);w.removeEventListener('error',onErr);w.removeEventListener('messageerror',onErr);}
    w.addEventListener('message',onMsg);w.addEventListener('error',onErr);w.addEventListener('messageerror',onErr);
    w.postMessage({id,name,buf,yara:sbxYaraText()},[buf]);
  });
}
async function sbxRunIn(mode,f){
  const buf=await f.arrayBuffer();
  if(mode==='inline'){await sbxLoadEngine();SBX.inline=SBX.inline||window.centinelaSandboxEngine();return SBX.inline.analyze(f.name,buf,{yara:sbxYaraText()});}
  if(typeof Worker==='undefined')throw sbxEnvErr('el navegador no admite Web Workers');
  return sbxJob(await sbxGetWorker(mode),f.name,buf);
}
/* Analiza un archivo con el mejor entorno disponible y recuerda el que funcionó */
async function sbxAnalyzeFile(f,setP){
  const all=location.protocol==='file:'?['blob','inline']:['file','blob','inline'];
  const modes=SBX.mode?all.slice(all.indexOf(SBX.mode)):all;
  let last;
  for(const m of modes){
    try{if(m==='inline'&&setP)setP('Analizando en modo compatibilidad…');const r=await sbxRunIn(m,f);SBX.mode=m;r.engineMode=m;return r;}
    catch(e){last=e;if(!e.env)throw e;}
  }
  throw new Error('No se pudo iniciar el motor de análisis: '+(last&&last.message||'error desconocido')+'. Publica sandbox-worker.js en la misma carpeta que index.html.');
}

/* ---- Enriquecimiento de CVE: CVSS y descripción (CIRCL/NVD), explotación activa (CISA KEV), probabilidad (EPSS) */
async function sbxEpss(ids){
  const out={};if(!ids.length)return out;
  try{for(let i=0;i<ids.length;i+=50){const r=await leakGet('https://api.first.org/data/v1/epss?cve='+encodeURIComponent(ids.slice(i,i+50).join(',')),15000);
    ((r.j&&r.j.data)||[]).forEach(d=>{out[String(d.cve).toUpperCase()]={epss:+d.epss,pct:+d.percentile,date:d.date};});}}catch(e){}
  return out;
}
async function sbxEnrichCves(list,setP){
  const ids=[...new Set(list.map(c=>c.id))].slice(0,40);if(!ids.length)return [];
  setP&&setP('Consultando CISA KEV y EPSS…');
  const [kev,epss]=await Promise.all([loadKEV(),sbxEpss(ids)]);
  const out=[];
  for(let i=0;i<ids.length;i++){
    setP&&setP('Enriqueciendo CVE '+(i+1)+'/'+ids.length+'…');
    const id=ids[i];const base=list.find(c=>c.id===id)||{};
    const info=base.cvss!=null||base.summary||CIRCL_LIMITED||i>=25?null:await circlCve(id);
    out.push({id,sev:base.sev||null,cvss:base.cvss!=null?base.cvss:(info?info.cvss:null),summary:base.summary||(info?info.summary:''),kev:kev.get(id)||null,epss:epss[id]||null,source:base.source||'contenido',pkg:base.pkg||null,fixed:base.fixed||null});
  }
  out.sort((a,b)=>(b.kev?1:0)-(a.kev?1:0)||((b.epss&&b.epss.epss)||0)-((a.epss&&a.epss.epss)||0)||(b.cvss||0)-(a.cvss||0));
  return out;
}
/* ---- Dependencias vulnerables (OSV.dev) */
function osvSev(v){
  const ds=(v.database_specific&&v.database_specific.severity)||'';
  const m={CRITICAL:'crit',HIGH:'high',MODERATE:'med',MEDIUM:'med',LOW:'low'}[String(ds).toUpperCase()];if(m)return m;
  const s=(v.severity||[]).find(x=>/CVSS_V3|CVSS_V4/.test(x.type));
  if(s){const sc=parseFloat((String(s.score).match(/\/?(\d+(?:\.\d+)?)$/)||[])[1]);if(sc>=0&&sc<=10)return sevFromCvss(sc);}
  return 'med';
}
async function sbxOsv(man,setP){
  const pk=man.packages.slice(0,1000);if(!pk.length)return {vulns:[],checked:0};
  setP&&setP('Consultando OSV.dev ('+pk.length+' paquetes)…');
  const r=await fetch('https://api.osv.dev/v1/querybatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:pk.map(p=>({package:{name:p.name,ecosystem:man.ecosystem},version:p.version}))})});
  if(!r.ok)throw new Error('OSV respondió '+r.status);
  const j=await r.json();const hits=[];
  (j.results||[]).forEach((res,i)=>(res.vulns||[]).forEach(v=>hits.push({pkg:pk[i],id:v.id})));
  const uniqIds=[...new Set(hits.map(h=>h.id))].slice(0,80);const det={};
  for(let i=0;i<uniqIds.length;i+=8){setP&&setP('Detalle de vulnerabilidades '+Math.min(i+8,uniqIds.length)+'/'+uniqIds.length+'…');
    await Promise.all(uniqIds.slice(i,i+8).map(async id=>{try{const x=await leakGet('https://api.osv.dev/v1/vulns/'+encodeURIComponent(id),15000);if(x.ok&&x.j)det[id]=x.j;}catch(e){}}));}
  const vulns=hits.filter(h=>det[h.id]).map(h=>{const v=det[h.id];
    let fixed='';(v.affected||[]).filter(a=>a.package&&a.package.name===h.pkg.name).forEach(a=>(a.ranges||[]).forEach(rg=>(rg.events||[]).forEach(ev=>{if(ev.fixed&&!fixed)fixed=ev.fixed;})));
    return {pkg:h.pkg.name,version:h.pkg.version,id:h.id,aliases:(v.aliases||[]).filter(a=>/^CVE-/.test(a)),summary:v.summary||(v.details||'').slice(0,300),sev:osvSev(v),fixed};});
  vulns.sort((a,b)=>SEV_RANK[b.sev]-SEV_RANK[a.sev]);
  return {vulns,checked:pk.length};
}
/* ---- Reputación del hash. CIRCL hashlookup (archivos conocidos, NSRL) admite consulta directa;
   VirusTotal, MalwareBazaar e Hybrid Analysis requieren claves y se consultan por el backend (worker-sandbox.js). */
async function sbxRep(sha256,setP){
  const rep={sources:{},malicious:false,knownGood:false,notes:[]};const b=leakBackend();
  setP&&setP('Consultando reputación del hash…');
  if(b){try{const r=await leakGet(b+'/sbx/hashlookup?hash='+sha256,12000);
    if(r.ok&&r.j&&!r.j.message){rep.sources.hashlookup={found:true,name:r.j.FileName||'',source:r.j.source||r.j.db||'NSRL',trust:r.j['hashlookup:trust']};rep.knownGood=(r.j['hashlookup:trust']||0)>=50;}
    else rep.sources.hashlookup={found:false};}catch(e){rep.sources.hashlookup={error:leakErr(e)};}}
  if(!b){rep.notes.push('Configura la URL del backend en Ajustes para consultar la reputación del hash (CIRCL hashlookup, VirusTotal, MalwareBazaar, Hybrid Analysis) y usar el sandbox dinámico. Mientras tanto, usa los enlaces de búsqueda de arriba.');return rep;}
  const [vt,mb,ha]=await Promise.all([
    leakGet(b+'/sbx/vt?hash='+sha256,25000).catch(e=>({err:leakErr(e)})),
    leakGet(b+'/sbx/mb?hash='+sha256,20000).catch(e=>({err:leakErr(e)})),
    leakGet(b+'/sbx/ha?hash='+sha256,20000).catch(e=>({err:leakErr(e)}))]);
  if(vt.err||!vt.ok&&vt.status!==404)rep.sources.vt={error:vt.err||(vt.j&&vt.j.error)||('HTTP '+vt.status)};
  else if(vt.status===404||!vt.j||!vt.j.found)rep.sources.vt={found:false};
  else{rep.sources.vt=vt.j;if((vt.j.stats&&vt.j.stats.malicious||0)>=5)rep.malicious=true;}
  if(mb.err||!mb.ok&&mb.status!==404)rep.sources.mb={error:mb.err||(mb.j&&mb.j.error)||('HTTP '+mb.status)};
  else if(mb.j&&mb.j.found){rep.sources.mb=mb.j;rep.malicious=true;}else rep.sources.mb={found:false};
  if(ha.err||!ha.ok&&ha.status!==404)rep.sources.ha={error:ha.err||(ha.j&&ha.j.error)||('HTTP '+ha.status)};
  else if(ha.j&&ha.j.found){rep.sources.ha=ha.j;if(/malicious/i.test(ha.j.verdict||''))rep.malicious=true;}else rep.sources.ha={found:false};
  return rep;
}

/* ---- Selección de archivos */
function sbxAddFiles(list){
  const skipped=[];
  for(const f of list){
    if(SBX.files.length>=SBX_MAX_FILES){skipped.push(f.name+' (límite de '+SBX_MAX_FILES+' archivos)');continue;}
    if(f.size>SBX_MAX_SIZE){skipped.push(f.name+' (supera 128 MB)');continue;}
    if(!f.size){skipped.push(f.name+' (vacío)');continue;}
    if(!SBX.files.some(x=>x.name===f.name&&x.size===f.size&&x.lastModified===f.lastModified))SBX.files.push(f);
  }
  sbxRenderList();if(skipped.length)$('#sbxList').insertAdjacentHTML('beforeend',`<span class="hint" data-s="width:100%">Omitidos: ${esc(skipped.join(' · '))}</span>`);
}
function sbxRenderList(){
  $('#sbxList').innerHTML=SBX.files.map((f,i)=>`<span class="tag">${esc(f.name)} · ${fmtBytes(f.size)} <button type="button" class="sbxrm" data-sbxrm="${i}" aria-label="Quitar ${esc(f.name)}" title="Quitar">✕</button></span>`).join('');
}
/* ---- Veredicto y recomendaciones */
function sbxVerdict(r){
  if(r.rep&&r.rep.malicious)return {t:'Malicioso (confirmado por reputación)',c:'crit',col:'var(--sev-crit)'};
  const s=r.score;
  if(s>=70)return {t:'Malicioso probable',c:'crit',col:'var(--sev-crit)'};
  if(s>=40)return {t:'Sospechoso',c:'high',col:'var(--sev-high)'};
  if(s>=15)return {t:'Riesgo bajo',c:'med',col:'var(--sev-med)'};
  return {t:'Sin indicadores relevantes',c:'ok',col:'var(--oktx)'};
}
function sbxRecs(r){
  const R=[],v=sbxVerdict(r).c,has=re=>r.findings.some(f=>re.test(f.title+' '+(f.attack||[]).join(' ')));
  if(v==='crit'||v==='high'){
    R.push('No abras ni ejecutes el archivo. Si ya se abrió, aísla el equipo de la red y avisa al equipo de respuesta a incidentes.');
    R.push('Bloquea el SHA-256 en el EDR/antivirus, la pasarela de correo y el proxy. Busca el mismo hash en otros equipos (threat hunting).');
    if(r.iocs&&(r.iocs.domains.length||r.iocs.ips.length||r.iocs.urls.length))R.push('Bloquea los IOCs de red (dominios, IP y URL listados) en firewall, DNS y proxy, y revisa en los registros si hubo conexiones hacia ellos.');
    R.push('Identifica el origen (remitente, sitio o dispositivo) y a los demás destinatarios. Retira el mensaje de los buzones si llegó por correo.');
  }
  if(has(/T1204\.002|macros?/i))R.push('Bloquea por política (GPO/Intune) las macros en archivos procedentes de Internet y la ejecución de contenido activo en documentos.');
  if(has(/T1553\.005|ISO|VHD/))R.push('Impide montar imágenes ISO/IMG/VHD procedentes de correo o descargas, o trátalas como adjuntos bloqueados.');
  if(has(/T1059\.001|PowerShell/))R.push('Activa el registro de PowerShell (Script Block Logging, Module Logging) y el modo de lenguaje restringido para usuarios estándar.');
  if(has(/T1218|LOLBin/i))R.push('Restringe con reglas ASR o WDAC los binarios del sistema abusables (mshta, regsvr32, rundll32, certutil, bitsadmin).');
  if(has(/T1003|T1555|credenciales/i))R.push('Si el archivo se ejecutó, cambia las contraseñas de los usuarios del equipo, revoca sesiones y habilita la protección de LSA/Credential Guard.');
  if(has(/T1486|T1490|rescate/i))R.push('Comprueba que existan copias de seguridad fuera de línea e inmutables. Prepara el plan de respuesta ante ransomware.');
  if(r.cveInfo&&r.cveInfo.some(c=>c.kev))R.push('Hay CVE en el catálogo CISA KEV (explotadas activamente): aplica los parches del proveedor con prioridad máxima.');
  if(r.osv&&r.osv.vulns.length)R.push('Actualiza las dependencias vulnerables a las versiones corregidas indicadas e integra el análisis de dependencias (SCA) en el CI.');
  if(r.mismatch)R.push('Configura el filtrado de adjuntos por tipo real de archivo (firma), no solo por extensión.');
  if(v==='med')R.push('Valida el origen del archivo con el remitente por un canal distinto antes de abrirlo. Si hay dudas, analízalo en un entorno aislado.');
  if(v==='ok')R.push('No se encontraron indicadores relevantes con análisis estático. Aun así, confirma el origen y la reputación antes de ejecutar software desconocido.');
  return [...new Set(R)];
}
/* ---- Reglas YARA propias (configuración del usuario, se conserva como el resto de ajustes) */
const sbxYaraText=()=>{const t=$('#sbxYara');return t?t.value:'';};
async function sbxYaraValidate(){
  const msg=$('#sbxYaraMsg');const src=sbxYaraText();
  if(!src.trim()){msg.textContent='';return;}
  try{await sbxLoadEngine();SBX.yaraEng=SBX.yaraEng||window.centinelaSandboxEngine();
    const c=SBX.yaraEng.yaraCompile(src);
    msg.innerHTML=(c.rules.length?`<span data-s="color:var(--oktx)">${c.rules.length} regla(s) válida(s): ${esc(c.rules.map(r=>r.name).join(', '))}</span>`:'')+(c.errors.length?`<br><span data-s="color:var(--wartx)">${esc(c.errors.join(' · '))}</span>`:'');
  }catch(e){msg.textContent='No se pudieron validar las reglas: '+e.message;}
}
(function(){
  const t=$('#sbxYara');if(!t)return;
  try{t.value=localStorage.getItem('ctn-yara')||'';}catch(e){}
  if(t.value.trim())$('#sbxYaraBox').open=true;
  let tm=null;t.addEventListener('input',()=>{clearTimeout(tm);tm=setTimeout(()=>{try{localStorage.setItem('ctn-yara',t.value.slice(0,65536));}catch(e){}sbxYaraValidate();},500);});
  $('#sbxYaraCheck').addEventListener('click',sbxYaraValidate);
  // Reglas base incluidas en el proyecto (yara/centinela-base.yar): se añaden a las del usuario
  $('#sbxYaraBase').addEventListener('click',async()=>{
    try{const r=await fetch('./yara/centinela-base.yar',{cache:'no-cache'});if(!r.ok)throw new Error('HTTP '+r.status);const txt=await r.text();
      if(/Centinela_PE_empaquetado_UPX/.test(t.value)){$('#sbxYaraMsg').textContent='Las reglas base ya están cargadas.';return;}
      t.value=(t.value.trim()?t.value.trim()+String.fromCharCode(10,10):'')+txt;try{localStorage.setItem('ctn-yara',t.value.slice(0,65536));}catch(e){}sbxYaraValidate();}
    catch(e){$('#sbxYaraMsg').textContent='No se pudieron cargar las reglas base ('+e.message+'). Si abriste index.html como archivo local, cárgalas con "Cargar archivo .yar" desde la carpeta yara/.';}
  });
  $('#sbxYaraClear').addEventListener('click',()=>{t.value='';try{localStorage.removeItem('ctn-yara');}catch(e){}$('#sbxYaraMsg').textContent='';});
  const fi=$('#sbxYaraFile');
  fi.addEventListener('change',async()=>{const f=fi.files[0];fi.value='';if(!f)return;if(f.size>65536){$('#sbxYaraMsg').textContent='El archivo de reglas supera 64 KB.';return;}
    const txt=await f.text();t.value=(t.value.trim()?t.value.trim()+'\n\n':'')+txt;try{localStorage.setItem('ctn-yara',t.value.slice(0,65536));}catch(e){}sbxYaraValidate();});
  document.querySelector('label[for="sbxYaraFile"]').addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();fi.click();}});
})();
/* ---- Enriquecimiento común (archivos y enlaces) */
async function sbxEnrich(r,opt,setP){
  r.analyzedAt=new Date();r.errors=r.errors||[];
  if(opt.rep){try{r.rep=await sbxRep(r.hashes.sha256,setP);}catch(e){r.errors.push('Reputación: '+leakErr(e));}}
  if(opt.osv&&r.manifest&&r.manifest.packages.length){try{r.osv=await sbxOsv(r.manifest,setP);}catch(e){r.errors.push('OSV: '+leakErr(e));}}
  if(opt.cve){
    const list=(r.cvesFromContent||[]).map(id=>({id,source:r.findings.some(f=>(f.cve||[]).includes(id))?'patrón de explotación':'mencionado en el contenido'}));
    if(r.osv)r.osv.vulns.forEach(v=>v.aliases.forEach(id=>list.push({id,source:'dependencia '+v.pkg+'@'+v.version,pkg:v.pkg,fixed:v.fixed,sev:v.sev,summary:v.summary})));
    try{r.cveInfo=await sbxEnrichCves(list,setP);}catch(e){r.errors.push('CVE: '+leakErr(e));}
  }
  if(r.urlInfo&&r.urlInfo.urlhaus&&r.urlInfo.urlhaus.found){r.rep=r.rep||{sources:{},notes:[]};r.rep.malicious=true;}
  r.verdict=sbxVerdict(r);r.recs=sbxRecs(r);
}
/* Recalcula puntuación y contadores tras añadir hallazgos (misma fórmula que el motor) */
function sbxRescore(r){
  const W={crit:35,high:20,med:8,low:3,info:0};const sum=r.findings.reduce((a,f)=>a+(W[f.sev]||0),0);
  r.score=Math.min(100,Math.round(100*(1-Math.exp(-sum/55))));
  r.counts={crit:0,high:0,med:0,low:0,info:0};r.findings.forEach(f=>r.counts[f.sev]++);
}
/* Quita la "desactivación" típica de IOCs compartidos: hxxp://, [.], (.), [:] */
const refang=s=>String(s).trim().replace(/^hxxp/i,'http').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.').replace(/\[:\]/g,':').replace(/\[\/\]/g,'/');
function sbxTab(t){
  ['file','url'].forEach(x=>{const b=$('#sbxTab'+(x==='file'?'File':'Url'));b.classList.toggle('active',x===t);b.setAttribute('aria-selected',x===t);});
  $('#sbxFilePane').hidden=t!=='file';$('#sbxFileBtns').style.display=t==='file'?'':'none';$('#sbxUrlPane').hidden=t!=='url';
}
/* ---- Análisis de un enlace sin visitarlo */
async function runSbxUrl(){
  if(SBX.busy)return;
  let raw=refang($('#sbxUrl').value);if(raw&&!/^https?:\/\//i.test(raw))raw='http://'+raw;
  let u;try{u=new URL(raw);}catch(e){alert('Ingresa un enlace válido, por ejemplo https://sitio.xyz/pagina');return;}
  const b=leakBackend();
  if(!b){$('#sbxOut').innerHTML=`<div class="glass phishcard"><b>El análisis de enlaces necesita el backend</b><p class="hint">Por seguridad, la página nunca se abre desde tu navegador: la descarga el backend (Cloudflare Worker) de forma aislada. Configúralo en Ajustes → URL del backend. Mientras tanto puedes hacer el análisis estático del enlace (dominio, edad, listas negras, parecido con marcas) en el módulo Phishing.</p><button class="btn ghost" id="sbxToPhish">${ico('hook')}Analizar en Phishing</button></div>`;
    $('#sbxToPhish').addEventListener('click',()=>{setMode('phish');$('#phishUrl').value=u.href;analyzePhish();});return;}
  SBX.busy=true;CIRCL_LIMITED=false;$('#goSbxUrl').disabled=true;$('#sbxOut').innerHTML='';SBX.results=[];
  const st=$('#sbxStatus');st.style.display='flex';$('#sbxBarwrap').style.display='block';
  const setP=t=>{$('#sbxStatusTxt').textContent=u.hostname+' — '+t;};
  const opt={cve:$('#sbxOptCve').checked,osv:false,rep:$('#sbxOptRep').checked};
  try{
    setP('Descargando el contenido de forma aislada (backend)…');$('#sbxBar').style.width='15%';
    const [res,uh]=await Promise.all([leakGet(b+'/sbx/url?u='+encodeURIComponent(u.href),40000),leakGet(b+'/sbx/urlhaus?q='+encodeURIComponent(u.href),20000).catch(()=>null)]);
    const J=res.j||{};
    if(!res.ok||!J.body&&J.body!==''){$('#sbxOut').innerHTML=`<div class="glass phishcard"><b>No se pudo descargar el enlace</b><p class="hint">${esc(J.error||('HTTP '+res.status))}</p>${J.chain&&J.chain.length?sbxChainHtml(J.chain):''}</div>`;return;}
    const bytes=Uint8Array.from(atob(J.body),c=>c.charCodeAt(0));
    const fin=new URL(J.final);
    const dispName=(J.disposition.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i)||[])[1];
    const isHtml=/html|xml/i.test(J.type)||(!dispName&&/<html|<!doctype/i.test(new TextDecoder().decode(bytes.subarray(0,2000))));
    const name=dispName?decodeURIComponent(dispName):isHtml?(fin.hostname+'.html'):(fin.pathname.split('/').pop()||fin.hostname+'.bin');
    setP('Analizando el contenido en el entorno aislado…');$('#sbxBar').style.width='45%';
    const file=new File([bytes],name,{type:J.type||''});
    const r=await sbxAnalyzeFile(file,setP);
    const regOf=h=>registrable(h);
    r.urlInfo={input:u.href,final:J.final,chain:J.chain||[],type:J.type,size:J.size,truncated:J.truncated,headers:J.headers||{},download:!!dispName||!isHtml,urlhaus:uh&&uh.ok?uh.j:(uh&&uh.status===404?{found:false}:(uh&&uh.j&&uh.j.error?{error:uh.j.error}:null))};
    // Hallazgos propios de un enlace
    const add=(sev,title,detail,attack,evidence)=>r.findings.push({sev,cat:'Enlace (URL)',title,detail,evidence:evidence||'',attack:attack||[],cve:[]});
    const hops=(J.chain||[]).length-1;
    if(hops>=1){const doms=[...new Set((J.chain||[]).map(c=>{try{return regOf(new URL(c.url).hostname);}catch(e){return '';}}).filter(Boolean))];
      add(doms.length>1?'med':'info',hops+' redirección(es)'+(doms.length>1?' a través de '+doms.length+' dominios distintos':''),doms.length>1?'Las cadenas de redirección entre dominios se usan para ocultar el destino real a filtros de correo y proxy.':'Redirección dentro del mismo dominio.',doms.length>1?['T1204.001']:[],doms.join(' → '));}
    if(r.urlInfo.download&&!isHtml)add(/exec|script|container|office_macro/.test(r.type.family)?'high':'low','El enlace descarga un archivo directamente: '+name,'Los enlaces que entregan archivos (sin página intermedia) son un vector habitual de malware.',['T1204.002','T1105'],J.type);
    if(fin.protocol==='http:')add('low','La página final no usa HTTPS','Cualquier dato enviado viaja sin cifrar.',[]);
    if(/(^|\.)xn--/.test(fin.hostname))add('high','Dominio con punycode/IDN (posible homógrafo)','Letras de otros alfabetos que imitan una marca.',['T1036'],fin.hostname);
    if(r.urlInfo.urlhaus&&r.urlInfo.urlhaus.found)add('crit','Enlace catalogado en URLhaus (abuse.ch)','URLhaus lo registra como distribuidor de malware'+(r.urlInfo.urlhaus.threat?' ('+r.urlInfo.urlhaus.threat+')':'')+'.',['T1105','T1204.001'],(r.urlInfo.urlhaus.tags||[]).join(', '));
    if(r.findings.some(f=>f.sev==='crit'||f.sev==='high'))r.findings.forEach(f=>{if(f.rule==='cred-form'||f.rule==='post-exfil')f.attack=[...new Set([...(f.attack||[]),'T1566.002'])];});
    sbxRescore(r);
    r.name=J.final;
    $('#sbxBar').style.width='70%';
    await sbxEnrich(r,opt,setP);
    SBX.results.push({file,r});
    $('#sbxBar').style.width='100%';
    renderSbx();
  }catch(e){$('#sbxOut').innerHTML=`<div class="glass phishcard"><b>Error</b><p class="hint">${esc(leakErr(e))}</p></div>`;}
  finally{SBX.busy=false;$('#goSbxUrl').disabled=false;st.style.display='none';$('#sbxBarwrap').style.display='none';}
}
function sbxChainHtml(chain){
  return `<div class="subh">Cadena de redirecciones</div><div class="sbxscroll"><table class="sbxtbl"><tr><th>#</th><th>Estado</th><th>URL</th><th>Servidor</th></tr>${chain.map((c,i)=>`<tr><td>${i+1}</td><td>${tag(String(c.status),c.status>=400?'r':c.status>=300?'y':'g')}</td><td class="m">${esc(c.url)}</td><td>${esc(c.server||'')}</td></tr>`).join('')}</table></div>`;
}
/* ---- Orquestación */
async function runSbx(){
  if(SBX.busy)return;
  if(!SBX.files.length){alert('Añade al menos un archivo para analizar');return;}
  SBX.busy=true;CIRCL_LIMITED=false;$('#goSbx').disabled=true;$('#sbxOut').innerHTML='';SBX.results=[];
  const st=$('#sbxStatus');st.style.display='flex';$('#sbxBarwrap').style.display='block';
  const opt={cve:$('#sbxOptCve').checked,osv:$('#sbxOptOsv').checked,rep:$('#sbxOptRep').checked};
  const N=SBX.files.length;
  try{
    for(let i=0;i<N;i++){
      const f=SBX.files[i];
      const setP=t=>{$('#sbxStatusTxt').textContent='['+(i+1)+'/'+N+'] '+f.name+' — '+t;};
      $('#sbxBar').style.width=Math.round(i/N*100)+'%';
      let r;
      try{
        setP('Analizando en el entorno aislado…');
        r=await sbxAnalyzeFile(f,setP);
        await sbxEnrich(r,opt,setP);
        SBX.results.push({file:f,r});
      }catch(e){SBX.results.push({file:f,error:e.message||String(e)});}
    }
    $('#sbxBar').style.width='100%';
    renderSbx();
  }finally{SBX.busy=false;$('#goSbx').disabled=false;st.style.display='none';$('#sbxBarwrap').style.display='none';}
}

/* ---- Render */
function sbxTechSev(r){const m={};r.findings.forEach(f=>(f.attack||[]).forEach(t=>{if(!(t in m)||SEV_RANK[f.sev]>SEV_RANK[m[t]])m[t]=f.sev;}));
  if(r.rep&&r.rep.sources.vt&&r.rep.sources.vt.mitre)r.rep.sources.vt.mitre.forEach(t=>{if(!(t in m))m[t]='high';});return m;}
function sbxMatrix(r){
  const m=sbxTechSev(r);const ids=Object.keys(m);if(!ids.length)return '<p class="hint">No se asociaron técnicas ATT&amp;CK.</p>';
  const cols=ATT_TACTICS.map(([ta,tn])=>{const ts=ids.filter(id=>(ATT_TECH[id]||[,[]])[1].includes(ta)).sort((a,b)=>SEV_RANK[m[b]]-SEV_RANK[m[a]]);
    return ts.length?`<div class="col"><h5>${esc(tn)}<span>${ta}</span></h5>${ts.map(id=>`<a class="sbxt ${m[id]}" target="_blank" rel="noopener noreferrer" href="${esc(attUrl(id))}" title="${esc(attName(id))}"><b>${esc(id)}</b>${esc(attName(id))}</a>`).join('')}</div>`:'';}).join('');
  const other=ids.filter(id=>!ATT_TECH[id]);
  return `<div class="sbxmx">${cols}${other.length?`<div class="col"><h5>Otras (sandbox dinámico)<span>—</span></h5>${other.map(id=>`<a class="sbxt ${m[id]}" target="_blank" rel="noopener noreferrer" href="${esc(attUrl(id))}"><b>${esc(id)}</b></a>`).join('')}</div>`:''}</div>
  <p class="hint" data-s="margin-top:6px">El color indica la severidad máxima del indicador asociado. Las capacidades informativas (p.ej. API comunes) aparecen sin color.</p>`;
}
function sbxEntropySvg(r){
  const B=r.entropyBlocks||[];if(!B.length)return '';const W=B.length*4,H=80,y=e=>H-(e/8)*H;
  return `<svg class="sbxent" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Entropía por bloques">
    <rect x="0" y="0" width="${W}" height="${H}" fill="var(--bg2)"/>
    ${B.map((b,i)=>`<rect x="${i*4}" y="${y(b.e).toFixed(1)}" width="3.2" height="${(H-y(b.e)).toFixed(1)}" fill="${b.e>=7.2?'var(--fail)':b.e>=6?'var(--warn)':'var(--accent)'}"><title>${fmtBytes(b.off)}: ${b.e}</title></rect>`).join('')}
    <line x1="0" x2="${W}" y1="${y(7.2)}" y2="${y(7.2)}" stroke="var(--fail)" stroke-dasharray="4 3" stroke-width="0.8"/></svg>
    <div class="hint">Entropía por bloques (0–8). Por encima de la línea (7,2) el contenido está comprimido o cifrado. Global: <b>${r.entropy}</b></div>`;
}
function sbxRepHtml(r){
  if(!r.rep)return '';const S=r.rep.sources,rows=[];
  const st=(o,fn)=>!o?'<span class="hint">no consultado</span>':o.error?`<span class="hint">error: ${esc(o.error)}</span>`:o.found===false?'<span class="tag">sin registros</span>':fn(o);
  rows.push(['CIRCL hashlookup (NSRL)',st(S.hashlookup,o=>tag('archivo conocido'+(o.name?': '+o.name:'')+(o.trust!=null?' · confianza '+o.trust:''),'g'))]);
  if('vt' in S)rows.push(['VirusTotal',st(S.vt,o=>`${tag((o.stats?o.stats.malicious:0)+' / '+(o.stats?Object.values(o.stats).reduce((a,b)=>a+b,0):0)+' motores lo detectan',(o.stats&&o.stats.malicious)>=5?'r':(o.stats&&o.stats.malicious)?'y':'g')}${o.label?' '+tag(o.label,'r'):''}${o.type?' '+tag(o.type):''}${o.first?` <span class="hint">visto por primera vez ${esc(o.first)}</span>`:''}${o.sandbox&&o.sandbox.length?`<div class="hint">Sandboxes: ${esc(o.sandbox.join(' · '))}</div>`:''}`)]);
  if('mb' in S)rows.push(['MalwareBazaar',st(S.mb,o=>`${tag('muestra de malware conocida','r')} ${o.signature?tag(o.signature,'r'):''} ${(o.tags||[]).slice(0,8).map(t=>tag(t)).join('')}${o.first?` <span class="hint">${esc(o.first)}</span>`:''}`)]);
  if('ha' in S)rows.push(['Hybrid Analysis',st(S.ha,o=>`${tag(o.verdict||'sin veredicto',/malicious/i.test(o.verdict||'')?'r':/suspicious/i.test(o.verdict||'')?'y':'g')} ${o.family?tag(o.family,'r'):''}${o.score!=null?' '+tag('puntaje '+o.score):''}`)]);
  return `<div class="subh">Reputación del hash</div><table class="kv">${rows.map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')}</table>${r.rep.notes.map(n=>`<p class="hint">${esc(n)}</p>`).join('')}`;
}
function sbxStructHtml(r){
  let h='';
  if(r.pe){const p=r.pe;
    h+=`<table class="kv"><tr><td>Arquitectura</td><td>${esc(p.arch)} · ${p.isDll?'DLL':'EXE'} · ${esc(p.subsystem)}${p.dotnet?' · '+tag('.NET','y'):''}</td></tr>
    <tr><td>Compilado</td><td>${esc(p.compiled||'—')}</td></tr><tr><td>Punto de entrada</td><td class="m">${esc(p.entryPoint)} (${esc(p.entrySection)})</td></tr>
    <tr><td>Firma Authenticode</td><td>${p.signed?tag('presente','g'):tag('ausente','y')}</td></tr>
    <tr><td>Mitigaciones</td><td>${[['ASLR',p.aslr],['DEP/NX',p.dep],['CFG',p.cfg]].map(([n,o])=>tag(n+(o?' ✓':' ✕'),o?'g':'y')).join('')}</td></tr>
    <tr><td>Importaciones</td><td>${p.importCount} funciones de ${p.imports.length} DLL${p.imphash?` · imphash <span class="m">${esc(p.imphash)}</span>`:''}</td></tr>
    ${p.overlay?`<tr><td>Overlay</td><td>${fmtBytes(p.overlay)}</td></tr>`:''}${p.pdb?`<tr><td>Ruta PDB</td><td class="m">${esc(p.pdb)}</td></tr>`:''}</table>
    <div class="sbxscroll"><table class="sbxtbl"><tr><th>Sección</th><th>Dir. virtual</th><th>Tam. virtual</th><th>Tam. en disco</th><th>Permisos</th><th>Entropía</th></tr>
    ${p.sections.map(s=>`<tr><td class="m">${esc(s.name)}</td><td class="m">${esc(s.va)}</td><td>${fmtBytes(s.vsize)}</td><td>${fmtBytes(s.rsize)}</td><td class="m">${esc(s.flags)}</td><td data-s="color:${s.entropy>=7.2?'var(--failtx)':s.entropy>=6.5?'var(--wartx)':'inherit'}">${s.entropy}</td></tr>`).join('')}</table></div>
    <details><summary>Importaciones por DLL (${p.imports.length})</summary><div class="raw sbxcode" tabindex="0">${esc(p.imports.map(i=>i.dll+' ('+i.count+'): '+i.funcs.join(', ')).join('\n\n'))}</div></details>`;}
  if(r.elf)h+=`<table class="kv">${Object.entries({Arquitectura:r.elf.machine+' · '+r.elf.bits+' bits · '+r.elf.endian,Tipo:r.elf.type,'ABI':r.elf.osabi,'Intérprete':r.elf.interp||'—','Símbolos':r.elf.stripped?'eliminados (stripped)':'presentes','Go':r.elf.golang?'sí':'no'}).map(([k,v])=>`<tr><td>${k}</td><td>${esc(v)}</td></tr>`).join('')}</table>`;
  if(r.macho)h+=`<table class="kv">${Object.entries(r.macho).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>`;
  if(r.pdf){const c=r.pdf.counts;h+=`<p class="hint">PDF ${esc(r.pdf.version)} · ${r.pdf.streams} streams (${r.pdf.inflated} descomprimidos)</p><div class="sbxlist">${Object.entries(c).filter(([k,v])=>v&&k.startsWith('/')).map(([k,v])=>tag(k+' '+v,/JS|JavaScript|Launch|OpenAction|AA|EmbeddedFile|XFA|RichMedia|SubmitForm/.test(k)?'y':'')).join('')}</div>
    ${r.pdf.javascript.length?`<details><summary>JavaScript extraído (${r.pdf.javascript.length})</summary><div class="raw sbxcode" tabindex="0">${esc(r.pdf.javascript.join('\n\n────────\n\n'))}</div></details>`:''}`;}
  const z=r.zip;if(z){h+=`<p class="hint">${esc(z.kindLabel)} · ${z.totalEntries} entradas</p>
    <details><summary>Contenido (${z.totalEntries})</summary><div class="sbxscroll"><table class="sbxtbl"><tr><th>Nombre</th><th>Tamaño</th><th>Cifrado</th></tr>${z.entries.map(e=>`<tr><td class="m">${esc(e.name)}</td><td>${fmtBytes(e.size)}</td><td>${e.encrypted?tag('sí','y'):''}</td></tr>`).join('')}</table></div></details>
    ${z.external&&z.external.length?`<div class="subh">Relaciones externas</div><div class="raw">${esc(z.external.map(x=>x.type+' → '+x.target).join('\n'))}</div>`:''}
    ${z.permissions&&z.permissions.length?`<div class="subh">Permisos Android</div><div class="sbxlist">${z.permissions.map(p=>tag(p.replace('android.permission.',''),/SMS|CALL|ACCESSIBILITY|CONTACTS|RECORD|SYSTEM_ALERT|INSTALL|ADMIN/.test(p)?'y':'')).join('')}</div>`:''}
    ${z.inner&&z.inner.length?`<div class="subh">Ejecutables internos</div><div class="raw">${esc(z.inner.map(x=>x.name+'  '+x.sha256).join('\n'))}</div>`:''}`;}
  const macros=(r.zip&&r.zip.macros)||(r.ole&&r.ole.macros)||[];
  if(r.ole)h+=`<p class="hint">${esc(r.ole.kindLabel)}${r.ole.streams.length?' · flujos: '+esc(r.ole.streams.slice(0,20).join(', ')):''}</p>`;
  if(macros.length)h+=`<details open><summary>Código de macros VBA extraído (${macros.length} módulo/s)</summary>${macros.map(m=>`<div class="hint" data-s="margin-top:6px"><b>${esc(m.name)}</b> · ${m.lines} líneas</div><div class="raw sbxcode" tabindex="0">${esc(m.code)}</div>`).join('')}</details>`;
  if(r.rtf)h+=`<p class="hint">RTF · ${r.rtf.objects} objetos · ${r.rtf.objdata} con datos${r.rtf.classes.length?' · clases: '+esc(r.rtf.classes.join(', ')):''}</p>`;
  if(r.lnk)h+=`<table class="kv">${[['Destino',r.lnk.target||r.lnk.relativePath],['Argumentos',r.lnk.arguments],['Directorio de trabajo',r.lnk.workingDir],['Icono',r.lnk.icon],['Descripción',r.lnk.name]].filter(x=>x[1]).map(([k,v])=>`<tr><td>${k}</td><td class="m">${esc(v)}</td></tr>`).join('')}</table>`;
  if(r.iso&&r.iso.files.length)h+=`<details><summary>Archivos en la imagen (${r.iso.files.length})</summary><div class="raw sbxcode" tabindex="0">${esc(r.iso.files.join('\n'))}</div></details>`;
  if(r.onenote&&r.onenote.embedded.length)h+=`<div class="raw">${esc(r.onenote.embedded.join('\n'))}</div>`;
  if(r.script)h+=`<table class="kv"><tr><td>Líneas</td><td>${r.script.lines}</td></tr><tr><td>Línea más larga</td><td>${r.script.longestLine}</td></tr><tr><td>Bloques Base64 grandes</td><td>${r.script.base64Blobs}</td></tr><tr><td>Proporción de símbolos</td><td>${r.script.symbolRatio}</td></tr></table>`;
  if(r.eml&&r.eml.attachments.length)h+=`<p class="hint">Adjuntos declarados: ${esc(r.eml.attachments.join(', '))}</p>`;
  return h?`<div class="subh">Estructura del archivo</div>${h}`:'';
}
function sbxIocHtml(r){
  const I=r.iocs||{};const groups=[['URLs',I.urls],['Dominios',I.domains],['Direcciones IP',I.ips],['Correos',I.emails],['Claves de registro',I.registry],['Rutas de archivo',I.paths],['Criptomonedas',I.crypto]].filter(g=>g[1]&&g[1].length);
  if(!groups.length)return '<div class="subh">Indicadores de compromiso (IOCs)</div><p class="hint">No se extrajeron IOCs de red o sistema.'+(I.domainsBenign?' Se omitieron '+I.domainsBenign+' dominios de infraestructura legítima (Microsoft, CAs, W3C…).':'')+'</p>';
  return `<div class="subh">Indicadores de compromiso (IOCs)</div>${groups.map(([n,a])=>`<details ${a.length<=12?'open':''}><summary>${n} (${a.length})</summary>${raw(a.join('\n'))}</details>`).join('')}
  ${I.ipsPrivate&&I.ipsPrivate.length?`<p class="hint">IP privadas (red interna): ${esc(I.ipsPrivate.join(', '))}</p>`:''}${I.domainsBenign?`<p class="hint">Se omitieron ${I.domainsBenign} dominios de infraestructura legítima.</p>`:''}`;
}
function sbxCveHtml(r){
  const C=r.cveInfo||[];if(!C.length)return '';
  return `<div class="subh">Vulnerabilidades (CVE) relacionadas</div><div class="sbxscroll"><table class="sbxtbl"><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>CISA KEV</th><th>Origen</th><th>Descripción</th></tr>
  ${C.map(c=>`<tr><td class="m"><a class="sbxchip cve" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}">${esc(c.id)}</a></td>
  <td>${c.cvss!=null?vSevChip(sevFromCvss(c.cvss)||'info')+' '+esc(c.cvss):c.sev?vSevChip(c.sev)+'<div class="hint">según OSV</div>':'n/d'}</td>
  <td>${c.epss?`<b>${(c.epss.epss*100).toFixed(2)}%</b><div class="hint">percentil ${(c.epss.pct*100).toFixed(0)}</div>`:'n/d'}</td>
  <td>${c.kev?tag('EXPLOTADA'+(c.kev.ransom?' · ransomware':''),'r')+(c.kev.due?`<div class="hint">límite ${esc(c.kev.due)}</div>`:''):'—'}</td>
  <td>${esc(c.source)}${c.fixed?`<div class="hint">corregido en ${esc(c.fixed)}</div>`:''}</td><td>${esc((c.summary||'').slice(0,400))}</td></tr>`).join('')}</table></div>
  <p class="hint">EPSS (FIRST) es la probabilidad estimada de explotación en los próximos 30 días. CISA KEV lista las vulnerabilidades con explotación activa confirmada.</p>`;
}
function sbxOsvHtml(r){
  if(!r.manifest)return '';const o=r.osv;
  const head=`<div class="subh">Dependencias (${esc(r.manifest.ecosystem)} · ${r.manifest.packages.length} paquetes${r.manifest.approx?' · versiones aproximadas por rangos':''})</div>`;
  if(!o)return head+'<p class="hint">No se consultó OSV.dev.</p>';
  if(!o.vulns.length)return head+`<p class="hint">OSV.dev no reporta vulnerabilidades para los ${o.checked} paquetes consultados.</p>`;
  return head+`<div class="sbxscroll"><table class="sbxtbl"><tr><th>Paquete</th><th>Severidad</th><th>Aviso</th><th>Corregido en</th><th>Resumen</th></tr>
  ${o.vulns.map(v=>`<tr><td class="m">${esc(v.pkg)}@${esc(v.version)}</td><td>${vSevChip(v.sev)}</td><td><a class="sbxchip" target="_blank" rel="noopener noreferrer" href="https://osv.dev/vulnerability/${esc(v.id)}">${esc(v.id)}</a>${v.aliases.map(a=>`<a class="sbxchip cve" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${esc(a)}">${esc(a)}</a>`).join('')}</td><td class="m">${esc(v.fixed||'—')}</td><td>${esc(v.summary)}</td></tr>`).join('')}</table></div>`;
}
function sbxFindingsHtml(r){
  const order=['Reglas YARA','Enlace (URL)','Nombre y tipo de archivo','Comportamiento e indicadores','Macros y contenido activo','Contenido activo del PDF','Acceso directo (LNK)','Contenido del contenedor','Correo electrónico','Ofuscación','Estructura del ejecutable','Capacidades (API importadas)','Estructura del archivo'];
  const F=r.findings;const cats=[...new Set(F.map(f=>f.cat))].sort((a,b)=>{const ia=order.indexOf(a),ib=order.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);});
  return cats.map(cat=>{const items=F.filter(f=>f.cat===cat).sort((a,b)=>SEV_RANK[b.sev]-SEV_RANK[a.sev]);
    const body=items.map(f=>`<div class="vfind ${VULN_SEV[f.sev].cls}"><h4>${vSevChip(f.sev)} ${esc(f.title)}</h4><div class="vmeta">${esc(f.detail)}</div>
      ${f.evidence?`<div class="vmeta">Evidencia: <span data-s="font-family:var(--mono);color:var(--txt);word-break:break-all">${esc(f.evidence)}</span></div>`:''}
      ${(f.attack||[]).length||(f.cve||[]).length?`<div>${(f.attack||[]).map(t=>`<a class="sbxchip" target="_blank" rel="noopener noreferrer" href="${esc(attUrl(t))}" title="${esc(attName(t))}">${esc(t)} · ${esc(attName(t))}</a>`).join('')}${(f.cve||[]).map(c=>`<a class="sbxchip cve" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${esc(c)}">${esc(c)}</a>`).join('')}</div>`:''}</div>`).join('');
    const onlyInfo=items.every(f=>f.sev==='info');
    return `<details ${onlyInfo?'':'open'}><summary>${esc(cat)} (${items.length})</summary>${body}</details>`;}).join('');
}
function sbxCard(r,idx){
  const v=r.verdict,H=r.hashes,sha=H.sha256;
  const piv=[['VirusTotal','https://www.virustotal.com/gui/file/'+sha],['MalwareBazaar','https://bazaar.abuse.ch/sample/'+sha+'/'],['Hybrid Analysis','https://www.hybrid-analysis.com/sample/'+sha],['Triage','https://tria.ge/s?q=sha256:'+sha],['AlienVault OTX','https://otx.alienvault.com/indicator/file/'+sha],['Joe Sandbox','https://www.joesandbox.com/search?q='+sha]];
  const TS=sbxTechSev(r),nAtt=Object.keys(TS).length,nAttSig=Object.values(TS).filter(x=>x!=='info').length,nCve=(r.cveInfo||[]).length||(r.cvesFromContent||[]).length,I=r.iocs||{},nIoc=['urls','domains','ips','emails','registry','crypto'].reduce((a,k)=>a+((I[k]||[]).length),0);
  const vtOk=!!leakBackend();
  return `<div class="glass phishcard sbxcard" id="sbxCard${idx}">
    <div class="vgrade"><div class="vgbadge" data-s="color:${v.col};font-size:30px">${r.score}</div>
      <div data-s="flex:1 1 240px"><div class="phverdict" data-s="margin:0;color:${v.col}">${esc(v.t)}</div>
      <div class="phurl" data-s="margin-bottom:0">${esc(r.name)} · ${fmtBytes(r.size)} · ${esc(r.type.label)}${r.mismatch?' · '+tag('extensión engañosa','r'):''}</div></div></div>
    <div class="kpis" data-s="margin-top:14px;margin-bottom:0">
      <div class="kpi ${r.counts.crit?'fail':'neut'}"><b>${r.counts.crit}</b><span>Críticos</span></div>
      <div class="kpi ${r.counts.high?'fail':'neut'}"><b>${r.counts.high}</b><span>Altos</span></div>
      <div class="kpi ${r.counts.med?'warn':'neut'}"><b>${r.counts.med}</b><span>Medios</span></div>
      <div class="kpi neut"><b>${r.counts.low}</b><span>Bajos</span></div>
      <div class="kpi ${nAttSig?'warn':'neut'}"><b>${nAtt}</b><span>técnicas ATT&amp;CK${nAtt&&!nAttSig?' (informativas)':''}</span></div>
      <div class="kpi ${nCve?'fail':'neut'}"><b>${nCve}</b><span>CVE</span></div>
      <div class="kpi neut"><b>${nIoc}</b><span>IOCs</span></div></div>
    ${r.rep&&r.rep.malicious?`<div class="vmeta" data-s="margin-top:10px;color:var(--failtx)"><b>${ico('alert')} Hash reportado como malicioso por fuentes de reputación.</b></div>`:''}
    ${r.rep&&r.rep.knownGood&&!r.rep.malicious?`<div class="vmeta" data-s="margin-top:10px;color:var(--oktx)"><b>${ico('check-circle')} Archivo conocido en bases de software legítimo (NSRL/CIRCL).</b> Aun así revisa los hallazgos.</div>`:''}
    <div class="rtoolbar">
      <button class="btn" data-sbxexp="txt" data-i="${idx}">${ico('download')}Informe (.txt)</button>
      <button class="btn ghost" data-sbxexp="json" data-i="${idx}">${ico('download')}Datos (.json)</button>
      <button class="btn ghost" data-sbxexp="ioc" data-i="${idx}">${ico('download')}IOCs (.csv)</button>
      <button class="btn ghost" data-sbxexp="nav" data-i="${idx}">${ico('layers')}Capa ATT&amp;CK Navigator</button>
      <button class="btn ghost" data-sbxexp="stix" data-i="${idx}">${ico('download')}STIX 2.1</button>
      <button class="btn ghost" data-sbxexp="print" data-i="${idx}">${ico('printer')}Imprimir / PDF</button>
      <button class="btn ghost" data-caseadd="sbx" data-i="${idx}">${ico('note')}Añadir a un caso</button>
      <button class="btn ghost" data-sbxdyn="${idx}" ${vtOk?'':'aria-disabled="true" data-s="opacity:.55" title="Requiere configurar la URL del backend en Ajustes"'}>${ico('bug')}Sandbox dinámico (VirusTotal)</button>
    </div>
    <div id="sbxDyn${idx}"></div>
    ${r.errors&&r.errors.length?`<p class="hint" data-s="color:var(--wartx)">Consultas con error: ${esc(r.errors.join(' · '))}</p>`:''}
    ${r.urlInfo?`<div class="subh">Enlace analizado</div><table class="kv"><tr><td>Enlace original</td><td class="m">${esc(r.urlInfo.input)}</td></tr><tr><td>Destino final</td><td class="m">${esc(r.urlInfo.final)}</td></tr><tr><td>Contenido</td><td>${esc(r.urlInfo.type||'—')} · ${fmtBytes(r.urlInfo.size||0)}${r.urlInfo.truncated?' (truncado a 5 MB)':''}</td></tr>
      <tr><td>URLhaus</td><td>${!r.urlInfo.urlhaus?'<span class="hint">no consultado</span>':r.urlInfo.urlhaus.error?'<span class="hint">'+esc(r.urlInfo.urlhaus.error)+'</span>':r.urlInfo.urlhaus.found?tag('catalogado'+(r.urlInfo.urlhaus.threat?': '+r.urlInfo.urlhaus.threat:''),'r')+' '+(r.urlInfo.urlhaus.status?tag(r.urlInfo.urlhaus.status):''):tag('sin registros','g')}</td></tr></table>
      ${sbxChainHtml(r.urlInfo.chain)}
      <div data-s="margin-top:8px">${[['urlscan.io','https://urlscan.io/search/#page.domain:'+encodeURIComponent(new URL(r.urlInfo.final).hostname)],['VirusTotal','https://www.virustotal.com/gui/domain/'+encodeURIComponent(new URL(r.urlInfo.final).hostname)],['URLhaus','https://urlhaus.abuse.ch/browse.php?search='+encodeURIComponent(new URL(r.urlInfo.final).hostname)]].map(p=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${esc(p[0])} ↗</a>`).join(' ')}</div>`:''}
    <div class="subh">Identificación</div>
    <table class="kv">${[['MD5',H.md5],['SHA-1',H.sha1],['SHA-256',H.sha256],['SHA-512',H.sha512]].concat(r.imphash?[['imphash',r.imphash]]:[]).map(([k,x])=>`<tr><td>${k}</td><td><span class="m" data-s="font-family:var(--mono);word-break:break-all">${esc(x)}</span> <span class="copy" data-copy="${esc(x)}" data-s="cursor:pointer;font-size:11px;color:var(--muted)">copiar</span></td></tr>`).join('')}
    <tr><td>Tipo real</td><td>${esc(r.type.label)}${r.type.mime?' · '+esc(r.type.mime):''}</td></tr><tr><td>Extensión</td><td>${r.ext?'.'+esc(r.ext)+' ('+esc(r.extClass)+')':'—'}</td></tr>
    <tr><td>Análisis</td><td>${esc(r.analyzedAt.toLocaleString('es-CO'))} · ${r.elapsedMs} ms en ${esc(SBX_MODE_LABEL[r.engineMode]||'entorno aislado')}</td></tr></table>
    <div data-s="margin-top:8px">${piv.map(p=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${esc(p[0])} ↗</a>`).join(' ')}</div>
    ${sbxRepHtml(r)}
    <div class="subh">Recomendaciones</div><ul class="findings">${r.recs.map(x=>`<li class="f-${v.c==='ok'?'ok':v.c==='med'?'warn':'fail'}"><span class="ic">${ico('wrench')}</span><div>${esc(x)}</div></li>`).join('')}</ul>
    <div class="subh">Matriz MITRE ATT&amp;CK</div>${sbxMatrix(r)}
    <div class="subh">Hallazgos (${r.findings.length})</div>${sbxFindingsHtml(r)}
    ${sbxCveHtml(r)}${sbxOsvHtml(r)}${sbxStructHtml(r)}
    <div class="subh">Entropía</div>${sbxEntropySvg(r)}
    ${sbxIocHtml(r)}
    ${r.interesting&&r.interesting.length?`<details><summary>Cadenas relevantes (${r.interesting.length} de ${r.stringsCount||'—'})</summary><div class="raw sbxcode" tabindex="0">${esc(r.interesting.join('\n'))}</div></details>`:''}
    ${r.parseError?`<p class="hint">Aviso del analizador: ${esc(r.parseError)}</p>`:''}
    ${r.yara?`<p class="hint">Reglas YARA: ${r.yara.rules} aplicadas · ${r.yara.matched.length} coincidencia(s)${r.yara.errors.length?` · <span data-s="color:var(--wartx)">${esc(r.yara.errors.join(' · '))}</span>`:''}</p>`:''}
    <p class="hint" data-s="margin-top:12px">Análisis estático y pasivo: el archivo no se ejecutó. Un resultado limpio no garantiza la ausencia de malware. Confírmalo con reputación, antivirus/EDR o un sandbox dinámico.</p>
  </div>`;
}
function renderSbx(){
  const ok=SBX.results.filter(x=>x.r),bad=SBX.results.filter(x=>x.error);
  let h='';
  if(SBX.results.length>1){
    h+=`<div class="glass phishcard"><div class="subh" data-s="margin-top:0">Resumen del lote (${SBX.results.length} archivos)</div><div class="sbxscroll"><table class="sbxtbl"><tr><th>Archivo</th><th>Veredicto</th><th>Puntaje</th><th>Tipo</th><th>ATT&amp;CK</th><th>SHA-256</th></tr>
    ${SBX.results.map((x,i)=>x.r?`<tr><td><a href="#sbxCard${ok.indexOf(x)}">${esc(x.r.name)}</a></td><td data-s="color:${x.r.verdict.col}">${esc(x.r.verdict.t)}</td><td>${x.r.score}</td><td>${esc(x.r.type.label)}</td><td>${Object.keys(sbxTechSev(x.r)).length}</td><td class="m">${esc(x.r.hashes.sha256.slice(0,16))}…</td></tr>`:`<tr><td>${esc(x.file.name)}</td><td colspan="5" data-s="color:var(--failtx)">${esc(x.error)}</td></tr>`).join('')}</table></div>
    <div class="rtoolbar"><button class="btn ghost" data-sbxexp="batch" data-i="-1">${ico('download')}Informe del lote (.json)</button>${ok.length>1?`<button class="btn ghost" id="sbxCmpOpen">${ico('compare')}Comparar archivos</button>`:''}</div>
    <div id="sbxCmp"></div></div>`;
  }
  ok.forEach((x,i)=>{h+=sbxCard(x.r,i);});
  bad.forEach(x=>{h+=`<div class="glass phishcard"><b>${esc(x.file.name)}</b><p class="hint" data-s="color:var(--failtx)">${esc(x.error)}</p></div>`;});
  $('#sbxOut').innerHTML=h;
  $('#sbxOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ---- Comparación de dos archivos analizados (relación entre muestras de una misma campaña) */
const jaccard=(A,B)=>{const a=new Set(A),b=new Set(B);if(!a.size&&!b.size)return null;let i=0;a.forEach(x=>{if(b.has(x))i++;});return i/(a.size+b.size-i);};
function sbxCompare(i,j){
  const L=sbxOk();const A=L[i]&&L[i].r,B=L[j]&&L[j].r;if(!A||!B)return '';
  const ta=Object.keys(sbxTechSev(A)),tb=Object.keys(sbxTechSev(B));
  const iocs=r=>[...(r.iocs.domains||[]),...(r.iocs.urls||[]),...(r.iocs.ips||[]),...(r.iocs.emails||[])];
  const ia=iocs(A),ib=iocs(B);const commonI=ia.filter(x=>ib.includes(x));
  const ya=(A.yara&&A.yara.matched||[]).map(m=>m.rule),yb=(B.yara&&B.yara.matched||[]).map(m=>m.rule);
  const js=jaccard(A.interesting||[],B.interesting||[]);const jt=jaccard(ta,tb);
  const same=(x,y)=>x&&y&&x===y;
  const rel=[];
  if(A.hashes.sha256===B.hashes.sha256)rel.push(['crit','Son el mismo archivo (SHA-256 idéntico)']);
  if(same(A.imphash,B.imphash))rel.push(['high','Mismo imphash: compilados con la misma tabla de importaciones (probable mismo origen o mismo empaquetador)']);
  if(A.pe&&B.pe&&A.pe.pdb&&A.pe.pdb===B.pe.pdb)rel.push(['high','Misma ruta PDB: mismo proyecto de compilación']);
  if(commonI.length)rel.push(['high',commonI.length+' indicador(es) de red en común (misma infraestructura)']);
  if(js!=null&&js>=0.5)rel.push(['med','Cadenas relevantes muy similares ('+Math.round(js*100)+'%)']);
  if(jt!=null&&jt>=0.6&&ta.length>=3)rel.push(['med','Comportamiento similar ('+Math.round(jt*100)+'% de técnicas ATT&CK compartidas)']);
  if(ya.some(x=>yb.includes(x)))rel.push(['med','Coinciden con las mismas reglas YARA: '+ya.filter(x=>yb.includes(x)).join(', ')]);
  const row=(k,x,y,eq)=>`<tr><td>${k}</td><td class="m">${x}</td><td class="m">${y}</td><td>${eq==null?'':eq?tag('igual','y'):tag('distinto')}</td></tr>`;
  const techList=arr=>arr.length?arr.map(t=>`<a class="sbxchip" target="_blank" rel="noopener noreferrer" href="${esc(attUrl(t))}" title="${esc(attName(t))}">${esc(t)}</a>`).join(''):'—';
  return `<div class="subh">Comparación: ${esc(A.name)} ↔ ${esc(B.name)}</div>
    ${rel.length?`<ul class="findings">${rel.map(([s,t])=>`<li class="f-${s==='crit'||s==='high'?'fail':'warn'}"><span class="ic">${ico('link')}</span><div><b>${esc(t)}</b></div></li>`).join('')}</ul>`:'<p class="hint">No se encontraron relaciones fuertes entre los dos archivos.</p>'}
    <div class="sbxscroll"><table class="sbxtbl"><tr><th>Atributo</th><th>${esc(A.name)}</th><th>${esc(B.name)}</th><th></th></tr>
      ${row('Tipo',esc(A.type.label),esc(B.type.label),A.type.label===B.type.label)}
      ${row('Tamaño',fmtBytes(A.size),fmtBytes(B.size),null)}
      ${row('Veredicto',esc(A.verdict.t)+' ('+A.score+')',esc(B.verdict.t)+' ('+B.score+')',null)}
      ${row('SHA-256',esc(A.hashes.sha256.slice(0,24))+'…',esc(B.hashes.sha256.slice(0,24))+'…',A.hashes.sha256===B.hashes.sha256)}
      ${row('imphash',esc(A.imphash||'—'),esc(B.imphash||'—'),A.imphash&&B.imphash?A.imphash===B.imphash:null)}
      ${A.pe||B.pe?row('Compilado',esc((A.pe&&A.pe.compiled)||'—'),esc((B.pe&&B.pe.compiled)||'—'),null)+row('Secciones',esc(A.pe?A.pe.sections.map(s=>s.name).join(' '):'—'),esc(B.pe?B.pe.sections.map(s=>s.name).join(' '):'—'),A.pe&&B.pe?A.pe.sections.map(s=>s.name).join()===B.pe.sections.map(s=>s.name).join():null):''}
      ${row('Entropía',A.entropy,B.entropy,null)}
      <tr><td>Similitud de cadenas</td><td colspan="3">${js==null?'—':Math.round(js*100)+'% (índice de Jaccard)'}</td></tr>
    </table></div>
    <div class="subh">Técnicas ATT&amp;CK</div>
    <table class="kv"><tr><td>En común (${ta.filter(t=>tb.includes(t)).length})</td><td>${techList(ta.filter(t=>tb.includes(t)))}</td></tr>
      <tr><td>Solo ${esc(A.name)}</td><td>${techList(ta.filter(t=>!tb.includes(t)))}</td></tr><tr><td>Solo ${esc(B.name)}</td><td>${techList(tb.filter(t=>!ta.includes(t)))}</td></tr></table>
    ${commonI.length?`<div class="subh">Indicadores en común (${commonI.length})</div>${raw(commonI.join('\n'))}`:''}`;
}
function sbxCmpUI(){
  const L=sbxOk();const box=$('#sbxCmp');if(!box||L.length<2)return;
  const opts=sel=>L.map((x,k)=>`<option value="${k}"${k===sel?' selected':''}>${esc(x.r.name)}</option>`).join('');
  box.innerHTML=`<div class="controls" data-s="margin-top:12px"><div class="field grow"><label for="sbxCmpA">Archivo A</label><select id="sbxCmpA">${opts(0)}</select></div><div class="field grow"><label for="sbxCmpB">Archivo B</label><select id="sbxCmpB">${opts(1)}</select></div></div><div id="sbxCmpOut"></div>`;
  const go=()=>{$('#sbxCmpOut').innerHTML=sbxCompare(+$('#sbxCmpA').value,+$('#sbxCmpB').value);};
  $('#sbxCmpA').addEventListener('change',go);$('#sbxCmpB').addEventListener('change',go);go();
}
/* ---- Exportaciones */
const sbxOk=()=>SBX.results.filter(x=>x.r);
const sbxSafe=n=>String(n).replace(/[^\w.-]+/g,'_').slice(0,60);
function sbxJson(r){
  return {tool:'Centinela',type:'file-sandbox-analysis',generated:r.analyzedAt.toISOString(),file:{name:r.name,size:r.size,extension:r.ext,type:r.type,hashes:r.hashes,imphash:r.imphash||null,entropy:r.entropy},
    verdict:r.verdict.t,score:r.score,counts:r.counts,
    attack:Object.entries(sbxTechSev(r)).map(([id,sev])=>({id,name:attName(id),tactics:((ATT_TECH[id]||[])[1]||[]).map(t=>(ATT_TACTICS.find(x=>x[0]===t)||[t,t])[1]),severity:sev,url:attUrl(id)})),
    findings:r.findings.map(f=>({severity:f.sev,category:f.cat,title:f.title,detail:f.detail,evidence:f.evidence||null,attack:f.attack||[],cve:f.cve||[]})),
    cves:r.cveInfo||[],dependencies:r.manifest?{ecosystem:r.manifest.ecosystem,packages:r.manifest.packages.length,vulnerabilities:(r.osv&&r.osv.vulns)||[]}:null,
    reputation:r.rep||null,iocs:r.iocs,structure:{pe:r.pe||null,elf:r.elf||null,macho:r.macho||null,pdf:r.pdf||null,zip:r.zip||null,ole:r.ole||null,rtf:r.rtf||null,lnk:r.lnk||null,iso:r.iso||null,onenote:r.onenote||null,script:r.script||null},
    recommendations:r.recs,interestingStrings:r.interesting||[],yara:r.yara||null};
}
function sbxTxt(r){
  const L=[],line=c=>L.push((c||'=').repeat(72)),H=r.hashes;
  L.push('INFORME DE ANÁLISIS DE ARCHIVO — CENTINELA SANDBOX');line();
  const org=(()=>{try{return localStorage.getItem('ctn-org')||'';}catch(e){return '';}})();if(org)L.push('Entidad    : '+org);
  L.push('Fecha      : '+r.analyzedAt.toLocaleString('es-CO'));
  L.push('Archivo    : '+r.name);L.push('Tamaño     : '+fmtBytes(r.size)+' ('+r.size+' bytes)');
  L.push('Tipo real  : '+r.type.label+(r.mismatch?'  [LA EXTENSIÓN NO COINCIDE]':''));
  L.push('VEREDICTO  : '+r.verdict.t.toUpperCase()+'  —  puntaje de riesgo '+r.score+'/100');
  L.push('Hallazgos  : '+r.counts.crit+' críticos · '+r.counts.high+' altos · '+r.counts.med+' medios · '+r.counts.low+' bajos · '+r.counts.info+' informativos');
  L.push('');L.push('IDENTIFICACIÓN');line('-');
  L.push('MD5     : '+H.md5);L.push('SHA-1   : '+H.sha1);L.push('SHA-256 : '+H.sha256);L.push('SHA-512 : '+H.sha512);if(r.imphash)L.push('imphash : '+r.imphash);
  L.push('Entropía: '+r.entropy+' / 8');
  if(r.rep){L.push('');L.push('REPUTACIÓN DEL HASH');line('-');const S=r.rep.sources;
    if(S.hashlookup)L.push('CIRCL hashlookup : '+(S.hashlookup.error?'error':S.hashlookup.found?'conocido ('+(S.hashlookup.name||'')+')':'sin registros'));
    if(S.vt)L.push('VirusTotal       : '+(S.vt.error?'error: '+S.vt.error:S.vt.found===false?'sin registros':(S.vt.stats?S.vt.stats.malicious:0)+' motores lo detectan'+(S.vt.label?' · '+S.vt.label:'')));
    if(S.mb)L.push('MalwareBazaar    : '+(S.mb.error?'error: '+S.mb.error:S.mb.found?'MUESTRA CONOCIDA '+(S.mb.signature||''):'sin registros'));
    if(S.ha)L.push('Hybrid Analysis  : '+(S.ha.error?'error: '+S.ha.error:S.ha.found?(S.ha.verdict||'')+' '+(S.ha.family||''):'sin registros'));
    r.rep.notes.forEach(n=>L.push('Nota: '+n));}
  L.push('');L.push('RECOMENDACIONES');line('-');r.recs.forEach((x,i)=>L.push((i+1)+'. '+x));
  L.push('');L.push('MATRIZ MITRE ATT&CK');line('-');
  const m=sbxTechSev(r);ATT_TACTICS.forEach(([ta,tn])=>{const ts=Object.keys(m).filter(id=>((ATT_TECH[id]||[])[1]||[]).includes(ta));if(ts.length){L.push(tn+' ('+ta+')');ts.forEach(id=>L.push('   '+id.padEnd(10)+' '+attName(id)+'  ['+VULN_SEV[m[id]].label+']  '+attUrl(id)));}});
  L.push('');L.push('HALLAZGOS DETALLADOS');line('-');
  r.findings.slice().sort((a,b)=>SEV_RANK[b.sev]-SEV_RANK[a.sev]).forEach(f=>{
    L.push('['+VULN_SEV[f.sev].label.toUpperCase()+'] '+f.title);L.push('   Categoría : '+f.cat);L.push('   Detalle   : '+f.detail);
    if(f.evidence)L.push('   Evidencia : '+f.evidence);if((f.attack||[]).length)L.push('   ATT&CK    : '+f.attack.map(t=>t+' '+attName(t)).join('; '));if((f.cve||[]).length)L.push('   CVE       : '+f.cve.join(', '));L.push('');});
  if(r.cveInfo&&r.cveInfo.length){L.push('VULNERABILIDADES (CVE)');line('-');r.cveInfo.forEach(c=>{L.push(c.id+'  CVSS '+(c.cvss!=null?c.cvss:'n/d')+'  EPSS '+(c.epss?(c.epss.epss*100).toFixed(2)+'%':'n/d')+(c.kev?'  [CISA KEV: EXPLOTADA ACTIVAMENTE'+(c.kev.ransom?', RANSOMWARE':'')+']':''));L.push('   Origen: '+c.source+(c.fixed?' · corregido en '+c.fixed:''));if(c.summary)L.push('   '+c.summary.slice(0,500));L.push('   https://nvd.nist.gov/vuln/detail/'+c.id);});L.push('');}
  if(r.osv&&r.osv.vulns.length){L.push('DEPENDENCIAS VULNERABLES ('+r.manifest.ecosystem+')');line('-');r.osv.vulns.forEach(v=>L.push('['+VULN_SEV[v.sev].label+'] '+v.pkg+'@'+v.version+'  '+v.id+(v.aliases.length?' ('+v.aliases.join(', ')+')':'')+(v.fixed?'  → actualizar a '+v.fixed:'')+'  '+v.summary));L.push('');}
  if(r.pe){const p=r.pe;L.push('ESTRUCTURA PE');line('-');L.push(p.arch+' · '+(p.isDll?'DLL':'EXE')+' · '+p.subsystem+' · compilado '+(p.compiled||'—')+' · firma '+(p.signed?'presente':'ausente')+(p.dotnet?' · .NET':''));
    p.sections.forEach(s=>L.push('   '+s.name.padEnd(10)+' '+s.flags+'  raw '+String(s.rsize).padStart(9)+'  entropía '+s.entropy));L.push('');}
  const macros=(r.zip&&r.zip.macros)||(r.ole&&r.ole.macros)||[];
  if(macros.length){L.push('MACROS VBA EXTRAÍDAS');line('-');macros.forEach(mm=>{L.push('--- '+mm.name+' ---');L.push(mm.code.slice(0,20000));});L.push('');}
  const I=r.iocs||{};L.push('INDICADORES DE COMPROMISO');line('-');
  [['URL',I.urls],['Dominio',I.domains],['IP',I.ips],['Correo',I.emails],['Registro',I.registry],['Ruta',I.paths],['Cripto',I.crypto]].forEach(([n,a])=>(a||[]).forEach(x=>L.push(n.padEnd(9)+' '+x)));
  L.push('');L.push('Análisis estático en un entorno aislado del navegador; el archivo no se ejecutó.');L.push('Generado por Centinela — Suite de Ciberseguridad.');
  return L.join('\n');
}
function sbxIocCsv(list){
  const q=v=>'"'+String(v).replace(/"/g,'""')+'"';const rows=[['tipo','valor','archivo','sha256']];
  list.forEach(r=>{const I=r.iocs||{};rows.push(['sha256',r.hashes.sha256,r.name,r.hashes.sha256],['md5',r.hashes.md5,r.name,r.hashes.sha256],['sha1',r.hashes.sha1,r.name,r.hashes.sha256]);
    [['url',I.urls],['domain',I.domains],['ipv4',I.ips],['email',I.emails],['registry',I.registry],['path',I.paths],['crypto',I.crypto]].forEach(([t,a])=>(a||[]).forEach(v=>rows.push([t,v,r.name,r.hashes.sha256])));});
  return rows.map(x=>x.map(q).join(',')).join('\r\n');
}
function sbxNavigator(r){
  const m=sbxTechSev(r),score={crit:100,high:75,med:50,low:25,info:10},col={crit:'#e5484d',high:'#f59a62',med:'#ebc15a',low:'#8e9af2',info:'#c9d1db'};
  return {name:'Centinela · '+r.name,versions:{attack:'17',navigator:'5.1.0',layer:'4.5'},domain:'enterprise-attack',
    description:'Técnicas asociadas al archivo '+r.name+' (SHA-256 '+r.hashes.sha256+'). Veredicto: '+r.verdict.t+' ('+r.score+'/100).',
    techniques:Object.entries(m).map(([id,sev])=>({techniqueID:id,score:score[sev],color:col[sev],comment:r.findings.filter(f=>(f.attack||[]).includes(id)).map(f=>f.title).join(' | ').slice(0,900),enabled:true,showSubtechniques:true})),
    gradient:{colors:['#8e9af2','#ebc15a','#e5484d'],minValue:0,maxValue:100},
    legendItems:[{label:'Crítica',color:col.crit},{label:'Alta',color:col.high},{label:'Media',color:col.med},{label:'Baja',color:col.low},{label:'Capacidad informativa',color:col.info}],
    metadata:[{name:'sha256',value:r.hashes.sha256},{name:'generado',value:r.analyzedAt.toISOString()}],showTacticRowBackground:true,selectSubtechniquesWithParent:false};
}
function sbxStix(r){
  const now=r.analyzedAt.toISOString(),uid=t=>t+'--'+(crypto.randomUUID?crypto.randomUUID():'00000000-0000-4000-8000-'+Math.random().toString(16).slice(2,14).padEnd(12,'0'));
  const ident={type:'identity',spec_version:'2.1',id:uid('identity'),created:now,modified:now,name:(()=>{try{return localStorage.getItem('ctn-org')||'Centinela';}catch(e){return 'Centinela';}})(),identity_class:'organization'};
  const file={type:'file',spec_version:'2.1',id:uid('file'),name:r.name,size:r.size,hashes:{MD5:r.hashes.md5,'SHA-1':r.hashes.sha1,'SHA-256':r.hashes.sha256,'SHA-512':r.hashes.sha512}};
  const I=r.iocs||{},scos=[...(I.domains||[]).slice(0,100).map(v=>({type:'domain-name',spec_version:'2.1',id:uid('domain-name'),value:v})),...(I.urls||[]).slice(0,100).map(v=>({type:'url',spec_version:'2.1',id:uid('url'),value:v})),...(I.ips||[]).slice(0,100).map(v=>({type:'ipv4-addr',spec_version:'2.1',id:uid('ipv4-addr'),value:v}))];
  const result=r.verdict.c==='crit'?'malicious':r.verdict.c==='high'?'suspicious':r.verdict.c==='ok'?'benign':'unknown';
  const ma={type:'malware-analysis',spec_version:'2.1',id:uid('malware-analysis'),created:now,modified:now,created_by_ref:ident.id,product:'Centinela Sandbox (análisis estático)',analysis_started:now,analysis_ended:now,result,sample_ref:file.id,analysis_sco_refs:scos.map(s=>s.id)};
  const ind={type:'indicator',spec_version:'2.1',id:uid('indicator'),created:now,modified:now,created_by_ref:ident.id,name:'Archivo '+r.name,description:r.verdict.t+' ('+r.score+'/100)',indicator_types:[result==='benign'?'benign':result==='malicious'?'malicious-activity':'anomalous-activity'],pattern:"[file:hashes.'SHA-256' = '"+r.hashes.sha256+"']",pattern_type:'stix',valid_from:now};
  const aps=Object.keys(sbxTechSev(r)).map(id=>({type:'attack-pattern',spec_version:'2.1',id:uid('attack-pattern'),created:now,modified:now,name:attName(id),external_references:[{source_name:'mitre-attack',external_id:id,url:attUrl(id)}]}));
  const vulns=(r.cveInfo||[]).map(c=>({type:'vulnerability',spec_version:'2.1',id:uid('vulnerability'),created:now,modified:now,name:c.id,description:(c.summary||'').slice(0,1000),external_references:[{source_name:'cve',external_id:c.id}]}));
  const rel=(s,t,type)=>({type:'relationship',spec_version:'2.1',id:uid('relationship'),created:now,modified:now,relationship_type:type,source_ref:s,target_ref:t});
  const rels=[...aps.map(a=>rel(ind.id,a.id,'indicates')),...vulns.map(v=>rel(ind.id,v.id,'related-to'))];
  return {type:'bundle',id:uid('bundle'),objects:[ident,file,ma,ind,...scos,...aps,...vulns,...rels]};
}
function sbxPrint(i){
  const cards=[...document.querySelectorAll('.sbxcard')];cards.forEach((c,k)=>{if(k!==i)c.style.display='none';});
  document.querySelectorAll('.sbxcard details').forEach(d=>{d.dataset.wasOpen=d.open?'1':'';d.open=true;});
  const restore=()=>{cards.forEach(c=>c.style.display='');document.querySelectorAll('.sbxcard details').forEach(d=>{d.open=!!d.dataset.wasOpen;});window.removeEventListener('afterprint',restore);};
  window.addEventListener('afterprint',restore);window.print();setTimeout(restore,1500);
}
function sbxExport(kind,i){
  if(kind==='batch'){const L=sbxOk().map(x=>sbxJson(x.r));downloadFile('centinela-sandbox-lote.json',JSON.stringify({tool:'Centinela',type:'file-sandbox-batch',generated:new Date().toISOString(),files:L},null,2),'application/json');return;}
  const x=sbxOk()[i];if(!x)return;const r=x.r,base='centinela-sandbox-'+sbxSafe(r.name);
  if(kind==='txt')downloadFile(base+'.txt',sbxTxt(r));
  else if(kind==='json')downloadFile(base+'.json',JSON.stringify(sbxJson(r),null,2),'application/json');
  else if(kind==='ioc')downloadFile(base+'-iocs.csv',sbxIocCsv([r]),'text/csv');
  else if(kind==='nav')downloadFile(base+'-attack-layer.json',JSON.stringify(sbxNavigator(r),null,2),'application/json');
  else if(kind==='stix')downloadFile(base+'-stix21.json',JSON.stringify(sbxStix(r),null,2),'application/json');
  else if(kind==='print')sbxPrint(i);
}
/* ---- Sandbox dinámico (VirusTotal a través del backend): solo con confirmación expresa */
async function sbxDynamic(i){
  const x=sbxOk()[i];if(!x)return;const b=leakBackend();const out=$('#sbxDyn'+i);
  if(!b){alert('Configura la URL del backend en Ajustes para usar el sandbox dinámico.');return;}
  if(x.file.size>32*1024*1024){alert('VirusTotal acepta hasta 32 MB por esta vía.');return;}
  if(!confirm('El archivo "'+x.r.name+'" se subirá a VirusTotal para ejecutarlo en sus sandboxes.\n\nVirusTotal comparte las muestras con su comunidad y sus socios: NO lo hagas con documentos confidenciales o datos personales.\n\n¿Continuar?'))return;
  const btn=document.querySelector('[data-sbxdyn="'+i+'"]');if(btn)btn.disabled=true;
  const say=t=>{out.innerHTML=`<div class="status-row" data-s="display:flex"><span class="spinner"></span><span>${esc(t)}</span></div>`;};
  try{
    say('Subiendo el archivo a VirusTotal…');
    const up=await fetch(b+'/sbx/vt/upload?name='+encodeURIComponent(x.r.name),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:x.file});
    const uj=await up.json().catch(()=>({}));if(!up.ok||!uj.id)throw new Error(uj.error||('HTTP '+up.status));
    let done=false;
    for(let k=0;k<24&&!done;k++){say('Analizando en los sandboxes de VirusTotal… ('+(k*15)+' s)');await new Promise(res=>setTimeout(res,15000));
      const a=await leakGet(b+'/sbx/vt/analysis?id='+encodeURIComponent(uj.id),20000);if(a.ok&&a.j&&a.j.status==='completed')done=true;}
    say('Recuperando resultados y técnicas ATT&CK observadas…');
    const r=x.r;r.rep=await sbxRep(r.hashes.sha256);r.verdict=sbxVerdict(r);r.recs=sbxRecs(r);
    renderSbx();
    const o2=$('#sbxDyn'+i);if(o2)o2.innerHTML=`<p class="hint" data-s="color:var(--oktx)">${done?'Análisis dinámico completado.':'El análisis sigue en curso en VirusTotal; vuelve a consultar más tarde.'} Las técnicas ATT&amp;CK observadas en ejecución se añadieron a la matriz.</p>`;
  }catch(e){out.innerHTML=`<p class="hint" data-s="color:var(--failtx)">No se pudo completar el sandbox dinámico: ${esc(leakErr(e))}</p>`;if(btn)btn.disabled=false;}
}
/* ---- Eventos */
(function(){
  const drop=$('#sbxDrop'),inp=$('#sbxFile');
  inp.addEventListener('change',()=>{sbxAddFiles([...inp.files]);inp.value='';});
  ['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
  ['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
  drop.addEventListener('drop',e=>{if(e.dataTransfer&&e.dataTransfer.files)sbxAddFiles([...e.dataTransfer.files]);});
  drop.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inp.click();}});
  $('#sbxList').addEventListener('click',e=>{const a=e.target.closest('[data-sbxrm]');if(a){e.preventDefault();SBX.files.splice(+a.dataset.sbxrm,1);sbxRenderList();}});
  $('#goSbx').addEventListener('click',runSbx);
  $('#goSbxUrl').addEventListener('click',runSbxUrl);
  $('#sbxUrl').addEventListener('keydown',e=>{if(e.key==='Enter')runSbxUrl();});
  document.querySelectorAll('[data-sbxtab]').forEach(b=>b.addEventListener('click',()=>sbxTab(b.dataset.sbxtab)));
  $('#sbxClear').addEventListener('click',()=>{if(SBX.busy)return;SBX.files=[];SBX.results=[];sbxRenderList();$('#sbxOut').innerHTML='';});
  $('#sbxOut').addEventListener('click',e=>{if(e.target.closest('#sbxCmpOpen')){sbxCmpUI();return;}const x=e.target.closest('[data-sbxexp]');if(x){sbxExport(x.dataset.sbxexp,+x.dataset.i);return;}const d=e.target.closest('[data-sbxdyn]');if(d)sbxDynamic(+d.dataset.sbxdyn);});
  // Evita que un archivo soltado fuera de la zona lo abra el navegador
  window.addEventListener('dragover',e=>{if(!document.getElementById('modeSbxWrap').contains(e.target))return;e.preventDefault();});
  window.addEventListener('drop',e=>{if(document.getElementById('modeSbxWrap').style.display!=='none')e.preventDefault();});
})();

/* ============================================================ Monitoreo + alertas */
let MON_TIMER=null;
function monList(){try{return JSON.parse(localStorage.getItem('ctn-watch')||'[]');}catch(e){return[];}}
function monSave(l){try{localStorage.setItem('ctn-watch',JSON.stringify(l));}catch(e){}}
function monAddDomain(){let d=$('#monInput').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Dominio inválido');return;}const l=monList();if(!l.includes(d))l.unshift(d);monSave(l.slice(0,25));$('#monInput').value='';renderMon();}
async function monCheck(d){
  RESOLVER='auto';
  const [txt,dmarc,mx,ns,a]=await Promise.all([query(d,'TXT'),query('_dmarc.'+d,'TXT'),query(d,'MX'),query(d,'NS'),query(d,'A')]);
  const spf=txt.answers.map(x=>x.data).find(x=>/^v=spf1/i.test(x))||'';
  const dm=dmarc.answers.map(x=>x.data).find(x=>/^v=DMARC1/i.test(x))||'';
  const mxs=mx.answers.map(x=>x.data).sort().join(' | ');
  const nss=ns.answers.map(x=>x.data.replace(/\.$/,'')).sort().join(' | ');
  let listed=[];const ip=a.answers.map(x=>x.data).find(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x));
  if(ip){for(const bl of ['zen.spamhaus.org','bl.spamcop.net']){const q=await query(ip.split('.').reverse().join('.')+'.'+bl,'A');if(q.answers.length&&!/^127\.255\.255\./.test(q.answers[0].data))listed.push(bl);}}
  return {spf,dm,mxs,nss,listed:listed.join(','),ip:ip||''};
}
async function monRunAll(silent){
  const l=monList();if(!l.length){renderMon();return;}
  const st=$('#monStatus');if(!silent){st.style.display='flex';}
  const results={};
  for(const d of l){if(!silent)$('#monStatusTxt').textContent='Revisando '+d+'…';
    try{const cur=await monCheck(d);const key='ctn-mon-'+d;let prev=null;try{prev=JSON.parse(localStorage.getItem(key)||'null');}catch(e){}
      const changes=[];
      if(prev){['spf','dm','mxs','nss'].forEach(f=>{if(prev[f]!==cur[f])changes.push(({spf:'SPF',dm:'DMARC',mxs:'MX',nss:'Nameservers'})[f]);});
        if(!prev.listed&&cur.listed)changes.push('¡Apareció en LISTA NEGRA!');}
      cur.changes=changes;cur.first=!prev;results[d]=cur;
      try{localStorage.setItem(key,JSON.stringify({spf:cur.spf,dm:cur.dm,mxs:cur.mxs,nss:cur.nss,listed:cur.listed}));}catch(e){}
      if(changes.length&&!cur.first)notifyChange(d,changes);
      monHistAdd(d,{s:cur.listed?'bl':(changes.length&&!cur.first)?'chg':'ok',c:changes,ip:cur.ip||''});
    }catch(e){results[d]={error:String(e.message||e)};monHistAdd(d,{s:'err',c:[],e:String(e.message||e).slice(0,120)});}
  }
  window.__monResults=results;renderMon();if(!silent)st.style.display='none';
}
function notifyChange(d,changes){
  try{if('Notification'in window&&Notification.permission==='granted')new Notification('Centinela — cambio detectado',{body:d+': '+changes.join(', ')});}catch(e){}
}
/* ---- Historial de monitoreo (ctn-monh-<dominio>): una entrada por revisión. Retención: 30 días (purgeHistory). */
const MONH_MAX=500;
const MONH_ST={ok:['Sin cambios','mh-ok','check-circle'],chg:['Cambio detectado','mh-chg','alert'],bl:['En lista negra','mh-bl','stop'],err:['Error al revisar','mh-err','ban']};
function monHist(d){try{const h=JSON.parse(localStorage.getItem('ctn-monh-'+d)||'[]');return Array.isArray(h)?h:[];}catch(e){return [];}}
function monHistAdd(d,e){const h=monHist(d);h.push(Object.assign({t:Date.now()},e));try{localStorage.setItem('ctn-monh-'+d,JSON.stringify(h.slice(-MONH_MAX)));}catch(x){}}
function monStrip(d){
  const h=monHist(d);if(!h.length)return '<span class="hint">sin historial todavía</span>';
  const last=h.slice(-60);const fmt=t=>new Date(t).toLocaleString('es-CO');
  const cnt={ok:0,chg:0,bl:0,err:0};h.forEach(x=>cnt[x.s]=(cnt[x.s]||0)+1);
  const days=Math.max(1,Math.round((h[h.length-1].t-h[0].t)/864e5));
  const okPct=Math.round(cnt.ok/h.length*100);
  const sum=h.length+' revisión(es) en '+days+' día(s) · '+okPct+'% sin cambios'+(cnt.chg?' · '+cnt.chg+' cambio(s)':'')+(cnt.bl?' · '+cnt.bl+' en lista negra':'')+(cnt.err?' · '+cnt.err+' error(es)':'');
  return `<div class="mhstrip" role="img" aria-label="${esc('Historial de '+d+': '+sum)}">${last.map(x=>`<span class="mhc ${MONH_ST[x.s][1]}" title="${esc(fmt(x.t)+' — '+MONH_ST[x.s][0]+(x.c&&x.c.length?': '+x.c.join(', '):'')+(x.e?': '+x.e:''))}"></span>`).join('')}</div>
    <div class="hint">${esc(sum)}${h.length>60?' · se muestran las últimas 60':''}</div>`;
}
function monEvents(d){
  const ev=monHist(d).filter((x,i,arr)=>x.s!=='ok'||i===0||i===arr.length-1).slice(-50).reverse();
  return ev.length?`<table class="mini"><tr><th>Fecha</th><th>Estado</th><th>Detalle</th></tr>${ev.map(x=>`<tr><td>${esc(new Date(x.t).toLocaleString('es-CO'))}</td><td>${ico(MONH_ST[x.s][2])} ${esc(MONH_ST[x.s][0])}</td><td>${esc((x.c||[]).join(', ')||x.e||(x.ip?'IP '+x.ip:'—'))}</td></tr>`).join('')}</table>`:'';
}
function renderMon(){
  const l=monList();const R=window.__monResults||{};
  if(!l.length){$('#monOut').innerHTML='<div class="glass phishcard"><p class="hint">Aún no monitoreas ningún dominio. Agrega uno arriba.</p></div>';return;}
  const rows=l.map(d=>{const r=R[d];const h=monHist(d);const lastH=h[h.length-1];let status='<span class="hint">sin revisar</span>';
    if(r&&r.error)status='<span class="mh-t-err">error</span>';
    else if(r&&r.listed)status='<span class="mh-t-bl">'+ico('alert')+' EN LISTA NEGRA</span>';
    else if(r&&r.changes&&r.changes.length)status='<span class="mh-t-chg">'+ico('alert')+' '+esc(r.changes.join(', '))+'</span>';
    else if(r)status='<span class="mh-t-ok">✓ sin cambios</span>';
    else if(lastH)status=`<span class="mh-t-${lastH.s}">${esc(MONH_ST[lastH.s][0])}</span> <span class="hint">· última revisión ${esc(new Date(lastH.t).toLocaleString('es-CO'))}</span>`;
    const ip=r&&r.ip?r.ip:(lastH&&lastH.ip)||'';
    return `<tr><td class="mh-dom">${esc(d)}</td><td>${status}</td><td>${ip?esc(ip):'—'}</td><td><button class="btn ghost monDel" data-d="${esc(d)}">quitar</button></td></tr>
      <tr class="mh-row"><td colspan="4">${monStrip(d)}${h.length?`<details><summary>Ver eventos de ${esc(d)}</summary>${monEvents(d)}</details>`:''}</td></tr>`;}).join('');
  $('#monOut').innerHTML=`<div class="glass phishcard"><div class="subh">${ico('pulse')}Dominios monitoreados (${l.length})</div>
    <table class="mini mhtable"><tr><th>Dominio</th><th>Estado</th><th>IP</th><th></th></tr>${rows}</table>
    <div class="mhlegend" aria-label="Leyenda">${Object.values(MONH_ST).map(([t,c,i])=>`<span><span class="mhc ${c}"></span>${ico(i)}${esc(t)}</span>`).join('')}</div>
    <p class="hint">El historial de revisiones se conserva 30 días en este navegador.</p></div>`;
  document.querySelectorAll('.monDel').forEach(b=>b.addEventListener('click',()=>{const d=b.dataset.d;monSave(monList().filter(x=>x!==d));try{localStorage.removeItem('ctn-mon-'+d);localStorage.removeItem('ctn-monh-'+d);}catch(e){}renderMon();}));
}

/* ============================================================ Herramientas de seguridad */
async function sha(algo, str) {
  const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hibp(pwd) {
  const h = (await sha('SHA-1', pwd)).toUpperCase();
  const pre = h.slice(0, 5), suf = h.slice(5);
  const r = await fetch('https://api.pwnedpasswords.com/range/' + pre, { headers: { 'Add-Padding': 'true' } });
  if (!r.ok) throw new Error('hibp ' + r.status);
  const t = await r.text(); let count = 0;
  t.split('\n').forEach(line => { const [s, c] = line.trim().split(':'); if (s === suf) count = parseInt(c) || 0; });
  return count;
}
function pwdStrength(p) {
  const len = p.length;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(re => re.test(p)).length;
  let pool = 0; if (/[a-z]/.test(p)) pool += 26; if (/[A-Z]/.test(p)) pool += 26; if (/[0-9]/.test(p)) pool += 10; if (/[^a-zA-Z0-9]/.test(p)) pool += 33;
  const entropy = p ? Math.round(len * Math.log2(pool || 1)) : 0;
  const common = /(1234|12345|password|qwerty|admin|contrasena|clave|abc123|111111|000000|iloveyou)/i.test(p);
  let label, pct, col;
  if (!p) { label = '—'; pct = 0; col = 'var(--muted2)'; }
  else if (common || entropy < 28) { label = 'Muy débil'; pct = 15; col = 'var(--fail)'; }
  else if (entropy < 40) { label = 'Débil'; pct = 40; col = 'var(--warn)'; }
  else if (entropy < 60) { label = 'Aceptable'; pct = 65; col = 'var(--warn)'; }
  else if (entropy < 80) { label = 'Fuerte'; pct = 85; col = 'var(--ok)'; }
  else { label = 'Muy fuerte'; pct = 100; col = 'var(--ok)'; }
  return { label, pct, col, entropy, classes, len, common };
}
function renderStrength() {
  const p = $('#pwdInput').value, s = pwdStrength(p);
  $('#pwdStrength').innerHTML = `<div data-s="display:flex;align-items:center;gap:10px"><div data-s="flex:1;height:8px;background:var(--line);border-radius:5px;overflow:hidden"><div data-s="height:100%;width:${s.pct}%;background:${s.col};transition:.2s"></div></div><b data-s="color:${s.col};min-width:90px;text-align:right">${s.label}</b></div><div class="hint" data-s="margin-top:4px">${p ? (s.len + ' caracteres · ' + s.classes + '/4 tipos · ~' + s.entropy + ' bits de entropía' + (s.common ? ' · patrón común, evítalo' : '')) : 'Escribe para evaluar la fortaleza.'}</div>`;
}
const GENWORDS = ['tigre', 'montana', 'rio', 'cielo', 'fuego', 'piedra', 'viento', 'luna', 'bosque', 'trueno', 'acero', 'nieve', 'coral', 'ambar', 'roble', 'lince', 'cobre', 'delta', 'faro', 'halcon', 'jade', 'loto', 'mango', 'zorro', 'aguila', 'brisa'];
function genPwd() {
  const len = +$('#genLen').value; let pool = 'abcdefghijkmnpqrstuvwxyz';
  if ($('#genUpper').checked) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if ($('#genNum').checked) pool += '23456789';
  if ($('#genSym').checked) pool += '!@#$%^&*()-_=+[]{}?';
  const arr = new Uint32Array(len); crypto.getRandomValues(arr);
  let out = ''; for (let i = 0; i < len; i++) out += pool[arr[i] % pool.length]; return out;
}
function genPhrase() {
  const n = 5, arr = new Uint32Array(n); crypto.getRandomValues(arr);
  return [...arr].map(x => GENWORDS[x % GENWORDS.length]).join('-') + '-' + (arr[0] % 100);
}
function jwtDecode(t) {
  const parts = t.trim().split('.'); if (parts.length < 2) throw new Error('No parece un JWT (faltan segmentos).');
  const dec = x => { x = x.replace(/-/g, '+').replace(/_/g, '/'); while (x.length % 4) x += '='; return decodeURIComponent(escape(atob(x))); };
  return { header: JSON.parse(dec(parts[0])), payload: JSON.parse(dec(parts[1])), sig: parts[2] || '' };
}

/* ============================================================ Escaneo de cabeceras HTTP */
async function runHeaders(){
  const backend=(function(){try{return (localStorage.getItem('ctn-backend')||'').replace(/\/$/,'');}catch(e){return'';}})();
  const raw=$('#hdrUrl').value.trim();
  if(!raw){alert('Ingresa una URL o dominio');return;}
  if(!backend){$('#hdrOut').innerHTML='<div class="glass phishcard"><div class="phverdict" data-s="color:var(--warn)"><svg class="i"><use href="#i-alert"/></svg> Necesitas configurar el backend</div><p class="hint">Ve a Ajustes → URL del backend y pega la URL de tu Cloudflare Worker (carpeta <b>centinela-backend</b>). El navegador no puede leer estas cabeceras por CORS, por eso el escaneo se hace a través del Worker (endpoint /headers).</p></div>';$('#hdrOut').scrollIntoView({behavior:'smooth',block:'nearest'});return;}
  $('#goHdr').disabled=true;$('#hdrStatus').style.display='flex';$('#hdrOut').innerHTML='';
  try{const r=await fetch(backend+'/headers?url='+encodeURIComponent(raw));const j=await r.json();
    if(j.error){$('#hdrOut').innerHTML='<div class="glass phishcard"><p class="hint">No se pudo escanear: '+esc(j.error)+'</p></div>';}
    else renderHeaders(j);
  }catch(e){$('#hdrOut').innerHTML='<div class="glass phishcard"><p class="hint">Error al contactar el backend: '+esc(e.message)+'. Verifica la URL en Ajustes.</p></div>';}
  finally{$('#goHdr').disabled=false;$('#hdrStatus').style.display='none';}
}
function renderHeaders(j){
  const h=j.headers||{};const f=[];let score=0,max=0;
  const add=(w,sev,t,why)=>{max+=w;if(sev==='ok')score+=w;else if(sev==='warn')score+=w*0.5;f.push({sev,t,why});};
  const hsts=h['strict-transport-security'];
  if(hsts){const age=+((hsts.match(/max-age=(\d+)/i)||[])[1]||0);
    if(age>=15768000)add(20,'ok','HSTS activo','max-age suficiente'+(/includeSubDomains/i.test(hsts)?' · includeSubDomains':'')+(/preload/i.test(hsts)?' · preload':''));
    else add(20,'warn','HSTS con max-age bajo','Sube a ≥ 31536000. Actual: '+esc(hsts));
  }else add(20,'fail','Falta HSTS','Añade: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
  const csp=h['content-security-policy'];
  if(csp){if(/unsafe-inline|unsafe-eval/i.test(csp))add(18,'warn','CSP presente pero con unsafe-inline/eval','Restringe scripts inline/eval para una defensa XSS real.');else add(18,'ok','CSP presente','Buena defensa contra XSS/inyección.');}
  else add(18,'warn','Falta Content-Security-Policy','Añade una CSP para mitigar XSS e inyección.');
  const xfo=h['x-frame-options'];const fa=csp&&/frame-ancestors/i.test(csp);
  if(xfo||fa)add(12,'ok','Protección anti-clickjacking',xfo?('X-Frame-Options: '+esc(xfo)):'CSP frame-ancestors');
  else add(12,'warn','Sin protección anti-clickjacking','Añade X-Frame-Options: DENY o CSP frame-ancestors.');
  if(/nosniff/i.test(h['x-content-type-options']||''))add(10,'ok','X-Content-Type-Options: nosniff','');
  else add(10,'warn','Falta X-Content-Type-Options: nosniff','Evita el MIME sniffing.');
  if(h['referrer-policy'])add(8,'ok','Referrer-Policy presente',esc(h['referrer-policy']));
  else add(8,'warn','Falta Referrer-Policy','p.ej. strict-origin-when-cross-origin.');
  if(h['permissions-policy'])add(8,'ok','Permissions-Policy presente','');
  else add(8,'warn','Falta Permissions-Policy','Restringe cámara, micrófono, geolocalización, etc.');
  if(h['cross-origin-opener-policy'])add(6,'ok','COOP presente','');
  else add(6,'info','Sin Cross-Origin-Opener-Policy','Opcional; aísla el contexto de navegación.');
  const leak=[];['server','x-powered-by','x-aspnet-version'].forEach(k=>{if(h[k]&&/\d/.test(h[k]))leak.push(k+': '+h[k]);});
  if(leak.length)add(6,'warn','Fuga de versión en cabeceras','Oculta versiones: '+esc(leak.join(' · ')));
  else add(6,'ok','Sin fuga evidente de versión','');
  const pct=max?Math.round(score/max*100):0;const grade=pct>=90?'A':pct>=75?'B':pct>=60?'C':pct>=40?'D':'F';
  const col=pct>=85?'var(--ok)':pct>=60?'var(--warn)':'var(--fail)';
  const sigH=f.map(x=>{const ic={ok:'✓',warn:'!',fail:'✕',info:'i'}[x.sev]||'•';return `<li class="f-${x.sev}"><span class="ic">${ic}</span><div><b>${esc(x.t)}</b>${x.why?`<span class="why">${x.why}</span>`:''}</div></li>`;}).join('');
  const rawH=Object.entries(h).map(([k,v])=>k+': '+v).join('\n')||'(sin cabeceras)';
  $('#hdrOut').innerHTML=`<div class="glass phishcard"><div class="phverdict" data-s="color:${col}"><svg class="i"><use href="#i-layers"/></svg> Seguridad de cabeceras: ${pct}/100 — Nota ${grade}</div><div class="phurl">${esc(j.url)} · HTTP ${j.status}</div><ul class="findings">${sigH}</ul><div class="subh">Cabeceras recibidas</div><div class="lookup-tree">${esc(rawH)}</div></div>`;
  $('#hdrOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ============================================================ Generador de configuración DNS */
const SPF_PROVIDERS=[
  ['m365','Microsoft 365','include:spf.protection.outlook.com','DKIM: en el Centro de administración de M365 → activa DKIM; publica los CNAME selector1._domainkey y selector2._domainkey que te indique.'],
  ['google','Google Workspace','include:_spf.google.com','DKIM: Consola de administración → Apps → Gmail → Autenticar correo; publica el TXT google._domainkey que genera.'],
  ['ses','Amazon SES','include:amazonses.com','DKIM: SES → Verified identities → Easy DKIM; publica los 3 CNAME que entrega.'],
  ['sendgrid','SendGrid','include:sendgrid.net','DKIM: Sender Authentication; publica los CNAME s1._domainkey y s2._domainkey.'],
  ['mailchimp','Mailchimp','include:servers.mcsv.net','DKIM: publica el CNAME k1._domainkey que indique Mailchimp.'],
  ['mailgun','Mailgun','include:mailgun.org','DKIM: publica el TXT/CNAME de dominio que genera Mailgun.'],
  ['zoho','Zoho Mail','include:zohomail.com','DKIM: publica el TXT del selector que genera Zoho (p. ej. zoho._domainkey).'],
  ['brevo','Brevo (Sendinblue)','include:spf.sendinblue.com','DKIM: publica el TXT mail._domainkey que entrega Brevo.'],
  ['postmark','Postmark','include:spf.mtasv.net','DKIM: publica el TXT del selector que genera Postmark.'],
];
function initGenProviders(){
  const c=$('#genProviders');if(!c||c.dataset.init)return;c.dataset.init='1';
  c.innerHTML=SPF_PROVIDERS.map(p=>`<label class="check"><input type="checkbox" class="genProv" value="${p[0]}"> ${esc(p[1])}</label>`).join('');
}
function recCard(host,type,value,note){
  return `<div class="apitem"><div class="aphead"><div data-s="flex:1"><b>${esc(type)}</b> <span class="hint">en <code>${esc(host)}</code></span></div></div><div class="raw"><span class="copy" data-copy="${esc(value)}">copiar</span>${esc(value)}</div>${note?`<div class="hint" data-s="margin-top:6px"><svg class="i"><use href="#i-bulb"/></svg> ${esc(note)}</div>`:''}</div>`;
}
function runGen(){
  let d=$('#genDom').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/\.$/,'');
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Ingresa un dominio válido');return;}
  const sel=[...document.querySelectorAll('.genProv:checked')].map(x=>x.value);
  const provs=SPF_PROVIDERS.filter(p=>sel.includes(p[0]));
  const rua=$('#genRua').value.trim()||('dmarc@'+d);
  const pol=$('#genDmarc').value;
  const cards=[];const plain=[];
  const push=(host,type,value,note)=>{cards.push(recCard(host,type,value,note));plain.push('# '+type+' ('+host+')\n'+value);};
  // SPF
  const spf='v=spf1 '+(provs.length?provs.map(p=>p[2]).join(' '):'')+(provs.length?' ':'')+'-all';
  push(d,'SPF (TXT)',spf.replace(/\s+/g,' ').trim(), provs.length?'Un solo registro SPF por dominio. -all rechaza lo no autorizado.':'No seleccionaste proveedores: este SPF bloquea TODO envío. Marca tus proveedores arriba.');
  // DMARC
  const dmarc=`v=DMARC1; p=${pol}; rua=mailto:${rua}; ruf=mailto:${rua}; fo=1; adkim=s; aspf=s; pct=100`;
  push('_dmarc.'+d,'DMARC (TXT)',dmarc, pol==='reject'?'Máxima protección. Si recién empiezas, arranca en p=none unas semanas y sube gradualmente.':'Sube a p=reject cuando confirmes que tu correo legítimo pasa.');
  // MTA-STS
  if($('#genMtasts').checked){
    push('_mta-sts.'+d,'MTA-STS (TXT)','v=STSv1; id='+new Date().toISOString().slice(0,10).replace(/-/g,'')+'01','Además, sirve el archivo en https://mta-sts.'+d+'/.well-known/mta-sts.txt (ver más abajo).');
    const policy='version: STSv1\nmode: enforce\nmx: '+ (provs.some(p=>p[0]==='m365')?'*.mail.protection.outlook.com':provs.some(p=>p[0]==='google')?'aspmx.l.google.com\nmx: *.google.com':'TU-SERVIDOR-MX') +'\nmax_age: 604800';
    cards.push(`<div class="apitem"><div class="aphead"><div data-s="flex:1"><b>Archivo de política MTA-STS</b> <span class="hint">en https://mta-sts.${esc(d)}/.well-known/mta-sts.txt</span></div></div><div class="raw"><span class="copy" data-copy="${esc(policy)}">copiar</span>${esc(policy)}</div><div class="hint" data-s="margin-top:6px"><svg class="i"><use href="#i-bulb"/></svg> Ajusta las líneas mx: a tus servidores reales. También crea un registro A/CNAME para el host mta-sts.${esc(d)}.</div></div>`);
    plain.push('# MTA-STS policy file (https://mta-sts.'+d+'/.well-known/mta-sts.txt)\n'+policy);
  }
  // TLS-RPT
  if($('#genTlsrpt').checked)push('_smtp._tls.'+d,'TLS-RPT (TXT)','v=TLSRPTv1; rua=mailto:'+rua,'Recibe reportes de fallos de cifrado en la entrega.');
  // CAA
  if($('#genCaa').checked)push(d,'CAA','0 issue "letsencrypt.org"\n0 issue "digicert.com"\n0 iodef "mailto:security@'+d+'"','Ajusta las autoridades certificadoras a las que realmente usas.');
  // DKIM notes
  const dkimNotes=provs.map(p=>'• '+p[1]+': '+p[3]).join('\n')|| '• Activa DKIM en tu proveedor de correo y publica el registro que te entregue (usa claves de 2048 bits).';
  const dkimCard=`<div class="apitem info"><div class="aphead"><div data-s="flex:1"><b>DKIM — instrucciones por proveedor</b><div class="hint">Las claves DKIM las genera cada proveedor; no se pueden inventar. Publica lo que te indique:</div></div></div><div class="lookup-tree">${esc(dkimNotes)}</div></div>`;
  const all=plain.join('\n\n')+'\n\n# DKIM\n'+dkimNotes+'\n\n# Generado con Centinela';
  $('#genDnsOut').innerHTML=`<div class="glass phishcard"><div data-s="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><div class="phverdict" data-s="margin:0"><svg class="i"><use href="#i-server"/></svg> Registros DNS para ${esc(d)}</div><button class="btn ghost" id="genDl" data-s="margin-left:auto"><svg class="i"><use href="#i-download"/></svg>Descargar (.txt)</button></div><div class="applist" data-s="margin-top:12px">${cards.join('')}${dkimCard}</div><p class="hint" data-s="margin-top:10px">Publica cada registro como <b>TXT</b> (salvo CAA que es tipo CAA) en el host indicado. Tras publicarlos, valídalos en el módulo "Dominio & correo".</p></div>`;
  const genDl=$('#genDl');if(genDl)genDl.addEventListener('click',()=>downloadFile('registros-dns-'+d+'.txt',all));
  $('#genDnsOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ============================================================ Filtraciones: correos comprometidos y entidades */
const LEAK={last:null};
const leakSleep=ms=>new Promise(r=>setTimeout(r,ms));
function leakBackend(){try{return (localStorage.getItem('ctn-backend')||'').replace(/\/$/,'');}catch(e){return'';}}
async function leakGet(url,ms=20000){
  const c=new AbortController();const t=setTimeout(()=>c.abort(),ms);
  try{const r=await fetch(url,{signal:c.signal,cache:'no-store',headers:{Accept:'application/json'}});const tx=await r.text();let j=null;try{j=tx?JSON.parse(tx):null;}catch(e){}return {ok:r.ok,status:r.status,j};}
  finally{clearTimeout(t);}
}
/* Hudson Rock y ransomware.live no permiten CORS: se consultan por el backend (Worker) si está configurado */
async function leakGetCors(direct,viaPath){
  const b=leakBackend();if(b)return leakGet(b+viaPath);
  try{return await leakGet(direct);}catch(e){if(e&&e.name==='AbortError')throw e;throw new Error('este servicio no permite consultas directas desde el navegador; configura el backend en Ajustes');}
}
const leakErr=e=>e&&e.name==='AbortError'?'tiempo de espera agotado':(e&&e.message)||'error de red o CORS';
/* Texto plano desde HTML externo sin ejecutar nada (DOMParser no carga imágenes ni scripts) */
const leakText=h=>{try{return new DOMParser().parseFromString(String(h||''),'text/html').body.textContent.trim();}catch(e){return '';}};
const leakNum=n=>(+n||0).toLocaleString('es-CO');
const LEAK_PW=/password|contraseña|credential|pin/i;
const hibpMap=b=>({name:b.Title||b.Name,domain:b.Domain||'',date:b.BreachDate||'',records:+b.PwnCount||0,data:b.DataClasses||[],logo:b.LogoPath||'',desc:leakText(b.Description),src:['Have I Been Pwned']});

/* --- Fuentes para correos --- */
async function leakXonEmail(email){
  try{const r=await leakGet('https://api.xposedornot.com/v1/breach-analytics?email='+encodeURIComponent(email));
    if(r.status===404||(r.j&&r.j.Error))return {state:'none',breaches:[],pastes:0};
    if(!r.ok||!r.j)throw new Error('HTTP '+r.status);
    const det=(r.j.ExposedBreaches&&r.j.ExposedBreaches.breaches_details)||[];
    const pastes=+((r.j.PastesSummary||{}).cnt)||0;
    return {state:det.length||pastes?'found':'none',pastes,breaches:det.map(b=>({name:b.breach,domain:b.domain||'',date:String(b.xposed_date||''),records:+b.xposed_records||0,data:String(b.xposed_data||'').split(';').map(s=>s.trim()).filter(Boolean),logo:b.logo||'',desc:leakText(b.details),src:['XposedOrNot']}))};
  }catch(e){return {state:'error',err:leakErr(e),breaches:[],pastes:0};}
}
async function leakHibpEmail(email,backend){
  if(!backend)return {state:'skip',breaches:[]};
  try{const r=await leakGet(backend+'/hibp?email='+encodeURIComponent(email));
    if(r.status===404)return {state:'none',breaches:[]};
    if(!r.ok||!Array.isArray(r.j))throw new Error((r.j&&r.j.error)||('HTTP '+r.status));
    return {state:r.j.length?'found':'none',breaches:r.j.map(hibpMap)};
  }catch(e){return {state:'error',err:leakErr(e),breaches:[]};}
}
async function leakHrEmail(email){
  try{const r=await leakGetCors('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email='+encodeURIComponent(email),'/hudsonrock?email='+encodeURIComponent(email));
    if(!r.ok||!r.j)throw new Error('HTTP '+r.status);
    const st=Array.isArray(r.j.stealers)?r.j.stealers:[];
    return {state:st.length?'found':'none',infections:st.map(s=>({date:String(s.date_compromised||'').slice(0,10),family:s.stealer_family||'',os:s.operating_system||'',corp:+s.total_corporate_services||0,user:+s.total_user_services||0}))};
  }catch(e){return {state:'error',err:leakErr(e),infections:[]};}
}
function leakMerge(lists){
  const m=new Map();
  lists.flat().forEach(b=>{if(!b||!b.name)return;const k=String(b.name).toLowerCase().replace(/[^a-z0-9]/g,'');const p=m.get(k);
    if(!p){m.set(k,{...b,src:[...b.src],data:[...b.data]});return;}
    b.src.forEach(s=>{if(!p.src.includes(s))p.src.push(s);});
    b.data.forEach(d=>{if(!p.data.some(x=>x.toLowerCase()===d.toLowerCase()))p.data.push(d);});
    p.records=Math.max(p.records,b.records);if(!p.logo)p.logo=b.logo;if(!p.desc)p.desc=b.desc;if(!p.domain)p.domain=b.domain;if(b.date&&b.date.length>p.date.length)p.date=b.date;});
  return [...m.values()].sort((a,b)=>String(b.date).localeCompare(String(a.date)));
}
function leakSetStatus(on,txt,pct){
  $('#leakStatus').style.display=on?'flex':'none';$('#leakBarwrap').style.display=on?'block':'none';
  if(txt)$('#leakStatusTxt').textContent=txt;if(pct!=null)$('#leakBar').style.width=pct+'%';
}

async function runLeakEmail(){
  const list=[...new Set($('#leakEmails').value.split(/[\s,;]+/).map(s=>s.trim().toLowerCase()).filter(Boolean))];
  if(!list.length){alert('Ingresa al menos un correo.');return;}
  const bad=list.filter(e=>!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(e));
  if(bad.length){alert('Estos correos no son válidos: '+bad.join(', '));return;}
  if(list.length>25){alert('Puedes consultar hasta 25 correos a la vez (ingresaste '+list.length+').');return;}
  const backend=leakBackend();
  $('#goLeakEmail').disabled=true;$('#leakOut').innerHTML='';
  const out=[];
  try{
    for(let i=0;i<list.length;i++){
      const email=list[i];leakSetStatus(true,'Consultando '+email+' ('+(i+1)+' de '+list.length+')…',Math.round(i/list.length*100));
      const [xon,hibp,hr]=await Promise.all([leakXonEmail(email),leakHibpEmail(email,backend),leakHrEmail(email)]);
      const breaches=leakMerge([xon.breaches,hibp.breaches]);
      const infections=hr.infections||[];
      const pw=breaches.some(b=>b.data.some(d=>LEAK_PW.test(d)));
      const anyOk=[xon,hibp,hr].some(s=>s.state==='found'||s.state==='none');
      const status=infections.length||pw?'fail':breaches.length||xon.pastes?'warn':anyOk?'ok':'neutral';
      out.push({email,status,breaches,infections,pastes:xon.pastes||0,passwordExposed:pw,sources:{XposedOrNot:xon,'Have I Been Pwned':hibp,'Hudson Rock':hr}});
      if(i<list.length-1)await leakSleep(1200); // respeta los límites de uso de las APIs gratuitas
    }
    leakSetStatus(true,'Listo',100);
    LEAK.last={type:'email',date:new Date().toISOString(),results:out};
    renderLeakEmail(out);
  }finally{$('#goLeakEmail').disabled=false;setTimeout(()=>leakSetStatus(false),400);}
}

function leakSrcChips(sources){
  return '<div class="lksrcrow">'+Object.entries(sources).map(([n,s])=>{
    if(s.state==='skip')return `<span class="vsrc off" title="Configura el backend con tu clave de HIBP en Ajustes">${esc(n)}: sin configurar</span>`;
    if(s.state==='error')return `<span class="vsrc err" title="${esc(s.err)}">${esc(n)}: no disponible</span>`;
    if(s.state==='found')return `<span class="vsrc hit">${esc(n)}: con resultados</span>`;
    return `<span class="vsrc on">${esc(n)}: sin resultados</span>`;}).join('')+'</div>';
}
function leakBreachRows(list,ctx){
  return list.map(b=>{
    const logo=/^https:\/\//.test(b.logo)?`<img src="${esc(b.logo)}" alt="" loading="lazy" referrerpolicy="no-referrer" data-rm-on-error>`:ico('database');
    const tags=b.data.map(d=>`<span class="tag${LEAK_PW.test(d)?' r':''}">${esc(d)}</span>`).join('');
    const meta=[b.domain,b.date,b.src.join(' + ')].filter(Boolean).map(esc).join(' · ');
    return `<div class="lkbreach"><div class="lklogo">${logo}</div><div data-s="min-width:0"><b>${esc(b.name)}</b><div class="meta2">${meta}</div>${tags?`<div class="tags">${tags}</div>`:''}${b.desc?`<div class="hint" data-s="margin-top:6px">${esc(b.desc.length>320?b.desc.slice(0,320)+'…':b.desc)}</div>`:''}${ctx?mitBreach(b,ctx):''}</div><div class="num">${b.records?leakNum(b.records)+' registros':''}</div></div>`;
  }).join('');
}
function leakFindings(items){
  return '<ul class="findings">'+items.map(([sev,t,why])=>{const ic={ok:'✓',warn:'!',fail:'✕',info:'i'}[sev]||'•';return `<li class="f-${sev}"><span class="ic">${ic}</span><div><b>${esc(t)}</b>${why?`<span class="why">${esc(why)}</span>`:''}</div></li>`;}).join('')+'</ul>';
}
function leakEmailActions(r){
  const a=[];
  if(r.infections.length)a.push(['fail','Tratar el equipo como comprometido','El malware infostealer roba las contraseñas guardadas en el navegador, cookies de sesión y datos de autocompletado. Analiza o reinstala el equipo, y desde un equipo limpio cambia todas las contraseñas y cierra las sesiones activas.']);
  if(r.passwordExposed)a.push(['fail','Cambiar la contraseña de esta cuenta','La filtración incluye contraseñas. Cámbiala también en cualquier otro servicio donde la hayas reutilizado.']);
  if(r.breaches.length||r.infections.length){a.push(['warn','Activar la verificación en dos pasos (MFA)','Evita que una contraseña filtrada baste para entrar a la cuenta.']);
    a.push(['info','Estar atento a correos de phishing dirigidos','Los datos filtrados (nombre, teléfono, cargo) se usan para escribir engaños más creíbles.']);}
  if(!a.length)a.push(['ok','No aparece en las fuentes consultadas','Esto no garantiza que nunca haya sido expuesto; solo que no figura en estas bases públicas.']);
  return a;
}
function renderLeakEmail(out){
  const comp=out.filter(r=>r.status==='fail'||r.status==='warn').length;
  const inf=out.filter(r=>r.infections.length).length;
  const pw=out.filter(r=>r.passwordExposed).length;
  const uniq=new Set(out.flatMap(r=>r.breaches.map(b=>b.name.toLowerCase()))).size;
  const col=inf||pw?'var(--fail)':comp?'var(--warn)':'var(--ok)';
  const verdict=inf?'Hay cuentas con credenciales robadas por malware':pw?'Hay cuentas con contraseñas filtradas':comp?'Hay cuentas expuestas en filtraciones':'Ningún correo aparece en las fuentes consultadas';
  const table=out.length>1?`<div class="lktablewrap"><table class="lktable"><thead><tr><th>Correo</th><th>Estado</th><th>Filtraciones</th><th>Infostealer</th><th>Contraseña expuesta</th></tr></thead><tbody>${out.map(r=>{const[bc,bt]=BADGE[r.status]||BADGE.neutral;return `<tr><td class="lkemail">${esc(r.email)}</td><td><span class="badge ${bc}"><span class="dot"></span>${bt}</span></td><td>${r.breaches.length}</td><td>${r.infections.length?'<b data-s="color:var(--fail)">Sí ('+r.infections.length+')</b>':'No'}</td><td>${r.passwordExposed?'<b data-s="color:var(--fail)">Sí</b>':'No'}</td></tr>`;}).join('')}</tbody></table></div>`:'';
  const head=`<div class="glass phishcard"><div class="phverdict" data-s="color:${col}">${esc(verdict)}</div><div class="phurl">${out.length} correo(s) verificado(s) · ${new Date().toLocaleString('es-CO')}</div>
    <div class="lkstats"><div class="lkstat ${comp?'warn':'ok'}"><b>${comp}</b><span>Correos expuestos</span></div><div class="lkstat ${inf?'fail':'ok'}"><b>${inf}</b><span>Con infostealer</span></div><div class="lkstat ${pw?'fail':'ok'}"><b>${pw}</b><span>Contraseña filtrada</span></div><div class="lkstat"><b>${uniq}</b><span>Filtraciones distintas</span></div></div>
    ${table}
    <div class="mitsum" id="leakMitSum" hidden></div>
    <div class="dashbtns"><button class="btn ghost" id="leakCsv">${ico('download')}<span class="t">CSV</span></button><button class="btn ghost" id="leakJson">${ico('download')}<span class="t">JSON</span></button><button class="btn ghost" id="leakCopy">${ico('copy')}<span class="t">Copiar resumen</span></button></div></div>`;
  const cards=out.map((r,i)=>{
    const[bc,bt]=BADGE[r.status]||BADGE.neutral;
    const infH=r.infections.length?`<div class="subh">Equipos infectados por infostealer (Hudson Rock)</div><table class="mini"><tr><th>Fecha</th><th>Familia de malware</th><th>Sistema</th><th>Credenciales robadas</th></tr>${r.infections.map(x=>`<tr><td>${esc(x.date||'—')}</td><td>${esc(x.family||'—')}</td><td>${esc(x.os||'—')}</td><td>${leakNum(x.corp+x.user)} (${leakNum(x.corp)} corporativas)</td></tr>`).join('')}</table>${mitStealerEmail(r)}`:'';
    const ctx={kind:'email',subject:r.email};
    const more=r.breaches.length>30?`<details class="help"><summary>Ver las otras ${r.breaches.length-30} filtraciones</summary>${leakBreachRows(r.breaches.slice(30),ctx)}</details>`:'';
    const brH=r.breaches.length?`<div class="subh">Filtraciones donde aparece (${r.breaches.length}) · abre "Mitigar" en cada una para ver qué hacer</div>${leakBreachRows(r.breaches.slice(0,30),ctx)}${more}`:'';
    const pasteH=r.pastes?`<p class="hint" data-s="margin-top:8px">También aparece en ${r.pastes} publicación(es) tipo <i>paste</i> según XposedOrNot.</p>`:'';
    const sub=r.breaches.length?r.breaches.length+' filtración(es)':r.infections.length?'Infostealer':'Sin hallazgos';
    return `<div class="section glass${out.length===1||r.status==='fail'?' open':''}" data-status="${r.status==='neutral'?'':r.status}" data-s="margin-top:11px"><div class="shead"><div class="sicon">${ico(r.infections.length?'bug':'mail')}</div><div class="stitle"><b class="lkemail">${esc(r.email)}</b><small>${esc(sub)}</small></div><div class="sledge"><span class="badge ${bc}"><span class="dot"></span>${bt}</span><span class="chev">▼</span></div></div><div class="sbody"><div class="sbodyin">${leakSrcChips(r.sources)}${infH}${brH}${pasteH}<div class="subh">Qué hacer</div>${leakFindings(leakEmailActions(r))}</div></div></div>`;
  }).join('');
  $('#leakOut').innerHTML=head+cards;
  $('#leakOut').querySelectorAll('.shead').forEach(h=>h.addEventListener('click',()=>h.parentElement.classList.toggle('open')));
  mitSummary();
  leakBindExports();
  $('#leakOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* --- Fuentes para entidades --- */
function leakKeyword(d,name){
  const p=d.split('.');const lbl=p.length>=3&&p[p.length-2].length<=3?p[p.length-3]:p[p.length-2]||'';
  const k=[];if(lbl&&lbl.length>=4)k.push(lbl);if(name&&name.trim().length>=4)k.push(name.trim());return k;
}
async function leakHibpDomain(d){
  try{const r=await leakGet('https://haveibeenpwned.com/api/v3/breaches?domain='+encodeURIComponent(d));
    if(!r.ok||!Array.isArray(r.j))throw new Error('HTTP '+r.status);
    return {state:r.j.length?'found':'none',breaches:r.j.map(hibpMap)};
  }catch(e){return {state:'error',err:leakErr(e),breaches:[]};}
}
async function leakXonDomain(d){
  try{const r=await leakGet('https://api.xposedornot.com/v1/breaches?domain='+encodeURIComponent(d));
    if(r.status===404)return {state:'none',breaches:[]};
    if(!r.ok||!r.j)throw new Error('HTTP '+r.status);
    const l=(r.j.exposedBreaches||r.j.Exposed_Breaches||[]).filter(b=>!b.domain||String(b.domain).toLowerCase()===d);
    return {state:l.length?'found':'none',breaches:l.map(b=>({name:b.breachID||b.breach,domain:b.domain||'',date:String(b.breachedDate||'').slice(0,10),records:+b.exposedRecords||0,data:Array.isArray(b.exposedData)?b.exposedData:String(b.exposedData||'').split(';').filter(Boolean),logo:b.logo||'',desc:leakText(b.exposureDescription),src:['XposedOrNot']}))};
  }catch(e){return {state:'error',err:leakErr(e),breaches:[]};}
}
async function leakHrDomain(d){
  try{const r=await leakGetCors('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain='+encodeURIComponent(d),'/hudsonrock?domain='+encodeURIComponent(d));
    if(!r.ok||!r.j)throw new Error('HTTP '+r.status);
    const j=r.j,dt=j.data||{};
    const urls=(a)=>(Array.isArray(a)?a:[]).map(u=>({url:u.url||'',n:+u.occurrence||0,type:u.type||''})).filter(u=>u.url).slice(0,12);
    const out={employees:+j.employees||0,users:+j.users||0,thirdParties:+j.third_parties||0,total:+j.total||0,lastEmployee:String(j.last_employee_compromised||'').slice(0,10),lastUser:String(j.last_user_compromised||'').slice(0,10),
      empUrls:urls(dt.employees_urls),userUrls:urls(dt.clients_urls),families:j.stealerFamilies&&typeof j.stealerFamilies==='object'?Object.entries(j.stealerFamilies).filter(([k])=>k!=='total').sort((a,b)=>b[1]-a[1]).slice(0,6):[]};
    out.state=out.employees||out.users||out.thirdParties?'found':'none';return out;
  }catch(e){return {state:'error',err:leakErr(e)};}
}
async function leakRansom(keys,d){
  if(!keys.length)return {state:'skip',victims:[]};
  try{const seen=new Map();let okAny=false,lastErr='';
    for(const k of keys){try{const r=await leakGetCors('https://api.ransomware.live/v2/searchvictims/'+encodeURIComponent(k),'/ransomware?q='+encodeURIComponent(k));
      if(!r.ok){lastErr=r.status===429?'demasiadas consultas seguidas; espera un minuto':'HTTP '+r.status;continue;}okAny=true;
      (Array.isArray(r.j)?r.j:[]).forEach(v=>{const name=v.victim||v.post_title||'';const web=String(v.website||'');
        const norm=s=>String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'');
        const hay=norm(name+' '+web);
        if(!hay.includes(norm(k))&&!hay.includes(d))return;
        const key=(name+'|'+(v.group||v.group_name||'')).toLowerCase();if(!seen.has(key))seen.set(key,{name,group:v.group||v.group_name||'',date:String(v.discovered||v.published||v.attackdate||'').slice(0,10),country:v.country||'',website:web,url:v.post_url||v.url||''});});
    }catch(e){lastErr=leakErr(e);}}
    if(!okAny)throw new Error(lastErr||'sin respuesta');
    const victims=[...seen.values()].sort((a,b)=>b.date.localeCompare(a.date));
    return {state:victims.length?'found':'none',victims};
  }catch(e){return {state:'error',err:leakErr(e),victims:[]};}
}

async function runLeakEntity(){
  const d=$('#leakEntity').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').replace(/^.*@/,'').replace(/\.$/,'');
  const name=$('#leakName').value.trim();
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)){alert('Ingresa el dominio de la entidad, por ejemplo tuentidad.gov.co');return;}
  $('#goLeakEntity').disabled=true;$('#leakOut').innerHTML='';
  try{
    leakSetStatus(true,'Consultando filtraciones del dominio '+d+'…',15);
    const keys=leakKeyword(d,name);
    const [hibp,xon,hr]=await Promise.all([leakHibpDomain(d),leakXonDomain(d),leakHrDomain(d)]);
    leakSetStatus(true,'Buscando la entidad en sitios de filtración de ransomware…',70);
    const rw=await leakRansom(keys,d);
    leakSetStatus(true,'Listo',100);
    const breaches=leakMerge([hibp.breaches,xon.breaches]);
    const res={domain:d,name,keywords:keys,breaches,infostealer:hr,ransomware:rw,sources:{'Have I Been Pwned':hibp,XposedOrNot:xon,'Hudson Rock':hr,'ransomware.live':rw}};
    LEAK.last={type:'entity',date:new Date().toISOString(),results:res};
    renderLeakEntity(res);
  }finally{$('#goLeakEntity').disabled=false;setTimeout(()=>leakSetStatus(false),400);}
}
function renderLeakEntity(r){
  const hr=r.infostealer,rw=r.ransomware;
  const emp=hr.employees||0,usr=hr.users||0,vic=(rw.victims||[]).length,br=r.breaches.length;
  const status=vic||emp?'fail':br||usr||hr.thirdParties?'warn':'ok';
  const col=status==='fail'?'var(--fail)':status==='warn'?'var(--warn)':'var(--ok)';
  const verdict=vic?'La entidad aparece en sitios de filtración de ransomware':emp?'Hay credenciales de empleados robadas por malware':br?'El dominio figura en filtraciones conocidas':usr?'Hay credenciales de usuarios del dominio robadas por malware':'Sin hallazgos en las fuentes consultadas';
  const sec=(icon,st,title,sub,body,open)=>{const[bc,bt]=BADGE[st]||BADGE.neutral;return `<div class="section glass${open?' open':''}" data-status="${st==='neutral'?'':st}" data-s="margin-top:11px"><div class="shead"><div class="sicon">${ico(icon)}</div><div class="stitle"><b>${esc(title)}</b><small>${esc(sub)}</small></div><div class="sledge"><span class="badge ${bc}"><span class="dot"></span>${bt}</span><span class="chev">▼</span></div></div><div class="sbody"><div class="sbodyin">${body}</div></div></div>`;};
  const stOf=s=>s.state==='found'?null:s.state==='error'?'neutral':s.state==='skip'?'neutral':'ok';
  // Ransomware
  const rwBody=rw.state==='skip'?'<p class="hint">Para buscar en sitios de ransomware escribe el nombre de la entidad (el dominio es demasiado corto para buscar por palabra clave).</p>':rw.state==='error'?`<p class="hint">No se pudo consultar ransomware.live: ${esc(rw.err)}.</p>`:vic?`<table class="mini"><tr><th>Víctima publicada</th><th>Grupo</th><th>Fecha</th><th>País</th></tr>${rw.victims.map(v=>`<tr><td>${/^https:\/\//.test(v.url)?`<a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer">${esc(v.name)}</a>`:esc(v.name)}${v.website?`<div class="hint">${esc(v.website)}</div>`:''}</td><td>${esc(v.group)}</td><td>${esc(v.date||'—')}</td><td>${esc(v.country||'—')}</td></tr><tr><td colspan="4" data-s="border-bottom:1px solid var(--line2)">${mitRansom(v,r)}</td></tr>`).join('')}</table><p class="hint" data-s="margin-top:8px">Coincidencias por palabra clave (${esc(r.keywords.join(', '))}); confirma que cada una corresponde realmente a tu entidad.</p>`:`<p class="hint">No hay publicaciones que coincidan con: ${esc(r.keywords.join(', '))}.</p>`;
  // Infostealers
  const urlT=(l,t)=>l&&l.length?`<div class="subh">${t}</div><table class="mini"><tr><th>URL</th><th>Credenciales</th></tr>${l.map(u=>`<tr><td data-s="word-break:break-all;font-family:var(--mono)">${esc(u.url)}</td><td>${leakNum(u.n)}</td></tr>`).join('')}</table>`:'';
  const hrBody=hr.state==='error'?`<p class="hint">No se pudo consultar Hudson Rock: ${esc(hr.err)}.</p>`:`<div class="lkstats"><div class="lkstat ${emp?'fail':'ok'}"><b>${leakNum(emp)}</b><span>Empleados comprometidos</span></div><div class="lkstat ${usr?'warn':'ok'}"><b>${leakNum(usr)}</b><span>Usuarios externos</span></div><div class="lkstat ${hr.thirdParties?'warn':'ok'}"><b>${leakNum(hr.thirdParties)}</b><span>Terceros</span></div></div>
    ${hr.lastEmployee||hr.lastUser?`<p class="hint" data-s="margin-top:10px">Última infección de empleado: <b>${esc(hr.lastEmployee||'—')}</b> · de usuario: <b>${esc(hr.lastUser||'—')}</b></p>`:''}
    ${hr.families&&hr.families.length?`<div class="subh">Familias de malware más frecuentes</div>${hr.families.map(([k,v])=>`<span class="tag">${esc(k)} · ${leakNum(v)}</span>`).join('')}`:''}
    ${urlT(hr.empUrls,'Accesos corporativos cuyas credenciales fueron robadas')}${urlT(hr.userUrls,'Accesos de usuarios/clientes cuyas credenciales fueron robadas')}
    ${emp||usr||hr.thirdParties?mitStealerEntity(r):''}`;
  // Filtraciones del sitio
  const brBody=br?leakBreachRows(r.breaches,{kind:'entity',subject:r.domain,r}):`<p class="hint">El dominio no figura como sitio vulnerado en Have I Been Pwned ni en XposedOrNot.</p>`;
  // Acciones
  const acts=[];
  if(vic)acts.push(['fail','Activar el plan de respuesta a incidentes','Un grupo de ransomware publicó a la entidad como víctima: suele implicar datos exfiltrados. Contacta al CSIRT de tu sector o a colCERT, preserva evidencias y evalúa la notificación a la autoridad de protección de datos (en Colombia, la SIC) si hay datos personales.']);
  if(emp)acts.push(['fail','Restablecer las credenciales de los empleados afectados','Fuerza el cambio de contraseña en los accesos listados, invalida sesiones y tokens, y revisa los equipos infectados con tu EDR/antivirus.']);
  if(usr)acts.push(['warn','Proteger las cuentas de usuarios externos','Activa MFA o verificación adicional en los portales listados y considera forzar el cambio de contraseña.']);
  if(br)acts.push(['warn','Revisar las filtraciones del propio dominio','Confirma que las cuentas afectadas cambiaron su contraseña y que la brecha fue cerrada.']);
  if(!acts.length)acts.push(['ok','Sin hallazgos en las fuentes consultadas','Repite la consulta periódicamente; puedes usar los enlaces de abajo para una investigación más profunda.']);
  acts.push(['info','Buscar los correos de la entidad uno a uno','En la pestaña "Correos comprometidos" puedes verificar hasta 25 cuentas a la vez.']);
  // Pivotes para investigación manual
  const q=encodeURIComponent;const piv=[
    ['Have I Been Pwned · búsqueda de dominio','https://haveibeenpwned.com/DomainSearch'],
    ['Intelligence X','https://intelx.io/?s='+q(r.domain)],
    ['DeHashed','https://dehashed.com/search?query='+q(r.domain)],
    ['LeakIX','https://leakix.net/domain/'+q(r.domain)],
    ['Google: filtraciones','https://www.google.com/search?q='+q('"'+r.domain+'" (filtración OR leak OR breach OR dump)')],
    ['Google: pastes','https://www.google.com/search?q='+q('"'+r.domain+'" site:pastebin.com OR site:ghostbin.com OR site:rentry.co')],
    ['Google: correos expuestos','https://www.google.com/search?q='+q('"@'+r.domain+'" filetype:txt OR filetype:csv OR filetype:sql OR filetype:xls')],
    ['GitHub: secretos','https://github.com/search?type=code&q='+q('"'+r.domain+'" password')],
  ];
  const pivH=`<div class="pivgrid">${piv.map(([t,u])=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${ico('link')}${esc(t)}</a>`).join('')}</div>
    <div class="mitsum" data-s="margin-top:12px">${ico('ban')}<span>¿Encontraste datos de la entidad publicados en alguna página?</span><button type="button" class="btn ghost" data-gotakedown data-s="margin-left:auto">${ico('ban')}<span class="t">Pedir la retirada del contenido</span></button></div>`;
  $('#leakOut').innerHTML=`<div class="glass phishcard"><div class="phverdict" data-s="color:${col}">${esc(verdict)}</div><div class="phurl">${esc(r.domain)}${r.name?' · '+esc(r.name):''} · ${new Date().toLocaleString('es-CO')}</div>
      <div class="lkstats"><div class="lkstat ${vic?'fail':'ok'}"><b>${vic}</b><span>Publicaciones ransomware</span></div><div class="lkstat ${emp?'fail':'ok'}"><b>${leakNum(emp)}</b><span>Empleados con infostealer</span></div><div class="lkstat ${usr?'warn':'ok'}"><b>${leakNum(usr)}</b><span>Usuarios con infostealer</span></div><div class="lkstat ${br?'warn':'ok'}"><b>${br}</b><span>Filtraciones del sitio</span></div></div>
      ${leakSrcChips(r.sources)}
      <div class="mitsum" id="leakMitSum" hidden></div>
      <div class="dashbtns"><button class="btn ghost" id="leakJson">${ico('download')}<span class="t">JSON</span></button><button class="btn ghost" id="leakCopy">${ico('copy')}<span class="t">Copiar resumen</span></button></div></div>
    ${sec('skull',vic?'fail':stOf(rw)||'ok','Sitios de filtración de ransomware','ransomware.live · grupos que publican datos robados',rwBody,!!vic)}
    ${sec('bug',emp?'fail':(usr||hr.thirdParties)?'warn':stOf(hr)||'ok','Credenciales robadas por infostealers','Hudson Rock · equipos infectados con accesos a '+r.domain,hrBody,!!(emp||usr))}
    ${sec('database',br?'warn':(stOf(r.sources['Have I Been Pwned'])==='neutral'&&stOf(r.sources.XposedOrNot)==='neutral'?'neutral':'ok'),'Filtraciones del sitio '+r.domain,'Have I Been Pwned · XposedOrNot',brBody,br>0)}
    ${sec('shield-check','info','Qué hacer','Acciones recomendadas según los hallazgos',leakFindings(acts),true)}
    ${sec('search','neutral','Investigación manual','Enlaces a otras fuentes (se abren en una pestaña nueva)',pivH,false)}`;
  $('#leakOut').querySelectorAll('.shead').forEach(h=>h.addEventListener('click',()=>h.parentElement.classList.toggle('open')));
  mitSummary();
  leakBindExports();
  $('#leakOut').scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ============================================================ Mitigación: acciones sobre cada sitio o hallazgo
   El avance (estado y pasos marcados) se guarda solo en este navegador, en localStorage. */
const MIT_KEY='ctn-leak-mit';
const MIT_STATES={pend:['Pendiente','b-warn'],prog:['En curso','b-info'],done:['Mitigado','b-ok']};
const LEAK_TPL={};let leakTplSeq=0;
function mitAll(){try{return JSON.parse(localStorage.getItem(MIT_KEY)||'{}')||{};}catch(e){return {};}}
function mitGet(k){const m=mitAll()[k];return m&&typeof m==='object'?{state:MIT_STATES[m.state]?m.state:'pend',steps:Array.isArray(m.steps)?m.steps:[]}:{state:'pend',steps:[]};}
function mitSave(k,m){try{const a=mitAll();a[k]={state:m.state,steps:m.steps,ts:new Date().toISOString()};localStorage.setItem(MIT_KEY,JSON.stringify(a));}catch(e){}}
const leakOrg=()=>{try{return localStorage.getItem('ctn-org')||'';}catch(e){return '';}};
const leakToday=()=>new Date().toLocaleDateString('es-CO',{year:'numeric',month:'long',day:'numeric'});
const leakSlug=s=>String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,40)||'hallazgo';
function mitPanel(key,o){
  const m=mitGet(key);const done=new Set(m.steps.filter(i=>i<o.steps.length));
  const [lbl,cls]=MIT_STATES[m.state];
  const steps=o.steps.map((s,i)=>`<label class="mitstep"><input type="checkbox" data-mitstep="${i}"${done.has(i)?' checked':''}><span><b>${esc(s[0])}</b>${s[1]?`<small>${esc(s[1])}</small>`:''}</span></label>`).join('');
  const links=(o.links||[]).filter(l=>l&&l[1]).map(([t,u,ic,tip])=>`<a class="btn ghost" href="${esc(u)}" target="_blank" rel="noopener noreferrer"${tip?` title="${esc(tip)}"`:''}>${ico(ic||'link')}<span class="t">${esc(t)}</span></a>`).join('');
  const tpls=(o.tpls||[]).map(t=>{const id='t'+(++leakTplSeq);LEAK_TPL[id]=t;return `<button type="button" class="btn ghost" data-tpl="${id}">${ico('file')}<span class="t">${esc(t.label)}</span></button>`;}).join('');
  return `<details class="mit" data-mitkey="${esc(key)}"${o.open?' open':''}><summary>${ico('shield-check')}<span>${esc(o.title||'Acciones de mitigación')}</span><span class="badge ${cls} mitbadge"><span class="dot"></span>${lbl}</span><span class="mitprog">${done.size}/${o.steps.length}</span></summary>
    <div class="mitbody"><div class="mitstate"><span class="hint">Estado</span><select class="rselect" data-mitstate aria-label="Estado de la mitigación">${Object.entries(MIT_STATES).map(([k,[l]])=>`<option value="${k}"${k===m.state?' selected':''}>${l}</option>`).join('')}</select></div>
    <div class="mitsteps">${steps}</div>${links?`<div class="mitlinks">${links}</div>`:''}${tpls?`<div class="mitlinks">${tpls}</div>`:''}<div class="mittpl" hidden></div></div></details>`;
}
function mitRefresh(p,m){
  const [lbl,cls]=MIT_STATES[m.state];const b=p.querySelector('.mitbadge');b.className='badge '+cls+' mitbadge';b.innerHTML='<span class="dot"></span>'+lbl;
  p.querySelector('.mitprog').textContent=p.querySelectorAll('[data-mitstep]:checked').length+'/'+p.querySelectorAll('[data-mitstep]').length;
  const sel=p.querySelector('[data-mitstate]');if(sel.value!==m.state)sel.value=m.state;
}
function mitSummary(){
  const el=$('#leakMitSum');if(!el)return;
  const ps=[...$('#leakOut').querySelectorAll('details.mit')];if(!ps.length){el.hidden=true;return;}
  const n=k=>ps.filter(p=>mitGet(p.dataset.mitkey).state===k).length;const done=n('done'),prog=n('prog'),pct=Math.round(done/ps.length*100);
  el.hidden=false;el.innerHTML=`${ico('shield-check')}<b>Plan de mitigación: ${done} de ${ps.length} hallazgos mitigados</b><span class="hint">${prog} en curso · ${ps.length-done-prog} pendientes</span><div class="rminibar"><span data-s="width:${pct}%"></span></div>`;
}
function mitStatusList(){return [...$('#leakOut').querySelectorAll('details.mit')].map(p=>{const m=mitGet(p.dataset.mitkey);return {hallazgo:p.querySelector('summary span').textContent,estado:MIT_STATES[m.state][0],pasos_completados:m.steps.length+'/'+p.querySelectorAll('[data-mitstep]').length};});}
/* Delegación: un solo manejador para todos los paneles, aunque se vuelvan a pintar los resultados */
$('#leakOut').addEventListener('change',e=>{
  const p=e.target.closest('details.mit');if(!p)return;const k=p.dataset.mitkey;const m=mitGet(k);
  if(e.target.matches('[data-mitstate]'))m.state=e.target.value;
  if(e.target.matches('[data-mitstep]')){
    m.steps=[...p.querySelectorAll('[data-mitstep]:checked')].map(x=>+x.dataset.mitstep);
    const total=p.querySelectorAll('[data-mitstep]').length;
    if(m.steps.length===total)m.state='done';else if(m.steps.length)m.state='prog';else if(m.state==='done')m.state='prog';
  }
  mitSave(k,m);mitRefresh(p,m);mitSummary();
});
$('#leakOut').addEventListener('click',e=>{
  const b=e.target.closest('[data-tpl]');
  if(b){const t=LEAK_TPL[b.dataset.tpl];if(!t)return;const box=b.closest('.mitbody,.tdbox').querySelector('.mittpl');box.hidden=false;
    const mail=t.to?`<a class="btn ghost" href="mailto:${encodeURIComponent(t.to)}?subject=${encodeURIComponent(t.subject||'')}&body=${encodeURIComponent(t.body.slice(0,1800))}">${ico('mail')}<span class="t">Abrir en mi correo${t.to.includes(',')?'':' ('+esc(t.to)+')'}</span></a>`:'';
    box.innerHTML=`<div class="hint"><b>${esc(t.label)}</b>${t.subject?' · Asunto: '+esc(t.subject):''} · Completa los campos entre [corchetes] antes de enviarla.</div><textarea class="code" rows="14" aria-label="${esc(t.label)}">${esc(t.body)}</textarea><div class="mitlinks"><button type="button" class="btn ghost" data-tplcopy>${ico('copy')}<span class="t">Copiar</span></button><button type="button" class="btn ghost" data-tpldl>${ico('download')}<span class="t">Descargar .txt</span></button>${mail}</div>`;
    box._t=t;box.querySelector('textarea').focus();return;}
  const c=e.target.closest('[data-tplcopy]');
  if(c){const box=c.closest('.mittpl');const txt=(box._t.subject?'Asunto: '+box._t.subject+'\n\n':'')+box.querySelector('textarea').value;navigator.clipboard.writeText(txt).then(()=>{btnTxt(c,'Copiada');setTimeout(()=>btnTxt(c,'Copiar'),1400);},()=>{box.querySelector('textarea').select();});return;}
  const d=e.target.closest('[data-tpldl]');
  if(d){const box=d.closest('.mittpl');downloadFile((box._t.fname||'plantilla')+'.txt',(box._t.subject?'Asunto: '+box._t.subject+'\n\n':'')+box.querySelector('textarea').value,'text/plain');}
});

/* --- Plantillas --- */
function tplErase(b,email){
  return {label:'Solicitud de supresión de datos',fname:'supresion-datos-'+leakSlug(b.name),subject:'Solicitud de supresión de datos personales – incidente de seguridad de '+b.name,
  body:`Señores
${b.name}${b.domain?' ('+b.domain+')':''}
Responsable del tratamiento de datos personales

Yo, [NOMBRE COMPLETO], titular de la cuenta asociada al correo ${email}, me dirijo a ustedes en ejercicio de mis derechos como titular de datos personales (artículo 8 de la Ley 1581 de 2012 de Colombia y, cuando aplique, artículos 15 y 17 del Reglamento General de Protección de Datos de la Unión Europea).

Según fuentes públicas de seguridad, mis datos aparecen en la filtración de ${b.name}${b.date?' ('+b.date+')':''}${b.data.length?', que habría expuesto: '+b.data.join(', '):''}.

Solicito:
1. Que me informen qué datos personales míos se vieron comprometidos y qué medidas tomaron para contener el incidente.
2. Que eliminen mi cuenta y todos mis datos personales, salvo los que deban conservar por obligación legal.
3. Que me confirmen por escrito la supresión realizada.

Recibiré la respuesta en: ${email}

Atentamente,

[NOMBRE COMPLETO]
[DOCUMENTO DE IDENTIDAD, solo si lo exigen para verificar la titularidad]
${leakToday()}`};
}
function tplUserAlert(b,email){
  const pw=b.data.some(d=>LEAK_PW.test(d));const org=leakOrg()||'[NOMBRE DE LA ENTIDAD]';
  return {label:'Aviso al titular de la cuenta',fname:'aviso-titular-'+leakSlug(b.name),to:email,subject:'Aviso de seguridad: tu cuenta aparece en una filtración de '+b.name,
  body:`Hola,

Te escribimos desde el equipo de seguridad de ${org}. Revisando fuentes públicas de filtraciones encontramos que el correo ${email} aparece en la filtración de ${b.name}${b.date?' ('+b.date+')':''}.
${b.data.length?'\nDatos expuestos: '+b.data.join(', ')+'.\n':''}
Te pedimos:
1. ${pw?'Cambiar la contraseña de ese servicio y de cualquier otro donde uses la misma.':'Cambiar la contraseña si usas la misma en otros servicios.'}
2. Activar la verificación en dos pasos en tu correo y en los servicios importantes.
3. Desconfiar de correos, SMS o llamadas que mencionen este servicio o te pidan datos.

Nadie de nuestro equipo te pedirá tu contraseña. Si tienes dudas, responde a este mensaje.

Equipo de seguridad
${org}`};
}
function tplSiteNotice(b,r){
  const org=r.name||leakOrg()||'[NOMBRE DE LA ENTIDAD]';
  return {label:'Comunicado a usuarios afectados',fname:'comunicado-'+leakSlug(b.name),subject:'Información sobre un incidente de seguridad en '+r.domain,
  body:`Estimado usuario:

${org} le informa que ${b.date?'el '+b.date+' ':''}se presentó un incidente de seguridad que afectó información de usuarios de ${r.domain}.
${b.data.length?'\nDatos que pudieron quedar expuestos: '+b.data.join(', ')+'.\n':''}
Qué hicimos:
- [DESCRIBA LAS MEDIDAS: corrección de la vulnerabilidad, cambio forzado de contraseñas, revisión de accesos].

Qué le recomendamos:
1. Cambiar su contraseña de ${r.domain} y la de cualquier servicio donde use la misma.
2. Activar la verificación en dos pasos si el servicio la ofrece.
3. Desconfiar de mensajes que digan venir de ${org} y le pidan datos o pagos. Nunca le pediremos su contraseña.

Para más información o para ejercer sus derechos como titular de datos personales (Ley 1581 de 2012) puede escribir a [CORREO DE CONTACTO].

${org}
${leakToday()}`};
}
function tplStealerUser(r){
  const org=leakOrg()||'[NOMBRE DE LA ENTIDAD]';const x=r.infections[0]||{};
  return {label:'Aviso al usuario del equipo infectado',fname:'aviso-infostealer-'+leakSlug(r.email),to:r.email,subject:'Urgente: tu equipo pudo estar infectado con malware que roba contraseñas',
  body:`Hola,

Te escribimos desde el equipo de seguridad de ${org}. Fuentes de inteligencia de amenazas indican que el correo ${r.email} estaba guardado en un equipo infectado por malware de tipo infostealer${x.date?' (infección registrada el '+x.date+(x.family?', familia '+x.family:'')+')':''}.

Este malware roba las contraseñas guardadas en el navegador, las cookies de sesión y los datos de autocompletado. Por eso te pedimos, en este orden:
1. No uses ese equipo para entrar a ninguna cuenta hasta que sea revisado.
2. Desde otro equipo o tu celular, cambia la contraseña de tu correo y de las cuentas importantes (banco, redes, accesos del trabajo).
3. Cierra todas las sesiones abiertas en esas cuentas y activa la verificación en dos pasos.
4. Lleva el equipo a soporte técnico para analizarlo o reinstalarlo.

Si usaste ese equipo para accesos de ${org}, avísanos respondiendo a este mensaje.

Equipo de seguridad
${org}`};
}
function tplStealerInternal(r){
  const hr=r.infostealer;const list=[...(hr.empUrls||[]),...(hr.userUrls||[])].map(u=>'- '+u.url+' ('+u.n+' credenciales)').join('\n');
  return {label:'Aviso interno a TI',fname:'aviso-ti-infostealer-'+leakSlug(r.domain),subject:'Credenciales de '+r.domain+' robadas por malware infostealer',
  body:`Para: Equipo de TI / Seguridad
De: [NOMBRE], [CARGO]
Fecha: ${leakToday()}

Según Hudson Rock, ${hr.employees||0} empleado(s) y ${hr.users||0} usuario(s) externo(s) de ${r.domain} tienen credenciales robadas por malware infostealer${hr.lastEmployee?' (última infección de empleado: '+hr.lastEmployee+')':''}.

Accesos afectados:
${list||'- [Sin detalle de URL]'}

Acciones solicitadas:
1. Forzar el cambio de contraseña y cerrar las sesiones en los accesos listados.
2. Exigir verificación en dos pasos en esos portales.
3. Revisar los registros de acceso desde la fecha de infección y reportar ingresos inusuales.
4. Identificar los equipos infectados con el EDR/antivirus y aislarlos.
5. Informar el avance a Seguridad antes del [FECHA LÍMITE].`};
}
function tplIncident(v,r){
  const org=r.name||leakOrg()||'[NOMBRE DE LA ENTIDAD]';
  return {label:'Reporte preliminar de incidente',fname:'reporte-incidente-'+leakSlug(r.domain),subject:'Reporte preliminar de incidente de seguridad – '+org,
  body:`REPORTE PRELIMINAR DE INCIDENTE DE SEGURIDAD
Fecha del reporte: ${leakToday()}

1. Entidad afectada: ${org}
   Dominio: ${r.domain}
   Contacto: [NOMBRE, CARGO, TELÉFONO, CORREO]

2. Descripción
   El grupo de ransomware "${v.group||'[GRUPO]'}" publicó a la entidad como víctima en su sitio de filtraciones${v.date?' el '+v.date:''}.
   Nombre publicado: ${v.name}
   Fuente de detección: ransomware.live${/^https:\/\//.test(v.url)?' – '+v.url:''}

3. Alcance conocido
   - Sistemas afectados: [POR DETERMINAR]
   - Datos posiblemente exfiltrados: [POR DETERMINAR]
   - ¿Incluye datos personales?: [SÍ / NO / POR DETERMINAR]

4. Acciones tomadas
   - [Activación del plan de respuesta a incidentes]
   - [Aislamiento de sistemas]
   - [Preservación de evidencias]

5. Apoyo solicitado
   [Describa el apoyo que requiere del CSIRT o de la autoridad]`};
}
function tplComms(v,r){
  const org=r.name||leakOrg()||'[NOMBRE DE LA ENTIDAD]';
  return {label:'Comunicado a titulares',fname:'comunicado-titulares-'+leakSlug(r.domain),subject:'Información importante sobre un incidente de seguridad en '+org,
  body:`Estimado ciudadano / usuario:

${org} informa que fue víctima de un ataque informático${v.date?' detectado alrededor del '+v.date:''}. Estamos investigando el alcance con el apoyo de las autoridades competentes.

Es posible que se hayan visto comprometidos los siguientes datos: [DESCRIBA LOS DATOS].

Le recomendamos:
1. Desconfiar de correos, llamadas o mensajes que digan venir de ${org} y le pidan datos, contraseñas o pagos.
2. Cambiar la contraseña de su cuenta en ${r.domain} y de cualquier servicio donde use la misma.
3. Reportarnos cualquier actividad sospechosa en [CANAL DE CONTACTO].

Le mantendremos informado. Para ejercer sus derechos como titular de datos personales (Ley 1581 de 2012) escriba a [CORREO].

${org}
${leakToday()}`};
}

/* --- Pasos de mitigación por tipo de hallazgo --- */
function mitBreach(b,ctx){
  const has=re=>b.data.some(d=>re.test(d));
  const site=b.domain?'https://'+b.domain:'';
  const steps=[];
  if(ctx.kind==='entity'){
    steps.push(['Confirmar que la brecha está cerrada','Verifica con TI o el proveedor que se corrigió la falla que permitió la filtración'+(b.date?' ('+b.date+')':'')+'.']);
    if(has(LEAK_PW))steps.push(['Forzar el cambio de contraseña de las cuentas afectadas','Invalida también las sesiones y tokens emitidos antes del incidente.']);
    steps.push(['Notificar a los titulares afectados','Explica qué datos salieron y qué deben hacer. Usa la plantilla de comunicado.']);
    steps.push(['Evaluar el reporte a la autoridad de protección de datos','En Colombia los incidentes con datos personales se reportan a la SIC.']);
    steps.push(['Documentar el incidente y las lecciones aprendidas','']);
    return mitPanel('d:'+ctx.subject+':breach:'+b.name.toLowerCase(),{title:'Mitigar '+b.name,steps,links:[['SIC – Protección de datos','https://www.sic.gov.co/','building']],tpls:[tplSiteNotice(b,ctx.r)]});
  }
  if(has(LEAK_PW))steps.push(['Cambiar la contraseña en '+b.name,'Usa una contraseña nueva y única.']);
  steps.push(['Cambiar la contraseña donde se haya reutilizado','Si usabas la misma en otros servicios (correo, banco, redes), cámbiala también allí.']);
  steps.push(['Activar la verificación en dos pasos',(b.domain?'En '+b.name+' si la ofrece, y s':'S')+'obre todo en el correo '+ctx.subject+'.']);
  if(has(/phone|tel[eé]fono/i))steps.push(['Protegerse de SMS y llamadas fraudulentas','Pide a tu operador bloquear la portabilidad y el duplicado de SIM sin verificación presencial.']);
  if(has(/credit|card|bank|tarjeta|banc|financ|payment|pago/i))steps.push(['Avisar al banco','Pide bloquear o reemplazar la tarjeta y revisa los movimientos recientes.']);
  if(has(/birth|nacimiento|government|passport|national id|identidad|address|direcci[oó]n|ssn/i))steps.push(['Vigilar posibles suplantaciones de identidad','Revisa tu historial en las centrales de riesgo y desconfía de solicitudes a tu nombre.']);
  if(has(/security question|hint|pregunta|pista/i))steps.push(['Cambiar las preguntas de seguridad y pistas','Las respuestas filtradas permiten recuperar la cuenta.']);
  steps.push(['Solicitar la eliminación de la cuenta si ya no la usas','Usa la plantilla de solicitud de supresión de datos.']);
  const links=site?[['Ir al sitio',site,'globe'],['Cambiar contraseña',site+'/.well-known/change-password','key','Abre la página de cambio de contraseña si el sitio la publica en la dirección estándar'],['Contacto de seguridad',site+'/.well-known/security.txt','shield','Archivo security.txt con el contacto de seguridad, si existe'],['Buscar su política de privacidad','https://www.google.com/search?q='+encodeURIComponent('site:'+b.domain+' (privacidad OR privacy OR "protección de datos")'),'search']]:[];
  return mitPanel('e:'+ctx.subject+':breach:'+b.name.toLowerCase(),{title:'Mitigar '+b.name,steps,links,tpls:[tplErase(b,ctx.subject),tplUserAlert(b,ctx.subject)]});
}
function mitStealerEmail(r){
  const dom=(r.email.split('@')[1]||'').toLowerCase();
  const links=/^(gmail|googlemail)\.com$/.test(dom)?[['Revisión de seguridad de Google','https://myaccount.google.com/security-checkup','shield'],['Dispositivos con sesión abierta','https://myaccount.google.com/device-activity','key']]:
    /^(outlook|hotmail|live|msn)\.[a-z.]+$/.test(dom)?[['Seguridad de la cuenta Microsoft','https://account.microsoft.com/security','shield'],['Actividad reciente','https://account.live.com/Activity','key']]:
    /^(yahoo|ymail)\.[a-z.]+$/.test(dom)?[['Seguridad de Yahoo','https://login.yahoo.com/account/security','shield']]:[];
  const steps=[
    ['Desconectar el equipo infectado de la red','Evita que el malware siga enviando datos.'],
    ['Analizar el equipo con un antivirus actualizado o reinstalarlo','Un infostealer puede dejar otros programas maliciosos; reinstalar es lo más seguro.'],
    ['Cambiar las contraseñas guardadas en el navegador desde un equipo limpio','Empieza por el correo, el banco y los accesos del trabajo.'],
    ['Cerrar todas las sesiones activas y revocar accesos de aplicaciones','El malware roba cookies de sesión que permiten entrar sin contraseña.'],
    ['Activar la verificación en dos pasos en las cuentas principales',''],
    ['Revisar reglas de reenvío y filtros del correo','Los atacantes crean reglas para reenviar o esconder correos.'],
    ['Dejar de guardar contraseñas en el navegador','Usa un gestor de contraseñas.'],
  ];
  if(r.infections.some(x=>x.corp>0))steps.splice(3,0,['Avisar al equipo de TI o de seguridad de la organización','La infección incluye credenciales corporativas.']);
  return mitPanel('e:'+r.email+':infostealer',{title:'Mitigar la infección por infostealer',steps,links,tpls:[tplStealerUser(r)],open:true});
}
function mitStealerEntity(r){
  const hr=r.infostealer;
  const urls=[...(hr.empUrls||[]).map(u=>['Acceso corporativo',u]),...(hr.userUrls||[]).map(u=>['Acceso de usuarios o clientes',u])];
  const steps=[['Identificar a los empleados y equipos afectados','Cruza los hallazgos con tu EDR/antivirus y con los registros de acceso.'],
    ...urls.map(([t,u])=>['Restablecer credenciales y sesiones de '+u.url,t+' · '+leakNum(u.n)+' credencial(es) robada(s)']),
    ['Exigir verificación en dos pasos en los portales afectados',''],
    ['Revisar los registros de acceso desde la fecha de infección','Busca ingresos desde IP o países inusuales'+(hr.lastEmployee||hr.lastUser?' (desde '+(hr.lastEmployee||hr.lastUser)+')':'')+'.'],
    ['Capacitar a los usuarios sobre descargas riesgosas','Los infostealers se distribuyen sobre todo en programas piratas, extensiones y anuncios falsos.']];
  return mitPanel('d:'+r.domain+':infostealer',{title:'Mitigar credenciales robadas',steps,links:[['Herramientas de Hudson Rock','https://www.hudsonrock.com/free-tools','bug']],tpls:[tplStealerInternal(r)],open:true});
}
function mitRansom(v,r){
  const steps=[['Confirmar que la publicación corresponde a la entidad','Revisa la ficha sin descargar los archivos publicados.'],
    ['Activar el plan de respuesta a incidentes','Convoca a TI, jurídica, comunicaciones y dirección.'],
    ['Aislar los sistemas comprometidos y preservar evidencias','Guarda registros, capturas con fecha y hora y la URL de la publicación. No borres ni reinstales antes de recoger evidencia.'],
    ['No pagar ni negociar sin asesoría','Pagar no garantiza que borren los datos y financia al grupo.'],
    ['Reportar el incidente a colCERT o al CSIRT de tu sector','Usa la plantilla de reporte preliminar.'],
    ['Denunciar ante la Policía Nacional','A través del CAI Virtual.'],
    ['Evaluar el reporte a la SIC si hay datos personales',''],
    ['Comunicar a los titulares afectados','Usa la plantilla de comunicado.'],
    ['Cambiar credenciales privilegiadas y revisar accesos remotos','VPN, escritorio remoto y cuentas de administrador suelen ser la vía de entrada.']];
  const links=[/^https:\/\//.test(v.url)?['Ver la ficha en ransomware.live',v.url,'skull']:null,['colCERT','https://www.colcert.gov.co/','shield'],['CAI Virtual – Policía','https://caivirtual.policia.gov.co/','shield-alert'],['SIC – Protección de datos','https://www.sic.gov.co/','building']].filter(Boolean);
  return mitPanel('d:'+r.domain+':rw:'+(v.name+'|'+v.group).toLowerCase(),{title:'Responder a la publicación de '+(v.group||'ransomware'),steps,links,tpls:[tplIncident(v,r),tplComms(v,r)],open:true});
}

/* ============================================================ Retirar contenido publicado (takedown) */
const TD_PLATFORMS=[
  [/(^|\.)(github\.com|githubusercontent\.com)$/,'GitHub','https://support.github.com/contact/private-information','Formulario para retirar información privada o credenciales publicadas.'],
  [/(^|\.)(google\.com|googleusercontent\.com)$/,'Google (Drive, Docs, Sites)','https://support.google.com/legal/answer/3110420','Solicitud legal de retirada de contenido.'],
  [/(^|\.)(t\.me|telegram\.org|telegram\.me)$/,'Telegram','','Escribe a abuse@telegram.org con el enlace exacto del canal o del mensaje.','abuse@telegram.org'],
  [/(^|\.)pastebin\.com$/,'Pastebin','https://pastebin.com/contact','Usa el formulario de contacto o el botón de reporte del propio paste.'],
  [/(^|\.)mega\.(nz|io)$/,'MEGA','https://mega.io/takedown','Formulario de retirada de contenido.'],
];
const TD_KIND={cred:'usuarios y contraseñas de acceso',pii:'datos personales de ciudadanos o clientes',docs:'documentos internos de la entidad',db:'una base de datos completa de la entidad'};
async function tdRdap(url){
  const r=await fetch(url,{headers:{Accept:'application/rdap+json'}});if(!r.ok)throw new Error('HTTP '+r.status);const j=await r.json();
  let abuse='',org='';
  const scan=en=>{const vc=en.vcardArray&&en.vcardArray[1];const roles=en.roles||[];
    if(roles.includes('abuse')&&!abuse){const em=vc&&vc.find(x=>x[0]==='email');if(em)abuse=String(em[3]);}
    if((roles.includes('registrar')||roles.includes('registrant'))&&!org){const fn=vc&&vc.find(x=>x[0]==='fn');if(fn)org=String(fn[3]);}
    (en.entities||[]).forEach(scan);};
  (j.entities||[]).forEach(scan);
  return {abuse,org,net:j.name||'',country:j.country||''};
}
async function tdRdapAny(kind,q){
  try{return await tdRdap('https://rdap.org/'+kind+'/'+encodeURIComponent(q));}
  catch(e){const b=leakBackend();if(!b)throw e;return tdRdap(b+'/rdap?'+kind+'='+encodeURIComponent(q));}
}
function tplTakedown(u,kind,to){
  const org=leakOrg()||'[NOMBRE DE LA ENTIDAD]';
  return {label:'Solicitud de retirada (español e inglés)',fname:'solicitud-retirada-'+leakSlug(u.hostname),to,subject:'Solicitud urgente de retirada de contenido / Urgent takedown request – '+u.hostname,
  body:`Señores equipo de abuso / Abuse team:

Escribo en representación de ${org} para solicitar la retirada inmediata del siguiente contenido, que publica ${TD_KIND[kind]} sin autorización:

URL: ${u.href}
Fecha en que lo detectamos: ${leakToday()}

La publicación expone información obtenida de forma ilícita y pone en riesgo a las personas afectadas. Su difusión vulnera la Ley 1581 de 2012 de protección de datos personales de Colombia y los términos de uso de su servicio.

Solicitamos:
1. Retirar o bloquear el contenido lo antes posible.
2. Conservar los registros asociados (cuenta que lo publicó, direcciones IP, fechas) por si las autoridades los requieren.
3. Confirmarnos la acción tomada a este correo.

---

To the abuse team:

On behalf of ${org}, I request the immediate removal of the content at the URL above, which publishes ${kind==='cred'?'stolen login credentials':kind==='pii'?'personal data of citizens or customers':kind==='docs'?'internal documents of our organization':'a complete database belonging to our organization'} without authorization. Please remove or disable access to it, preserve the related logs (uploader account, IP addresses, timestamps) for law enforcement, and confirm the action taken.

[NOMBRE / NAME]
[CARGO / TITLE]
${org}
[TELÉFONO / PHONE] · [CORREO / EMAIL]`};
}
async function runTakedown(){
  let raw=$('#tdUrl').value.trim();if(raw&&!/^https?:\/\//i.test(raw))raw='https://'+raw;
  let u;try{u=new URL(raw);}catch(e){alert('Ingresa la dirección completa de la página, por ejemplo https://pastebin.com/abc123');return;}
  const host=u.hostname.toLowerCase().replace(/^www\./,'');const reg=registrable(host);const kind=$('#tdKind').value;
  $('#goTakedown').disabled=true;$('#leakOut').innerHTML='';
  try{
    leakSetStatus(true,'Buscando quién registra '+reg+'…',25);
    let dom=null,domErr='';try{dom=await tdRdapAny('domain',reg);}catch(e){domErr=leakErr(e);}
    leakSetStatus(true,'Buscando quién aloja el servidor…',60);
    let ip='',net=null,netErr='';
    try{const q=await query(host,'A');ip=(q.answers.find(a=>/^\d+\.\d+\.\d+\.\d+$/.test(a.data))||{}).data||'';}catch(e){}
    if(ip){try{net=await tdRdapAny('ip',ip);}catch(e){netErr=leakErr(e);}}else netErr='no se pudo resolver la IP del servidor';
    leakSetStatus(true,'Listo',100);
    const plat=TD_PLATFORMS.find(p=>p[0].test(host));
    const cf=!!(net&&/cloudflare/i.test((net.net||'')+' '+(net.org||'')+' '+(net.abuse||'')));
    const emails=[plat&&plat[4],net&&net.abuse,dom&&dom.abuse].filter(Boolean);
    const to=[...new Set(emails)].join(',');
    const tile=(title,val,sub,links)=>`<div class="geotile"><div class="lbl">${esc(title)}</div><div class="val">${val}</div>${sub?`<div class="hint">${sub}</div>`:''}${links?`<div class="mitlinks">${links}</div>`:''}</div>`;
    const a=(t,h,ic)=>`<a class="btn ghost" href="${esc(h)}" target="_blank" rel="noopener noreferrer">${ico(ic||'link')}<span class="t">${esc(t)}</span></a>`;
    const who=[
      plat?tile('1 · Plataforma',esc(plat[1]),esc(plat[3]),plat[2]?a('Formulario oficial',plat[2],'file'):''):tile('1 · Plataforma',esc(host),'No es una plataforma conocida: pide la retirada al hosting y al registrador.',''),
      tile('2 · Proveedor de hosting',net?esc(net.net||net.org||'Desconocido')+(net.country?' <small>('+esc(net.country)+')</small>':''):'No disponible',net?(net.abuse?'Contacto de abuso: <b>'+esc(net.abuse)+'</b>':'Sin correo de abuso publicado')+(ip?' · IP '+esc(ip):'')+(cf?'. Cloudflare solo hace de intermediario: usa su formulario y ellos reenvían la queja al hosting real.':''):esc(netErr),cf?a('Formulario de abuso de Cloudflare','https://abuse.cloudflare.com/','file'):''),
      tile('3 · Registrador del dominio',dom?esc(dom.org||'Desconocido'):'No disponible',dom?(dom.abuse?'Contacto de abuso: <b>'+esc(dom.abuse)+'</b>':'Sin correo de abuso publicado'):esc(domErr)+' · puedes consultarlo en ICANN',dom?'':a('Buscar en ICANN','https://lookup.icann.org/en/lookup?name='+encodeURIComponent(reg),'search')),
      tile('4 · Buscadores','Google y Bing','Pide que dejen de mostrar la página en los resultados.',a('Google','https://support.google.com/websearch/answer/9673730','search')+a('Bing','https://www.bing.com/webmasters/tools/contentremoval','search')),
    ].join('');
    const steps=[['Guardar evidencia sin redistribuir los datos','Toma capturas de pantalla con fecha y hora y anota la URL. No descargues ni reenvíes el contenido.'],
      plat?['Reportar a '+plat[1],plat[3]]:null,
      ['Pedir la retirada al proveedor de hosting',cf?'Usa el formulario de abuso de Cloudflare.':net&&net.abuse?'Escribe a '+net.abuse+'.':'Busca el contacto de abuso del proveedor.'],
      ['Pedir la retirada al registrador del dominio',dom&&dom.abuse?'Escribe a '+dom.abuse+'.':'Consulta el contacto en ICANN.'],
      ['Solicitar la desindexación en Google y Bing',''],
      kind==='cred'?['Cambiar las credenciales expuestas','Fuerza el cambio de contraseña y cierra las sesiones de las cuentas publicadas.']:['Notificar a los titulares afectados','Informa qué datos se publicaron y cómo protegerse.'],
      ['Reportar a colCERT y denunciar ante la Policía (CAI Virtual)',''],
      ['Verificar en unos días que el contenido ya no está disponible','']].filter(Boolean);
    LEAK.last={type:'takedown',date:new Date().toISOString(),results:{url:u.href,host,registeredDomain:reg,kind,ip,platform:plat?plat[1]:'',hosting:net,registrar:dom,contacts:emails}};
    $('#leakOut').innerHTML=`<div class="glass phishcard tdbox"><div class="phverdict">A quién pedir la retirada</div><div class="phurl">${esc(u.href)}</div>
      <div class="tdwho">${who}</div>
      <div class="mitlinks" data-s="margin-top:14px"><button type="button" class="btn" data-tpl="${(()=>{const id='t'+(++leakTplSeq);LEAK_TPL[id]=tplTakedown(u,kind,to);return id;})()}">${ico('file')}<span class="t">Preparar la solicitud de retirada</span></button><a class="btn ghost" href="https://www.colcert.gov.co/" target="_blank" rel="noopener noreferrer">${ico('shield')}<span class="t">colCERT</span></a><a class="btn ghost" href="https://caivirtual.policia.gov.co/" target="_blank" rel="noopener noreferrer">${ico('shield-alert')}<span class="t">CAI Virtual</span></a></div>
      <div class="mittpl" hidden></div>
      <div class="mitsum" id="leakMitSum" hidden></div>
      ${mitPanel('td:'+u.href,{title:'Seguimiento de la retirada',steps,open:true})}</div>`;
    mitSummary();
    $('#leakOut').scrollIntoView({behavior:'smooth',block:'nearest'});
  }finally{$('#goTakedown').disabled=false;setTimeout(()=>leakSetStatus(false),400);}
}

/* --- Exportar --- */
function leakSummary(){
  const base=leakSummaryBase();const m=mitStatusList();
  return m.length?base+'\n\nPlan de mitigación:\n'+m.map(x=>`• ${x.hallazgo}: ${x.estado} (${x.pasos_completados} pasos)`).join('\n'):base;
}
function leakSummaryBase(){
  const L=LEAK.last;if(!L)return '';
  if(L.type==='takedown'){const t=L.results;return `Centinela — Retirada de contenido (${new Date(L.date).toLocaleString('es-CO')})\n• URL: ${t.url}\n• Plataforma: ${t.platform||t.host}\n• Contactos de abuso: ${t.contacts.join(', ')||'no encontrados'}`;}
  if(L.type==='email')return 'Centinela — Correos comprometidos ('+new Date(L.date).toLocaleString('es-CO')+')\n'+L.results.map(r=>`• ${r.email}: ${(BADGE[r.status]||BADGE.neutral)[1]} · ${r.breaches.length} filtración(es)${r.breaches.length?' ('+r.breaches.map(b=>b.name).join(', ')+')':''}${r.infections.length?' · INFOSTEALER ('+r.infections.length+')':''}${r.passwordExposed?' · contraseña expuesta':''}`).join('\n');
  const r=L.results;return `Centinela — Filtraciones de ${r.domain}${r.name?' ('+r.name+')':''} (${new Date(L.date).toLocaleString('es-CO')})\n• Publicaciones en sitios de ransomware: ${(r.ransomware.victims||[]).length}${(r.ransomware.victims||[]).length?' ('+r.ransomware.victims.map(v=>v.group+' '+v.date).join(', ')+')':''}\n• Empleados con credenciales robadas (infostealer): ${r.infostealer.employees||0}\n• Usuarios con credenciales robadas (infostealer): ${r.infostealer.users||0}\n• Filtraciones del sitio: ${r.breaches.length}${r.breaches.length?' ('+r.breaches.map(b=>b.name+' '+b.date).join(', ')+')':''}`;
}
function leakBindExports(){
  const L=LEAK.last;const tag=L.type==='email'?'correos':L.results.domain;
  const j=$('#leakJson');if(j)j.addEventListener('click',()=>downloadFile('filtraciones-'+tag+'.json',JSON.stringify({...L,mitigacion:mitStatusList()},null,2),'application/json'));
  const c=$('#leakCsv');if(c)c.addEventListener('click',()=>{const rows=[['correo','estado','filtraciones','nombres_filtraciones','infostealer','contraseña_expuesta']].concat(L.results.map(r=>[r.email,r.status,r.breaches.length,r.breaches.map(b=>b.name).join(' | '),r.infections.length,r.passwordExposed?'si':'no']));downloadFile('filtraciones-correos.csv','﻿'+rows.map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\n'),'text/csv');});
  const p=$('#leakCopy');if(p)p.addEventListener('click',()=>{try{navigator.clipboard.writeText(leakSummary());btnTxt(p,'Copiado');setTimeout(()=>btnTxt(p,'Copiar resumen'),1400);}catch(e){}});
}
function leakTab(t){
  const ids={email:'Email',entity:'Entity',takedown:'Takedown'};
  Object.entries(ids).forEach(([x,n])=>{const b=$('#leakTab'+n);const on=x===t;b.classList.toggle('active',on);b.setAttribute('aria-selected',on?'true':'false');$('#leak'+n+'Pane').hidden=!on;});
}
$('#leakTabEmail').addEventListener('click',()=>leakTab('email'));
$('#leakTabEntity').addEventListener('click',()=>leakTab('entity'));
$('#leakTabTakedown').addEventListener('click',()=>leakTab('takedown'));
$('#goTakedown').addEventListener('click',runTakedown);
$('#tdUrl').addEventListener('keydown',e=>{if(e.key==='Enter')runTakedown();});
$('#leakOut').addEventListener('click',e=>{if(e.target.closest('[data-gotakedown]')){leakTab('takedown');$('#modeLeakWrap').scrollIntoView({behavior:'smooth',block:'start'});setTimeout(()=>$('#tdUrl').focus(),300);}});
$('#goLeakEmail').addEventListener('click',runLeakEmail);
$('#goLeakEntity').addEventListener('click',runLeakEntity);
['#leakEntity','#leakName'].forEach(s=>$(s).addEventListener('keydown',e=>{if(e.key==='Enter')runLeakEntity();}));
$('#leakEmails').addEventListener('keydown',e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey))runLeakEmail();});
$('#mbLeak').addEventListener('click',()=>setMode('leak'));

function setMode(m){document.querySelectorAll('.modebtn').forEach(b=>{const on=b.dataset.mode===m;b.classList.toggle('active',on);if(on)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});['home','domain','phish','geo','cmp','recon','vuln','ioc','cases','report','eml','sbx','leak','mon','tools','tls','headers','gen'].forEach(x=>{const w=$('#mode'+x.charAt(0).toUpperCase()+x.slice(1)+'Wrap');if(w)w.style.display=m===x?'':'none';});if(m==='mon')renderMon();if(m==='gen')initGenProviders();if(m==='home'&&typeof renderHome==='function')renderHome();if(m==='cases'&&typeof renderCases==='function')renderCases();}
$('#mbTools').addEventListener('click',()=>setMode('tools'));
$('#mbHeaders').addEventListener('click',()=>setMode('headers'));
$('#mbGen').addEventListener('click',()=>{setMode('gen');});
$('#goHdr').addEventListener('click',runHeaders);
$('#hdrUrl').addEventListener('keydown',e=>{if(e.key==='Enter')runHeaders();});
$('#goGen').addEventListener('click',runGen);
$('#pwdShow').addEventListener('click',()=>{const i=$('#pwdInput');i.type=i.type==='password'?'text':'password';});
$('#pwdInput').addEventListener('input',renderStrength);
$('#pwdCheck').addEventListener('click',async()=>{
  const p=$('#pwdInput').value;if(!p){$('#pwdOut').innerHTML='';return;}
  $('#pwdOut').innerHTML='<span class="hint">Consultando…</span>';
  try{const n=await hibp(p);
    $('#pwdOut').innerHTML=n>0
      ?`<div class="findings"><li class="f-fail"><span class="ic">✕</span><div><b>Filtrada: aparece ${n.toLocaleString('es-CO')} vez/veces en brechas conocidas</b><span class="why">No la uses. Cámbiala en cualquier sitio donde la tengas.</span></div></li></div>`
      :`<div class="findings"><li class="f-ok"><span class="ic">✓</span><div><b>No aparece en las brechas de Have I Been Pwned</b><span class="why">No garantiza que sea fuerte; revisa el medidor de arriba.</span></div></li></div>`;
  }catch(e){$('#pwdOut').innerHTML='<span class="hint">No se pudo consultar (revisa tu conexión).</span>';}
});
$('#genLen').addEventListener('input',()=>$('#genLenVal').textContent=$('#genLen').value);
$('#genBtn').addEventListener('click',()=>{$('#genOut').innerHTML=raw(genPwd());});
$('#genPhrase').addEventListener('click',()=>{$('#genOut').innerHTML=raw(genPhrase());});
document.querySelectorAll('[data-hash]').forEach(b=>b.addEventListener('click',async()=>{
  const t=$('#hashIn').value;if(!t){$('#hashOut').innerHTML='';return;}
  try{const h=await sha(b.dataset.hash,t);$('#hashOut').innerHTML=`<div class="hint" data-s="margin-bottom:3px">${b.dataset.hash}:</div>`+raw(h);}catch(e){$('#hashOut').innerHTML='<span class="hint">Error: '+esc(e.message)+'</span>';}
}));
document.querySelectorAll('[data-enc]').forEach(b=>b.addEventListener('click',()=>{
  const t=$('#hashIn').value;let out='';
  try{
    if(b.dataset.enc==='b64e')out=btoa(unescape(encodeURIComponent(t)));
    else if(b.dataset.enc==='b64d')out=decodeURIComponent(escape(atob(t.trim())));
    else if(b.dataset.enc==='urle')out=encodeURIComponent(t);
    else if(b.dataset.enc==='urld')out=decodeURIComponent(t);
    $('#hashOut').innerHTML=raw(out);
  }catch(e){$('#hashOut').innerHTML='<span class="hint">Entrada inválida para esa operación.</span>';}
}));
$('#jwtBtn').addEventListener('click',()=>{
  try{const d=jwtDecode($('#jwtIn').value);
    const exp=d.payload.exp?new Date(d.payload.exp*1000):null;
    const expTxt=exp?(exp<new Date()?'<span data-s="color:var(--fail)">EXPIRADO ('+exp.toLocaleString('es-CO')+')</span>':'<span data-s="color:var(--ok)">válido hasta '+exp.toLocaleString('es-CO')+'</span>'):'sin exp';
    $('#jwtOut').innerHTML=`<div class="subh">Header</div>${raw(JSON.stringify(d.header,null,2))}<div class="subh">Payload</div>${raw(JSON.stringify(d.payload,null,2))}<div class="hint" data-s="margin-top:6px">Algoritmo: <b>${esc(d.header.alg||'?')}</b> · Expiración: ${expTxt}${d.header.alg==='none'?' · <span data-s="color:var(--fail)">alg=none es inseguro</span>':''}</div>`;
  }catch(e){$('#jwtOut').innerHTML='<span class="hint">'+esc(e.message)+'</span>';}
});
$('#mbDomain').addEventListener('click',()=>setMode('domain'));
$('#mbPhish').addEventListener('click',()=>setMode('phish'));
$('#mbGeo').addEventListener('click',()=>setMode('geo'));
$('#mbCmp').addEventListener('click',()=>setMode('cmp'));
$('#mbRecon').addEventListener('click',()=>setMode('recon'));
$('#mbVuln').addEventListener('click',()=>setMode('vuln'));
$('#mbReport').addEventListener('click',()=>setMode('report'));
$('#mbEml').addEventListener('click',()=>setMode('eml'));
$('#mbSbx').addEventListener('click',()=>setMode('sbx'));
$('#mbMon').addEventListener('click',()=>setMode('mon'));
$('#goCmp').addEventListener('click',runCompare);
$('#goRecon').addEventListener('click',runRecon);
$('#reconInput').addEventListener('keydown',e=>{if(e.key==='Enter')runRecon();});
$('#goVuln').addEventListener('click',runVuln);
$('#vulnInput').addEventListener('keydown',e=>{if(e.key==='Enter')runVuln();});
$('#goReport').addEventListener('click',runReport);
$('#reportInput').addEventListener('keydown',e=>{if(e.key==='Enter')runReport();});
$('#goEml').addEventListener('click',analyzeEml);
$('#monAdd').addEventListener('click',monAddDomain);
$('#monInput').addEventListener('keydown',e=>{if(e.key==='Enter')monAddDomain();});
$('#monRun').addEventListener('click',()=>monRunAll(false));
$('#monNotif').addEventListener('click',()=>{if('Notification'in window)Notification.requestPermission().then(p=>{btnTxt('#monNotif',p==='granted'?'Notificaciones activas':'Activar notificaciones');});});
$('#monEvery').addEventListener('change',()=>{if(MON_TIMER){clearInterval(MON_TIMER);MON_TIMER=null;}const min=parseInt($('#monEvery').value);if(min>0){MON_TIMER=setInterval(()=>monRunAll(true),min*60000);monRunAll(false);}});
$('#goPhish').addEventListener('click',analyzePhish);
$('#phishUrl').addEventListener('keydown',e=>{if(e.key==='Enter')analyzePhish();});
$('#goGeo').addEventListener('click',runGeo);
$('#geoInput').addEventListener('keydown',e=>{if(e.key==='Enter')runGeo();});
document.addEventListener('click',e=>{const ch=e.target.closest('.chip');if(ch&&ch.dataset.geo){$('#geoInput').value=ch.dataset.geo;runGeo();}});

/* ---- Historial local ---- */
function saveHistory(domain,score){
  try{let h=JSON.parse(localStorage.getItem('ctn-hist')||'[]');h=h.filter(x=>x.domain!==domain);h.unshift({domain,score,date:Date.now()});localStorage.setItem('ctn-hist',JSON.stringify(h.slice(0,20)));}catch(e){}
  renderHistory();
}
function renderHistory(){
  const w=$('#histWrap');if(!w)return;let h=[];try{h=JSON.parse(localStorage.getItem('ctn-hist')||'[]');}catch(e){}
  if(!h.length){w.innerHTML='';return;}
  const col=s=>s>=85?'var(--ok)':s>=60?'var(--warn)':'var(--fail)';
  w.innerHTML=`<div class="glass" data-s="padding:14px 16px;margin-top:14px"><div data-s="display:flex;align-items:center;gap:10px;margin-bottom:9px"><b data-s="font-size:14px;display:inline-flex;align-items:center;gap:7px"><svg class="i"><use href="#i-clock"/></svg>Historial reciente</b><span class="hint">se borra automáticamente tras ${esc(RET.opts[retHours()])}</span><button class="btn ghost" id="histClear" data-s="margin-left:auto;padding:5px 12px;font-size:12px">Limpiar</button></div><div data-s="display:flex;flex-wrap:wrap;gap:8px">${h.map(x=>`<span class="chip histchip" data-h="${esc(x.domain)}" title="${new Date(x.date).toLocaleString('es-CO')}"><b data-s="color:${col(x.score)};margin-right:5px">${x.score}</b>${esc(x.domain)}</span>`).join('')}</div></div>`;
  w.querySelectorAll('.histchip').forEach(c=>c.addEventListener('click',()=>{$('#domain').value=c.dataset.h;run();}));
  const cl=$('#histClear');if(cl)cl.addEventListener('click',()=>{try{localStorage.removeItem('ctn-hist');}catch(e){}renderHistory();});
}
/* (el historial se pinta al iniciar la retención de datos, tras la limpieza por antigüedad) */

/* ---- Retención de datos: borrado automático del historial ----
   Qué se borra: historial de dominios validados (ctn-hist), seguimiento de mitigaciones de filtraciones
   (ctn-leak-mit, puede contener correos) e instantáneas de monitoreo de dominios que ya no se vigilan.
   Qué se conserva: la configuración (membrete, claves, backend, idioma, tema, lista de monitoreo).
   Reglas, para no interferir con el trabajo en curso:
   - Nada creado durante la sesión activa se borra. La sesión vive en sessionStorage: sobrevive a recargas
     y termina al cerrar la pestaña o tras RET.idleH horas sin actividad.
   - Historial: se conserva retHours() horas (24 por defecto). Mitigaciones: al menos RET.mitDays días
     desde su último cambio, por ser trabajo de respuesta en curso.
   - Tras la inactividad se limpian además los resultados en pantalla, salvo que haya un análisis en curso
     o el monitoreo automático esté activo. */
const RET={opts:{1:'1 hora',24:'24 horas',168:'7 días'},def:24,mitDays:7,idleH:2,checkMin:5};
function retHours(){try{const v=+localStorage.getItem('ctn-retention');return RET.opts[v]?v:RET.def;}catch(e){return RET.def;}}
const ssGet=k=>{try{return +sessionStorage.getItem(k)||0;}catch(e){return 0;}};
const ssSet=(k,v)=>{try{sessionStorage.setItem(k,String(v));}catch(e){}};
let RET_LAST_ACT=Date.now();
function sessStart(){let s=ssGet('ctn-sess');if(!s){s=Date.now();ssSet('ctn-sess',s);}return s;}
function purgeHistory(all){
  const now=Date.now(),keepFrom=all?Infinity:sessStart();
  const cutH=all?Infinity:now-retHours()*3600e3;
  const cutM=all?Infinity:now-Math.max(retHours(),RET.mitDays*24)*3600e3;
  const gone=(t,cut)=>!(t>0)||(t<cut&&t<keepFrom);
  let n=0;
  try{const h=JSON.parse(localStorage.getItem('ctn-hist')||'[]');const k=h.filter(x=>!gone(+x.date,cutH));n+=h.length-k.length;
    if(k.length)localStorage.setItem('ctn-hist',JSON.stringify(k));else localStorage.removeItem('ctn-hist');}catch(e){try{localStorage.removeItem('ctn-hist');}catch(x){}}
  try{const m=JSON.parse(localStorage.getItem(MIT_KEY)||'{}')||{};const k={};Object.entries(m).forEach(([id,v])=>{if(v&&!gone(Date.parse(v.ts),cutM))k[id]=v;else n++;});
    if(Object.keys(k).length)localStorage.setItem(MIT_KEY,JSON.stringify(k));else localStorage.removeItem(MIT_KEY);}catch(e){try{localStorage.removeItem(MIT_KEY);}catch(x){}}
  try{const cutC=all?Infinity:now-30*864e5;   /* casos: 30 días sin cambios */const cs=JSON.parse(localStorage.getItem('ctn-cases')||'[]');const keep=cs.filter(c=>!gone(Date.parse(c.updated),cutC));n+=cs.length-keep.length;
    if(keep.length)localStorage.setItem('ctn-cases',JSON.stringify(keep));else localStorage.removeItem('ctn-cases');}catch(e){}
  try{const watch=new Set(monList().map(w=>typeof w==='string'?w:(w&&w.domain)).filter(Boolean));
    for(let i=localStorage.length-1;i>=0;i--){const key=localStorage.key(i);if(key&&key.startsWith('ctn-mon-')&&!watch.has(key.slice(8))){localStorage.removeItem(key);n++;}}
    // Historial de monitoreo: 30 días; se borra entero si el dominio ya no se vigila (o con "Borrar historial ahora")
    const cutMH=all?Infinity:now-30*864e5;
    for(let i=localStorage.length-1;i>=0;i--){const key=localStorage.key(i);if(!key||!key.startsWith('ctn-monh-'))continue;
      if(!watch.has(key.slice(9))||all){localStorage.removeItem(key);n++;continue;}
      const h=JSON.parse(localStorage.getItem(key)||'[]');const k=h.filter(x=>!gone(+x.t,cutMH));n+=h.length-k.length;
      if(k.length)localStorage.setItem(key,JSON.stringify(k));else localStorage.removeItem(key);}}catch(e){}
  try{localStorage.setItem('ctn-last-purge',String(now));}catch(e){}
  renderHistory();retInfo();
  return n;
}
function retInfo(){
  const el=$('#retInfo');if(!el)return;let lp=0;try{lp=+localStorage.getItem('ctn-last-purge')||0;}catch(e){}
  const lpTxt=lp?new Date(lp).toLocaleString(document.documentElement.lang==='en'?'en-US':'es-CO'):'';
  if(document.documentElement.lang==='en'){el.innerHTML=`Privacy: search history is deleted automatically after <b>${esc(({1:'1 hour',24:'24 hours',168:'7 days'})[retHours()])}</b> mitigation tracking <b>${RET.mitDays} days</b> after its last change and cases and monitoring history after <b>30 days</b>. Nothing done in the active session is ever deleted. After ${RET.idleH} h of inactivity the session ends and on-screen results are cleared. Settings are kept.${lp?' Last cleanup: '+esc(lpTxt)+'.':''}`;return;}
  el.innerHTML=`Privacidad: el historial de búsquedas se borra automáticamente pasadas <b>${esc(RET.opts[retHours()])}</b> el seguimiento de mitigaciones a los <b>${RET.mitDays} días</b> de su último cambio y los casos y el historial de monitoreo a los <b>30 días</b>. Nunca se borra lo hecho en la sesión activa. Tras ${RET.idleH} h sin actividad la sesión termina y se limpian los resultados en pantalla. La configuración se conserva.${lp?' Última limpieza: '+esc(new Date(lp).toLocaleString('es-CO'))+'.':''}`;
}
/* ¿Hay trabajo en curso que no debe interrumpirse? */
function retBusy(){return !!(SBX.busy||MON_TIMER||document.querySelector('.main button.btn:disabled')||(document.querySelector('dialog[open]')));}
function retActivity(){RET_LAST_ACT=Date.now();ssSet('ctn-last-act',RET_LAST_ACT);}
(function(){
  // Una sesión abandonada (pestaña recargada tras mucha inactividad) se trata como sesión nueva
  const prevAct=ssGet('ctn-last-act');
  if(prevAct&&Date.now()-prevAct>RET.idleH*3600e3)ssSet('ctn-sess',Date.now());
  sessStart();retActivity();
  purgeHistory(false);
  ['pointerdown','keydown','wheel','touchstart'].forEach(ev=>window.addEventListener(ev,retActivity,{passive:true,capture:true}));
  document.addEventListener('visibilitychange',()=>{if(!document.hidden){retCheckIdle();retActivity();}});
  setInterval(retCheckIdle,RET.checkMin*60000);
})();
function retCheckIdle(){
  if(Date.now()-RET_LAST_ACT<RET.idleH*3600e3)return;
  if(retBusy()){retActivity();return;}
  // Fin de sesión por inactividad: nueva sesión, limpieza por antigüedad y recarga para vaciar los resultados en pantalla
  ssSet('ctn-sess',Date.now());ssSet('ctn-last-act',Date.now());
  purgeHistory(false);
  location.reload();
}
(function(){
  const sel=$('#setRet');if(!sel)return;
  $('#setBtn').addEventListener('click',()=>{sel.value=String(retHours());retInfo();});
  $('#setSave').addEventListener('click',()=>{try{localStorage.setItem('ctn-retention',sel.value);}catch(e){}purgeHistory(false);});
  $('#retNow').addEventListener('click',()=>{
    if(!confirm('Se borrará todo el historial de búsquedas y el seguimiento de mitigaciones guardado en este navegador, incluido el de esta sesión. La configuración se conserva.\n\n¿Continuar?'))return;
    const n=purgeHistory(true);btnTxt('#retNow','Borrado ('+n+')');setTimeout(()=>btnTxt('#retNow','Borrar historial ahora'),1800);
  });
  retInfo();
})();

/* ---- Impresión en tema claro: el fondo pasa a blanco y los textos deben usar la paleta clara ---- */
let PRINT_THEME=null;
window.addEventListener('beforeprint',()=>{PRINT_THEME=document.documentElement.dataset.theme;document.documentElement.dataset.theme='light';
  // Informe ejecutivo en pantalla (con botón o con Ctrl+P): portada como primera página, sin la cabecera de la app
  if($('#modeReportWrap').style.display!=='none'&&$('#reportOut').childElementCount)document.body.classList.add('printing-report');});
window.addEventListener('afterprint',()=>{if(PRINT_THEME)document.documentElement.dataset.theme=PRINT_THEME;PRINT_THEME=null;document.body.classList.remove('printing-report');});
/* ---- Membrete en impresión ---- */
window.addEventListener('beforeprint',()=>{try{const org=localStorage.getItem('ctn-org')||'';const ph=$('#printHead');if(ph){ph.innerHTML=(org?'<b>'+esc(org)+'</b><br>':'<b>Centinela — Informe de seguridad</b><br>')+'<span>Generado: '+new Date().toLocaleString('es-CO')+'</span>';}}catch(e){}});

/* ---- Google Safe Browsing (opcional) ---- */
async function safeBrowsingCheck(u,key){
  const body={client:{clientId:'centinela',clientVersion:'1.0'},threatInfo:{threatTypes:['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],platformTypes:['ANY_PLATFORM'],threatEntryTypes:['URL'],threatEntries:[{url:u}]}};
  const r=await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+encodeURIComponent(key),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok)throw new Error('gsb '+r.status);
  const j=await r.json();
  return (j.matches&&j.matches.length)?'listed':'clean';
}
/* ---- Settings ---- */
function loadSettings(){try{$('#setOrg').value=localStorage.getItem('ctn-org')||'';$('#setGsb').value=localStorage.getItem('ctn-gsb')||'';$('#setBackend').value=localStorage.getItem('ctn-backend')||'';}catch(e){}}
$('#setBtn').addEventListener('click',()=>{const s=$('#settings');s.style.display=s.style.display==='none'?'block':'none';loadSettings();});
$('#setSave').addEventListener('click',()=>{try{localStorage.setItem('ctn-org',$('#setOrg').value.trim());localStorage.setItem('ctn-gsb',$('#setGsb').value.trim());localStorage.setItem('ctn-backend',$('#setBackend').value.trim().replace(/\/$/,''));}catch(e){}btnTxt('#setSave','Guardado');setTimeout(()=>{btnTxt('#setSave','Guardar');$('#settings').style.display='none';},1000);});
loadSettings();

/* ---- i18n ES/EN ----
   La interfaz se escribe en español. Al elegir EN se traducen, por coincidencia exacta, los textos y los
   atributos (placeholder, title, aria-label) de toda la interfaz, y un observador traduce las etiquetas
   comunes de los resultados que se generan después (títulos, severidades, indicadores, botones).
   Las descripciones detalladas de los hallazgos y los textos legales se mantienen en español.
   Al volver a ES se restauran los textos originales. */
const I18N_EN={
 // Cabecera y ajustes
 'Plataforma de ciberseguridad de dominios, correo e infraestructura':'Cybersecurity platform for domains, email and infrastructure',
 'Ajustes':'Settings','Cambiar tema':'Change theme','Instalar app':'Install app',
 'Membrete / entidad (aparece en la denuncia e impresión)':'Letterhead / organization (shown on reports and printouts)',
 'p.ej. Nombre de tu entidad o empresa — Equipo de Ciberseguridad':'e.g. Your organization or company — Cybersecurity Team',
 'Clave API Google Safe Browsing':'Google Safe Browsing API key','(opcional, para verificación automática)':'(optional, for automatic verification)',
 'AIza… (se guarda solo en tu navegador)':'AIza… (stored only in your browser)','URL del backend (Cloudflare Worker)':'Backend URL (Cloudflare Worker)','(opcional)':'(optional)',
 'Animación de fondo':'Background animation','Activada':'On','Desactivada':'Off','Activado':'On','Desactivado':'Off',
 'Conservar historial':'Keep history','1 hora':'1 hour','24 horas (recomendado)':'24 hours (recommended)','7 días':'7 days','24 horas':'24 hours',
 'Guardar':'Save','Guardado':'Saved','Borrar historial ahora':'Clear history now',
 'Tus datos se guardan solo en este navegador (localStorage), nunca se envían a servidores propios. Si configuras un backend (Worker), la verificación automática (VirusTotal / Safe Browsing) se hace a través de él sin límites de CORS y sin exponer claves.':'Your data is stored only in this browser (localStorage) and is never sent to our servers. If you configure a backend (Worker), automatic verification (VirusTotal / Safe Browsing) goes through it, without CORS limits and without exposing keys.',
 // Menú
 'Dominio & correo':'Domain & email','Comparar dominios':'Compare domains','Generador DNS':'DNS generator','Amenazas':'Threats','Analizar correo':'Analyze email',
 'Sandbox de archivos':'File sandbox','Filtraciones':'Data leaks','Monitoreo':'Monitoring','Ciberinteligencia':'Cyber intelligence','Reconocimiento OSINT':'OSINT reconnaissance',
 'Análisis de vulnerabilidades':'Vulnerability analysis','Informe ejecutivo':'Executive report','Infraestructura':'Infrastructure','Geolocalización IP':'IP geolocation',
 'Cabeceras HTTP':'HTTP headers','Utilidades':'Utilities','Herramientas':'Tools','Inicio':'Home','Panel':'Dashboard',
 'Dominio':'Domain','Intel':'Intel','Infra':'Infra','Útiles':'Tools','Módulos':'Modules',
 // Dominio & correo
 'Resolutor DNS':'DNS resolver','Automático (respaldo múltiple)':'Automatic (multiple fallback)','Validar dominio':'Validate domain','Opciones avanzadas':'Advanced options',
 'Selectores DKIM adicionales (coma)':'Additional DKIM selectors (comma-separated)','p.ej. mailchimp, sendgrid, s1024':'e.g. mailchimp, sendgrid, s1024',
 'Chequeo de listas negras':'Blacklist check','Ejemplos:':'Examples:','Consultando…':'Querying…','de 100':'of 100','Imprimir / PDF':'Print / PDF','Copiar resumen':'Copy summary','Enlace':'Link',
 'Todo':'All','Correo':'Email','Seguridad':'Security','Dominio & DNS':'Domain & DNS','Historial reciente':'Recent history','Limpiar':'Clear',
 // Phishing
 'URL o dominio sospechoso':'Suspicious URL or domain','Marca / dominio real suplantado':'Impersonated brand / real domain','p.ej. tudominio.gov.co':'e.g. yourdomain.gov.co',
 'Analizar y reportar':'Analyze & report','Sirve para:':'Useful for:','Sitios que copian tu página real':'Sites copying your real page','Correos/enlaces de phishing':'Phishing emails/links',
 'Dominios parecidos al tuyo':'Look-alike domains','Analizando…':'Analyzing…',
 // Geo / comparar
 'IP o dominio a geolocalizar':'IP or domain to locate','8.8.8.8  ó  ejemplo.com':'8.8.8.8  or  example.com','ejemplo.com':'example.com','Localizar':'Locate','Mi IP pública':'My public IP','Localizando…':'Locating…',
 'Dominio A':'Domain A','Dominio B':'Domain B','dominio-uno.com':'domain-one.com','dominio-dos.com':'domain-two.com','Comparar':'Compare','Comparando…':'Comparing…',
 // Recon
 'Reconocimiento de ciberinteligencia — superficie, deep y dark web':'Cyber-intelligence reconnaissance — surface, deep and dark web',
 'Dominio objetivo a proteger / investigar':'Target domain to protect / investigate','Profundidad':'Depth','Rápida (typosquatting)':'Quick (typosquatting)','Profunda (recomendada)':'Deep (recommended)',
 'Exhaustiva':'Exhaustive','Iniciar reconocimiento':'Start reconnaissance','Combina:':'Combines:','Variantes typosquatting':'Typosquatting variants','DNS en vivo':'Live DNS','+40 pivotes OSINT':'+40 OSINT pivots',
 '¿Cómo funciona?':'How does it work?','Descubre dominios parecidos o suplantados combinando':'Discovers look-alike or impersonating domains by combining','tres fuentes':'three sources',
 ': (1) generación algorítmica de variantes (homóglifos, typos, combosquatting, TLDs alternos), (2) barrido de':': (1) algorithmic generation of variants (homoglyphs, typos, combosquatting, alternate TLDs), (2) a sweep of',
 '(crt.sh) que revela dominios':'(crt.sh) revealing domains','realmente registrados':'actually registered','que contienen tu marca, y (3) resolución DNS en vivo. De cada hallazgo levanta un':'that contain your brand, and (3) live DNS resolution. For each finding it builds a',
 'expediente':'dossier',': IP(s), geolocalización completa, hosting/ASN, proveedor de correo (MX) y política':': IP(s), full geolocation, hosting/ASN, mail provider (MX) and',
 '(spoofeabilidad), nameservers, registrador (RDAP), contacto abuse, puertos/CVEs (Shodan), historial en':'policy (spoofability), nameservers, registrar (RDAP), abuse contact, ports/CVEs (Shodan), history on',
 ', detección de':', detection of','IDN/homóglifo':'IDN/homoglyph',', similitud con tu marca y reputación. Incluye':', similarity to your brand and reputation. Includes',
 '(superficie, deep y dark web), panorama de infraestructura y exportación de IOCs en TXT/CSV/JSON.':'(surface, deep and dark web), infrastructure overview and IOC export in TXT/CSV/JSON.','Buscando…':'Searching…',
 // Vulnerabilidades
 'Análisis de vulnerabilidades multi-fuente':'Multi-source vulnerability analysis','Dominio o IP a auditar':'Domain or IP to audit','tudominio.gov.co  ·  o  203.0.113.10':'yourdomain.gov.co  ·  or  203.0.113.10',
 'Alcance':'Scope','Estándar':'Standard','Profundo (más CVEs)':'Deep (more CVEs)','Analizar vulnerabilidades':'Analyze vulnerabilities','Fuentes:':'Sources:','Pasivo, sin explotación':'Passive, no exploitation',
 'Evaluación':'A','pasiva':'passive','de la exposición y las debilidades del objetivo, correlacionando':'assessment of the target’s exposure and weaknesses, correlating','varias fuentes':'several sources',
 '(puertos y servicios expuestos, CVEs por host),':'(exposed ports and services, CVEs per host),','y':'and','(CVSS, descripción y severidad de cada CVE),':'(CVSS, description and severity of each CVE),',
 '(superficie de ataque: subdominios y certificados), y':'(attack surface: subdomains and certificates), and','(postura de correo SPF/DKIM/DMARC, DNSSEC, CAA, MTA-STS). Devuelve un':'(email posture SPF/DKIM/DMARC, DNSSEC, CAA, MTA-STS). Returns a',
 'puntaje y calificación (A–F)':'score and grade (A–F)',', hallazgos clasificados por':', findings classified by','criticidad':'criticality','(Crítica/Alta/Media/Baja) con evidencia, referencias y':'(Critical/High/Medium/Low) with evidence, references and',
 'remediación':'remediation','concreta. No realiza pruebas intrusivas ni explotación — es seguro y legal para auditar tu propia infraestructura.':'steps. It performs no intrusive tests or exploitation — safe and legal for auditing your own infrastructure.',
 // Informe ejecutivo
 'Informe ejecutivo unificado':'Unified executive report','Dominio a evaluar':'Domain to assess','tudominio.gov.co':'yourdomain.gov.co','Generar informe':'Generate report','Vulnerabilidades':'Vulnerabilities',
 'Suplantación (OSINT)':'Impersonation (OSINT)','Ejecuta los módulos seleccionados sobre un mismo dominio y consolida todo en un':'Runs the selected modules on one domain and consolidates everything into an',
 'informe ejecutivo':'executive report','con portada, prioridades de actuación, calificación de seguridad, vulnerabilidades por criticidad (incl. CISA KEV), postura de correo/DNS, dominios suplantadores, filtraciones de datos, archivos analizados en el sandbox y estado de monitoreo. Luego pulsa':'with a cover, action priorities, security grade, vulnerabilities by criticality (incl. CISA KEV), email/DNS posture, impersonating domains, data leaks, files analyzed in the sandbox and monitoring status. Then click',
 'Guardar como PDF':'Save as PDF','(usa la impresión del navegador → destino «Guardar como PDF»). Sugerencia: pon el nombre de tu organización en Ajustes (icono de engranaje, arriba) para que aparezca en la portada.':'(uses the browser print dialog → destination “Save as PDF”). Tip: set your organization name in Settings (gear icon, top) so it appears on the cover.',
 'Generando…':'Generating…',
 // Correo
 'Pega el correo completo (con encabezados / código fuente)':'Paste the full email (with headers / source)',
 "Pega aquí el correo. En Gmail: ⋮ → 'Mostrar original'. En Outlook: Archivo → Propiedades → Encabezados de Internet.":"Paste the email here. In Gmail: ⋮ → 'Show original'. In Outlook: File → Properties → Internet headers.",
 // Sandbox
 'Sandbox de archivos · análisis estático aislado':'File sandbox · isolated static analysis','Arrastra aquí los archivos o haz clic para elegirlos':'Drop files here or click to choose them',
 'Hasta 20 archivos de 128 MB. Ejecutables, documentos Office, PDF, scripts, accesos directos, comprimidos, imágenes y manifiestos de dependencias.':'Up to 20 files of 128 MB. Executables, Office documents, PDFs, scripts, shortcuts, archives, images and dependency manifests.',
 'Enriquecer CVE (CIRCL · CISA KEV · EPSS)':'Enrich CVEs (CIRCL · CISA KEV · EPSS)','Dependencias vulnerables (OSV.dev)':'Vulnerable dependencies (OSV.dev)',
 'Reputación del hash (CIRCL hashlookup; VirusTotal, MalwareBazaar e Hybrid Analysis vía backend)':'Hash reputation (CIRCL hashlookup; VirusTotal, MalwareBazaar and Hybrid Analysis via backend)',
 'Analizar en sandbox':'Analyze in sandbox','Motor local (Web Worker aislado)':'Local engine (isolated Web Worker)','Cada archivo se abre en un':'Each file is opened in an','Web Worker aislado':'isolated Web Worker',
 ', sin acceso a la página, a tus datos ni a la red, y':', with no access to the page, your data or the network, and','nunca se ejecuta':'is never executed',
 '. Solo se leen sus bytes. El motor identifica el tipo real por su firma y lo compara con la extensión. Examina la estructura del formato: ejecutables PE/ELF/Mach-O, Office con extracción de macros VBA, PDF, RTF, LNK, OneNote, ISO y ZIP/JAR/APK. Además extrae indicadores (URLs, dominios, IP, rutas, registro), mide la entropía y aplica reglas de comportamiento asociadas a':'. Only its bytes are read. The engine identifies the real type by its signature and compares it with the extension. It inspects the format structure: PE/ELF/Mach-O executables, Office (with VBA macro extraction), PDF, RTF, LNK, OneNote, ISO and ZIP/JAR/APK. It also extracts indicators (URLs, domains, IPs, paths, registry), measures entropy and applies behavior rules mapped to',
 'técnicas MITRE ATT&CK':'MITRE ATT&CK techniques','y a':'and to','conocidos. Los CVE se enriquecen con CVSS (CIRCL/NVD), explotación activa (CISA KEV) y probabilidad de explotación (EPSS). Los manifiestos de dependencias se contrastan con OSV.dev. A servicios externos solo se envían':'. CVEs are enriched with CVSS (CIRCL/NVD), active exploitation (CISA KEV) and exploitation probability (EPSS). Dependency manifests are checked against OSV.dev. Only',
 'hashes':'hashes',
 'e identificadores. El sandbox dinámico de VirusTotal es opcional y solo se usa si pulsas el botón correspondiente: el archivo se sube a VirusTotal y queda disponible para su comunidad, así que no envíes documentos confidenciales. Este análisis es orientativo y no sustituye a un antivirus/EDR ni a un análisis forense.':'and identifiers are sent to external services. The VirusTotal dynamic sandbox is optional and only used if you click its button: the file is uploaded to VirusTotal and becomes available to its community, so do not submit confidential documents. This analysis is guidance and does not replace an antivirus/EDR or a forensic analysis.',
 'Analizando en el entorno aislado…':'Analyzing in the isolated environment…','Sandbox dinámico (VirusTotal)':'Dynamic sandbox (VirusTotal)','Capa ATT&CK Navigator':'ATT&CK Navigator layer',
 'Sin indicadores relevantes':'No relevant indicators','Riesgo bajo':'Low risk','Sospechoso':'Suspicious','Malicioso probable':'Likely malicious','Malicioso (confirmado por reputación)':'Malicious (confirmed by reputation)',
 'técnicas ATT&CK':'ATT&CK techniques','técnicas ATT&CK (informativas)':'ATT&CK techniques (informational)','Matriz MITRE ATT&CK':'MITRE ATT&CK matrix','Identificación':'Identification','Reputación del hash':'Hash reputation',
 'Recomendaciones':'Recommendations','Hallazgos':'Findings','Estructura del archivo':'File structure','Entropía':'Entropy','Indicadores de compromiso (IOCs)':'Indicators of compromise (IOCs)',
 'Vulnerabilidades (CVE) relacionadas':'Related vulnerabilities (CVE)','Tipo real':'Real type','Extensión':'Extension','Análisis':'Analysis','Arquitectura':'Architecture','Compilado':'Compiled',
 'Punto de entrada':'Entry point','Firma Authenticode':'Authenticode signature','Mitigaciones':'Mitigations','Importaciones':'Imports','Ruta PDB':'PDB path','Sección':'Section',
 'Dir. virtual':'Virtual addr.','Tam. virtual':'Virtual size','Tam. en disco':'Raw size','Permisos':'Permissions','Nombre':'Name','Tamaño':'Size','Cifrado':'Encrypted','Relaciones externas':'External relationships',
 'Permisos Android':'Android permissions','Ejecutables internos':'Embedded executables','Líneas':'Lines','Línea más larga':'Longest line','Bloques Base64 grandes':'Large Base64 blobs','Proporción de símbolos':'Symbol ratio',
 'Paquete':'Package','Severidad':'Severity','Aviso':'Advisory','Corregido en':'Fixed in','Resumen':'Summary','Origen':'Source','Descripción':'Description','Archivo':'File','Veredicto':'Verdict','Puntaje':'Score','Tipo':'Type',
 'Capacidad informativa':'Informational capability','Otras (sandbox dinámico)':'Other (dynamic sandbox)',
 'Acceso inicial':'Initial access','Ejecución':'Execution','Persistencia':'Persistence','Escalada de privilegios':'Privilege escalation','Evasión de defensas':'Defense evasion','Acceso a credenciales':'Credential access',
 'Descubrimiento':'Discovery','Movimiento lateral':'Lateral movement','Recolección':'Collection','Comando y control':'Command and control','Exfiltración':'Exfiltration','Impacto':'Impact',
 // Filtraciones
 'Búsqueda de filtraciones de datos':'Data leak search','Tipo de búsqueda':'Search type','Correos comprometidos':'Compromised emails','Filtraciones de una entidad':'Leaks of an organization',
 'Retirar contenido publicado':'Take down published content','Correos a verificar':'Emails to check','(uno por línea, hasta 25)':'(one per line, up to 25)','funcionario@tuentidad.gov.co':'employee@yourorg.gov.co',
 'Buscar en filtraciones':'Search leaks','Dominio de la entidad':'Organization domain','tuentidad.gov.co':'yourorg.gov.co','Mejora la búsqueda en sitios de ransomware':'Improves the search on ransomware sites',
 'Nombre de la entidad':'Organization name','p.ej. Ministerio de Educación':'e.g. Ministry of Education','Consultar filtraciones':'Check leaks','Página donde están publicados los datos':'Page where the data is published',
 'Qué se publicó':'What was published','Usuarios y contraseñas':'Usernames and passwords','Datos personales de ciudadanos o clientes':'Personal data of citizens or customers','Documentos internos de la entidad':'Internal documents',
 'Base de datos completa':'Full database','Preparar la retirada':'Prepare takedown',
 'Centinela no abre la página: solo consulta quién registra el dominio y quién aloja el servidor para saber a quién pedir la retirada, y prepara la solicitud.':'Centinela does not open the page: it only looks up who registered the domain and who hosts the server, to know whom to ask for the takedown, and drafts the request.',
 'Hudson Rock (infostealers)':'Hudson Rock (infostealers)','Correos comprometidos:':'Compromised emails:','busca cada dirección en bases públicas de filtraciones conocidas (':'looks up each address in public databases of known breaches (',
 ', y':', and','si configuras el backend con tu clave de HIBP) y en':'if you configure the backend with your HIBP key) and in',', que indica si la cuenta aparece en equipos infectados por malware':', which shows whether the account appears on devices infected by',
 '(robo de contraseñas guardadas en el navegador).':'malware (theft of passwords saved in the browser).','Filtraciones de una entidad:':'Leaks of an organization:',
 'revisa si el dominio fue un sitio vulnerado (HIBP y XposedOrNot), cuántos empleados y usuarios del dominio tienen credenciales robadas por infostealers (Hudson Rock) y si la entidad aparece publicada en sitios de filtración de grupos de':'checks whether the domain was a breached site (HIBP and XposedOrNot), how many employees and users of the domain have credentials stolen by infostealers (Hudson Rock) and whether the organization appears on leak sites of',
 '(ransomware.live). XposedOrNot y la lista pública de HIBP funcionan sin configurar nada; Hudson Rock y ransomware.live necesitan el backend (Ajustes → URL del backend, rutas en':'groups (ransomware.live). XposedOrNot and the public HIBP list work with no setup; Hudson Rock and ransomware.live need the backend (Settings → Backend URL, routes in',
 ') porque no permiten consultas directas desde el navegador.':') because they do not allow direct queries from the browser.','Mitigar:':'Mitigate:',
 'cada sitio o hallazgo trae su panel con los pasos a seguir, enlaces directos (cambio de contraseña, contacto de seguridad, colCERT, CAI Virtual, SIC) y plantillas listas para enviar; marca los pasos y el estado para llevar el seguimiento (se guarda solo en este navegador).':'each site or finding comes with a panel of steps, direct links (password change, security contact, colCERT, CAI Virtual, SIC) and ready-to-send templates; tick the steps and status to track progress (stored only in this browser).',
 'Retirar contenido:':'Take down content:',
 'si encuentras datos publicados en una página, indica a quién pedir la retirada (plataforma, hosting, registrador y buscadores) y prepara la solicitud. Nunca se muestran contraseñas. Los correos y dominios que consultes se envían a esos servicios; úsalo solo con cuentas y entidades que te corresponda proteger.':'if you find data published on a page, it tells you whom to ask for removal (platform, hosting, registrar and search engines) and drafts the request. Passwords are never shown. The emails and domains you query are sent to those services; use it only with accounts and organizations you are responsible for protecting.',
 'Pendiente':'Pending','En curso':'In progress','Mitigado':'Mitigated','Qué hacer':'What to do',
 // Monitoreo
 'Agregar dominio a monitorear':'Add domain to monitor','Agregar':'Add','Revisar ahora':'Check now','Auto-revisión':'Auto-check','Cada 15 min':'Every 15 min','Cada 30 min':'Every 30 min','Cada hora':'Every hour',
 'Activar notificaciones':'Enable notifications','Notificaciones activas':'Notifications on','Vigila listas negras y cambios en SPF/DMARC/MX/NS. Te notifica en el escritorio si algo cambia.':'Watches blacklists and changes in SPF/DMARC/MX/NS. Sends a desktop notification if anything changes.',
 'Solo funciona mientras esta pestaña esté abierta':'Only works while this tab is open','; para alertas 24/7 con la pestaña cerrada se necesita un servicio programado en un servidor.':'; 24/7 alerts with the tab closed require a scheduled service on a server.','Revisando…':'Checking…',
 // Herramientas
 'Verificador de contraseñas filtradas + fortaleza':'Leaked password checker + strength','Contraseña a evaluar':'Password to check','escribe una contraseña…':'type a password…','Ver':'Show','Verificar filtración':'Check leaks',
 'Privacidad garantizada (k-anonymity): solo se envían los primeros 5 caracteres del hash SHA-1 a la base':'Privacy guaranteed (k-anonymity): only the first 5 characters of the SHA-1 hash are sent to the',
 '; tu contraseña nunca sale del navegador.':' database; your password never leaves the browser.','Generador de contraseñas y frases':'Password and passphrase generator','Longitud:':'Length:',
 'Mayúsculas':'Uppercase','Números':'Numbers','Símbolos':'Symbols','Generar':'Generate','Frase (passphrase)':'Passphrase','Hash y codificación':'Hashing and encoding','Texto de entrada…':'Input text…','Texto de entrada':'Input text',
 'Decodificador JWT':'JWT decoder','Pega un token JWT (eyJ...) — no se verifica la firma, solo se decodifica':'Paste a JWT (eyJ...) — the signature is not verified, only decoded','Token JWT':'JWT token','Decodificar':'Decode',
 // Cabeceras / generador
 'URL o dominio a escanear':'URL or domain to scan','https://tudominio.gov.co':'https://yourdomain.gov.co','Escanear cabeceras':'Scan headers',
 'Analiza HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP y fugas de versión.':'Analyzes HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP and version leaks.',
 'Requiere el backend':'Requires the backend','(Ajustes → URL del backend): el navegador no puede leer estas cabeceras por CORS.':'(Settings → Backend URL): the browser cannot read these headers because of CORS.','Escaneando…':'Scanning…',
 'Política DMARC objetivo':'Target DMARC policy','reject (máxima)':'reject (strictest)','none (monitoreo)':'none (monitoring)','Proveedores de correo saliente (marca los que usas)':'Outgoing email providers (tick the ones you use)',
 'Correo para reportes (rua/ruf)':'Reporting email (rua/ruf)','dmarc@tudominio.gov.co':'dmarc@yourdomain.gov.co','Incluir extras':'Include extras','Generar registros':'Generate records',
 // Pie
 'Los resultados de listas negras consultadas a través de resolutores públicos pueden ser limitados por los operadores de RBL; úsalos como orientación.':'Blacklist results queried through public resolvers may be limited by RBL operators; use them as guidance.',
 'Información legal':'Legal information','Saltar al contenido':'Skip to content','Cargar reglas base':'Load base rules','Sin cambios':'No changes','Cambio detectado':'Change detected','En lista negra':'Blacklisted','Error al revisar':'Check error','sin historial todavía':'no history yet',
  'sin revisar':'not checked','quitar':'remove','Leyenda':'Legend','El historial de revisiones se conserva 30 días en este navegador.':'Check history is kept for 30 days in this browser.','✓ sin cambios':'✓ no changes','Aún no monitoreas ningún dominio. Agrega uno arriba.':'You are not monitoring any domain yet. Add one above.',"rule ejemplo_upx : empaquetador {\n  meta:\n    description = \"Ejecutable empaquetado con UPX\"\n    severity = \"medium\"\n    attack = \"T1027.002\"\n  strings:\n    $a = \"UPX0\"\n    $b = \"UPX1\"\n  condition:\n    uint16(0) == 0x5A4D and all of them\n}":"rule example_upx : packer {\n  meta:\n    description = \"Executable packed with UPX\"\n    severity = \"medium\"\n    attack = \"T1027.002\"\n  strings:\n    $a = \"UPX0\"\n    $b = \"UPX1\"\n  condition:\n    uint16(0) == 0x5A4D and all of them\n}",'Casos':'Cases','Gestor de casos':'Case manager','Nuevo caso':'New case','Crear caso':'Create case','Severidad':'Severity','Añadir a un caso':'Add to a case',
  'p.ej. Campaña de phishing con facturas falsas':'e.g. Phishing campaign with fake invoices','Título':'Title','Descripción':'Description','Añadir nota':'Add note','Línea de tiempo':'Timeline','Informe del caso (.txt)':'Case report (.txt)','Eliminar caso':'Delete case',
  'Abierto':'Open','En investigación':'Investigating','Contenido (aislado)':'Contained','Cerrado':'Closed','Caso':'Case','Título del nuevo caso':'New case title','Cancelar':'Cancel','Añadir':'Add','Añadido al caso.':'Added to the case.',
  'Agrupa hallazgos, indicadores y notas de un incidente.':'Groups findings, indicators and notes of an incident.','Elemento':'Item','Añadido':'Added','Tipo':'Type','Resumen':'Summary',
  'Acciones realizadas, decisiones, contactos…':'Actions taken, decisions, contacts…','Selecciona o crea un caso.':'Select or create a case.','Sin elementos todavía.':'No items yet.',
  'Aún no hay casos. Crea uno arriba o usa "Añadir a un caso" en otros módulos.':'No cases yet. Create one above or use "Add to a case" in other modules.',
  'Agrupa en un caso lo que encuentres en los demás módulos con el botón':'Group what you find in the other modules into a case with the','(sandbox, consulta de IOCs, informe ejecutivo), y documenta el avance con notas. Los casos se guardan solo en este navegador; un caso':'button (sandbox, IOC lookup, executive report), and document progress with notes. Cases are stored only in this browser; a case',
  'sin cambios durante 30 días se borra automáticamente':'with no changes for 30 days is deleted automatically','(nunca durante la sesión activa): exporta el caso para conservarlo.':'(never during the active session): export the case to keep it.','Comparar archivos':'Compare files','Archivo A':'File A','Archivo B':'File B','Atributo':'Attribute','igual':'same','distinto':'different',
  'Similitud de cadenas':'String similarity','En común':'In common','No se encontraron relaciones fuertes entre los dos archivos.':'No strong relationships were found between the two files.','TLS y certificados':'TLS & certificates','Análisis TLS y certificados':'TLS & certificate analysis','Dominio o servidor':'Domain or server','Servicio':'Service',
  'Analizar TLS':'Analyze TLS','Sockets TCP desde el backend':'TCP sockets from the backend','Certificado X.509':'X.509 certificate','Versiones del protocolo':'Protocol versions','Certificado':'Certificate','Configuración HTTPS':'HTTPS configuration',
  'Sujeto':'Subject','Emisor':'Issuer','Validez':'Validity','Nombres (SAN)':'Names (SAN)','Clave':'Key','Firma':'Signature','Número de serie':'Serial number','Cifrado preferido en TLS 1.2':'Preferred cipher in TLS 1.2',
  'habilitado':'enabled','deshabilitado':'disabled','sin respuesta':'no response','coincide':'matches','no coincide':'does not match','autofirmado':'self-signed','caducado':'expired','ausente':'missing','redirige':'redirects','no redirige':'does not redirect',
  'Versiones TLS, certificado, HSTS y calificación A+–F.':'TLS versions, certificate, HSTS and A+–F grade.',
  'El backend abre una conexión TCP con el servidor y le propone cada versión de TLS (1.3, 1.2, 1.1 y 1.0) para saber cuáles acepta, sin completar la conexión ni enviar datos. Lee el certificado (emisor, validez, nombres, tipo y tamaño de clave, algoritmo de firma), la cabecera HSTS y la redirección de HTTP a HTTPS, y asigna una calificación de A+ a F. Requiere el backend con sockets habilitados; los sitios detrás de Cloudflare no pueden analizarse por esta vía (limitación de Cloudflare Workers). Úsalo con servidores que te corresponda evaluar.':'The backend opens a TCP connection to the server and offers each TLS version (1.3, 1.2, 1.1 and 1.0) to learn which ones it accepts, without completing the connection or sending data. It reads the certificate (issuer, validity, names, key type and size, signature algorithm), the HSTS header and the HTTP-to-HTTPS redirect, and assigns an A+ to F grade. Requires the backend with sockets enabled; sites behind Cloudflare cannot be analyzed this way (a Cloudflare Workers limitation). Use it on servers you are responsible for assessing.','Reglas YARA propias':'Custom YARA rules','Reglas YARA':'YARA rules',
  'Reglas que se aplicarán a cada archivo analizado':'Rules applied to every analyzed file','(se guardan solo en este navegador)':'(stored only in this browser)','Validar reglas':'Validate rules','Cargar archivo .yar':'Load .yar file','Vaciar':'Clear',
  'Subconjunto de YARA: cadenas de texto (nocase, wide, ascii, fullword), hexadecimales (??, nibbles, saltos [n-m], alternativas), expresiones regulares y condiciones con of / them / #, at, in, filesize y uint8/16/32. En':'YARA subset: text strings (nocase, wide, ascii, fullword), hex strings (??, nibbles, jumps [n-m], alternatives), regular expressions and conditions with of / them / #, at, in, filesize and uint8/16/32. In',
  '(critical, high, medium, low, info) fija la severidad y':'(critical, high, medium, low, info) sets the severity and','las técnicas MITRE ATT&CK. No se admiten módulos (pe, math…) ni referencias entre reglas.':'the MITRE ATT&CK techniques. Modules (pe, math…) and references between rules are not supported.','Cumplimiento normativo (ISO/IEC 27001 · NIST CSF 2.0 · CIS v8)':'Compliance (ISO/IEC 27001 · NIST CSF 2.0 · CIS v8)','cumplimiento estimado':'estimated compliance',
  'conformes':'compliant','con brechas':'with gaps','no conformes':'non-compliant','no evaluados':'not assessed','Conforme':'Compliant','Con brechas':'With gaps','No conforme':'Non-compliant','No evaluado':'Not assessed',
  'Área de control':'Control area','Estado':'Status','Evidencia':'Evidence','Ver datos en tabla':'View data as table','Categoría':'Category','Valor':'Value','Hallazgos por severidad':'Findings by severity',
  'Postura de seguridad por área (0–100, más alto es mejor)':'Security posture by area (0–100, higher is better)','Correo y DNS':'Email and DNS','Suplantación':'Impersonation','Archivos analizados':'Files analyzed',
  'Índices orientativos calculados a partir de los hallazgos de cada módulo; consulta las secciones para el detalle.':'Indicative indexes computed from each module’s findings; see the sections for details.','Longitud de la contraseña':'Password length','Política de tratamiento de datos':'Data processing policy','Términos y condiciones':'Terms and conditions','Aviso legal':'Legal notice',
 'Centinela. Todos los derechos reservados.':'Centinela. All rights reserved.','Cerrar':'Close',
 // Etiquetas comunes en resultados
 'Crítica':'Critical','Alta':'High','Media':'Medium','Baja':'Low','Informativa':'Informational','Críticas':'Critical','Altas':'High','Medias':'Medium','Bajas':'Low',
 'Críticos':'Critical','Altos':'High','Medios':'Medium','Bajos':'Low','Crítico':'Critical','Correcto':'OK','Correctos':'OK','Atención':'Warning','Info':'Info','N/D':'N/A',
 'explotadas':'exploited','puertos':'ports','Informe (.txt)':'Report (.txt)','Datos (.json)':'Data (.json)','IOCs (.csv)':'IOCs (.csv)','IOCs (.json)':'IOCs (.json)','Copiar IOCs':'Copy IOCs',
 'Descargar (.txt)':'Download (.txt)','Descargar denuncia (.txt)':'Download complaint (.txt)','Descargar plan (.txt)':'Download plan (.txt)','Calificación de seguridad':'Security grade',
 'Detalle del correo':'Email details','Detalle técnico':'Technical details','Cabeceras recibidas':'Received headers','Estado':'Status','Fecha':'Date','Registro':'Record','Servicio':'Service','Sistema':'System',
 'País':'Country','Ciudad / Región':'City / Region','Coordenadas':'Coordinates','Zona horaria':'Time zone','Organización / ISP':'Organization / ISP','ASN / Red':'ASN / Network','Riesgo':'Risk',
 'Puertos expuestos':'Exposed ports','Expedientes de los dominios detectados':'Dossiers of detected domains','Candidatos analizados':'Candidates analyzed','Registrados / activos':'Registered / active',
 'con IP activa':'with live IP','con correo (MX)':'with email (MX)','en lista negra':'blacklisted','riesgo alto':'high risk','suplantadores':'impersonators','registrados':'registered',
 'vuln. altas':'high vulns','vuln. críticas':'critical vulns','fallos correo/DNS':'email/DNS issues','Controles evaluados':'Controls assessed','Validación DNS completa':'Full DNS validation',
 'Credenciales':'Credentials','Credenciales robadas':'Stolen credentials','Contraseña expuesta':'Password exposed','Contraseña filtrada':'Password leaked','Correos expuestos':'Exposed emails',
 'Empleados comprometidos':'Compromised employees','Empleados con infostealer':'Employees with infostealer','Usuarios con infostealer':'Users with infostealer','Usuarios externos':'External users',
 'Filtraciones del sitio':'Site breaches','Filtraciones distintas':'Distinct breaches','Publicaciones ransomware':'Ransomware posts','Víctima publicada':'Published victim','Grupo':'Group',
 'Familia de malware':'Malware family','Familias de malware más frecuentes':'Most frequent malware families','Equipos infectados por infostealer (Hudson Rock)':'Devices infected by infostealers (Hudson Rock)',
 'Datos del sitio':'Site data','Reportada en':'Reported on','Terceros':'Third parties','Aviso al titular de la cuenta':'Notice to the account holder','Aviso interno a TI':'Internal notice to IT',
 'Comunicado a titulares':'Notice to data subjects','Analizar como phishing':'Analyze as phishing','Sitio web (A)':'Website (A)','Host MX':'MX host','Resumen del lote':'Batch summary'
};
Object.assign(I18N_EN,{'Nombre y tipo de archivo':'File name and type','Comportamiento e indicadores':'Behavior and indicators','Macros y contenido activo':'Macros and active content',
 'Contenido activo del PDF':'PDF active content','Acceso directo (LNK)':'Shortcut (LNK)','Contenido del contenedor':'Container contents','Correo electrónico':'Email','Ofuscación':'Obfuscation',
 'Estructura del ejecutable':'Executable structure','Capacidades (API importadas)':'Capabilities (imported APIs)','Importaciones por DLL':'Imports per DLL','Contenido':'Contents',
 'Hallazgos':'Findings','Resumen del lote':'Batch summary','Informe del lote (.json)':'Batch report (.json)','Sin registros':'No records','sin registros':'no records','no consultado':'not queried'});
const i18nKey=t=>t.replace(/\s+/g,' ').trim();
const I18N_MAP=new Map(Object.entries(I18N_EN).map(([k,v])=>[i18nKey(k),v]));
/* Textos con cifras: "Hallazgos (12)", "Resumen del lote (3 archivos)", "se borra automáticamente tras 24 horas" */
const I18N_RE=[
 [/^(.+?) \((\d+)\)$/,(m,a,n)=>I18N_MAP.has(a)?I18N_MAP.get(a)+' ('+n+')':null],
 [/^(.+?) \((\d+) archivos\)$/,(m,a,n)=>I18N_MAP.has(a)?I18N_MAP.get(a)+' ('+n+' files)':null],
 [/^se borra automáticamente tras (.+)$/,(m,a)=>'auto-deleted after '+(I18N_MAP.get(a)||a)]
];
function i18nLookup(k){const v=I18N_MAP.get(k);if(v)return v;for(const [re,fn] of I18N_RE){const m=k.match(re);if(m){const r=fn(...m);if(r)return r;}}return null;}
const I18N_ATTRS=['placeholder','title','aria-label'];
const I18N_SKIP=new Set(['SCRIPT','STYLE','TEXTAREA','CODE','PRE','svg','SVG','symbol']);
const I18N_DONE=[]; // [nodo, texto original] para restaurar al volver a español
let I18N_LANG='es',I18N_OBS=null;
function i18nText(n){
  const raw=n.nodeValue;if(!raw)return;const k=i18nKey(raw);if(!k)return;const en=i18nLookup(k);if(!en||en===k)return;
  const lead=raw.match(/^\s*/)[0],trail=raw.match(/\s*$/)[0];I18N_DONE.push([n,raw]);n.nodeValue=lead+en+trail;
}
function i18nEl(el){
  I18N_ATTRS.forEach(a=>{const v=el.getAttribute&&el.getAttribute(a);if(!v)return;const en=i18nLookup(i18nKey(v));if(en&&!el.hasAttribute('data-i18n-'+a)){el.setAttribute('data-i18n-'+a,v);el.setAttribute(a,en);}});
}
function i18nTree(root){
  if(root.nodeType===3){if(!(root.parentNode&&I18N_SKIP.has(root.parentNode.nodeName)))i18nText(root);return;}
  if(root.nodeType!==1||I18N_SKIP.has(root.nodeName)||root.closest&&root.closest('.raw,.sbxcode,#legalBody,[data-noi18n]'))return;
  i18nEl(root);root.querySelectorAll&&root.querySelectorAll('['+I18N_ATTRS.join('],[')+']').forEach(i18nEl);
  const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,{acceptNode:n=>{let p=n.parentNode;while(p&&p!==root.parentNode){if(I18N_SKIP.has(p.nodeName)||(p.classList&&(p.classList.contains('raw')||p.classList.contains('sbxcode'))))return NodeFilter.FILTER_REJECT;p=p.parentNode;}return NodeFilter.FILTER_ACCEPT;}});
  const list=[];while(w.nextNode())list.push(w.currentNode);list.forEach(i18nText);
}
function i18nRestore(){
  I18N_DONE.splice(0).forEach(([n,raw])=>{n.nodeValue=raw;});
  document.querySelectorAll('[data-i18n-placeholder],[data-i18n-title],[data-i18n-aria-label]').forEach(el=>I18N_ATTRS.forEach(a=>{const o=el.getAttribute('data-i18n-'+a);if(o!=null){el.setAttribute(a,o);el.removeAttribute('data-i18n-'+a);}}));
}
function applyLang(l){
  l=l==='en'?'en':'es';I18N_LANG=l;document.documentElement.lang=l;document.documentElement.dataset.lang=l;
  if(I18N_OBS){I18N_OBS.disconnect();I18N_OBS=null;}
  i18nRestore();
  const f=$('#footNote');
  if(f)f.innerHTML=l==='en'
    ?'<b>Centinela</b> — free cybersecurity suite · Queries via DNS-over-HTTPS (Google, Cloudflare, DNS.SB), RDAP and geo-IP, run from your browser. No data is sent to our servers.<br>Blacklist results queried through public resolvers may be limited by RBL operators; use them as guidance. Detailed finding descriptions and legal texts are shown in Spanish.'
    :'<b>Centinela</b> — suite gratuita de ciberseguridad · Consultas vía DNS-over-HTTPS (Google, Cloudflare, DNS.SB), RDAP y geo-IP, ejecutadas desde tu navegador. Ningún dato se envía a servidores propios.<br>Los resultados de listas negras consultadas a través de resolutores públicos pueden ser limitados por los operadores de RBL; úsalos como orientación.';
  if(l==='en'){
    i18nTree(document.body);
    // Traduce también lo que se genere después (resultados, hojas del menú móvil, estados)
    I18N_OBS=new MutationObserver(ms=>ms.forEach(m=>m.addedNodes.forEach(n=>{if(n.nodeType===3||n.nodeType===1)i18nTree(n);})));
    I18N_OBS.observe(document.body,{childList:true,subtree:true});
  }
  if(typeof retInfo==='function')retInfo();
  if(window.HOME_READY){homeHint();homeCheckSources(false);renderHomeActivity();const ho=$('#homeOut');if(ho&&ho.childElementCount){const c=homeClassify($('#homeQ').value);if(c&&c.t==='hash')homeGo();}}
  $('#langBtn').textContent=l.toUpperCase();
  try{localStorage.setItem('ctn-lang',l);}catch(e){}
}
$('#langBtn').addEventListener('click',()=>applyLang(I18N_LANG==='en'?'es':'en'));
try{const sl=localStorage.getItem('ctn-lang');if(sl){document.documentElement.dataset.lang=sl;applyLang(sl);}}catch(e){}

// theme
const themeBtn=$('#themeBtn');
function setTheme(t){document.documentElement.dataset.theme=t;themeBtn.innerHTML=ico(t==='dark'?'moon':'sun');const mc=document.querySelector('meta[name="theme-color"]');if(mc)mc.content=t==='dark'?'#10161F':'#F4F6F9';try{localStorage.setItem('dnsg-theme',t);}catch(e){}}
themeBtn.addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
try{const s=localStorage.getItem('dnsg-theme');if(s)setTheme(s);}catch(e){}
// PWA (instalable al publicar en un hosting).
// El manifiesto estático (manifest.webmanifest) es el principal; este manifiesto en memoria es solo un respaldo si falta.
if(!document.querySelector('link[rel="manifest"]'))try{const mani={name:'Centinela — Ciberseguridad',short_name:'Centinela',start_url:'.',display:'standalone',background_color:'#10161F',theme_color:'#10161F',description:'Suite de ciberseguridad de dominios y correo',icons:[{src:'data:image/svg+xml,'+encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#10161F"/><path d="M32 8 49 15 49 31 C49 42 42 49 32 52.5 C22 49 15 42 15 31 L15 15 Z" fill="rgba(86,194,224,.08)" stroke="#56C2E0" stroke-width="2"/><circle cx="32" cy="30.5" r="13" fill="none" stroke="#56C2E0" stroke-opacity=".3" stroke-width="1.3"/><circle cx="32" cy="30.5" r="2.6" fill="#56C2E0"/><path d="M32 15v2.6M32 43.4V46M16.4 30.5H19M45 30.5h2.6" stroke="#56C2E0" stroke-width="1.5"/></svg>'),sizes:'any',type:'image/svg+xml',purpose:'any'}]};const link=document.createElement('link');link.rel='manifest';link.href=URL.createObjectURL(new Blob([JSON.stringify(mani)],{type:'application/manifest+json'}));document.head.appendChild(link);}catch(e){}
// Service worker: funcionamiento sin conexión y actualizaciones (solo por http/https; no existe en file://)
if('serviceWorker' in navigator&&/^https?:$/.test(location.protocol))window.addEventListener('load',()=>{navigator.serviceWorker.register('./sw.js').catch(()=>{});});
let deferredPrompt=null;
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();deferredPrompt=e;const ib=$('#installBtn');if(ib)ib.style.display='grid';});
$('#installBtn').addEventListener('click',async()=>{if(deferredPrompt){deferredPrompt.prompt();try{await deferredPrompt.userChoice;}catch(e){}deferredPrompt=null;$('#installBtn').style.display='none';}});
// Cifras que cuentan hasta su valor al aparecer (indicadores y estadísticas de resultados)
(function(){
  if(matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  const SEL='.kpi b,.lkstat b';
  const count=el=>{
    if(el.dataset.counted)return;el.dataset.counted='1';
    const txt=el.textContent.trim();if(!/^\d{1,3}(\.\d{3})+$|^\d+$/.test(txt))return;
    const target=+txt.replace(/\./g,'');if(!target)return;
    const t0=performance.now(),dur=Math.min(900,380+target*45);
    const tick=now=>{const p=Math.min(1,(now-t0)/dur),e=1-Math.pow(1-p,3);el.textContent=p<1?Math.round(target*e).toLocaleString('es-CO'):txt;if(p<1)requestAnimationFrame(tick);};
    requestAnimationFrame(tick);
  };
  new MutationObserver(ms=>ms.forEach(m=>m.addedNodes.forEach(n=>{if(n.nodeType!==1)return;if(n.matches(SEL))count(n);n.querySelectorAll(SEL).forEach(count);})))
    .observe(document.querySelector('.main'),{childList:true,subtree:true});
})();
// Navegación inferior en teléfono: una pestaña por grupo del menú lateral; los grupos con varios módulos abren una hoja encima
(function(){
  const nav=document.querySelector('aside.nav');if(!nav)return;
  const SHORT=['Inicio','Dominio','Amenazas','Intel','Infra','Útiles'];
  const bar=document.createElement('nav');bar.className='mnav';bar.setAttribute('aria-label','Módulos');
  const sheet=document.createElement('div');sheet.className='msheet';sheet.hidden=true;
  [...nav.querySelectorAll('.nav-group')].forEach((g,i)=>{
    const mods=[...g.querySelectorAll('.modebtn')];if(!mods.length)return;
    const tab=document.createElement('button');tab.type='button';tab.className='mtab';tab._mods=mods;
    tab.appendChild(mods[0].querySelector('svg').cloneNode(true));
    const s=document.createElement('span');s.textContent=SHORT[i]||g.querySelector('.lbl').textContent;tab.appendChild(s);
    tab.addEventListener('click',()=>{
      if(mods.length===1){mods[0].click();sheet.hidden=true;return;}
      if(!sheet.hidden&&sheet._g===i){sheet.hidden=true;return;}
      sheet.innerHTML='';
      mods.forEach(mb=>{const c=mb.cloneNode(true);c.removeAttribute('id');c.addEventListener('click',()=>{mb.click();sheet.hidden=true;window.scrollTo({top:0,behavior:'smooth'});});sheet.appendChild(c);});
      sheet._g=i;sheet.hidden=false;
    });
    bar.appendChild(tab);
  });
  document.body.appendChild(sheet);document.body.appendChild(bar);
  const sync=()=>bar.querySelectorAll('.mtab').forEach(t=>t.classList.toggle('on',t._mods.some(m=>m.classList.contains('active'))));
  new MutationObserver(sync).observe(nav,{subtree:true,attributes:true,attributeFilter:['class']});sync();
  document.addEventListener('click',e=>{if(!sheet.hidden&&!sheet.contains(e.target)&&!bar.contains(e.target))sheet.hidden=true;});
  document.addEventListener('keydown',e=>{if(e.key==='Escape')sheet.hidden=true;});
})();
/* ============================================================ Fondo animado de ciberseguridad
   Retícula hexagonal, red de nodos con paquetes de datos, barrido de radar que "detecta" nodos
   y amenazas que pasan de roja a mitigada. Se dibuja en canvas a la resolución real de la pantalla
   (hasta 3840×2160, nítido en monitores 4K), a 30 fps, en pausa si la pestaña no está visible,
   y como imagen fija si el sistema pide reducir el movimiento. */
const BGFX=(function(){
  const cv=$('#bgfx');if(!cv||!cv.getContext)return null;
  const ctx=cv.getContext('2d');
  const reduce=matchMedia('(prefers-reduced-motion: reduce)');
  const MAXPX=3840*2160, LINK=150, FPS=30;
  let W=0,H=0,S=1,nodes=[],packets=[],threats=[],grid=null,sweep=null,col=null,raf=0,last=0,lastSpawn=0,lastThreat=0,on=true;
  try{on=localStorage.getItem('ctn-bgfx')!=='off';}catch(e){}
  const hex=h=>{h=String(h).trim().replace('#','');if(h.length===3)h=[...h].map(c=>c+c).join('');const n=parseInt(h,16);return isNaN(n)?[86,194,224]:[n>>16&255,n>>8&255,n&255];};
  const rgba=(c,a)=>'rgba('+c[0]+','+c[1]+','+c[2]+','+Math.max(0,Math.min(1,a)).toFixed(3)+')';
  function colors(){const cs=getComputedStyle(document.documentElement);const dark=document.documentElement.dataset.theme!=='light';
    col={acc:hex(cs.getPropertyValue('--accent')),fail:hex(cs.getPropertyValue('--fail')),ok:hex(cs.getPropertyValue('--ok')),k:dark?1:1.35};grid=null;}
  function resize(){
    W=innerWidth;H=innerHeight;
    // Resolución real de la pantalla, limitada a 4K para no gastar memoria en pantallas mayores
    S=Math.max(.5,Math.min(window.devicePixelRatio||1,Math.sqrt(MAXPX/(W*H))));
    cv.width=Math.round(W*S);cv.height=Math.round(H*S);
    const n=Math.round(Math.min(160,Math.max(26,W*H/14000)));
    nodes=Array.from({length:n},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16,r:Math.random()*1.3+1.1,hit:0}));
    packets=[];threats=[];grid=null;
  }
  function buildGrid(){
    grid=document.createElement('canvas');grid.width=cv.width;grid.height=cv.height;
    const g=grid.getContext('2d');g.setTransform(S,0,0,S,0,0);
    const R=28,dx=R*Math.sqrt(3),dy=R*1.5;
    g.strokeStyle=rgba(col.acc,.045*col.k);g.lineWidth=1;g.beginPath();
    for(let row=0,y=-R;y<H+R;row++,y+=dy)for(let x=row%2?dx/2:0;x<W+dx;x+=dx)
      for(let k=0;k<=6;k++){const a=Math.PI/3*k+Math.PI/6,px=x+R*Math.cos(a),py=y+R*Math.sin(a);k?g.lineTo(px,py):g.moveTo(px,py);}
    g.stroke();
    // Viñeta: la retícula se desvanece hacia el centro, donde está el contenido
    g.globalCompositeOperation='destination-out';
    const v=g.createRadialGradient(W*.5,H*.55,0,W*.5,H*.55,Math.max(W,H)*.62);v.addColorStop(0,'rgba(0,0,0,.85)');v.addColorStop(1,'rgba(0,0,0,0)');
    g.fillStyle=v;g.fillRect(0,0,W,H);
  }
  function frame(now){
    if(!grid)buildGrid();
    const t=now/1000;
    ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,cv.width,cv.height);ctx.drawImage(grid,0,0);
    ctx.setTransform(S,0,0,S,0,0);
    // Radar: anillos y barrido, anclado arriba a la derecha
    const cx=W*.84,cy=H*.14,RR=Math.hypot(W,H)*.62,ang=(t*.34)%(Math.PI*2);
    ctx.lineWidth=1;
    for(let i=1;i<=5;i++){ctx.strokeStyle=rgba(col.acc,(.06-i*.008)*col.k);ctx.beginPath();ctx.arc(cx,cy,RR*i/5,0,Math.PI*2);ctx.stroke();}
    if(ctx.createConicGradient){
      // El barrido se pinta en una capa aparte para difuminarlo con la distancia al centro
      if(!sweep||sweep.width!==cv.width||sweep.height!==cv.height){sweep=document.createElement('canvas');sweep.width=cv.width;sweep.height=cv.height;}
      const sg=sweep.getContext('2d');sg.setTransform(1,0,0,1,0,0);sg.clearRect(0,0,sweep.width,sweep.height);sg.setTransform(S,0,0,S,0,0);
      sg.globalCompositeOperation='source-over';
      const cg=sg.createConicGradient(ang-1.1,cx,cy),w=1.1/(Math.PI*2);
      cg.addColorStop(0,rgba(col.acc,0));cg.addColorStop(w*.75,rgba(col.acc,.035*col.k));cg.addColorStop(w*.97,rgba(col.acc,.11*col.k));cg.addColorStop(w,rgba(col.acc,0));cg.addColorStop(1,rgba(col.acc,0));
      sg.fillStyle=cg;sg.beginPath();sg.moveTo(cx,cy);sg.arc(cx,cy,RR,ang-1.1,ang+.02);sg.closePath();sg.fill();
      const rl=sg.createLinearGradient(cx,cy,cx+Math.cos(ang)*RR,cy+Math.sin(ang)*RR);rl.addColorStop(0,rgba(col.acc,.3*col.k));rl.addColorStop(1,rgba(col.acc,0));
      sg.strokeStyle=rl;sg.lineWidth=1.2;sg.beginPath();sg.moveTo(cx,cy);sg.lineTo(cx+Math.cos(ang)*RR,cy+Math.sin(ang)*RR);sg.stroke();
      sg.globalCompositeOperation='destination-in';
      const fade=sg.createRadialGradient(cx,cy,0,cx,cy,RR);fade.addColorStop(0,'rgba(0,0,0,1)');fade.addColorStop(.55,'rgba(0,0,0,.55)');fade.addColorStop(1,'rgba(0,0,0,0)');
      sg.fillStyle=fade;sg.fillRect(0,0,W,H);
      ctx.setTransform(1,0,0,1,0,0);ctx.drawImage(sweep,0,0);ctx.setTransform(S,0,0,S,0,0);
    }
    // Mover nodos y detectar los que cruza el barrido
    for(const n of nodes){
      n.x+=n.vx;n.y+=n.vy;
      if(n.x<-20)n.x=W+20;else if(n.x>W+20)n.x=-20;if(n.y<-20)n.y=H+20;else if(n.y>H+20)n.y=-20;
      const d=Math.hypot(n.x-cx,n.y-cy);if(d<RR){let a=Math.atan2(n.y-cy,n.x-cx);if(a<0)a+=Math.PI*2;let diff=ang-a;if(diff<0)diff+=Math.PI*2;if(diff<.06)n.hit=1;}
      n.hit*=.965;
    }
    // Conexiones (agrupadas por intensidad para dibujar pocas rutas)
    const buckets=[[],[],[],[]];
    for(let i=0;i<nodes.length;i++){const a=nodes[i];for(let j=i+1;j<nodes.length;j++){const b=nodes[j],dx=a.x-b.x,dy=a.y-b.y;if(Math.abs(dx)>LINK||Math.abs(dy)>LINK)continue;const d=Math.hypot(dx,dy);if(d<LINK)buckets[Math.min(3,Math.floor((1-d/LINK)*4))].push(a,b);}}
    buckets.forEach((l,k)=>{if(!l.length)return;ctx.strokeStyle=rgba(col.acc,(.035+k*.035)*col.k);ctx.beginPath();for(let i=0;i<l.length;i+=2){ctx.moveTo(l[i].x,l[i].y);ctx.lineTo(l[i+1].x,l[i+1].y);}ctx.stroke();});
    // Nodos
    for(const n of nodes){
      ctx.fillStyle=rgba(col.acc,(.28+n.hit*.6)*col.k);ctx.beginPath();ctx.arc(n.x,n.y,n.r+n.hit*1.2,0,Math.PI*2);ctx.fill();
      if(n.hit>.08){ctx.strokeStyle=rgba(col.acc,n.hit*.35*col.k);ctx.beginPath();ctx.arc(n.x,n.y,n.r+4+(1-n.hit)*10,0,Math.PI*2);ctx.stroke();}
    }
    // Paquetes de datos que viajan entre nodos vecinos
    if(now-lastSpawn>260&&packets.length<40){lastSpawn=now;const a=nodes[Math.random()*nodes.length|0];let b=null,bd=LINK;
      for(const m of nodes){if(m===a)continue;const d=Math.hypot(m.x-a.x,m.y-a.y);if(d<bd&&Math.random()<.6){bd=d;b=m;}}
      if(b)packets.push({a,b,p:0,sp:.012+Math.random()*.018});}
    for(let i=packets.length-1;i>=0;i--){const k=packets[i];k.p+=k.sp;if(k.p>=1){k.b.hit=Math.max(k.b.hit,.55);packets.splice(i,1);continue;}
      const x=k.a.x+(k.b.x-k.a.x)*k.p,y=k.a.y+(k.b.y-k.a.y)*k.p,tx=k.a.x+(k.b.x-k.a.x)*Math.max(0,k.p-.18),ty=k.a.y+(k.b.y-k.a.y)*Math.max(0,k.p-.18);
      const lg=ctx.createLinearGradient(tx,ty,x,y);lg.addColorStop(0,rgba(col.acc,0));lg.addColorStop(1,rgba(col.acc,.75*col.k));
      ctx.strokeStyle=lg;ctx.lineWidth=1.6;ctx.beginPath();ctx.moveTo(tx,ty);ctx.lineTo(x,y);ctx.stroke();ctx.lineWidth=1;
      ctx.fillStyle=rgba(col.acc,.95);ctx.beginPath();ctx.arc(x,y,1.6,0,Math.PI*2);ctx.fill();}
    // Amenazas: pulso rojo que luego pasa a "mitigada" (verde) y se desvanece
    if(now-lastThreat>5200){lastThreat=now;threats.push({n:nodes[Math.random()*nodes.length|0],t0:now});}
    for(let i=threats.length-1;i>=0;i--){const th=threats[i],age=(now-th.t0)/1000;if(age>5){threats.splice(i,1);continue;}
      const mitig=age>2.8,c=mitig?col.ok:col.fail,fade=mitig?1-(age-2.8)/2.2:Math.min(1,age*2);
      for(let r=0;r<2;r++){const ph=((age*1.3+r*.5)%1);ctx.strokeStyle=rgba(c,(1-ph)*.5*fade*col.k);ctx.beginPath();ctx.arc(th.n.x,th.n.y,4+ph*22,0,Math.PI*2);ctx.stroke();}
      ctx.fillStyle=rgba(c,.8*fade);ctx.beginPath();ctx.arc(th.n.x,th.n.y,2.6,0,Math.PI*2);ctx.fill();
      if(mitig){ctx.strokeStyle=rgba(c,.8*fade);ctx.lineWidth=1.4;ctx.beginPath();ctx.moveTo(th.n.x-4,th.n.y-9);ctx.lineTo(th.n.x-1.5,th.n.y-6.5);ctx.lineTo(th.n.x+3.5,th.n.y-11.5);ctx.stroke();ctx.lineWidth=1;}}
  }
  function loop(now){raf=requestAnimationFrame(loop);if(now-last<1000/FPS)return;last=now;frame(now);}
  function start(){cancelAnimationFrame(raf);if(!on){cv.style.display='none';return;}cv.style.display='block';
    if(reduce.matches||document.hidden){frame(performance.now());return;}raf=requestAnimationFrame(loop);}
  colors();resize();start();
  let rt=0;addEventListener('resize',()=>{clearTimeout(rt);rt=setTimeout(()=>{resize();start();},150);});
  document.addEventListener('visibilitychange',start);
  reduce.addEventListener&&reduce.addEventListener('change',start);
  new MutationObserver(()=>{colors();if(!raf||reduce.matches)start();}).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
  return {set(v){on=!!v;try{localStorage.setItem('ctn-bgfx',on?'on':'off');}catch(e){}start();},get on(){return on;}};
})();
{const fx=$('#setFx');if(fx){fx.value=BGFX&&BGFX.on?'on':'off';fx.addEventListener('change',()=>BGFX&&BGFX.set(fx.value==='on'));}}
/* ============================================================ Textos legales del pie de página
   Datos del responsable del sitio: complétalos aquí una sola vez; se usan en los tres textos.
   Mientras quede algún [MARCADOR], cada texto muestra un aviso de que está pendiente de completar.
   Estos textos son una base de referencia; conviene que los revise un abogado antes de publicarlos. */
const LEGAL={
  responsable:'[NOMBRE O RAZÓN SOCIAL DEL RESPONSABLE]',
  identificacion:'[NIT O CÉDULA]',
  domicilio:'[CIUDAD], Colombia',
  direccion:'[DIRECCIÓN FÍSICA]',
  correo:'[CORREO DE CONTACTO PARA DATOS PERSONALES]',
  vigencia:'28 de septiembre de 2026',
};
const LEGAL_DOCS={
  'privacidad':{title:'Política de tratamiento de datos personales',html:L=>`
<p>Esta política explica qué datos personales trata Centinela, para qué y cómo puedes ejercer tus derechos, conforme a la Ley 1581 de 2012 y al Decreto 1074 de 2015 (que compila el Decreto 1377 de 2013).</p>
<h3>1. Responsable del tratamiento</h3>
<ul><li>Responsable: ${L.responsable}</li><li>Identificación: ${L.identificacion}</li><li>Domicilio: ${L.direccion}, ${L.domicilio}</li><li>Correo para asuntos de datos personales: ${L.correo}</li><li>Sitio: ${esc(location.origin)}</li></ul>
<h3>2. Cómo funciona Centinela</h3>
<p>Centinela se ejecuta en tu navegador. No tenemos una base de datos propia ni guardamos en nuestros servidores lo que consultas. Para obtener resultados, tu navegador envía directamente a servicios de terceros el dato que escribes (un dominio, una IP, una URL, un correo o un encabezado de correo).</p>
<h3>3. Datos que se tratan y con quién se comparten</h3>
<ul>
<li><b>Dominios, IP y URL</b> que consultas: se envían a resolutores DNS (Google, Cloudflare, DNS.SB), registros RDAP, servicios de geolocalización de IP (ipwho.is, ipapi.co), transparencia de certificados (crt.sh), Shodan InternetDB, Internet Archive, bases de vulnerabilidades (CIRCL, OSV, CISA) y ransomware.live.</li>
<li><b>Correos electrónicos</b> que verificas en "Filtraciones": se envían a XposedOrNot, Hudson Rock y, si configuras tu propio backend con clave, a Have I Been Pwned.</li>
<li><b>Contraseñas</b> en "Herramientas": nunca salen del navegador. Solo se envían los 5 primeros caracteres de su huella SHA-1 a Have I Been Pwned (técnica de k-anonimato), que no permite reconstruir la contraseña.</li>
<li><b>Datos técnicos de conexión</b>: como en cualquier sitio web, los servicios anteriores y los proveedores de fuentes tipográficas (Google Fonts) y del mapa (OpenStreetMap) reciben tu dirección IP y los datos técnicos de tu navegador.</li>
</ul>
<p>Cada tercero trata esos datos según su propia política de privacidad. No vendemos ni cedemos datos, y no los usamos para publicidad ni para crear perfiles.</p>
<h3>4. Datos guardados en tu navegador</h3>
<p>Centinela guarda en el almacenamiento local de tu navegador (<i>localStorage</i>), y solo allí: tus preferencias (tema, idioma, animación), los ajustes que escribas (membrete, clave de Google Safe Browsing, URL de tu backend), el historial de dominios consultados, la lista de monitoreo y el avance de las mitigaciones. No usamos cookies de rastreo ni herramientas de analítica. Puedes borrarlo todo desde la configuración de privacidad de tu navegador.</p>
<h3>5. Backend opcional</h3>
<p>Si configuras en Ajustes la URL de un backend propio (por ejemplo un Cloudflare Worker), las consultas que lo usan pasan por esa infraestructura, que administras tú y queda bajo tu responsabilidad.</p>
<h3>6. Finalidad</h3>
<p>Los datos se tratan únicamente para prestar la función de análisis de seguridad que solicitas: mostrar el resultado de la consulta y las acciones recomendadas.</p>
<h3>7. Datos de terceras personas</h3>
<p>Si consultas correos o información de otras personas, declaras que tienes autorización o un interés legítimo para hacerlo, por ejemplo proteger las cuentas de tu organización, y que usarás el resultado solo con fines de seguridad.</p>
<h3>8. Derechos del titular</h3>
<p>Como titular de datos personales puedes, de forma gratuita (artículo 8 de la Ley 1581 de 2012):</p>
<ul><li>Conocer, actualizar y rectificar tus datos.</li><li>Solicitar prueba de la autorización otorgada.</li><li>Ser informado sobre el uso dado a tus datos.</li><li>Presentar quejas ante la Superintendencia de Industria y Comercio (SIC).</li><li>Revocar la autorización y pedir la supresión de tus datos.</li><li>Acceder a tus datos objeto de tratamiento.</li></ul>
<h3>9. Cómo ejercer tus derechos</h3>
<p>Escribe a ${L.correo} indicando tu nombre, tu solicitud y un medio de respuesta. Las consultas se atienden en un máximo de 10 días hábiles, prorrogables 5 días hábiles más; los reclamos, en un máximo de 15 días hábiles, prorrogables 8 días hábiles más, según los artículos 14 y 15 de la Ley 1581 de 2012. Como Centinela no guarda tus consultas en servidores propios, en la mayoría de los casos no tendremos datos tuyos que entregar o suprimir; para los datos tratados por terceros debes dirigirte a cada uno de ellos.</p>
<h3>10. Seguridad</h3>
<p>El sitio se sirve por HTTPS, aplica una política de seguridad de contenido (CSP) que limita a qué servicios puede conectarse, y no almacena tus consultas en servidores propios.</p>
<h3>11. Menores de edad</h3>
<p>Centinela no está dirigido a menores de edad.</p>
<h3>12. Vigencia y cambios</h3>
<p>Esta política rige desde el ${L.vigencia}. Si cambia, publicaremos la nueva versión en este mismo lugar indicando su fecha.</p>`},
  'terminos':{title:'Términos y condiciones de uso',html:L=>`
<p>Al usar Centinela aceptas estos términos. Si no estás de acuerdo, no uses el sitio.</p>
<h3>1. El servicio</h3>
<p>Centinela es una herramienta gratuita de análisis de seguridad de dominios, correo e infraestructura. Realiza consultas pasivas a fuentes públicas y a servicios de terceros; no ejecuta pruebas intrusivas ni de explotación.</p>
<h3>2. Uso permitido</h3>
<p>Solo puedes usar Centinela sobre dominios, cuentas, sistemas e infraestructura propios, o sobre aquellos para los que tengas autorización expresa, con fines de protección, investigación o respuesta a incidentes. Está prohibido usarlo para:</p>
<ul><li>Preparar o ejecutar accesos no autorizados, ataques o fraudes.</li><li>Acosar, vigilar o recolectar información de personas sin una base legítima.</li><li>Interferir con los servicios de terceros o eludir sus límites de uso.</li><li>Cualquier actividad contraria a la ley colombiana, incluida la Ley 1273 de 2009 sobre delitos informáticos.</li></ul>
<h3>3. Naturaleza de los resultados</h3>
<p>Los resultados son orientativos: se basan en heurísticas y en información de terceros que puede estar incompleta, desactualizada o ser errónea, y pueden incluir falsos positivos o falsos negativos. No constituyen asesoría legal, una auditoría certificada ni una prueba pericial. Verifica los hallazgos antes de tomar decisiones.</p>
<h3>4. Servicios de terceros</h3>
<p>Centinela depende de servicios externos con sus propios términos y límites de uso. No controlamos su disponibilidad ni la exactitud de sus datos, y pueden dejar de responder sin aviso.</p>
<h3>5. Plantillas y denuncias</h3>
<p>Las plantillas de denuncia, solicitud de retirada y comunicado son borradores. Eres responsable de revisarlas, completarlas y decidir si las envías, así como del contenido de lo que envíes.</p>
<h3>6. Propiedad intelectual</h3>
<p>El software, el diseño, los textos y la marca Centinela pertenecen a ${L.responsable}. Todos los derechos reservados. Las marcas y nombres de servicios de terceros mencionados pertenecen a sus respectivos titulares y se citan solo para identificarlos.</p>
<h3>7. Limitación de responsabilidad</h3>
<p>Centinela se ofrece "tal cual", sin garantías de disponibilidad, exactitud ni idoneidad para un fin concreto. En la medida en que lo permita la ley, ${L.responsable} no responde por daños derivados del uso del sitio, de sus resultados o de los servicios de terceros.</p>
<h3>8. Cambios</h3>
<p>Podemos modificar el servicio o estos términos en cualquier momento. La versión vigente es la publicada en este lugar.</p>
<h3>9. Ley aplicable</h3>
<p>Estos términos se rigen por las leyes de la República de Colombia. Cualquier controversia se someterá a los jueces competentes de ${L.domicilio}.</p>
<h3>10. Contacto</h3>
<p>${L.correo}</p>
<p class="lmeta">Vigentes desde el ${L.vigencia}.</p>`},
  'aviso-legal':{title:'Aviso legal',html:L=>`
<h3>Titular del sitio</h3>
<ul><li>${L.responsable}</li><li>Identificación: ${L.identificacion}</li><li>Domicilio: ${L.direccion}, ${L.domicilio}</li><li>Contacto: ${L.correo}</li></ul>
<h3>Derechos reservados</h3>
<p>© ${new Date().getFullYear()} ${L.responsable}. Todos los derechos reservados. Queda prohibida la reproducción, distribución o modificación del software, el diseño y los contenidos de Centinela sin autorización previa y por escrito del titular, salvo en los casos que permita la ley.</p>
<h3>Enlaces externos</h3>
<p>Centinela incluye enlaces a sitios y servicios de terceros para facilitar la investigación y la denuncia. No somos responsables de su contenido, disponibilidad ni políticas. Algunos resultados apuntan a sitios potencialmente maliciosos: ábrelos solo en un entorno seguro.</p>
<h3>Uso responsable</h3>
<p>El uso de Centinela está sujeto a los <a href="#terminos" data-legal="terminos">Términos y condiciones</a> y a la <a href="#privacidad" data-legal="privacidad">Política de tratamiento de datos personales</a>.</p>`},
};
(function(){
  const dlg=$('#legalDlg');if(!dlg)return;
  $('#footYear').textContent=new Date().getFullYear();
  const pending=Object.values(LEGAL).some(v=>/\[[^\]]+\]/.test(v));
  function openLegal(key){
    const doc=LEGAL_DOCS[key];if(!doc)return;
    const L=Object.fromEntries(Object.entries(LEGAL).map(([k,v])=>[k,esc(v)]));
    $('#legalTitle').textContent=doc.title;
    $('#legalBody').innerHTML=(pending?'<p class="lnote">Texto de referencia pendiente de completar: el responsable del sitio debe reemplazar los datos entre corchetes.</p>':'')+doc.html(L)+(key==='privacidad'?`<p class="lmeta">Vigente desde el ${L.vigencia}.</p>`:'');
    $('#legalBody').scrollTop=0;
    if(!dlg.open){try{dlg.showModal();}catch(e){dlg.setAttribute('open','');}}
    if(location.hash!=='#'+key)history.replaceState(null,'','#'+key);
  }
  // Al cerrar se quita el #texto de la dirección en el momento, sin esperar al evento close (que puede llegar tarde)
  const clearHash=()=>{if(LEGAL_DOCS[location.hash.slice(1)])history.replaceState(null,'',location.pathname+location.search);};
  function closeLegal(){dlg.close();clearHash();}
  dlg.addEventListener('cancel',clearHash);   // tecla Esc
  dlg.addEventListener('close',()=>{if(!dlg.open)clearHash();});
  dlg.addEventListener('click',e=>{if(e.target===dlg)closeLegal();});   // clic fuera del contenido
  $('#legalClose').addEventListener('click',closeLegal);
  document.addEventListener('click',e=>{const a=e.target.closest('[data-legal]');if(!a)return;e.preventDefault();openLegal(a.dataset.legal);});
  const fromHash=()=>{const k=location.hash.slice(1);if(LEGAL_DOCS[k])openLegal(k);};
  addEventListener('hashchange',fromHash);fromHash();
})();
// deep link
/* ============================================================ Consulta de IOCs
   Clasifica cada indicador y lo consulta en las fuentes adecuadas. Veredictos: mal (malicioso), sus (sospechoso),
   ok (sin reportes en las fuentes consultadas), nd (sin datos: no se pudo consultar ninguna fuente relevante). */
const IOC={last:null,busy:false};
const IOC_V={mal:['Malicioso','r','crit'],sus:['Sospechoso','y','high'],ok:['Sin reportes','g','low'],nd:['Sin datos','','info']};
const defang=v=>String(v).replace(/^http/i,'hxxp').replace(/\.(?=[^.]*$)/,'[.]');
function iocParse(text){
  const out=[],seen=new Set();
  String(text).split(/[\s,;]+/).map(refang).map(x=>x.replace(/^[<("'\[]+|[>)"'\]]+$/g,'')).filter(Boolean).forEach(v=>{
    const c=homeClassify(v);const t=c?c.t:(/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)?'email':null);
    const val=c?c.v:v;const k=(t||'?')+'|'+val;if(seen.has(k))return;seen.add(k);out.push({t:t||'unknown',v:val});});
  return out;
}
const iocAbuse=async(q,path)=>{const b=leakBackend();if(!b)return null;try{const r=await leakGet(b+path+'?q='+encodeURIComponent(q),20000);if(r.status===404)return {found:false};if(!r.ok)return {error:(r.j&&r.j.error)||('HTTP '+r.status)};return r.j;}catch(e){return {error:leakErr(e)};}};
async function iocRbl(ip){
  const q=await query(ip.split('.').reverse().join('.')+'.zen.spamhaus.org','A');
  const a=(q.answers||[]).map(x=>x.data);
  if(a.some(x=>/^127\.255\.255\./.test(x)))return {blocked:true};   // Spamhaus no responde a resolutores públicos
  return {listed:a.filter(x=>/^127\.0\.0\./.test(x))};
}
async function iocDomainAge(d){
  try{const r=await fetch('https://rdap.org/domain/'+encodeURIComponent(registrable(d)),{headers:{Accept:'application/rdap+json'}});if(!r.ok)return null;
    const j=await r.json();const ev=(j.events||[]).find(e=>e.eventAction==='registration');return ev?Math.round((Date.now()-new Date(ev.eventDate))/864e5):null;}catch(e){return null;}
}
async function iocCheck(it,cveMap){
  const R={t:it.t,v:it.v,v2:'nd',why:[],src:[],links:[],info:{}};
  const mal=(w,src)=>{R.v2='mal';R.why.push(w);if(src)R.src.push(src);};
  const sus=(w,src)=>{if(R.v2!=='mal')R.v2='sus';R.why.push(w);if(src)R.src.push(src);};
  const okk=src=>{if(R.v2==='nd')R.v2='ok';if(src&&!R.src.includes(src))R.src.push(src);};
  const note=w=>R.why.push(w);
  const tf=r=>{if(!r)return;if(r.error){note('ThreatFox: '+r.error);return;}if(r.found)mal('ThreatFox: '+(r.malware||r.threat||'IOC reportado')+(r.confidence!=null?' (confianza '+r.confidence+'%)':''),'ThreatFox');else okk('ThreatFox');};
  const uh=r=>{if(!r)return;if(r.error){note('URLhaus: '+r.error);return;}if(r.found)mal('URLhaus: '+(r.threat||'distribución de malware')+(r.status?' · '+r.status:''),'URLhaus');else okk('URLhaus');};
  if(it.t==='ip'){
    const [sh,geo,rbl,tfr]=await Promise.all([shodanIDB(it.v).catch(()=>null),geoLookup(it.v).catch(()=>null),iocRbl(it.v).catch(()=>null),iocAbuse(it.v,'/sbx/threatfox')]);
    if(geo){R.info.geo=[geo.country,geo.asn,geo.org||geo.isp].filter(Boolean).join(' · ');okk('Geo/ASN');}
    if(sh){okk('Shodan');R.info.ports=(sh.ports||[]).slice(0,20);const tg=sh.tags||[];R.info.tags=tg;
      if(tg.some(x=>/malware|compromised|c2|botnet/i.test(x)))mal('Shodan lo etiqueta como '+tg.filter(x=>/malware|compromised|c2|botnet/i.test(x)).join(', '),'Shodan');
      else if(tg.some(x=>/tor|proxy|vpn|scanner/i.test(x)))sus('Shodan: '+tg.join(', ')+' (anonimización o escaneo)','Shodan');
      if((sh.vulns||[]).length)note((sh.vulns||[]).length+' CVE expuestos en el host (Shodan)');}
    if(rbl){if(rbl.listed&&rbl.listed.length)mal('Listado en Spamhaus ZEN ('+rbl.listed.join(', ')+')','Spamhaus');else if(!rbl.blocked)okk('Spamhaus');}
    tf(tfr);
    R.links=[['Shodan','https://www.shodan.io/host/'+it.v],['AbuseIPDB','https://www.abuseipdb.com/check/'+it.v],['VirusTotal','https://www.virustotal.com/gui/ip-address/'+it.v],['ThreatFox','https://threatfox.abuse.ch/browse.php?search=ioc%3A'+it.v],['GreyNoise','https://viz.greynoise.io/ip/'+it.v]];
  }
  else if(it.t==='domain'||it.t==='url'){
    const host=it.t==='url'?new URL(it.v).hostname:it.v;
    const isIp=/^\d+\.\d+\.\d+\.\d+$/.test(host);
    const tasks=[isIp?null:query(host,'A').catch(()=>null),isIp?null:query(registrable(host)+'.dbl.spamhaus.org','A').catch(()=>null),isIp?null:iocDomainAge(host),iocAbuse(it.t==='url'?it.v:host,'/sbx/urlhaus'),it.t==='domain'?iocAbuse(host,'/sbx/threatfox'):null];
    const gsbKey=(()=>{try{return localStorage.getItem('ctn-gsb')||'';}catch(e){return '';}})();
    if(it.t==='url'&&gsbKey)tasks.push(safeBrowsingCheck(it.v,gsbKey).catch(()=>null));
    const [a,dbl,age,uhr,tfr,gsb]=await Promise.all(tasks);
    if(a){const ips=(a.answers||[]).map(x=>x.data).filter(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x));R.info.ips=ips.slice(0,4);if(!ips.length)note('No resuelve a ninguna IP');okk('DNS');}
    if(dbl){const d=(dbl.answers||[]).map(x=>x.data);if(d.some(x=>/^127\.0\.1\.\d+$/.test(x)))mal('Listado en Spamhaus DBL','Spamhaus DBL');else if(!d.some(x=>/^127\.255\.255\./.test(x)))okk('Spamhaus DBL');}
    if(age!=null){R.info.age=age;if(age<30)sus('Dominio muy reciente ('+age+' días)','RDAP');else okk('RDAP');}
    uh(uhr);tf(tfr);
    if(gsb==='listed')mal('Catalogado por Google Safe Browsing','Safe Browsing');else if(gsb==='clean')okk('Safe Browsing');
    if(/(^|\.)xn--/.test(host))sus('Dominio IDN/punycode (posible homógrafo)');
    R.links=[['VirusTotal',it.t==='url'?'https://www.virustotal.com/gui/search/'+encodeURIComponent(it.v):'https://www.virustotal.com/gui/domain/'+host],['urlscan.io','https://urlscan.io/search/#page.domain:'+encodeURIComponent(host)],['URLhaus','https://urlhaus.abuse.ch/browse.php?search='+encodeURIComponent(host)],['ThreatFox','https://threatfox.abuse.ch/browse.php?search=ioc%3A'+encodeURIComponent(host)]];
  }
  else if(it.t==='hash'){
    const b=leakBackend();
    if(b){const [rep,tfr]=await Promise.all([it.v.length===64?sbxRep(it.v).catch(()=>null):(async()=>{const rr={sources:{}};const [vt,mb]=await Promise.all([leakGet(b+'/sbx/vt?hash='+it.v,25000).catch(()=>null),leakGet(b+'/sbx/mb?hash='+it.v,20000).catch(()=>null)]);if(vt)rr.sources.vt=vt.status===404?{found:false}:vt.ok?vt.j:{error:(vt.j&&vt.j.error)||'HTTP '+vt.status};if(mb)rr.sources.mb=mb.status===404?{found:false}:mb.ok?mb.j:{error:(mb.j&&mb.j.error)||'HTTP '+mb.status};return rr;})(),iocAbuse(it.v,'/sbx/threatfox')]);
      const S=(rep&&rep.sources)||{};
      if(S.vt&&S.vt.found!==false&&!S.vt.error){const m=(S.vt.stats&&S.vt.stats.malicious)||0;if(m>=5)mal('VirusTotal: '+m+' motores lo detectan'+(S.vt.label?' ('+S.vt.label+')':''),'VirusTotal');else if(m>0)sus('VirusTotal: '+m+' motor(es) lo detectan','VirusTotal');else okk('VirusTotal');}
      else if(S.vt&&S.vt.found===false)okk('VirusTotal');
      if(S.mb&&S.mb.found)mal('MalwareBazaar: '+(S.mb.signature||'muestra conocida'),'MalwareBazaar');else if(S.mb&&S.mb.found===false)okk('MalwareBazaar');
      if(S.ha&&S.ha.found){if(/malicious/i.test(S.ha.verdict||''))mal('Hybrid Analysis: '+S.ha.verdict+(S.ha.family?' ('+S.ha.family+')':''),'Hybrid Analysis');else if(/suspicious/i.test(S.ha.verdict||''))sus('Hybrid Analysis: sospechoso','Hybrid Analysis');else okk('Hybrid Analysis');}
      if(S.hashlookup&&S.hashlookup.found&&R.v2!=='mal'){R.v2='ok';R.why.push('Archivo conocido legítimo (NSRL): '+(S.hashlookup.name||''));R.src.push('CIRCL hashlookup');}
      tf(tfr);
      Object.entries(S).forEach(([k,o])=>{if(o&&o.error)note(k+': '+o.error);});
    } else note('Configura el backend para consultar la reputación del hash; usa los enlaces de búsqueda.');
    R.links=[['VirusTotal','https://www.virustotal.com/gui/file/'+it.v],['MalwareBazaar','https://bazaar.abuse.ch/browse.php?search=hash%3A'+it.v],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query='+it.v],['Triage','https://tria.ge/s?q='+it.v],['AlienVault OTX','https://otx.alienvault.com/indicator/file/'+it.v]];
  }
  else if(it.t==='cve'){
    const c=cveMap[it.v];
    if(c){R.info.cve=c;if(c.kev)mal('Explotada activamente (CISA KEV)'+(c.kev.ransom?' · usada por ransomware':''),'CISA KEV');
      else if((c.epss&&c.epss.epss>=0.1)||(c.cvss!=null&&c.cvss>=9))sus('Riesgo alto: CVSS '+(c.cvss!=null?c.cvss:'n/d')+' · EPSS '+(c.epss?(c.epss.epss*100).toFixed(1)+'%':'n/d'),'CVSS/EPSS');
      else okk('CVSS/EPSS');
      R.why.push('CVSS '+(c.cvss!=null?c.cvss:'n/d')+' · EPSS '+(c.epss?(c.epss.epss*100).toFixed(2)+'%':'n/d')+(c.summary?' · '+c.summary.slice(0,160):''));}
    R.links=[['NVD','https://nvd.nist.gov/vuln/detail/'+it.v],['CIRCL','https://cve.circl.lu/vuln/'+it.v],['OSV','https://osv.dev/vulnerability/'+it.v]];
  }
  else if(it.t==='email'){note('Los correos se consultan en el módulo Filtraciones.');R.links=[['Filtraciones','#leak']];}
  else note('Tipo de indicador no reconocido.');
  R.src=[...new Set(R.src)];
  return R;
}
async function runIoc(){
  if(IOC.busy)return;
  const items=iocParse($('#iocInput').value).slice(0,100);
  if(!items.length){alert('Pega al menos un indicador (IP, dominio, URL, hash o CVE)');return;}
  IOC.busy=true;$('#goIoc').disabled=true;$('#iocOut').innerHTML='';CIRCL_LIMITED=false;
  const st=$('#iocStatus');st.style.display='flex';$('#iocBarwrap').style.display='block';
  const setP=(p,t)=>{$('#iocBar').style.width=p+'%';$('#iocStatusTxt').textContent=t;};
  RESOLVER='auto';cache.clear();
  try{
    const cves=items.filter(x=>x.t==='cve').map(x=>({id:x.v,source:'consulta'}));
    const cveMap={};
    if(cves.length){setP(5,'Consultando CVE…');(await sbxEnrichCves(cves)).forEach(c=>cveMap[c.id]=c);}
    const res=new Array(items.length);let done=0;const B=4;
    for(let i=0;i<items.length;i+=B){
      await Promise.all(items.slice(i,i+B).map(async(it,k)=>{try{res[i+k]=await iocCheck(it,cveMap);}catch(e){res[i+k]={t:it.t,v:it.v,v2:'nd',why:['Error: '+leakErr(e)],src:[],links:[],info:{}};}done++;setP(10+Math.round(done/items.length*88),'Consultando '+done+'/'+items.length+'…');}));
    }
    IOC.last={when:new Date(),items:res};
    renderIoc();
  }finally{IOC.busy=false;$('#goIoc').disabled=false;st.style.display='none';$('#iocBarwrap').style.display='none';}
}
const IOC_TL={ip:'IP',domain:'Dominio',url:'URL',hash:'Hash',cve:'CVE',email:'Correo',unknown:'?'};
function renderIoc(){
  const L=IOC.last;if(!L)return;const I=L.items;
  const n=k=>I.filter(x=>x.v2===k).length;
  const order={mal:0,sus:1,nd:2,ok:3};
  const rows=I.map((x,i)=>({x,i})).sort((a,b)=>order[a.x.v2]-order[b.x.v2]||a.i-b.i);
  $('#iocOut').innerHTML=`<div class="glass phishcard">
    <div class="kpis" data-s="margin-bottom:0">
      <div class="kpi neut"><b>${I.length}</b><span>indicadores</span></div>
      <div class="kpi ${n('mal')?'fail':'neut'}"><b>${n('mal')}</b><span>maliciosos</span></div>
      <div class="kpi ${n('sus')?'warn':'neut'}"><b>${n('sus')}</b><span>sospechosos</span></div>
      <div class="kpi ok"><b>${n('ok')}</b><span>sin reportes</span></div>
      <div class="kpi neut"><b>${n('nd')}</b><span>sin datos</span></div>
    </div>
    ${leakBackend()?'':'<p class="hint" data-s="margin-top:10px">Sin backend: URLhaus, ThreatFox y la reputación de hashes no se consultaron (Ajustes → URL del backend).</p>'}
    <div class="rtoolbar">
      <label class="sbxopt" data-s="flex:0 0 auto"><input type="checkbox" id="iocDefang" checked> Exportar desactivados (defang)</label>
      <button class="btn" data-iocexp="csv">${ico('download')}CSV</button>
      <button class="btn ghost" data-iocexp="json">${ico('download')}JSON</button>
      <button class="btn ghost" data-iocexp="stix">${ico('download')}STIX 2.1</button>
      <button class="btn ghost" data-iocexp="copy">${ico('copy')}Copiar maliciosos</button>
      <button class="btn ghost" data-caseadd="ioc">${ico('note')}Añadir a un caso</button>
    </div>
    <div class="sbxscroll" data-s="margin-top:12px"><table class="sbxtbl"><tr><th>Indicador</th><th>Tipo</th><th>Veredicto</th><th>Motivo y contexto</th><th>Fuentes</th><th>Investigar</th></tr>
    ${rows.map(({x})=>{const V=IOC_V[x.v2];const ctx=[x.info.geo,x.info.ips&&x.info.ips.length?'IP: '+x.info.ips.join(', '):'',x.info.ports&&x.info.ports.length?'puertos: '+x.info.ports.join(', '):'',x.info.age!=null?'dominio de '+x.info.age+' días':''].filter(Boolean).join(' · ');
      return `<tr><td class="m">${esc(defang(x.v))}</td><td>${esc(IOC_TL[x.t]||x.t)}</td><td>${tag(V[0],V[1])}</td><td>${esc(x.why.join(' · ')||(x.v2==='ok'?'Sin coincidencias en las fuentes consultadas':'—'))}${ctx?`<div class="hint">${esc(ctx)}</div>`:''}</td><td>${x.src.map(s=>`<span class="tag">${esc(s)}</span>`).join('')}</td><td>${x.links.map(l=>l[1].startsWith('#')?`<a class="tag" href="#" data-iocgo="${esc(l[1].slice(1))}" data-s="text-decoration:none">${esc(l[0])}</a>`:`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(l[1])}">${esc(l[0])} ↗</a>`).join('')}</td></tr>`;}).join('')}
    </table></div>
    <p class="hint" data-s="margin-top:10px">"Sin reportes" significa que las fuentes consultadas no tienen registros, no que el indicador sea seguro. Los indicadores se muestran desactivados ([.] y hxxp) para evitar clics accidentales.</p>
  </div>`;
}
function iocExport(kind){
  const L=IOC.last;if(!L)return;const df=$('#iocDefang')&&$('#iocDefang').checked;const val=v=>df?defang(v):v;const stamp=L.when.toISOString().slice(0,10);
  if(kind==='csv'){const q=v=>'"'+String(v).replace(/"/g,'""')+'"';downloadFile('centinela-iocs-'+stamp+'.csv',[['indicador','tipo','veredicto','motivo','fuentes'].join(',')].concat(L.items.map(x=>[val(x.v),x.t,IOC_V[x.v2][0],x.why.join(' | '),x.src.join(' | ')].map(q).join(','))).join('\r\n'),'text/csv');}
  else if(kind==='json')downloadFile('centinela-iocs-'+stamp+'.json',JSON.stringify({tool:'Centinela',type:'ioc-lookup',generated:L.when.toISOString(),defanged:!!df,indicators:L.items.map(x=>({value:val(x.v),type:x.t,verdict:x.v2==='mal'?'malicious':x.v2==='sus'?'suspicious':x.v2==='ok'?'no-reports':'no-data',reasons:x.why,sources:x.src,context:x.info}))},null,2),'application/json');
  else if(kind==='copy'){const t=L.items.filter(x=>x.v2==='mal').map(x=>val(x.v)).join('\n');try{navigator.clipboard.writeText(t);}catch(e){}btnTxt(document.querySelector('[data-iocexp="copy"]'),t?'Copiados':'Sin maliciosos');}
  else if(kind==='stix'){
    const now=L.when.toISOString(),uid=t=>t+'--'+(crypto.randomUUID?crypto.randomUUID():Date.now().toString(16).padStart(8,'0')+'-0000-4000-8000-'+Math.random().toString(16).slice(2,14).padEnd(12,'0'));
    const q=v=>String(v).replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    const pat=x=>x.t==='ip'?"[ipv4-addr:value = '"+q(x.v)+"']":x.t==='domain'?"[domain-name:value = '"+q(x.v)+"']":x.t==='url'?"[url:value = '"+q(x.v)+"']":x.t==='hash'?"[file:hashes.'"+(x.v.length===64?'SHA-256':x.v.length===40?'SHA-1':'MD5')+"' = '"+x.v+"']":null;
    const ident={type:'identity',spec_version:'2.1',id:uid('identity'),created:now,modified:now,name:(()=>{try{return localStorage.getItem('ctn-org')||'Centinela';}catch(e){return 'Centinela';}})(),identity_class:'organization'};
    const objs=[ident];
    L.items.filter(x=>(x.v2==='mal'||x.v2==='sus')&&pat(x)).forEach(x=>objs.push({type:'indicator',spec_version:'2.1',id:uid('indicator'),created:now,modified:now,created_by_ref:ident.id,name:x.v,description:x.why.join(' | '),indicator_types:[x.v2==='mal'?'malicious-activity':'anomalous-activity'],pattern:pat(x),pattern_type:'stix',valid_from:now,confidence:x.v2==='mal'?80:40}));
    L.items.filter(x=>x.t==='cve').forEach(x=>objs.push({type:'vulnerability',spec_version:'2.1',id:uid('vulnerability'),created:now,modified:now,name:x.v,external_references:[{source_name:'cve',external_id:x.v}]}));
    downloadFile('centinela-iocs-'+stamp+'-stix21.json',JSON.stringify({type:'bundle',id:uid('bundle'),objects:objs},null,2),'application/json');
  }
}
(function(){
  $('#mbIoc').addEventListener('click',()=>setMode('ioc'));
  $('#goIoc').addEventListener('click',runIoc);
  $('#iocClear').addEventListener('click',()=>{if(IOC.busy)return;$('#iocInput').value='';$('#iocOut').innerHTML='';IOC.last=null;});
  $('#iocOut').addEventListener('click',e=>{const x=e.target.closest('[data-iocexp]');if(x){iocExport(x.dataset.iocexp);return;}const g=e.target.closest('[data-iocgo]');if(g){e.preventDefault();setMode(g.dataset.iocgo);}});
})();

/* ============================================================ TLS y certificados (vía backend con sockets) */
const TLS={last:null,busy:false};
function tlsAssess(r){
  const F=[];const add=(sev,title,detail,rem)=>F.push({sev,title,detail,rem});
  const V=r.versions||{},c=r.cert;let caps=[];
  const modern=V['TLS 1.3']||V['TLS 1.2'];
  if(!modern){add('crit','No admite TLS 1.2 ni TLS 1.3','Solo ofrece versiones obsoletas e inseguras del protocolo.','Habilita TLS 1.2 y TLS 1.3 en el servidor y desactiva TLS 1.0/1.1.');caps.push('F');}
  if(V['TLS 1.0']||V['TLS 1.1']){add('high','Versiones obsoletas habilitadas: '+['TLS 1.0','TLS 1.1'].filter(v=>V[v]).join(' y '),'TLS 1.0 y 1.1 están retiradas (RFC 8996) y tienen debilidades conocidas; los navegadores ya no las aceptan.','Desactiva TLS 1.0 y 1.1 en el servidor o balanceador.');caps.push('B');}
  if(!V['TLS 1.3']&&modern)add('low','TLS 1.3 no está habilitado','TLS 1.3 es más rápido y elimina cifrados heredados.','Habilita TLS 1.3 (OpenSSL 1.1.1+, nginx/Apache recientes).');
  const weak=/3DES|RC4/.test(V.cipher12||'')||/3DES|RC4/.test((r.best&&r.best.cipher)||'');
  if(weak){add('high','Se negocia un cifrado débil ('+(V.cipher12||r.best.cipher)+')','3DES y RC4 son vulnerables (Sweet32, ataques a RC4).','Prioriza suites AEAD (AES-GCM, ChaCha20-Poly1305) con ECDHE.');caps.push('C');}
  else if(V.cipher12&&!/GCM|CHACHA/.test(V.cipher12))add('low','En TLS 1.2 se prefiere un cifrado CBC ('+V.cipher12+')','Las suites CBC son más propensas a ataques de relleno que las AEAD.','Ordena las suites para preferir AES-GCM o ChaCha20-Poly1305.');
  if(V.cipher12&&/^RSA-/.test(V.cipher12))add('med','Intercambio de claves sin secreto perfecto hacia adelante (RSA estático)','Si la clave privada se filtra, el tráfico grabado podría descifrarse.','Prioriza suites ECDHE.');
  if(c){
    if(c.daysLeft!=null&&c.daysLeft<0){add('crit','Certificado caducado hace '+(-c.daysLeft)+' días','Los navegadores muestran un error de seguridad y bloquean el acceso.','Renueva el certificado y automatiza la renovación (p.ej. ACME/Let’s Encrypt).');caps.push('F');}
    else if(c.daysLeft!=null&&c.daysLeft<15){add('crit','El certificado vence en '+c.daysLeft+' días','Riesgo inminente de interrupción del servicio.','Renueva el certificado de inmediato y automatiza la renovación.');caps.push('B');}
    else if(c.daysLeft!=null&&c.daysLeft<30)add('med','El certificado vence en '+c.daysLeft+' días','Conviene renovarlo pronto.','Programa la renovación o automatízala.');
    if(c.selfSigned){add('crit','Certificado autofirmado','No lo emite una autoridad de confianza: los usuarios verán advertencias y quedan expuestos a interceptación.','Usa un certificado de una CA de confianza.');caps.push('F');}
    if(!c.nameMatch){add('crit','El certificado no corresponde al nombre '+r.host,'Los nombres del certificado ('+(c.sans.slice(0,4).join(', ')||c.subject.CN||'—')+') no incluyen este host.','Emite un certificado que incluya '+r.host+' en sus SAN.');caps.push('F');}
    if(c.keyType==='RSA'&&c.keyBits&&c.keyBits<2048){add('high','Clave RSA de '+c.keyBits+' bits','Por debajo del mínimo recomendado (2048 bits).','Reemite el certificado con RSA de 2048+ bits o ECDSA P-256.');caps.push('C');}
    if(/sha1|md5/i.test(c.sigAlg)){add('high','Firma con algoritmo obsoleto ('+c.sigAlg+')','SHA-1 y MD5 admiten colisiones; los navegadores rechazan estos certificados.','Reemite el certificado con SHA-256 o superior.');caps.push('C');}
  } else add('info','No se pudo leer el certificado',r.certError||'','Consulta el certificado en crt.sh o con el navegador.');
  if(r.port===443){
    const m=/max-age=(\d+)/i.exec(r.hsts||'');const age=m?+m[1]:0;
    if(!r.hsts)add('med','Sin HSTS (Strict-Transport-Security)','Sin HSTS, un atacante en la red puede forzar la conexión por HTTP (SSL stripping).','Añade Strict-Transport-Security: max-age=31536000; includeSubDomains.');
    else if(age<15552000)add('low','HSTS con duración corta ('+Math.round(age/86400)+' días)','Se recomienda al menos 180 días (ideal 1 año).','Aumenta max-age a 31536000.');
    if(r.httpRedirect==='no')add('med','HTTP no redirige a HTTPS','Los usuarios que entren por http:// navegan sin cifrar.','Redirige todo el tráfico HTTP a HTTPS con 301.');
  }
  const order=['F','C','B','A-','A','A+'];let grade='A';
  if(caps.length)grade=caps.sort((x,y)=>order.indexOf(x)-order.indexOf(y))[0];
  else{const m=/max-age=(\d+)/i.exec(r.hsts||'');if(r.port!==443||(m&&+m[1]>=15552000&&r.httpRedirect!=='no'))grade=V['TLS 1.3']?'A+':'A';else grade=r.hsts?'A':'A-';}
  return {grade,findings:F.sort((x,y)=>SEV_RANK[y.sev]-SEV_RANK[x.sev])};
}
async function runTls(){
  if(TLS.busy)return;
  const host=$('#tlsHost').value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/[\/:].*$/,'');const port=+$('#tlsPort').value;
  if(!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)){alert('Ingresa un dominio válido, por ejemplo tudominio.gov.co');return;}
  const b=leakBackend();const out=$('#tlsOut');
  if(!b){out.innerHTML=`<div class="glass phishcard"><b>Este análisis necesita el backend</b><p class="hint">Un navegador no puede ver los detalles de TLS de otro servidor. Configura el backend en Ajustes → URL del backend (con sockets habilitados). Mientras tanto, el historial de certificados del dominio está en <a target="_blank" rel="noopener noreferrer" href="https://crt.sh/?q=${encodeURIComponent(host)}">crt.sh ↗</a>.</p></div>`;return;}
  TLS.busy=true;$('#goTls').disabled=true;out.innerHTML='';$('#tlsStatus').style.display='flex';$('#tlsStatusTxt').textContent='Probando versiones de TLS en '+host+':'+port+'…';
  try{
    const r=await leakGet(b+'/sbx/tls?host='+encodeURIComponent(host)+'&port='+port,90000);
    if(!r.ok||!r.j||r.j.error){out.innerHTML=`<div class="glass phishcard"><b>No se pudo analizar ${esc(host)}</b><p class="hint">${esc((r.j&&r.j.error)||('HTTP '+r.status))}</p></div>`;return;}
    const R=r.j;const A=tlsAssess(R);TLS.last={r:R,a:A,when:new Date()};renderTls();
  }catch(e){out.innerHTML=`<div class="glass phishcard"><b>Error</b><p class="hint">${esc(leakErr(e))}</p></div>`;}
  finally{TLS.busy=false;$('#goTls').disabled=false;$('#tlsStatus').style.display='none';}
}
function renderTls(){
  const {r:R,a:A}=TLS.last;const c=R.cert;const gc={'A+':'var(--oktx)',A:'var(--oktx)','A-':'var(--oktx)',B:'var(--wartx)',C:'var(--sev-high)',F:'var(--sev-crit)'}[A.grade];
  const V=R.versions||{};
  const vrow=(k,good)=>`<tr><td>${k}</td><td>${V[k]===true?tag('habilitado',good?'g':'r'):V[k]===false?tag('deshabilitado',good?'y':'g'):tag('sin respuesta','y')}</td></tr>`;
  $('#tlsOut').innerHTML=`<div class="glass phishcard">
    <div class="vgrade"><div class="vgbadge" data-s="color:${gc}">${esc(A.grade)}</div><div data-s="flex:1 1 240px"><div class="phverdict" data-s="margin:0;color:${gc}">Calificación TLS: ${esc(A.grade)}</div>
      <div class="phurl" data-s="margin-bottom:0">${esc(R.host)}:${R.port}${R.best?' · mejor: '+esc(R.best.version)+' · '+esc(R.best.cipher):''}</div></div></div>
    <div class="subh">Versiones del protocolo</div><table class="kv">${vrow('TLS 1.3',true)}${vrow('TLS 1.2',true)}${vrow('TLS 1.1',false)}${vrow('TLS 1.0',false)}${V.cipher12?`<tr><td>Cifrado preferido en TLS 1.2</td><td class="m" data-s="font-family:var(--mono)">${esc(V.cipher12)}</td></tr>`:''}</table>
    <div class="subh">Certificado</div>${c?`<table class="kv">
      <tr><td>Sujeto</td><td>${esc(c.subject.CN||'—')}${c.subject.O?' · '+esc(c.subject.O):''}</td></tr><tr><td>Emisor</td><td>${esc([c.issuer.CN,c.issuer.O].filter(Boolean).join(' · '))}${c.selfSigned?' '+tag('autofirmado','r'):''}</td></tr>
      <tr><td>Validez</td><td>${esc((c.notBefore||'').slice(0,10))} → ${esc((c.notAfter||'').slice(0,10))} ${c.daysLeft<0?tag('caducado','r'):c.daysLeft<30?tag(c.daysLeft+' días','y'):tag(c.daysLeft+' días','g')}</td></tr>
      <tr><td>Nombres (SAN)</td><td>${esc(c.sans.slice(0,12).join(', ')||'—')}${c.sans.length>12?' …':''} ${c.nameMatch?tag('coincide','g'):tag('no coincide','r')}</td></tr>
      <tr><td>Clave</td><td>${esc(c.keyType)} ${c.keyBits?esc(c.keyBits)+' bits':''}${c.curve?' · '+esc(c.curve):''}</td></tr><tr><td>Firma</td><td>${esc(c.sigAlg)}</td></tr>
      <tr><td>Número de serie</td><td data-s="font-family:var(--mono);word-break:break-all">${esc(c.serial)}</td></tr></table>`:`<p class="hint">${esc(R.certError||'No disponible')}</p>`}
    ${R.port===443?`<div class="subh">Configuración HTTPS</div><table class="kv"><tr><td>HSTS</td><td>${R.hsts?`<span data-s="font-family:var(--mono);word-break:break-all">${esc(R.hsts)}</span>`:tag('ausente','y')}</td></tr><tr><td>HTTP → HTTPS</td><td>${R.httpRedirect==='https'?tag('redirige','g'):R.httpRedirect==='no'?tag('no redirige','r'):tag(R.httpRedirect||'n/d','y')}</td></tr></table>`:''}
    <div class="subh">Hallazgos (${A.findings.length})</div>${A.findings.length?A.findings.map(f=>`<div class="vfind ${VULN_SEV[f.sev].cls}"><h4>${vSevChip(f.sev)} ${esc(f.title)}</h4><div class="vmeta">${esc(f.detail)}</div>${f.rem?`<div class="vrem">${ico('wrench')} <b>Remediación:</b> ${esc(f.rem)}</div>`:''}</div>`).join(''):'<p class="hint">Sin hallazgos: configuración TLS sólida.</p>'}
    <div data-s="margin-top:10px">${[['crt.sh','https://crt.sh/?q='+encodeURIComponent(R.host)],['SSL Labs','https://www.ssllabs.com/ssltest/analyze.html?d='+encodeURIComponent(R.host)],['HSTS preload','https://hstspreload.org/?domain='+encodeURIComponent(R.host)]].map(p=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${esc(p[0])} ↗</a>`).join(' ')}</div>
    <div class="rtoolbar"><button class="btn ghost" id="tlsJson">${ico('download')}Datos (.json)</button></div>
  </div>`;
  $('#tlsJson').addEventListener('click',()=>downloadFile('centinela-tls-'+R.host+'.json',JSON.stringify({tool:'Centinela',type:'tls-assessment',generated:TLS.last.when.toISOString(),grade:A.grade,result:R,findings:A.findings},null,2),'application/json'));
}
(function(){
  $('#mbTls').addEventListener('click',()=>setMode('tls'));
  $('#goTls').addEventListener('click',runTls);
  $('#tlsHost').addEventListener('keydown',e=>{if(e.key==='Enter')runTls();});
})();

/* ============================================================ Gestor de casos
   Guardado en localStorage (ctn-cases). Retención: 30 días sin cambios, nunca durante la sesión activa (ver purgeHistory). */
const CASES={sel:null,pending:null};const CASE_KEY='ctn-cases',CASE_DAYS=30,CASE_MAX=50;
const CASE_ST={open:'Abierto',inv:'En investigación',cont:'Contenido (aislado)',closed:'Cerrado'};
const caseAll=()=>{try{const a=JSON.parse(localStorage.getItem(CASE_KEY)||'[]');return Array.isArray(a)?a:[];}catch(e){return [];}};
function caseSave(list){try{localStorage.setItem(CASE_KEY,JSON.stringify(list.slice(0,CASE_MAX)));return true;}catch(e){alert('No se pudo guardar el caso: el almacenamiento del navegador está lleno. Exporta y elimina casos antiguos.');return false;}}
const caseId=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,7);
function caseTouch(c,text){const now=new Date().toISOString();c.updated=now;c.log=c.log||[];c.log.unshift({ts:now,text});c.log=c.log.slice(0,300);}
function caseCreate(title,sev){
  const list=caseAll();if(list.length>=CASE_MAX){alert('Se alcanzó el máximo de '+CASE_MAX+' casos; elimina o exporta alguno.');return null;}
  const now=new Date().toISOString();const c={id:caseId(),title:String(title).slice(0,120),sev:sev||'high',status:'open',desc:'',created:now,updated:now,items:[],log:[]};
  caseTouch(c,'Caso creado');list.unshift(c);return caseSave(list)?c:null;
}
function caseUpdate(id,fn){const list=caseAll();const c=list.find(x=>x.id===id);if(!c)return null;fn(c);caseSave(list);return c;}
/* Elementos que se pueden añadir desde otros módulos (resumen compacto, sin contenido de los archivos) */
function caseItemFromSbx(i){const x=sbxOk()[i];if(!x)return null;const r=x.r;
  return {kind:r.urlInfo?'url':'file',title:r.urlInfo?r.urlInfo.final:r.name,summary:r.verdict.t+' ('+r.score+'/100) · '+r.type.label,
    data:{sha256:r.hashes.sha256,md5:r.hashes.md5,verdict:r.verdict.t,score:r.score,attack:Object.keys(sbxTechSev(r)),cves:(r.cveInfo||[]).map(c=>c.id),iocs:[...(r.iocs.domains||[]).slice(0,30),...(r.iocs.urls||[]).slice(0,30),...(r.iocs.ips||[]).slice(0,30)],url:r.urlInfo?r.urlInfo.final:null}};}
function caseItemFromIoc(){const L=IOC.last;if(!L)return null;const sel=L.items.filter(x=>x.v2==='mal'||x.v2==='sus');const use=sel.length?sel:L.items;
  return {kind:'ioc',title:use.length+' indicador(es)'+(sel.length?' maliciosos/sospechosos':''),summary:use.slice(0,5).map(x=>defang(x.v)).join(', ')+(use.length>5?' …':''),data:{indicators:use.map(x=>({value:x.v,type:x.t,verdict:x.v2,reasons:x.why}))}};}
function caseItemFromReport(){const D=REPORT_DATA;if(!D)return null;
  return {kind:'report',title:'Informe ejecutivo · '+D.target,summary:[D.vuln?'calificación '+D.vuln.grade:'',D.compliance&&D.compliance.pct!=null?'cumplimiento '+D.compliance.pct+'%':''].filter(Boolean).join(' · ')||'Informe generado',data:{target:D.target,grade:D.vuln?D.vuln.grade:null,score:D.vuln?D.vuln.score:null,compliance:D.compliance?D.compliance.pct:null}};}
function caseAddDialog(item){
  if(!item)return;CASES.pending=item;const list=caseAll();const d=$('#caseDlg');
  $('#caseDlgWhat').textContent=item.title+' — '+item.summary;
  $('#caseDlgSel').innerHTML=list.map(c=>`<option value="${esc(c.id)}">${esc(c.title)} · ${esc(CASE_ST[c.status])}</option>`).join('')+'<option value="__new">+ Crear un caso nuevo</option>';
  if(CASES.sel&&list.some(c=>c.id===CASES.sel))$('#caseDlgSel').value=CASES.sel;else if(!list.length)$('#caseDlgSel').value='__new';
  const sync=()=>{$('#caseDlgNewWrap').style.display=$('#caseDlgSel').value==='__new'?'':'none';};sync();$('#caseDlgSel').onchange=sync;
  $('#caseDlgNew').value=item.title.slice(0,80);d.showModal();($('#caseDlgSel').value==='__new'?$('#caseDlgNew'):$('#caseDlgSel')).focus();
}
function caseAddConfirm(){
  const item=CASES.pending;if(!item)return;let id=$('#caseDlgSel').value;
  if(id==='__new'){const c=caseCreate($('#caseDlgNew').value.trim()||item.title,'high');if(!c)return;id=c.id;}
  caseUpdate(id,c=>{c.items.unshift(Object.assign({id:caseId(),ts:new Date().toISOString()},item));c.items=c.items.slice(0,200);caseTouch(c,'Añadido: '+item.title);});
  CASES.sel=id;CASES.pending=null;$('#caseDlg').close();
  const t=document.createElement('div');t.className='hint';t.setAttribute('role','status');t.textContent='Añadido al caso.';t.style.cssText='position:fixed;bottom:18px;right:18px;background:var(--panel);border:1px solid var(--accent);padding:10px 14px;border-radius:10px;z-index:999';document.body.appendChild(t);setTimeout(()=>t.remove(),2200);
}
function renderCases(){
  const list=caseAll();const L=$('#caseList');
  if(CASES.sel&&!list.some(c=>c.id===CASES.sel))CASES.sel=null;if(!CASES.sel&&list[0])CASES.sel=list[0].id;
  L.innerHTML=`<div class="subh" data-s="margin-top:0">Casos (${list.length})</div>`+(list.length?list.map(c=>`<button type="button" class="caseitem" data-case="${esc(c.id)}" aria-current="${c.id===CASES.sel}"><b>${esc(c.title)}</b><span>${vSevChip(c.sev)} ${esc(CASE_ST[c.status])} · ${c.items.length} elemento(s) · ${esc(new Date(c.updated).toLocaleDateString('es-CO'))}</span></button>`).join(''):'<p class="hint">Aún no hay casos. Crea uno arriba o usa "Añadir a un caso" en otros módulos.</p>');
  const c=list.find(x=>x.id===CASES.sel);const D=$('#caseDetail');
  if(!c){D.innerHTML='<p class="hint">Selecciona o crea un caso.</p>';return;}
  const left=CASE_DAYS-Math.floor((Date.now()-Date.parse(c.updated))/864e5);
  const kindL={file:'Archivo',url:'Enlace',ioc:'Indicadores',report:'Informe',note:'Nota'};
  D.innerHTML=`<div class="controls"><div class="field grow"><label for="caseEdTitle">Título</label><input type="text" id="caseEdTitle" value="${esc(c.title)}" maxlength="120"></div>
      <div class="field res"><label for="caseEdSt">Estado</label><select id="caseEdSt">${Object.entries(CASE_ST).map(([k,v])=>`<option value="${k}"${c.status===k?' selected':''}>${v}</option>`).join('')}</select></div>
      <div class="field res"><label for="caseEdSev">Severidad</label><select id="caseEdSev">${['crit','high','med','low'].map(k=>`<option value="${k}"${c.sev===k?' selected':''}>${VULN_SEV[k].label}</option>`).join('')}</select></div></div>
    <div class="field" data-s="margin-top:8px"><label for="caseEdDesc">Descripción</label><textarea id="caseEdDesc" rows="2" maxlength="2000">${esc(c.desc||'')}</textarea></div>
    <p class="hint">Creado ${esc(new Date(c.created).toLocaleString('es-CO'))} · se borrará automáticamente en ${left} día(s) si no tiene cambios.</p>
    <div class="subh">Elementos (${c.items.length})</div>
    ${c.items.length?`<div class="sbxscroll"><table class="sbxtbl"><tr><th>Tipo</th><th>Elemento</th><th>Resumen</th><th>Añadido</th><th></th></tr>${c.items.map(it=>`<tr><td>${esc(kindL[it.kind]||it.kind)}</td><td class="m">${esc(it.kind==='url'?defang(it.title):it.title)}</td><td>${esc(it.summary||'')}${it.data&&it.data.attack&&it.data.attack.length?`<div>${it.data.attack.slice(0,8).map(t=>`<a class="sbxchip" target="_blank" rel="noopener noreferrer" href="${esc(attUrl(t))}">${esc(t)}</a>`).join('')}</div>`:''}</td><td>${esc(new Date(it.ts).toLocaleString('es-CO'))}</td><td><button type="button" class="sbxrm" data-caserm="${esc(it.id)}" aria-label="Quitar ${esc(it.title)}">✕</button></td></tr>`).join('')}</table></div>`:'<p class="hint">Sin elementos todavía.</p>'}
    <div class="field" data-s="margin-top:12px"><label for="caseNote">Añadir nota</label><textarea id="caseNote" rows="2" maxlength="4000" placeholder="Acciones realizadas, decisiones, contactos…"></textarea></div>
    <div class="dashbtns" data-s="justify-content:flex-start;margin-top:8px"><button class="btn ghost" id="caseNoteAdd" type="button">${ico('plus')}Añadir nota</button></div>
    <div class="subh">Línea de tiempo</div><ul class="caselog">${(c.log||[]).map(l=>`<li><time datetime="${esc(l.ts)}">${esc(new Date(l.ts).toLocaleString('es-CO'))}</time><span>${esc(l.text)}</span></li>`).join('')}</ul>
    <div class="rtoolbar"><button class="btn" id="caseTxt" type="button">${ico('download')}Informe del caso (.txt)</button><button class="btn ghost" id="caseJson" type="button">${ico('download')}Datos (.json)</button><button class="btn ghost" id="caseDel" type="button">${ico('ban')}Eliminar caso</button></div>`;
}
function caseTxt(c){
  const L=[];const line=ch=>L.push((ch||'=').repeat(72));const kindL={file:'Archivo',url:'Enlace',ioc:'Indicadores',report:'Informe',note:'Nota'};
  L.push('INFORME DE CASO — CENTINELA');line();L.push('Caso      : '+c.title);L.push('Estado    : '+CASE_ST[c.status]);L.push('Severidad : '+VULN_SEV[c.sev].label);
  L.push('Creado    : '+new Date(c.created).toLocaleString('es-CO'));L.push('Actualizado: '+new Date(c.updated).toLocaleString('es-CO'));if(c.desc){L.push('');L.push(c.desc);}
  L.push('');L.push('ELEMENTOS ('+c.items.length+')');line('-');
  c.items.forEach(it=>{L.push('['+(kindL[it.kind]||it.kind)+'] '+it.title);if(it.summary)L.push('   '+it.summary);const d=it.data||{};
    if(d.sha256)L.push('   SHA-256: '+d.sha256);if(d.attack&&d.attack.length)L.push('   ATT&CK : '+d.attack.join(', '));if(d.cves&&d.cves.length)L.push('   CVE    : '+d.cves.join(', '));
    if(d.indicators)d.indicators.forEach(x=>L.push('   '+x.verdict.padEnd(4)+' '+x.type.padEnd(7)+' '+defang(x.value)));if(d.iocs&&d.iocs.length)L.push('   IOCs   : '+d.iocs.map(defang).join(', '));
    if(it.text)L.push('   '+it.text);L.push('');});
  L.push('LÍNEA DE TIEMPO');line('-');(c.log||[]).slice().reverse().forEach(l=>L.push(new Date(l.ts).toLocaleString('es-CO')+'  '+l.text));
  L.push('');L.push('Indicadores desactivados ([.] y hxxp) para evitar clics accidentales. Generado por Centinela.');return L.join('\n');
}
(function(){
  $('#mbCases').addEventListener('click',()=>setMode('cases'));
  $('#caseNew').addEventListener('click',()=>{const t=$('#caseTitle').value.trim();if(!t){alert('Escribe un título para el caso');return;}const c=caseCreate(t,$('#caseSev').value);if(c){CASES.sel=c.id;$('#caseTitle').value='';renderCases();}});
  $('#caseTitle').addEventListener('keydown',e=>{if(e.key==='Enter')$('#caseNew').click();});
  $('#caseList').addEventListener('click',e=>{const b=e.target.closest('[data-case]');if(b){CASES.sel=b.dataset.case;renderCases();}});
  const D=$('#caseDetail');
  D.addEventListener('change',e=>{const id=CASES.sel;if(!id)return;
    if(e.target.id==='caseEdTitle'){const v=e.target.value.trim();if(v)caseUpdate(id,c=>{c.title=v;caseTouch(c,'Título cambiado');});}
    else if(e.target.id==='caseEdSt')caseUpdate(id,c=>{c.status=e.target.value;caseTouch(c,'Estado: '+CASE_ST[c.status]);});
    else if(e.target.id==='caseEdSev')caseUpdate(id,c=>{c.sev=e.target.value;caseTouch(c,'Severidad: '+VULN_SEV[c.sev].label);});
    else if(e.target.id==='caseEdDesc')caseUpdate(id,c=>{c.desc=e.target.value.slice(0,2000);caseTouch(c,'Descripción actualizada');});
    else return;renderCases();});
  D.addEventListener('click',e=>{const id=CASES.sel;if(!id)return;
    const rm=e.target.closest('[data-caserm]');if(rm){caseUpdate(id,c=>{const it=c.items.find(x=>x.id===rm.dataset.caserm);c.items=c.items.filter(x=>x.id!==rm.dataset.caserm);if(it)caseTouch(c,'Quitado: '+it.title);});renderCases();return;}
    if(e.target.closest('#caseNoteAdd')){const t=$('#caseNote').value.trim();if(!t)return;caseUpdate(id,c=>{c.items.unshift({id:caseId(),ts:new Date().toISOString(),kind:'note',title:t.slice(0,80)+(t.length>80?'…':''),summary:'',text:t});caseTouch(c,'Nota añadida');});renderCases();return;}
    const c=caseAll().find(x=>x.id===id);if(!c)return;const fn='centinela-caso-'+c.title.replace(/[^\w.-]+/g,'_').slice(0,40);
    if(e.target.closest('#caseTxt'))downloadFile(fn+'.txt',caseTxt(c));
    else if(e.target.closest('#caseJson'))downloadFile(fn+'.json',JSON.stringify(Object.assign({tool:'Centinela',type:'case'},c),null,2),'application/json');
    else if(e.target.closest('#caseDel')){if(confirm('¿Eliminar el caso "'+c.title+'"? Esta acción no se puede deshacer.')){caseSave(caseAll().filter(x=>x.id!==id));CASES.sel=null;renderCases();}}
  });
  $('#caseDlgOk').addEventListener('click',caseAddConfirm);$('#caseDlgCancel').addEventListener('click',()=>$('#caseDlg').close());
  $('#caseDlgNew').addEventListener('keydown',e=>{if(e.key==='Enter')caseAddConfirm();});
  // Botones "Añadir a un caso" en sandbox, consulta de IOCs e informe ejecutivo (delegación)
  document.addEventListener('click',e=>{const b=e.target.closest('[data-caseadd]');if(!b)return;const k=b.dataset.caseadd;
    caseAddDialog(k==='ioc'?caseItemFromIoc():k==='report'?caseItemFromReport():caseItemFromSbx(+b.dataset.i));});
})();

/* ============================================================ Panel de inicio */
const HOME_DESC={cases:'Agrupa hallazgos, indicadores y notas de un incidente.',tls:'Versiones TLS, certificado, HSTS y calificación A+–F.',ioc:'Reputación de IPs, dominios, URLs, hashes y CVE en lote.',domain:'SPF, DKIM, DMARC, DNSSEC, listas negras y puntaje del dominio.',cmp:'Postura de dos dominios lado a lado.',gen:'Registros SPF, DMARC, MTA-STS y CAA listos para publicar.',
  phish:'Analiza una URL sospechosa y prepara la denuncia.',eml:'Encabezados de un correo: autenticación y origen.',sbx:'Análisis aislado de archivos con MITRE ATT&CK y CVE.',
  leak:'Correos y entidades en filtraciones de datos.',mon:'Vigila cambios y listas negras de tus dominios.',recon:'Dominios suplantadores y typosquatting.',
  vuln:'Puertos, CVE expuestos y superficie de ataque.',report:'Informe ejecutivo consolidado e imprimible.',geo:'Ubicación, ASN y proveedor de una IP.',
  headers:'Cabeceras de seguridad HTTP de un sitio.',tools:'Contraseñas, hashes, Base64 y JWT.'};
Object.assign(I18N_EN,{'Análisis rápido':'Quick analysis','Escribe un dominio, IP, URL, correo, hash o CVE y Centinela abrirá el módulo adecuado':'Type a domain, IP, URL, email, hash or CVE and Centinela will open the right module',
  'ejemplo.com · 8.8.8.8 · https://… · usuario@dominio.com · SHA-256 · CVE-2021-44228':'example.com · 8.8.8.8 · https://… · user@domain.com · SHA-256 · CVE-2021-44228','Analizar':'Analyze',
  '¿Tienes un archivo sospechoso? Abrir el sandbox':'Got a suspicious file? Open the sandbox','Estado de las fuentes de datos':'Data source status','Comprobar ahora':'Check now','Actividad de esta sesión':'Activity in this session',
  'General':'General','Inicio':'Home','Backend':'Backend','no configurado':'not configured','configurado':'configured','responde':'responding','no responde':'not responding','comprobando…':'checking…',
  'Aún no hay actividad en esta sesión.':'No activity in this session yet.','Dominios validados':'Validated domains','Archivos analizados':'Files analyzed','Buscar en':'Search on',
  'SPF, DKIM, DMARC, DNSSEC, listas negras y puntaje del dominio.':'SPF, DKIM, DMARC, DNSSEC, blacklists and domain score.','Postura de dos dominios lado a lado.':'Two domains’ posture side by side.',
  'Registros SPF, DMARC, MTA-STS y CAA listos para publicar.':'Ready-to-publish SPF, DMARC, MTA-STS and CAA records.','Analiza una URL sospechosa y prepara la denuncia.':'Analyzes a suspicious URL and drafts the report.',
  'Encabezados de un correo: autenticación y origen.':'Email headers: authentication and origin.','Análisis aislado de archivos con MITRE ATT&CK y CVE.':'Isolated file analysis with MITRE ATT&CK and CVE.',
  'Correos y entidades en filtraciones de datos.':'Emails and organizations in data breaches.','Vigila cambios y listas negras de tus dominios.':'Watches your domains for changes and blacklisting.',
  'Dominios suplantadores y typosquatting.':'Impersonating domains and typosquatting.','Puertos, CVE expuestos y superficie de ataque.':'Ports, exposed CVEs and attack surface.',
  'Informe ejecutivo consolidado e imprimible.':'Consolidated, printable executive report.','Ubicación, ASN y proveedor de una IP.':'Location, ASN and provider of an IP.',
  'Cabeceras de seguridad HTTP de un sitio.':'A site’s HTTP security headers.',
  'Filtraciones de la entidad':'Organization data leaks','Archivos analizados en el sandbox (sesión)':'Files analyzed in the sandbox (session)','Prioridades de actuación':'Action priorities',
  'filtraciones':'leaks','empleados con infostealer':'employees with infostealer','archivos de riesgo':'risky files','Metodología y alcance':'Methodology and scope',
  'Informe ejecutivo de ciberseguridad':'Cybersecurity executive report','Consulta de IOCs':'IOC lookup','Consulta de indicadores de compromiso (IOCs)':'Indicators of compromise (IOC) lookup',
  'Indicadores a consultar':'Indicators to look up','(hasta 100; uno por línea o separados por comas: IP, dominio, URL, hash MD5/SHA-1/SHA-256 o CVE; admite hxxp:// y [.])':'(up to 100; one per line or comma-separated: IP, domain, URL, MD5/SHA-1/SHA-256 hash or CVE; accepts hxxp:// and [.])',
  'Consultar indicadores':'Look up indicators','Spamhaus ZEN / DBL':'Spamhaus ZEN / DBL','Google Safe Browsing (clave)':'Google Safe Browsing (key)','URLhaus · ThreatFox · VirusTotal · MalwareBazaar · Hybrid Analysis (backend)':'URLhaus · ThreatFox · VirusTotal · MalwareBazaar · Hybrid Analysis (backend)',
  'Detecta el tipo de cada indicador y lo consulta en las fuentes que le corresponden. Clasifica cada uno como':'Detects each indicator’s type and queries the matching sources. Classifies each one as','malicioso':'malicious','sospechoso':'suspicious','sin reportes':'no reports','sin datos':'no data',
  ', con el motivo y enlaces para investigarlo. Las fuentes de abuse.ch (URLhaus, ThreatFox) y las de reputación de hashes requieren el backend con sus claves; sin él, esos indicadores muestran enlaces de búsqueda. Exporta en CSV, JSON y STIX 2.1, con la opción de "desactivar" (defang) los indicadores para compartirlos sin riesgo de clic. Los indicadores se envían a los servicios consultados: no incluyas datos personales.':', with the reason and links to investigate it. abuse.ch sources (URLhaus, ThreatFox) and hash reputation require the backend with its keys; without it those indicators show search links. Exports CSV, JSON and STIX 2.1, optionally defanged so they can be shared without click risk. Indicators are sent to the queried services: do not include personal data.',
  'indicadores':'indicators','maliciosos':'malicious','sospechosos':'suspicious','Malicioso':'Malicious','Sin reportes':'No reports','Sin datos':'No data','Indicador':'Indicator','Motivo y contexto':'Reason and context','Fuentes':'Sources','Investigar':'Investigate',
  'Exportar desactivados (defang)':'Export defanged','Copiar maliciosos':'Copy malicious','Copiados':'Copied','Sin maliciosos':'No malicious','Reputación de IPs, dominios, URLs, hashes y CVE en lote.':'Bulk reputation of IPs, domains, URLs, hashes and CVEs.','Analizar el contenido en el sandbox':'Analyze the content in the sandbox','Archivos':'Files','Enlace (URL)':'Link (URL)','Qué analizar':'What to analyze',
  'Enlace sospechoso a analizar sin visitarlo':'Suspicious link to analyze without visiting it','Analizar enlace':'Analyze link','Enlace analizado':'Analyzed link',
  'Enlace original':'Original link','Destino final':'Final destination','Cadena de redirecciones':'Redirect chain','Servidor':'Server','Analizar en Phishing':'Analyze in Phishing',
  'El backend descarga la página o el archivo de forma aislada (tu navegador nunca visita el sitio), sigue las redirecciones y el contenido pasa por el mismo motor del sandbox: formularios de credenciales, HTML smuggling, scripts ofuscados, descargas maliciosas, MITRE ATT&CK e IOCs. También consulta URLhaus. Requiere configurar el backend en Ajustes.':'The backend downloads the page or file in isolation (your browser never visits the site), follows redirects and runs the content through the same sandbox engine: credential forms, HTML smuggling, obfuscated scripts, malicious downloads, MITRE ATT&CK and IOCs. It also checks URLhaus. Requires configuring the backend in Settings.',
  'https://sitio-sospechoso.xyz/factura  ·  admite hxxp:// y [.]':'https://suspicious-site.xyz/invoice  ·  accepts hxxp:// and [.]','Hallazgos principales':'Main findings','Dominios de mayor riesgo':'Highest-risk domains','Contraseñas, hashes, Base64 y JWT.':'Passwords, hashes, Base64 and JWT.'});
I18N_MAP.clear();Object.entries(I18N_EN).forEach(([k,v])=>I18N_MAP.set(i18nKey(k),v));
if(I18N_LANG==='en')i18nTree(document.body);
/* Clasifica lo que escribe el usuario */
function homeClassify(q){
  q=q.trim();if(!q)return null;
  if(/^CVE-\d{4}-\d{4,7}$/i.test(q))return {t:'cve',v:q.toUpperCase()};
  if(/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(q))return {t:'hash',v:q.toLowerCase()};
  if(/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(q))return {t:'email',v:q.toLowerCase()};
  if(/^https?:\/\//i.test(q))return {t:'url',v:q};
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(q)||/^[0-9a-f:]{3,45}$/i.test(q)&&q.includes(':'))return {t:'ip',v:q};
  const d=q.toLowerCase().replace(/^www\./,'').replace(/\/.*$/,'').replace(/\.$/,'');
  if(/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))return {t:'domain',v:d};
  return null;
}
const HOME_LABEL={cve:'CVE',hash:'hash',email:'correo',url:'URL',ip:'IP',domain:'dominio'};
function homeHint(){const c=homeClassify($('#homeQ').value);const en=I18N_LANG==='en';
  const dest={cve:en?'CVE details (CVSS, EPSS, CISA KEV)':'detalle del CVE (CVSS, EPSS, CISA KEV)',hash:en?'hash search and reputation':'búsqueda y reputación del hash',email:en?'Data leaks':'Filtraciones',url:en?'Phishing':'Phishing',ip:en?'IP geolocation':'Geolocalización IP',domain:en?'Domain & email':'Dominio & correo'};
  $('#homeHint').textContent=c?(en?'Detected ':'Detectado: ')+HOME_LABEL[c.t]+' → '+dest[c.t]:'';}
async function homeGo(){
  const qv=$('#homeQ').value.trim();
  if(/[\s,;]/.test(qv)&&iocParse(qv).length>1){setMode('ioc');$('#iocInput').value=qv.split(/[\s,;]+/).join('\n');runIoc();return;}
  const c=homeClassify(qv);const out=$('#homeOut');out.innerHTML='';
  if(!c){$('#homeHint').textContent=I18N_LANG==='en'?'Not recognized. Try a domain, IP, URL, email, hash or CVE.':'No se reconoce el dato. Prueba con un dominio, IP, URL, correo, hash o CVE.';return;}
  if(c.t==='domain'){setMode('domain');$('#domain').value=c.v;run();}
  else if(c.t==='ip'){setMode('geo');$('#geoInput').value=c.v;runGeo();}
  else if(c.t==='url'){setMode('phish');$('#phishUrl').value=c.v;analyzePhish();}
  else if(c.t==='email'){setMode('leak');leakTab('email');$('#leakEmails').value=c.v;runLeakEmail();}
  else if(c.t==='cve'){
    out.innerHTML='<p class="hint">'+(I18N_LANG==='en'?'Querying…':'Consultando…')+'</p>';
    try{const info=await sbxEnrichCves([{id:c.v,source:I18N_LANG==='en'?'search':'búsqueda'}]);out.innerHTML=sbxCveHtml({cveInfo:info})+`<div data-s="margin-top:6px">${[['NVD','https://nvd.nist.gov/vuln/detail/'+c.v],['CIRCL','https://cve.circl.lu/vuln/'+c.v],['CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+c.v],['OSV','https://osv.dev/vulnerability/'+c.v]].map(p=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${esc(p[0])} ↗</a>`).join(' ')}</div>`;}
    catch(e){out.innerHTML='<p class="hint">'+esc(leakErr(e))+'</p>';}
  }
  else if(c.t==='hash'&&leakBackend()){setMode('ioc');$('#iocInput').value=c.v;runIoc();}
  else if(c.t==='hash'){
    const h=c.v;const piv=[['VirusTotal','https://www.virustotal.com/gui/file/'+h],['MalwareBazaar','https://bazaar.abuse.ch/browse.php?search=hash%3A'+h],['Hybrid Analysis','https://www.hybrid-analysis.com/search?query='+h],['Triage','https://tria.ge/s?q='+h],['AlienVault OTX','https://otx.alienvault.com/indicator/file/'+h]];
    out.innerHTML=`<div data-s="margin-top:8px"><span class="hint">${I18N_LANG==='en'?'Search on':'Buscar en'}:</span> ${piv.map(p=>`<a class="tag" data-s="text-decoration:none" target="_blank" rel="noopener noreferrer" href="${esc(p[1])}">${esc(p[0])} ↗</a>`).join(' ')}</div><div id="homeRep"></div>`;
    if(h.length===64&&leakBackend()){try{const rep=await sbxRep(h);$('#homeRep').innerHTML=sbxRepHtml({rep});}catch(e){}}
  }
}
function renderHomeGrid(){
  const g=$('#homeGrid');if(!g||g.childElementCount)return;
  document.querySelectorAll('aside.nav .nav-group').forEach(grp=>{const gl=grp.querySelector('.lbl').textContent;grp.querySelectorAll('.modebtn').forEach(b=>{const m=b.dataset.mode;if(m==='home')return;
    const c=document.createElement('button');c.type='button';c.className='homecard';c.dataset.go=m;
    c.appendChild(b.querySelector('svg').cloneNode(true));
    const d=document.createElement('div');d.innerHTML=`<p class="grp">${esc(gl)}</p><b>${esc(b.querySelector('span').textContent)}</b><span>${esc(HOME_DESC[m]||'')}</span>`;
    c.appendChild(d);g.appendChild(c);});});
}
/* Comprueba si responden las fuentes públicas (una vez cada 10 min por sesión, o al pulsar el botón) */
const HOME_SRC=[
  ['DNS-over-HTTPS',()=>fetch('https://dns.google/resolve?name=example.com&type=A',{cache:'no-store'})],
  ['CIRCL CVE',()=>fetch('https://cve.circl.lu/api/cve/CVE-2021-44228',{cache:'no-store'})],
  ['FIRST EPSS',()=>fetch('https://api.first.org/data/v1/epss?cve=CVE-2021-44228',{cache:'no-store'})],
  ['OSV.dev',()=>fetch('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:{name:'lodash',ecosystem:'npm'},version:'4.17.21'})})],
  ['CISA KEV',()=>fetch('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',{method:'HEAD',cache:'no-store'})],
  ['Shodan InternetDB',()=>fetch('https://internetdb.shodan.io/8.8.8.8',{cache:'no-store'})],
  ['crt.sh',()=>fetch('https://crt.sh/?q=example.com&output=json&exclude=expired',{cache:'no-store'})]
];
async function homeCheckSources(force){
  const box=$('#homeSrc');if(!box)return;let en=I18N_LANG==='en';
  let cached=null;try{cached=JSON.parse(sessionStorage.getItem('ctn-src')||'null');}catch(e){}
  const b=leakBackend();
  const chip=(n,st,tip)=>`<span class="srcchip ${st}" title="${esc(tip||'')}"><i></i>${esc(n)}</span>`;
  const backendChip=()=>b?chip('Backend',BACK_OK===true?'ok':BACK_OK===false?'fail':'',BACK_WHY||b):chip('Backend: '+(en?'not configured':'no configurado'),'warn',en?'Settings → Backend URL':'Ajustes → URL del backend');
  if(!force&&cached&&Date.now()-cached.t<600000){box.innerHTML=cached.r.map(x=>chip(x[0],x[1]?'ok':'fail',x[1]?(en?'responding':'responde'):(en?'not responding':'no responde'))).join('')+backendChip();return;}
  box.innerHTML=HOME_SRC.map(x=>chip(x[0],'',en?'checking…':'comprobando…')).join('')+backendChip();
  const res=await Promise.all(HOME_SRC.map(async ([n,f])=>{try{const c=new AbortController();const to=setTimeout(()=>c.abort(),12000);const r=await Promise.race([f(),new Promise((_,rej)=>c.signal.addEventListener('abort',()=>rej(new Error('timeout'))))]);clearTimeout(to);return [n,r.ok];}catch(e){return [n,false];}}));
  if(b){try{const r=await fetch(b+'/sbx/ping',{cache:'no-store'});BACK_OK=r.status<500&&r.status!==403;BACK_WHY=r.status===403?(en?'This page’s origin is not in ALLOWED_ORIGINS':'El origen de esta página no está en ALLOWED_ORIGINS del Worker'):'';}catch(e){BACK_OK=false;BACK_WHY=en?'Not reachable (or origin not allowed by CORS)':'No responde (o el origen no está permitido por CORS)';}}
  try{sessionStorage.setItem('ctn-src',JSON.stringify({t:Date.now(),r:res}));}catch(e){}
  en=I18N_LANG==='en'; // el idioma pudo cambiar mientras se comprobaban las fuentes
  box.innerHTML=res.map(x=>chip(x[0],x[1]?'ok':'fail',x[1]?(en?'responding':'responde'):(en?'not responding':'no responde'))).join('')+backendChip();
}
let BACK_OK=null,BACK_WHY='';
function renderHomeActivity(){
  const el=$('#homeAct');if(!el)return;const en=I18N_LANG==='en';const s0=sessStart();
  let h=[];try{h=JSON.parse(localStorage.getItem('ctn-hist')||'[]').filter(x=>+x.date>=s0);}catch(e){}
  const files=SBX.results.filter(x=>x.r);
  if(!h.length&&!files.length){el.innerHTML=`<p class="hint">${en?'No activity in this session yet.':'Aún no hay actividad en esta sesión.'}</p>`;return;}
  const col=s=>s>=85?'var(--ok)':s>=60?'var(--warn)':'var(--fail)';
  el.innerHTML=(h.length?`<div class="hint">${en?'Validated domains':'Dominios validados'} (${h.length})</div><div class="sbxlist">${h.slice(0,12).map(x=>`<span class="chip histchip" data-h="${esc(x.domain)}"><b data-s="color:${col(x.score)};margin-right:5px">${x.score}</b>${esc(x.domain)}</span>`).join('')}</div>`:'')+
    (files.length?`<div class="hint" data-s="margin-top:8px">${en?'Files analyzed':'Archivos analizados'} (${files.length})</div><div class="sbxlist">${files.slice(0,12).map(x=>`<span class="chip" data-gosbx="1" data-s="cursor:pointer"><b data-s="color:${x.r.verdict.col};margin-right:5px">${x.r.score}</b>${esc(x.r.name)}</span>`).join('')}</div>`:'');
}
function renderHome(){renderHomeGrid();renderHomeActivity();homeCheckSources(false);}
(function(){
  $('#mbHome').addEventListener('click',()=>setMode('home'));
  $('#homeGo').addEventListener('click',homeGo);
  $('#homeQ').addEventListener('keydown',e=>{if(e.key==='Enter')homeGo();});
  $('#homeQ').addEventListener('input',homeHint);
  $('#homeFile').addEventListener('click',()=>setMode('sbx'));
  $('#homeSrcBtn').addEventListener('click',()=>homeCheckSources(true));
  $('#homeGrid').addEventListener('click',e=>{const c=e.target.closest('[data-go]');if(c){setMode(c.dataset.go);window.scrollTo({top:0,behavior:'smooth'});}});
  $('#homeAct').addEventListener('click',e=>{const c=e.target.closest('.histchip');if(c){setMode('domain');$('#domain').value=c.dataset.h;run();return;}if(e.target.closest('[data-gosbx]'))setMode('sbx');});
  renderHome();window.HOME_READY=true;
})();

/* ============================================================ Paleta de comandos (Ctrl+K, ⌘K o "/")
   Salta a cualquier módulo, lanza el análisis adecuado si se escribe un indicador y ofrece acciones rápidas. */
Object.assign(I18N_EN,{'Buscar módulo o analizar (Ctrl+K)':'Search module or analyze (Ctrl+K)','Buscar módulo o analizar':'Search module or analyze','Buscar módulo o escribir un indicador':'Search a module or type an indicator',
  'Busca un módulo o escribe un dominio, IP, URL, hash o CVE…':'Search a module or type a domain, IP, URL, hash or CVE…','Resultados':'Results','navegar':'navigate','abrir':'open','cerrar':'close',
  'Acciones':'Actions','Cambiar tema claro/oscuro':'Toggle light/dark theme','Cambiar idioma (ES/EN)':'Switch language (ES/EN)','Abrir ajustes':'Open settings','Imprimir esta pantalla':'Print this screen',
  'Sin coincidencias':'No matches','Analizar':'Analyze','Consultar varios indicadores':'Look up several indicators'});
I18N_MAP.clear();Object.entries(I18N_EN).forEach(([k,v])=>I18N_MAP.set(i18nKey(k),v));if(I18N_LANG==='en')i18nTree(document.body);
const CMDK={items:[],sel:0};
const cmdkNorm=t=>String(t).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'');
function cmdkSource(){
  const en=I18N_LANG==='en';const out=[];
  document.querySelectorAll('aside.nav .nav-group').forEach(g=>{const gl=g.querySelector('.lbl').textContent;g.querySelectorAll('.modebtn').forEach(b=>{
    out.push({kind:'mod',label:b.querySelector('span').textContent,grp:gl,svg:b.querySelector('svg').outerHTML,hay:cmdkNorm(b.querySelector('span').textContent+' '+gl+' '+(HOME_DESC[b.dataset.mode]||'')+' '+(I18N_EN[HOME_DESC[b.dataset.mode]]||'')+' '+b.dataset.mode),run:()=>{setMode(b.dataset.mode);window.scrollTo({top:0});}});});});
  const A=en?'Actions':'Acciones';
  out.push({kind:'act',label:en?'Toggle light/dark theme':'Cambiar tema claro/oscuro',grp:A,svg:ico('moon'),hay:'tema theme oscuro claro dark light',run:()=>themeBtn.click()});
  out.push({kind:'act',label:en?'Switch language (ES/EN)':'Cambiar idioma (ES/EN)',grp:A,svg:ico('globe'),hay:'idioma language ingles español english spanish',run:()=>$('#langBtn').click()});
  out.push({kind:'act',label:en?'Open settings':'Abrir ajustes',grp:A,svg:ico('sliders'),hay:'ajustes settings configuracion backend clave retencion historial',run:()=>{const st=$('#settings');if(st.style.display==='none')$('#setBtn').click();st.scrollIntoView({behavior:'smooth'});}});
  out.push({kind:'act',label:en?'Print this screen':'Imprimir esta pantalla',grp:A,svg:ico('printer'),hay:'imprimir print pdf',run:()=>window.print()});
  return out;
}
function cmdkRender(){
  const q=$('#cmdkQ').value.trim();const en=I18N_LANG==='en';
  const src=cmdkSource();let items=[];
  const many=q&&/[\s,;]/.test(q)&&iocParse(q).length>1;
  const c=!many&&homeClassify(q);
  if(many)items.push({kind:'go',label:(en?'Look up several indicators':'Consultar varios indicadores')+' ('+iocParse(q).length+')',grp:en?'IOC lookup':'Consulta de IOCs',svg:ico('search'),run:()=>{setMode('ioc');$('#iocInput').value=q.split(/[\s,;]+/).join('\n');runIoc();}});
  else if(c){const dest={domain:en?'Domain & email':'Dominio & correo',ip:en?'IP geolocation':'Geolocalización IP',url:'Phishing',email:en?'Data leaks':'Filtraciones',hash:en?'IOC lookup':'Consulta de IOCs',cve:en?'Home':'Inicio'}[c.t];
    items.push({kind:'go',label:(en?'Analyze':'Analizar')+' '+c.v,grp:dest,svg:ico('target'),run:()=>{setMode('home');$('#homeQ').value=c.v;homeHint();homeGo();}});
    if(c.t==='url')items.push({kind:'go',label:(en?'Analyze in sandbox':'Analizar en el sandbox')+' '+c.v,grp:en?'File sandbox':'Sandbox de archivos',svg:ico('bug'),run:()=>{setMode('sbx');sbxTab('url');$('#sbxUrl').value=c.v;runSbxUrl();}});
    if(c.t==='domain')items.push({kind:'go',label:(en?'Look for impersonators of':'Buscar suplantadores de')+' '+c.v,grp:en?'OSINT reconnaissance':'Reconocimiento OSINT',svg:ico('radar'),run:()=>{setMode('recon');$('#reconInput').value=c.v;runRecon();}},{kind:'go',label:(en?'Vulnerabilities of':'Vulnerabilidades de')+' '+c.v,grp:en?'Vulnerability analysis':'Análisis de vulnerabilidades',svg:ico('shield-alert'),run:()=>{setMode('vuln');$('#vulnInput').value=c.v;runVuln();}});
  }
  const nq=cmdkNorm(q);const words=nq.split(/\s+/).filter(Boolean);
  const match=src.filter(x=>!words.length||words.every(w=>x.hay.includes(w)||cmdkNorm(x.label).includes(w)));
  items=items.concat(c||many?match.slice(0,4):match);
  CMDK.items=items;CMDK.sel=Math.min(CMDK.sel,Math.max(0,items.length-1));
  const ul=$('#cmdkList');
  ul.innerHTML=items.length?items.map((x,i)=>`<li role="option" id="cmdk${i}" aria-selected="${i===CMDK.sel}" data-i="${i}">${x.svg}<span>${esc(x.label)}</span><span class="grp">${esc(x.grp)}</span></li>`).join(''):`<li class="empty" role="option" aria-disabled="true">${en?'No matches':'Sin coincidencias'}</li>`;
  $('#cmdkQ').setAttribute('aria-activedescendant',items.length?'cmdk'+CMDK.sel:'');
}
function cmdkMove(d){if(!CMDK.items.length)return;CMDK.sel=(CMDK.sel+d+CMDK.items.length)%CMDK.items.length;
  document.querySelectorAll('#cmdkList li').forEach((li,i)=>li.setAttribute('aria-selected',i===CMDK.sel));
  const li=$('#cmdk'+CMDK.sel);if(li)li.scrollIntoView({block:'nearest'});$('#cmdkQ').setAttribute('aria-activedescendant','cmdk'+CMDK.sel);}
function cmdkRun(i){const x=CMDK.items[i];if(!x)return;$('#cmdkDlg').close();x.run();}
function cmdkOpen(){const d=$('#cmdkDlg');if(d.open)return;CMDK.sel=0;$('#cmdkQ').value='';cmdkRender();d.showModal();$('#cmdkQ').focus();}
(function(){
  const d=$('#cmdkDlg');
  $('#cmdkBtn').addEventListener('click',cmdkOpen);
  $('#cmdkQ').addEventListener('input',()=>{CMDK.sel=0;cmdkRender();});
  $('#cmdkQ').addEventListener('keydown',e=>{
    if(e.key==='ArrowDown'){e.preventDefault();cmdkMove(1);}else if(e.key==='ArrowUp'){e.preventDefault();cmdkMove(-1);}
    else if(e.key==='Enter'){e.preventDefault();cmdkRun(CMDK.sel);}});
  $('#cmdkList').addEventListener('click',e=>{const li=e.target.closest('li[data-i]');if(li)cmdkRun(+li.dataset.i);});
  $('#cmdkList').addEventListener('mousemove',e=>{const li=e.target.closest('li[data-i]');if(li&&+li.dataset.i!==CMDK.sel){CMDK.sel=+li.dataset.i;cmdkMove(0);}});
  d.addEventListener('click',e=>{if(e.target===d)d.close();});   // clic fuera del cuadro
  document.addEventListener('keydown',e=>{
    const typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement&&document.activeElement.tagName)||(document.activeElement&&document.activeElement.isContentEditable);
    if((e.ctrlKey||e.metaKey)&&!e.altKey&&e.key.toLowerCase()==='k'){e.preventDefault();d.open?d.close():cmdkOpen();}
    else if(e.key==='/'&&!typing&&!d.open&&!document.querySelector('dialog[open]')){e.preventDefault();cmdkOpen();}
  });
})();

const pm=new URLSearchParams(location.search);
if(pm.get('report')){setMode('phish');$('#phishUrl').value=pm.get('report');if(pm.get('brand'))$('#phishBrand').value=pm.get('brand');setTimeout(analyzePhish,300);}
else if(pm.get('d')){setMode('domain');$('#domain').value=pm.get('d');setTimeout(run,300);}

/* Imágenes externas opcionales (logos de filtraciones): se quitan si no cargan. Sustituye al antiguo onerror en línea,
   que la CSP sin 'unsafe-inline' bloquearía. */
document.addEventListener('error',e=>{const t=e.target;if(t&&t.tagName==='IMG'&&t.hasAttribute('data-rm-on-error'))t.remove();},true);
