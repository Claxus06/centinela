# Centinela — Suite de ciberseguridad

Centinela es una aplicación web gratuita de ciberseguridad para validar la postura de dominios y correo, detectar suplantación y phishing, analizar archivos sospechosos y generar informes. Funciona completamente en el navegador: no necesita servidor propio ni instalación, y se puede instalar como app (PWA).

> **Uso responsable.** Centinela realiza evaluaciones **pasivas** (consultas públicas de DNS, RDAP, certificados, reputación) y análisis **estático** de archivos. No ejecuta exploits ni pruebas intrusivas. Úsala sobre dominios, cuentas e infraestructura que te corresponda proteger.

## Módulos

| Grupo | Módulo | Qué hace |
|---|---|---|
| General | **Paleta de comandos** (Ctrl+K, ⌘K o `/`) | Salta a cualquier módulo o lanza el análisis adecuado escribiendo un dominio, IP, URL, hash o CVE. |
| | **Inicio** | Panel de seguridad con datos **en vivo** (se releen cada 5–60 min): postura de tus dominios, casos, monitoreo, ataques en Colombia y **inteligencia de amenazas** (CISA KEV, CVE críticos de NVD con EPSS e IOCs recientes de ThreatFox y URLhaus). Búsqueda rápida (detecta si es dominio, IP, URL, correo, hash o CVE y abre el módulo adecuado) y accesos directos a todos los módulos. |
| Dominio & correo | **Dominio & correo** | SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, DANE, CAA, listas negras, RDAP, certificados, puntaje y plan de acción. |
| | **Comparar dominios** | Postura de dos dominios lado a lado. |
| | **Generador DNS** | Registros SPF/DMARC/MTA-STS/TLS-RPT/CAA listos para publicar. |
| Amenazas | **Phishing** | Análisis de URL/dominio sospechoso y denuncia preparada. |
| | **Analizar correo** | Encabezados de un correo: autenticación, origen y riesgo de suplantación. |
| | **Sandbox de archivos** | Análisis estático aislado de archivos (ejecutables, Office con macros, PDF, scripts, LNK, ISO, ZIP/APK…) y de **enlaces** (el backend descarga la página sin que el usuario la visite y sigue las redirecciones): MITRE ATT&CK, CVE con CVSS/EPSS/CISA KEV, dependencias vulnerables (OSV), URLhaus e IOCs. Admite **reglas YARA propias** y un paquete de **reglas base** incluido (`yara/centinela-base.yar`) (subconjunto: cadenas de texto/hex/regex y condiciones habituales) y **comparación de archivos** (imphash, PDB, técnicas e indicadores comunes). Exporta TXT, JSON, CSV, capa de ATT&CK Navigator y STIX 2.1. |
| | **Filtraciones** | Correos comprometidos, filtraciones de una entidad, mitigación y retirada de contenido. |
| | **Monitoreo** | Vigila listas negras y cambios en SPF/DMARC/MX/NS mientras la pestaña está abierta, con historial de revisiones y gráfico de estados. |
| Ciberinteligencia | **Ataques en Colombia** | Ciberataques conocidos contra organizaciones colombianas: **confirmados** (por la víctima o la prensa) y **reclamados** por grupos de ransomware. Por incidente: qué se filtró (tipos de datos, volumen y rescate según el actor), quién se lo adjudica, sector, credenciales robadas por infostealers, noticia y fuentes. Indicadores de los últimos 12 meses, gráfico mensual, grupos y sectores más afectados, filtros, exportación CSV/JSON, "Explicar con IA" y "Añadir a un caso". Datos actualizados cada 6 horas por GitHub Actions; ver "Datos de ataques en Colombia". |
| | **Reconocimiento OSINT** | Dominios parecidos o suplantadores (typosquatting, Certificate Transparency, DNS en vivo). |
| | **Análisis de vulnerabilidades** | Puertos y CVE expuestos (Shodan InternetDB, CIRCL, NVD, CISA KEV), superficie de ataque y subdomain takeover. |
| | **Consulta de IOCs** | Reputación en lote de IPs, dominios, URLs, hashes y CVE (Shodan, Spamhaus, RDAP, CISA KEV, EPSS; URLhaus, ThreatFox, VirusTotal, MalwareBazaar e Hybrid Analysis vía backend). Admite indicadores desactivados (`hxxp`, `[.]`) y exporta CSV/JSON/STIX 2.1. |
| | **Casos** | Agrupa archivos, enlaces, indicadores, informes y notas de un incidente, con estado, severidad, línea de tiempo y exportación. |
| | **Informe ejecutivo** | Consolida dominio, vulnerabilidades, suplantación, filtraciones, archivos del sandbox y monitoreo, con prioridades de actuación, gráficos de postura, **mapeo de cumplimiento** (ISO/IEC 27001:2022, NIST CSF 2.0, CIS v8) y PDF con portada, índice y numeración. |
| Infraestructura | **Geolocalización IP** | Ubicación, ASN y proveedor de una IP. |
| | **TLS y certificados** | Versiones TLS admitidas, cifrado, certificado (emisor, validez, nombres, clave, firma), HSTS y calificación A+–F (requiere backend con sockets). |
| | **Cabeceras HTTP** | Evaluación de cabeceras de seguridad (requiere backend). |
| Ayuda | **Asistente de IA** (botón *Preguntar*) | Responde en lenguaje sencillo: explica el resultado en pantalla, dice qué módulo usar y qué hacer después. Gratuito (Cloudflare Workers AI con respaldo de Groq); requiere el backend. Ver "Asistente de IA". |
| Utilidades | **Herramientas** | Contraseñas filtradas (k-anonimato), generador, hashes, Base64/URL y decodificador JWT. |

## Publicar en GitHub Pages

1. Crea un repositorio y sube **todos estos archivos juntos en la raíz** (o en la carpeta que publiques):

   | Archivo | Obligatorio | Para qué |
   |---|---|---|
   | `index.html` | Sí | La interfaz. |
   | `app.js`, `boot.js`, `styles.css` | Sí | La lógica de la aplicación (separada del HTML para una CSP estricta). |
   | `colombia.js`, `data/colombia.json` | Sí | Módulo "Ataques en Colombia" y sus datos (los renueva la acción *Actualizar ataques en Colombia*). |
   | `data/amenazas.json` | Sí | Inteligencia de amenazas del panel de inicio (la renueva cada hora la acción *Actualizar inteligencia de amenazas*). |
   | `asistente.js`, `config.js` | Sí | Panel del asistente de IA y configuración del sitio (URL del backend para todos los visitantes). |
   | `sandbox-worker.js` | Sí | Motor del sandbox de archivos. Sin él, el módulo muestra un error indicando que falta. |
   | `sw.js` | Sí | Service worker (funcionamiento sin conexión y actualizaciones). |
   | `manifest.webmanifest`, `icon.svg` | Sí | Instalación como app. |
   | `yara/` | Sí | Reglas YARA base que el sandbox carga con el botón "Cargar reglas base". |
   | `fonts/` | Sí | Tipografías Inter, Manrope e IBM Plex alojadas localmente (SIL Open Font License, textos de licencia incluidos). |
   | `worker-filtraciones.js`, `worker-sandbox.js`, `worker-asistente.js`, `backend/` | No | Backend opcional para Cloudflare (ver "Backend opcional"). La página no los usa. |
   | `README.md` | No | Esta guía. |

2. En el repositorio: **Settings → Pages → Build and deployment → Deploy from a branch**, rama `main`, carpeta `/ (root)`.
3. Abre la URL que indica GitHub (`https://<usuario>.github.io/<repositorio>/`).

Tras cada actualización, el service worker descarga la versión nueva automáticamente (el HTML y el JavaScript siempre se piden primero a la red). Si cambias archivos estáticos, incrementa la constante `CACHE` en `sw.js` (p.ej. `centinela-v9`) para renovar la caché.

**Abrir en local:** con doble clic sobre `index.html` funcionan casi todos los módulos, pero el navegador bloquea la lectura de `data/*.json` (gráficos del panel, Ataques en Colombia e inteligencia de amenazas), la instalación como app y el service worker. Para verlo todo, sírvelo por `http://` (p. ej. `python -m http.server` o `npx serve`).

## Datos en vivo: inteligencia de amenazas

El panel de inicio muestra CVE, vulnerabilidades explotadas e IOCs recientes sin backend ni claves:

- **Fuentes:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (vulnerabilidades explotadas activamente), [NVD](https://nvd.nist.gov/) (CVE críticos publicados en los últimos 7 días), [FIRST EPSS](https://www.first.org/epss/) (probabilidad de explotación) y abuse.ch: [ThreatFox](https://threatfox.abuse.ch/) (IOCs de las últimas 48 h) y [URLhaus](https://urlhaus.abuse.ch/) (URLs de malware).
- **Cómo se actualiza:** la acción **Actualizar inteligencia de amenazas** (`.github/workflows/amenazas.yml`) ejecuta `scripts/actualizar-amenazas.mjs` cada hora y publica `data/amenazas.json` (unos 12 KB) solo si hay novedades. El navegador relee ese archivo y `data/colombia.json` cada 15 minutos (configurable en *Ajustes → Actualización automática*: desactivada, 5, 15, 30 o 60 min), con la pestaña visible; al volver a una pestaña con datos vencidos se actualiza en el acto. Las filas nuevas se resaltan un momento.
- **Privacidad y seguridad:** el navegador solo pide archivos del propio sitio (la IP del visitante no llega a las fuentes). Los IOCs se publican desactivados (`hxxp://`, `[.]`) y se muestran como texto, nunca como enlace. Si una fuente falla, se conserva su sección anterior.
- **Primera vez:** tras subir el proyecto, lánzala a mano desde *Actions → Actualizar inteligencia de amenazas → Run workflow*. Requiere los mismos permisos de escritura que la acción de Colombia (ver abajo).
- **Actualizar en local:** `node scripts/actualizar-amenazas.mjs`.

## Datos de ataques en Colombia

El módulo **Ataques en Colombia** no usa backend: lee `data/colombia.json`, un archivo estático del propio sitio.

- **Fuente:** [ransomware.live](https://www.ransomware.live/country/co) (API v2 pública). Se combinan los ataques reportados por la prensa o la víctima (`/countrycyberattacks/CO`) y las víctimas publicadas por grupos de ransomware (`/countryvictims/CO`). Si un ataque confirmado coincide con una reclamación (mismo dominio o nombre, ±180 días), se muestran como un solo incidente "Confirmado y reclamado".
- **Un incidente por ataque, sin duplicados:** las publicaciones de la misma víctima separadas por menos de 180 días se unen en un solo incidente con todos sus actores y la cronología de publicaciones (reposteos del mismo grupo o un segundo grupo que se adjudica el ataque). Los grupos que republican filtraciones antiguas de otros (Babuk 2.0) se unen al incidente original hasta 2 años después y se marcan como republicación. Varias noticias del mismo caso se agrupan en un único incidente confirmado. Publicaciones separadas por más de 180 días son ataques distintos (p. ej., EPM en 2022 y en 2026). Cada incidente tiene un identificador estable (fecha + dominio).
- **Actualización automática:** la acción **Actualizar ataques en Colombia** (`.github/workflows/colombia.yml`) ejecuta `scripts/actualizar-colombia.mjs` cada 6 horas y hace commit de `data/colombia.json` solo si hay incidentes nuevos o cambios. También puedes lanzarla a mano desde *Actions → Run workflow*. Si la API falla o devuelve una lista sospechosamente corta, el archivo anterior se conserva.
- **Si la acción falla al hacer `git push` (error 403):** en *Settings → Actions → General → Workflow permissions*, marca **Read and write permissions**. Si la rama `main` está protegida, permite que GitHub Actions publique en ella.
- **Privacidad y ética:** nunca se guardan enlaces a sitios de filtración (`.onion`) ni datos filtrados; solo metadatos públicos del incidente. De las descripciones de los actores se eliminan correos y teléfonos. Las reclamaciones de grupos criminales no están confirmadas y la interfaz lo indica en cada incidente. Los "tipos de datos" se detectan por palabras clave en la descripción del actor o la noticia: son orientativos.
- **Condiciones de uso:** ransomware.live indica que su API v2 gratuita es para uso personal y ofrece una API PRO, también gratuita con registro, para uso corporativo. Si publicas Centinela para una organización, revisa sus condiciones.
- **Actualizar en local:** `node scripts/actualizar-colombia.mjs`.

## Backend opcional (Cloudflare Worker)

Sin backend, casi todo funciona. El backend solo es necesario para servicios que exigen clave de API o que no permiten consultas desde el navegador (CORS). La carpeta `backend/` contiene un Worker listo para desplegar.

| Función | Ruta | Secreto |
|---|---|---|
| Have I Been Pwned por correo | `/hibp` | `HIBP_KEY` |
| Hudson Rock (infostealers) · ransomware.live · RDAP | `/hudsonrock` · `/ransomware` · `/rdap` | — |
| Reputación del hash: CIRCL hashlookup | `/sbx/hashlookup` | — |
| VirusTotal (reputación + sandbox dinámico) | `/sbx/vt`, `/sbx/vt/upload`, `/sbx/vt/analysis` | `VT_KEY` |
| MalwareBazaar · URLhaus · ThreatFox (abuse.ch) | `/sbx/mb` · `/sbx/urlhaus` · `/sbx/threatfox` | `ABUSECH_KEY` (Auth-Key gratuita de abuse.ch; también se acepta `MB_KEY`) |
| Hybrid Analysis | `/sbx/ha` | `HA_KEY` |
| Análisis de enlaces sin visitarlos | `/sbx/url` | — |
| Análisis TLS (versiones, certificado, HSTS) | `/sbx/tls` | — |
| Cabeceras HTTP de seguridad | `/headers` | — |
| Verificación de URL (módulo Phishing) | `/verify` | `GSB_KEY` y/o `VT_KEY` |
| Catálogo CISA KEV (respaldo) | `/kev` | — |
| Asistente de IA | `/ai/status`, `/ai/chat` | Binding `AI` (Workers AI, ya declarado en `wrangler.toml`); `GROQ_KEY` opcional como respaldo |

### Despliegue paso a paso

Requisitos: una cuenta gratuita de Cloudflare y Node.js 22 o superior.

1. **Configura los orígenes permitidos.** Edita `backend/wrangler.toml` y sustituye `https://TU_USUARIO.github.io` por la URL de tu Centinela publicado (puedes añadir varias separadas por comas). Es imprescindible: sin esta lista, cualquier sitio web podría usar tu Worker como proxy y consumir tus claves y cuotas.
2. **Ensambla y publica:**
   ```bash
   cd backend
   node build.mjs          # genera dist/worker.js a partir de worker-filtraciones.js, worker-sandbox.js y worker-asistente.js
   npx wrangler login      # abre el navegador para autorizar tu cuenta
   npx wrangler deploy     # publica y muestra la URL, p.ej. https://centinela-backend.tucuenta.workers.dev
   ```
3. **Añade las claves que quieras usar** (cada función se activa solo si existe su clave):
   ```bash
   npx wrangler secret put VT_KEY
   npx wrangler secret put ABUSECH_KEY
   npx wrangler secret put HA_KEY
   npx wrangler secret put HIBP_KEY
   npx wrangler secret put GSB_KEY
   npx wrangler secret put GROQ_KEY      # opcional: respaldo del asistente de IA
   ```
4. **Conecta la app:** en Centinela → Ajustes → *URL del backend*, pega la URL del Worker y guarda. A partir de ese momento los módulos que requieren backend (VirusTotal, TLS, cabeceras HTTP, filtraciones) quedan operativos.

**Despliegue desde GitHub (opcional):** crea en el repositorio los secretos `CLOUDFLARE_API_TOKEN` (plantilla *Edit Cloudflare Workers*) y `CLOUDFLARE_ACCOUNT_ID`, y ejecuta manualmente la acción **Desplegar backend**. La acción ejecuta las pruebas del backend antes de publicar.

### Asistente de IA

Botón **Preguntar** (abajo a la derecha). Abre un panel que responde en lenguaje sencillo: explica el resultado que el usuario está viendo, recomienda el módulo adecuado (los nombres de módulos en la respuesta son enlaces) y propone los siguientes pasos. Las respuestas llegan en streaming.

- **Proveedor principal: Cloudflare Workers AI** (`@cf/meta/llama-3.1-8b-instruct-fp8`). Gratis: 10.000 neuronas al día, unas **350 consultas diarias**. Se renueva a las 00:00 UTC. En el plan gratuito nunca se cobra: al agotarse, deja de responder hasta el día siguiente. Cloudflare no usa el contenido para entrenar modelos.
- **Respaldo opcional: Groq** (`openai/gpt-oss-20b`). Si existe el secreto `GROQ_KEY` (clave gratuita en console.groq.com), se usa cuando Workers AI falla o agota su cuota: unas **110 consultas diarias** más (límite de 200.000 tokens al día).
- **Protecciones:** `ALLOWED_ORIGINS`; límite de 6 preguntas por minuto y por IP (`AI_LIMIT` en `wrangler.toml`); historial recortado a 8 mensajes de 1.500 caracteres; contexto de pantalla de hasta 3.000 caracteres; respuestas de hasta 700 tokens. Las instrucciones del asistente están en el servidor y limitan los temas a ciberseguridad defensiva y al uso de Centinela.
- **Privacidad:** se envían la pregunta, el historial de la conversación y, si la casilla *Incluir el resultado que tengo en pantalla* está marcada, un extracto del módulo abierto. Nada se guarda: ni en el Worker ni en el navegador.
- **Para todos los visitantes:** pon la URL de tu Worker en `config.js` (`window.CENTINELA_BACKEND = 'https://…workers.dev'`). Si alguien configura otra en *Ajustes → URL del backend*, se usa la suya. Si publicas el Worker en un dominio propio (no `*.workers.dev`), añádelo a `connect-src` en la CSP de `index.html`.
- **Despliegue desde GitHub:** si la acción falla al publicar el binding `AI` por permisos, edita el token `CLOUDFLARE_API_TOKEN` y añade el permiso de cuenta *Workers AI*.

**Límite de peticiones (opcional):** `wrangler.toml` incluye, comentado, un *binding* de Rate Limiting llamado `SBX_LIMIT`; actívalo tras comprobar la sintaxis vigente en la documentación de Cloudflare.

**Limitaciones conocidas:** el análisis TLS usa sockets TCP, y Cloudflare no permite abrir sockets hacia sitios que están detrás de su propia red. Las claves viven solo en el Worker; nunca llegan al navegador.

**Si ya tienes un Worker propio:** copia las funciones de `worker-filtraciones.js`, `worker-sandbox.js` y `worker-asistente.js` (añade también `const ai = await handleAiRoutes(request, url, env); if (ai) return ai;` y el binding `[ai]`) y, en tu enrutador, añade `const leak = await handleLeakRoutes(url, env, request); if (leak) return leak;` y `const sbx = await handleSandboxRoutes(request, url, env); if (sbx) return sbx;`. Para TLS, empieza el módulo con `import { connect } from 'cloudflare:sockets'; globalThis.CF_CONNECT = connect;`.

## Privacidad y retención de datos

- **Sin servidores propios.** Los datos de uso se guardan solo en el navegador de cada usuario (`localStorage`/`sessionStorage`). Las consultas van directamente a los servicios públicos (DNS-over-HTTPS, RDAP, crt.sh, CIRCL, OSV, FIRST…) o a tu backend.
- **Borrado automático del historial:**
  - Historial de búsquedas: se conserva **24 h** (configurable en Ajustes: 1 h, 24 h o 7 días).
  - Seguimiento de mitigaciones de filtraciones: **7 días** desde su último cambio.
  - Casos: **30 días** sin cambios (exporta el caso para conservarlo).
  - Historial de monitoreo: **30 días**; al quitar un dominio se borra su historial.
  - Nada creado durante la **sesión activa** se borra. La sesión termina al cerrar la pestaña o tras **2 h sin actividad**; en ese momento también se limpian los resultados en pantalla (salvo que haya un análisis en curso o monitoreo automático activo).
  - Botón **"Borrar historial ahora"** en Ajustes.
  - La configuración (membrete, claves, backend, idioma, tema, dominios monitoreados, reglas YARA) se conserva.
- **Sandbox de archivos:** el archivo se analiza dentro del navegador y **nunca se ejecuta**. A servicios externos solo se envían hashes e identificadores. El sandbox dinámico de VirusTotal es opcional, pide confirmación y **sube el archivo a VirusTotal** (queda disponible para su comunidad): no lo uses con documentos confidenciales.
- Las exportaciones (TXT, JSON, CSV, STIX, PDF) quedan en el equipo del usuario y son su responsabilidad.

## Idiomas

La interfaz está en español e inglés (botón **ES/EN**). Las descripciones detalladas de los hallazgos y los textos legales se muestran en español.

## Accesibilidad

La interfaz cumple WCAG 2.1 A/AA según la auditoría automática de axe-core en todos los módulos y en ambos temas: navegación completa con teclado, foco visible, enlace "Saltar al contenido", avisos de estado para lectores de pantalla, contraste suficiente y respeto a la preferencia de movimiento reducido.

## Pruebas automáticas

La carpeta `tests/` contiene pruebas que no dependen de servicios externos (usan muestras sintéticas e inofensivas generadas en memoria):

- `unit.test.js`: motor del sandbox (hashes, PE, Office/VBA, PDF, contenedores, falsos positivos, manifiestos, YARA).
- `backend.test.js`: rutas del Worker sin red (orígenes permitidos, límite de peticiones, bloqueo de destinos internos, secretos ausentes) y del asistente de IA con un modelo simulado (streaming, respaldo a Groq, cuota agotada, recortes y límite por IP).
- `browser.test.js`: la aplicación en Chrome/Edge headless (carga, CSP, módulos, idioma, accesibilidad con axe-core, sandbox en sus tres entornos, paleta de comandos, retención y casos).

```bash
cd tests
npm install
npm test            # define CHROME_PATH si Chrome/Edge no está en una ruta habitual
```

El flujo `.github/workflows/tests.yml` las ejecuta en GitHub Actions en cada cambio.

## Seguridad del proyecto

- Content Security Policy restrictiva: `script-src 'self'` y `style-src 'self'` (sin JavaScript ni CSS en línea: un script o una hoja de estilos inyectados no se aplican) y conexiones solo a las fuentes de datos declaradas.
- Tipografías servidas desde el propio sitio: la app no hace peticiones a Google Fonts ni a otros terceros al cargar.
- Service worker para funcionamiento sin conexión; el HTML y el JavaScript se sirven siempre en la misma versión.
- Protección anti-clickjacking y política de referer estricta.
- Toda la salida de datos externos se escapa antes de mostrarse.
- El backend admite una lista de orígenes permitidos (`ALLOWED_ORIGINS`) y un límite de peticiones (`SBX_LIMIT`), y bloquea destinos internos (SSRF) en el análisis de enlaces y de TLS.

¿Encontraste una vulnerabilidad? Repórtala de forma privada al mantenedor del repositorio en lugar de abrir un issue público.

## Estructura

```
index.html              Interfaz
colombia.js             Módulo "Ataques en Colombia"
data/colombia.json      Datos del módulo (los genera scripts/actualizar-colombia.mjs)
scripts/                Script de actualización de datos de Colombia
config.js               Configuración del sitio (URL del backend para todos los visitantes)
app.js                  Lógica de la aplicación
asistente.js            Asistente de IA (panel "Preguntar")
styles.css              Hoja de estilos
boot.js                 Arranque temprano (anti-clickjacking)
sandbox-worker.js       Motor de análisis estático de archivos (Web Worker)
sw.js                   Service worker
manifest.webmanifest    Manifiesto PWA
icon.svg                Icono
fonts/                  Tipografías (WOFF2) y sus licencias OFL
yara/                   Reglas YARA base (genéricas y defensivas)
worker-filtraciones.js  Rutas opcionales del backend: filtraciones
worker-sandbox.js       Rutas opcionales del backend: reputación, sandbox dinámico, enlaces, TLS, KEV, cabeceras, verificación
worker-asistente.js     Rutas opcionales del backend: asistente de IA (Workers AI + Groq)
backend/                Worker listo para desplegar (wrangler.toml + build.mjs)
tests/                  Pruebas automáticas (Node y navegador headless)
.github/workflows/      Integración continua (GitHub Actions)
```
