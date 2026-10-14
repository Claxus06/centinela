# Centinela — Suite de ciberseguridad

Centinela es una aplicación web gratuita de ciberseguridad para validar la postura de dominios y correo, detectar suplantación y phishing, analizar archivos sospechosos y generar informes. Funciona completamente en el navegador: no necesita servidor propio ni instalación, y se puede instalar como app (PWA).

> **Uso responsable.** Centinela realiza evaluaciones **pasivas** (consultas públicas de DNS, RDAP, certificados, reputación) y análisis **estático** de archivos. No ejecuta exploits ni pruebas intrusivas. Úsala sobre dominios, cuentas e infraestructura que te corresponda proteger.

## Módulos

| Grupo | Módulo | Qué hace |
|---|---|---|
| General | **Paleta de comandos** (Ctrl+K, ⌘K o `/`) | Salta a cualquier módulo o lanza el análisis adecuado escribiendo un dominio, IP, URL, hash o CVE. |
| | **Inicio** | Búsqueda rápida (detecta si es dominio, IP, URL, correo, hash o CVE y abre el módulo adecuado), accesos a todos los módulos, estado de las fuentes de datos y actividad de la sesión. |
| Dominio & correo | **Dominio & correo** | SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, DANE, CAA, listas negras, RDAP, certificados, puntaje y plan de acción. |
| | **Comparar dominios** | Postura de dos dominios lado a lado. |
| | **Generador DNS** | Registros SPF/DMARC/MTA-STS/TLS-RPT/CAA listos para publicar. |
| Amenazas | **Phishing** | Análisis de URL/dominio sospechoso y denuncia preparada. |
| | **Analizar correo** | Encabezados de un correo: autenticación, origen y riesgo de suplantación. |
| | **Sandbox de archivos** | Análisis estático aislado de archivos (ejecutables, Office con macros, PDF, scripts, LNK, ISO, ZIP/APK…) y de **enlaces** (el backend descarga la página sin que el usuario la visite y sigue las redirecciones): MITRE ATT&CK, CVE con CVSS/EPSS/CISA KEV, dependencias vulnerables (OSV), URLhaus e IOCs. Admite **reglas YARA propias** y un paquete de **reglas base** incluido (`yara/centinela-base.yar`) (subconjunto: cadenas de texto/hex/regex y condiciones habituales) y **comparación de archivos** (imphash, PDB, técnicas e indicadores comunes). Exporta TXT, JSON, CSV, capa de ATT&CK Navigator y STIX 2.1. |
| | **Filtraciones** | Correos comprometidos, filtraciones de una entidad, mitigación y retirada de contenido. |
| | **Monitoreo** | Vigila listas negras y cambios en SPF/DMARC/MX/NS mientras la pestaña está abierta, con historial de revisiones y gráfico de estados. |
| Ciberinteligencia | **Reconocimiento OSINT** | Dominios parecidos o suplantadores (typosquatting, Certificate Transparency, DNS en vivo). |
| | **Análisis de vulnerabilidades** | Puertos y CVE expuestos (Shodan InternetDB, CIRCL, NVD, CISA KEV), superficie de ataque y subdomain takeover. |
| | **Consulta de IOCs** | Reputación en lote de IPs, dominios, URLs, hashes y CVE (Shodan, Spamhaus, RDAP, CISA KEV, EPSS; URLhaus, ThreatFox, VirusTotal, MalwareBazaar e Hybrid Analysis vía backend). Admite indicadores desactivados (`hxxp`, `[.]`) y exporta CSV/JSON/STIX 2.1. |
| | **Casos** | Agrupa archivos, enlaces, indicadores, informes y notas de un incidente, con estado, severidad, línea de tiempo y exportación. |
| | **Informe ejecutivo** | Consolida dominio, vulnerabilidades, suplantación, filtraciones, archivos del sandbox y monitoreo, con prioridades de actuación, gráficos de postura, **mapeo de cumplimiento** (ISO/IEC 27001:2022, NIST CSF 2.0, CIS v8) y PDF con portada, índice y numeración. |
| Infraestructura | **Geolocalización IP** | Ubicación, ASN y proveedor de una IP. |
| | **TLS y certificados** | Versiones TLS admitidas, cifrado, certificado (emisor, validez, nombres, clave, firma), HSTS y calificación A+–F (requiere backend con sockets). |
| | **Cabeceras HTTP** | Evaluación de cabeceras de seguridad (requiere backend). |
| Utilidades | **Herramientas** | Contraseñas filtradas (k-anonimato), generador, hashes, Base64/URL y decodificador JWT. |

## Publicar en GitHub Pages

1. Crea un repositorio y sube **todos estos archivos juntos en la raíz** (o en la carpeta que publiques):

   | Archivo | Obligatorio | Para qué |
   |---|---|---|
   | `index.html` | Sí | La interfaz. |
   | `app.js`, `boot.js`, `styles.css` | Sí | La lógica de la aplicación (separada del HTML para una CSP estricta). |
   | `sandbox-worker.js` | Sí | Motor del sandbox de archivos. Sin él, el módulo muestra un error indicando que falta. |
   | `sw.js` | Sí | Service worker (funcionamiento sin conexión y actualizaciones). |
   | `manifest.webmanifest`, `icon.svg` | Sí | Instalación como app. |
   | `yara/` | Sí | Reglas YARA base que el sandbox carga con el botón "Cargar reglas base". |
   | `fonts/` | Sí | Tipografías Manrope e IBM Plex alojadas localmente (SIL Open Font License, textos de licencia incluidos). |
   | `worker-filtraciones.js`, `worker-sandbox.js`, `backend/` | No | Backend opcional para Cloudflare (ver "Backend opcional"). La página no los usa. |
   | `README.md` | No | Esta guía. |

2. En el repositorio: **Settings → Pages → Build and deployment → Deploy from a branch**, rama `main`, carpeta `/ (root)`.
3. Abre la URL que indica GitHub (`https://<usuario>.github.io/<repositorio>/`).

Tras cada actualización, el service worker descarga la versión nueva automáticamente (el HTML y el JavaScript siempre se piden primero a la red). Si cambias archivos estáticos, incrementa la constante `CACHE` en `sw.js` (p.ej. `centinela-v9`) para renovar la caché.

**Abrir en local:** puedes abrir `index.html` con doble clic; todo funciona, aunque la instalación como app y el service worker requieren servirla por `http(s)://` (p.ej. `python -m http.server`).

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

### Despliegue paso a paso

Requisitos: una cuenta gratuita de Cloudflare y Node.js 22 o superior.

1. **Configura los orígenes permitidos.** Edita `backend/wrangler.toml` y sustituye `https://TU_USUARIO.github.io` por la URL de tu Centinela publicado (puedes añadir varias separadas por comas). Es imprescindible: sin esta lista, cualquier sitio web podría usar tu Worker como proxy y consumir tus claves y cuotas.
2. **Ensambla y publica:**
   ```bash
   cd backend
   node build.mjs          # genera dist/worker.js a partir de worker-filtraciones.js y worker-sandbox.js
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
   ```
4. **Conecta la app:** en Centinela → Ajustes → *URL del backend*, pega la URL del Worker y guarda. En **Inicio → Estado de las fuentes de datos**, el indicador *Backend* debe aparecer en verde.

**Despliegue desde GitHub (opcional):** crea en el repositorio los secretos `CLOUDFLARE_API_TOKEN` (plantilla *Edit Cloudflare Workers*) y `CLOUDFLARE_ACCOUNT_ID`, y ejecuta manualmente la acción **Desplegar backend**. La acción ejecuta las pruebas del backend antes de publicar.

**Límite de peticiones (opcional):** `wrangler.toml` incluye, comentado, un *binding* de Rate Limiting llamado `SBX_LIMIT`; actívalo tras comprobar la sintaxis vigente en la documentación de Cloudflare.

**Limitaciones conocidas:** el análisis TLS usa sockets TCP, y Cloudflare no permite abrir sockets hacia sitios que están detrás de su propia red. Las claves viven solo en el Worker; nunca llegan al navegador.

**Si ya tienes un Worker propio:** copia las funciones de `worker-filtraciones.js` y `worker-sandbox.js` y, en tu enrutador, añade `const leak = await handleLeakRoutes(url, env, request); if (leak) return leak;` y `const sbx = await handleSandboxRoutes(request, url, env); if (sbx) return sbx;`. Para TLS, empieza el módulo con `import { connect } from 'cloudflare:sockets'; globalThis.CF_CONNECT = connect;`.

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
- `backend.test.js`: rutas del Worker sin red (orígenes permitidos, límite de peticiones, bloqueo de destinos internos, secretos ausentes).
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
app.js                  Lógica de la aplicación
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
backend/                Worker listo para desplegar (wrangler.toml + build.mjs)
tests/                  Pruebas automáticas (Node y navegador headless)
.github/workflows/      Integración continua (GitHub Actions)
```
