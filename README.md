# Centinela — Guía de despliegue (URL pública gratis + PWA)

Esta carpeta es el sitio completo, listo para publicar. Contiene:

- `index.html` — la app (con manifest y service worker enlazados)
- `manifest.webmanifest` — hace la app instalable (PWA)
- `sw.js` — service worker (offline + instalación)
- `icon.svg` — ícono de la app
- `netlify.toml` — cabeceras recomendadas (solo Netlify)

> Importante: la PWA (instalación) y el service worker **solo funcionan sobre HTTPS** (es decir, ya publicada). Abriendo `index.html` con doble clic funciona la app, pero no se instala.

---

## Opción A — Netlify (la más rápida, sin cuenta técnica)

1. Entra a https://app.netlify.com/drop
2. Arrastra **toda esta carpeta** (`centinela-deploy`) a la zona de "drag and drop".
3. En segundos te da una URL tipo `https://centinela-xxxx.netlify.app`.
4. (Opcional) Crea una cuenta gratis para conservarla y ponerle un nombre.

## Opción B — Cloudflare Pages

1. Ve a https://pages.cloudflare.com → **Create a project** → **Direct Upload**.
2. Sube el contenido de esta carpeta.
3. Obtienes `https://centinela.pages.dev`.

## Opción C — GitHub Pages (para versionar)

1. Crea un repositorio en GitHub (p. ej. `centinela`).
2. Sube estos archivos a la raíz del repo (botón **Add file → Upload files**).
3. Ve a **Settings → Pages** → *Source: Deploy from a branch* → rama `main`, carpeta `/root` → **Save**.
4. En 1–2 min queda en `https://TUUSUARIO.github.io/centinela/`.

> Si usas GitHub Pages en una **subcarpeta** (como el ejemplo de arriba), todo funciona porque las rutas son relativas (`./`).

---

## Instalar como app (PWA)

Una vez publicada (HTTPS), abre la URL en Chrome/Edge:
- Aparecerá el botón **⬇️** en la cabecera, o el ícono de "Instalar" en la barra de direcciones.
- También en móvil: menú → **Agregar a pantalla de inicio**.

---

## Conectar el backend de monitoreo (opcional)

Si además despliegas el **Cloudflare Worker** (carpeta `centinela-backend`), pega su URL en
**⚙️ Ajustes → URL del backend** dentro de la app. Con eso la verificación automática
(VirusTotal / Google Safe Browsing) se hace a través del Worker, sin límites de CORS y
sin exponer tus claves en el navegador.

---

## Dominio propio (opcional)

Tanto Netlify como Cloudflare Pages permiten conectar un dominio propio gratis
(p. ej. `seguridad.tudominio.gov.co`) desde su panel → *Custom domains*.
