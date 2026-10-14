/* Centinela — Service Worker
   Cachea el "shell" para funcionar offline, pero SIN quedarse con versiones viejas:
   - La página (HTML) y el código propio (.js) usan "network-first": siempre la última versión, y juntos.
   - Los estáticos usan "stale-while-revalidate": rápidos, pero se actualizan en segundo plano.
   - El nombre de caché lleva versión: al cambiarla se borran las anteriores. */
const CACHE = 'centinela-v15';
const SHELL = ['./', './index.html', './styles.css', './boot.js', './app.js', './sandbox-worker.js', './manifest.webmanifest', './icon.svg', './yara/centinela-base.yar',
  './fonts/manrope-var.woff2', './fonts/ibm-plex-sans-var.woff2', './fonts/ibm-plex-mono-400.woff2', './fonts/ibm-plex-mono-500.woff2'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Permite forzar la actualización desde la página si hiciera falta
self.addEventListener('message', e => { if (e.data === 'skipWaiting') self.skipWaiting(); });

self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);
  if (url.origin !== location.origin || req.method !== 'GET') return; // no tocar APIs externas
  const isHTML = req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');
  // El HTML y el JS propio deben ir siempre en la misma versión: ambos "network-first"
  const isCode = isHTML || /\.js$/.test(url.pathname);

  if (isCode) {
    // network-first: la última versión gana; si no hay red, usa caché
    e.respondWith(
      fetch(req).then(resp => {
        const copy = resp.clone();
        caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
        return resp;
      }).catch(() => caches.match(req).then(r => r || (isHTML ? caches.match('./index.html') : undefined)))
    );
    return;
  }
  // estáticos: stale-while-revalidate
  e.respondWith(
    caches.match(req).then(cached => {
      const net = fetch(req).then(resp => {
        const copy = resp.clone();
        caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
        return resp;
      }).catch(() => cached);
      return cached || net;
    })
  );
});
