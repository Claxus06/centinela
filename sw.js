/* Centinela — Service Worker
   Cachea solo el "shell" (mismo origen) para funcionar offline y ser instalable.
   NO intercepta las llamadas a DNS/geo/APIs externas (deben ir siempre a la red). */
const CACHE = 'centinela-v1';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icon.svg'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Solo el mismo origen (el shell). Todo lo cross-origin pasa directo a la red.
  if (url.origin === location.origin && e.request.method === 'GET') {
    e.respondWith(
      caches.match(e.request).then(cached =>
        cached || fetch(e.request).then(resp => {
          const copy = resp.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
          return resp;
        }).catch(() => cached)
      )
    );
  }
});
