const CACHE_NAME = 'hexstore-static-v3';
const STATIC_ASSETS = ['/', '/index.html', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE_NAME).then((c) => c.addAll(STATIC_ASSETS)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))));
  self.clients.claim();
});

// Page loads: use the network when it answers fast, otherwise show the saved copy
// right away (no more long white screens on a weak connection).
function networkFirst(req, ms) {
  return new Promise((resolve) => {
    let settled = false;
    const useCache = () => caches.match(req).then((c) => c || caches.match('/')).then((c) => c || Response.error());
    const timer = setTimeout(() => { if (!settled) { settled = true; useCache().then(resolve); } }, ms);
    fetch(req).then((res) => {
      if (res.status === 200) { const copy = res.clone(); caches.open(CACHE_NAME).then((c) => c.put(req, copy)); }
      clearTimeout(timer);
      if (!settled) { settled = true; resolve(res); }
    }).catch(() => { clearTimeout(timer); if (!settled) { settled = true; useCache().then(resolve); } });
  });
}

// Icons, manifest, etc: show the saved copy instantly and refresh it in the background.
function staleWhileRevalidate(req) {
  return caches.match(req).then((cached) => {
    const net = fetch(req).then((res) => {
      if (res.status === 200) { const copy = res.clone(); caches.open(CACHE_NAME).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => cached || Response.error());
    return cached || net;
  });
}

self.addEventListener('fetch', (e) => {
  const req = e.request, url = new URL(req.url);
  // Never cache API calls, file downloads, APKs or share pages
  if (req.method !== 'GET' || url.origin !== self.location.origin ||
      url.pathname.startsWith('/api/') || url.pathname.startsWith('/files/') ||
      url.pathname.startsWith('/a/') || url.pathname.endsWith('.apk')) return;
  const isPage = req.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html';
  e.respondWith(isPage ? networkFirst(req, 3000) : staleWhileRevalidate(req));
});
