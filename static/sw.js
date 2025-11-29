self.addEventListener("install", e => {
  e.waitUntil(
    caches.open("bis-cache").then(cache => {
      return cache.addAll(["/", "/static/manifest.json"]);
    })
  );
});

self.addEventListener("fetch", e => {
  e.respondWith(
    caches.match(e.request).then(resp => resp || fetch(e.request))
  );
});
