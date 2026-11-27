/* networkmap service worker：静态资源网络优先（离线时回退缓存），API 不缓存 */
const CACHE = "networkmap-v0.3.0";
const ASSETS = [
  "./",
  "./index.html",
  "./style.css?v=0.3.0",
  "./app.js?v=0.3.0",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png",
  "./vendor/qrcode.js?v=0.3.0",
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  if (url.pathname.startsWith("/api/")) return;  // 动态数据不缓存

  if (req.mode === "navigate") {
    // 页面：网络优先，离线回退到缓存外壳
    event.respondWith(fetch(req).catch(() => caches.match("./index.html")));
    return;
  }
  // 静态资源：网络优先并更新缓存，断网时用缓存（避免发版后样式/脚本残留旧版）
  event.respondWith(
    fetch(req)
      .then(resp => {
        if (resp && resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
        }
        return resp;
      })
      .catch(() => caches.match(req))
  );
});
