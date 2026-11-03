/* Vault service worker core (shared by every app folder; each folder's sw.js sets CACHE and imports this).
   The public repo holds only ciphertext (*.enc). This worker fetches the .enc file, decrypts it on the
   device with the vault private key kept in IndexedDB (non-extractable RSA-OAEP CryptoKey), and serves the plaintext.
   Without a key it passes requests through, so the public loader page (index.html) is what loads.
   Cache stores ciphertext only. */
const VAULT_ROOT = new URL("../", self.location).pathname;          // e.g. /pwa/
const PUBLIC_FILES = /\/(manifest\.json|keywrap\.json|sw\.js|vault-sw\.js|vault-client\.js)$/;
const ENCRYPTED_EXT = /\.(html|json|md|js|css|txt)$/;
const MAGIC = [86, 76, 84, 50];                                      // "VLT2"

function idbGetKey(){
  return new Promise((res)=>{
    const r = indexedDB.open("vault", 1);
    r.onupgradeneeded = ()=> r.result.createObjectStore("k");
    r.onerror = ()=> res(null);
    r.onsuccess = ()=>{
      try{
        const tx = r.result.transaction("k", "readonly").objectStore("k").get("bundle");
        tx.onsuccess = ()=> res(tx.result || null); tx.onerror = ()=> res(null);
      }catch(e){ res(null); }
    };
  });
}
const TYPES = { html:"text/html; charset=utf-8", json:"application/json; charset=utf-8", md:"text/markdown; charset=utf-8",
                js:"application/javascript; charset=utf-8", css:"text/css; charset=utf-8", txt:"text/plain; charset=utf-8" };

async function fetchCipher(encUrl){
  const cache = await caches.open(CACHE);
  try{
    const ctl = new AbortController(); const t = setTimeout(()=>ctl.abort(), 15000);
    const r = await fetch(encUrl, { cache:"no-cache", signal:ctl.signal }); clearTimeout(t);
    if(r.ok){ cache.put(encUrl, r.clone()); return r; }
    if(r.status === 404) return null;
  }catch(e){}
  return (await cache.match(encUrl)) || null;
}
async function serveDecrypted(req, path){
  const key = await idbGetKey();
  if(!key) return null;
  const rel = path.slice(VAULT_ROOT.length);                       // e.g. t/index.html
  const encUrl = VAULT_ROOT + rel + ".enc";
  const r = await fetchCipher(encUrl);
  if(!r) return null;
  const buf = new Uint8Array(await r.arrayBuffer());
  if(MAGIC.some((b,i)=>buf[i]!==b)) return null;
  try{
    const wl = (buf[4]<<8) | buf[5];
    const wrapped = buf.slice(6, 6+wl), iv = buf.slice(6+wl, 18+wl), ct = buf.slice(18+wl);
    const raw = await crypto.subtle.decrypt({ name:"RSA-OAEP" }, key, wrapped);
    const fk = await crypto.subtle.importKey("raw", raw, { name:"AES-GCM" }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv, additionalData:new TextEncoder().encode(rel) }, fk, ct);
    const ext = (rel.match(/\.([a-z0-9]+)$/)||[])[1] || "html";
    return new Response(pt, { status:200, headers:{ "Content-Type":TYPES[ext]||"application/octet-stream", "Cache-Control":"no-store", "X-Vault":"1" } });
  }catch(e){ return null; }
}

self.addEventListener("install", ()=> self.skipWaiting());
self.addEventListener("activate", (e)=>{
  e.waitUntil((async()=>{
    const keys = await caches.keys();
    await Promise.all(keys.filter(k=>k!==CACHE && k.startsWith(CACHE.split("-v")[0])).map(k=>caches.delete(k)));
    await self.clients.claim();
  })());
});
self.addEventListener("message", (e)=>{ if(e.data==="vault-ping" && e.source) e.source.postMessage("vault-pong"); });
self.addEventListener("fetch", (e)=>{
  const req = e.request;
  if(req.method !== "GET") return;
  const url = new URL(req.url);
  if(url.origin !== self.location.origin || !url.pathname.startsWith(VAULT_ROOT)) return;
  let path = url.pathname;
  if(path.endsWith("/")) path += "index.html";
  if(PUBLIC_FILES.test(path) || !ENCRYPTED_EXT.test(path) || path.endsWith(".enc")) return;   // icons, shell files, raw ciphertext
  e.respondWith((async()=>{
    const out = await serveDecrypted(req, path);
    if(out) return out;
    // No key yet / not an encrypted file: the public file (for index.html this is the unlock page).
    try{ return await fetch(req); }catch(err){ return new Response("offline", { status:503 }); }
  })());
});
