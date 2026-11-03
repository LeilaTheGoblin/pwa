/* Public unlock page logic. Holds nothing secret.
   Device setup: passphrase → PBKDF2 (same parameters the apps use for cloud sync) → data key, saved on
   this device → unwraps the bundle key from keywrap.json → bundle key saved in IndexedDB as a
   non-extractable key → the service worker can now decrypt the app. On devices that already have the
   data key (entered once in the app before), no passphrase is asked. */
(function(){
  const E2E_LS = "e2e_key_v1";
  const E2E_SALT_HEX = "6865616c74682d617070737c6532657c76317c37663363396131652d326236342d346430652d396335352d613831663065366232643437";
  const E2E_ITER = 600000;
  const WRAP_AAD = "vault-keywrap-v1";
  const ROOT = new URL("../", location.href);
  const FORCE_INLINE = location.hash === "#inline";   // test / escape hatch: skip the service worker
  const $ = (id)=>document.getElementById(id);
  const b64d = (s)=>{ const b=atob(s), u=new Uint8Array(b.length); for(let i=0;i<b.length;i++) u[i]=b.charCodeAt(i); return u; };
  const b64e = (u8)=>{ let s=""; for(let i=0;i<u8.length;i+=0x8000) s+=String.fromCharCode.apply(null,u8.subarray(i,i+0x8000)); return btoa(s); };
  const msg = (t, err)=>{ const m=$("v-msg"); if(m){ m.textContent=t; m.style.color = err ? "#B42318" : "#85747A"; } };

  function idb(mode, fn){
    return new Promise((res, rej)=>{
      const r = indexedDB.open("vault", 1);
      r.onupgradeneeded = ()=> r.result.createObjectStore("k");
      r.onerror = ()=> rej(r.error);
      r.onsuccess = ()=>{ const st = r.result.transaction("k", mode).objectStore("k"); const q = fn(st); q.onsuccess=()=>res(q.result); q.onerror=()=>rej(q.error); };
    });
  }
  const getBundleKey = ()=> idb("readonly", st=>st.get("bundle")).catch(()=>null);
  const putBundleKey = (k)=> idb("readwrite", st=>st.put(k, "bundle"));

  async function derive(pass){
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt:Uint8Array.from(E2E_SALT_HEX.match(/../g), h=>parseInt(h,16)), iterations:E2E_ITER }, base, 256);
    return b64e(new Uint8Array(bits));
  }
  async function unwrap(rawDataKey){
    const w = await (await fetch(new URL("keywrap.json", ROOT), { cache:"no-cache" })).json();
    const dk = await crypto.subtle.importKey("raw", b64d(rawDataKey), { name:"AES-GCM" }, false, ["decrypt"]);
    const kb = await crypto.subtle.decrypt({ name:"AES-GCM", iv:b64d(w.iv), additionalData:new TextEncoder().encode(WRAP_AAD) }, dk, b64d(w.ct));
    const pk = await crypto.subtle.importKey("pkcs8", new Uint8Array(kb), { name:"RSA-OAEP", hash:"SHA-256" }, false, ["decrypt"]);   // non-extractable
    new Uint8Array(kb).fill(0);
    return pk;
  }
  async function swReady(){
    if(!("serviceWorker" in navigator)) throw new Error("הדפדפן לא תומך ב-Service Worker");
    await navigator.serviceWorker.register("./sw.js");
    const reg = await navigator.serviceWorker.ready;
    if(!navigator.serviceWorker.controller){
      await new Promise((res)=>{ navigator.serviceWorker.addEventListener("controllerchange", res, { once:true }); setTimeout(res, 3000); });
    }
    return reg;
  }
  // Decrypt one vault file in the page (same format the service worker uses).
  const TYPES = { html:"text/html; charset=utf-8", json:"application/json; charset=utf-8", md:"text/markdown; charset=utf-8" };
  async function decryptRel(rel, key, rawFetch){
    const r = await rawFetch(ROOT.pathname + rel + ".enc", { cache:"no-cache" });
    if(!r.ok) throw new Error("enc " + r.status);
    const buf = new Uint8Array(await r.arrayBuffer());
    if(buf[0]!==86||buf[1]!==76||buf[2]!==84||buf[3]!==50) throw new Error("format");
    const wl = (buf[4]<<8) | buf[5];
    const raw = await crypto.subtle.decrypt({ name:"RSA-OAEP" }, key, buf.slice(6, 6+wl));
    const fk = await crypto.subtle.importKey("raw", raw, { name:"AES-GCM" }, false, ["decrypt"]);
    return crypto.subtle.decrypt({ name:"AES-GCM", iv:buf.slice(6+wl, 18+wl), additionalData:new TextEncoder().encode(rel) }, fk, buf.slice(18+wl));
  }
  // Fallback when the browser's service worker doesn't serve the app (seen on iPhone Safari):
  // decrypt in the page, route the app's own data fetches through the same decryption, render.
  async function inlineBoot(key){
    let rel = location.pathname.slice(ROOT.pathname.length); if(!rel || rel.endsWith("/")) rel += "index.html";
    const rawFetch = window.fetch.bind(window);
    const html = new TextDecoder().decode(await decryptRel(rel, key, rawFetch));
    window.fetch = async (input, init)=>{
      try{
        const u = new URL(typeof input === "string" ? input : input.url, location.href);
        if(u.origin === location.origin && u.pathname.startsWith(ROOT.pathname) && /\.(html|json|md)$/.test(u.pathname) && !/(manifest|keywrap)\.json$/.test(u.pathname)){
          const r = u.pathname.slice(ROOT.pathname.length);
          const pt = await decryptRel(r, key, rawFetch);
          return new Response(pt, { status:200, headers:{ "Content-Type": TYPES[(r.match(/\.([a-z]+)$/)||[])[1]] || "text/plain" } });
        }
      }catch(e){}
      return rawFetch(input, init);
    };
    let fired = false; window.addEventListener("load", ()=>{ fired = true; }, { once:true });
    document.open(); document.write(html); document.close();
    setTimeout(()=>{ if(!fired){ try{ window.dispatchEvent(new Event("load")); }catch(e){} } }, 800);
  }
  // Prefer the service worker (works offline); if it isn't serving within a few seconds, boot inline.
  async function go(){
    let why = FORCE_INLINE ? "forced" : "";
    for(let i=0;i<(FORCE_INLINE?0:8);i++){
      try{
        const r = await fetch(location.href, { cache:"no-store" });
        if(r.headers.get("X-Vault")==="1"){ location.reload(); return; }
        why = navigator.serviceWorker && navigator.serviceWorker.controller ? "sw-no-decrypt" : "sw-not-active";
      }catch(e){ why = "net"; }
      await new Promise(s=>setTimeout(s, 600));
    }
    try{
      const key = await getBundleKey();
      if(!key) throw new Error("no-key");
      await inlineBoot(key);
    }catch(e){
      showForm("לא ניתן היה לפתוח כרגע (" + why + " / " + (e && e.message || e) + "). צלם את ההודעה ושלח.");
    }
  }
  function showForm(note){
    $("v-form").style.display = "block"; $("v-wait").style.display = "none";
    if(note) msg(note, true);
    setTimeout(()=>{ const i=$("v-pass"); if(i) i.focus(); }, 50);
  }
  async function submit(ev){
    if(ev) ev.preventDefault();
    const p = $("v-pass").value; if(!p){ msg("הזן סיסמה.", true); return; }
    $("v-go").disabled = true; msg("פותח…");
    try{
      const raw = await derive(p);
      let kb;
      try{ kb = await unwrap(raw); }catch(e){ $("v-go").disabled=false; msg("סיסמה שגויה.", true); return; }
      localStorage.setItem(E2E_LS, raw);
      await putBundleKey(kb);
      if(!FORCE_INLINE){ try{ await swReady(); }catch(e){} }
      go();
    }catch(e){ $("v-go").disabled=false; msg("שגיאה: "+(e && e.message || e), true); }
  }
  // Retire the old, unencrypted app copies this origin may still hold (old service workers + their caches).
  async function retireLegacy(){
    try{
      for(const g of await navigator.serviceWorker.getRegistrations()){
        if(!new URL(g.scope).pathname.startsWith(ROOT.pathname)) await g.unregister();
      }
      for(const k of await caches.keys()){
        if(!/^[a-z]-v[0-9a-z]+$/.test(k)) await caches.delete(k);
      }
    }catch(e){}
  }
  async function start(){
    $("v-f").addEventListener("submit", submit);
    if(!FORCE_INLINE) await retireLegacy();
    try{
      if(!FORCE_INLINE){ try{ await swReady(); }catch(e){} }
      if(await getBundleKey()){ go(); return; }
      const raw = localStorage.getItem(E2E_LS);
      if(raw){
        try{ await putBundleKey(await unwrap(raw)); go(); return; }catch(e){ /* stale key → ask */ }
      }
      showForm();
    }catch(e){ showForm("שגיאה: "+(e && e.message || e)); }
  }
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", start) : start();
})();
