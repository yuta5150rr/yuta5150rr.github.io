// sw.js - service worker for web push ONLY: `push` and `notificationclick`.
// No `fetch` handler, no Cache/Cache Storage, no skipWaiting/claim: it cannot intercept, cache or serve any page, so it can never make an approval screen stale.
// Written (best effort, own IndexedDB 'xgate-open'): the verified {id,req} of a tapped approve notification ('last'), the verified approve request of every received push ('inbox'), and a one-line arrival note of every push ('lastpush'): a tap can then never be lost when the OS ignores the URL
// or the message of an already-open window. The app re-verifies and consumes it. Notification texts come from this file by kind, never from the payload. A click can only open THIS app's own scope with a request that is cryptographically bound to the id
// (sha-256 of the carried request bytes == id); anything else opens the plain app root. Nothing is ever signed, stored or sent from here.
'use strict';
const KINDS = ['approve', 'received', 'completed', 'test'];
const TEXTS = {
  approve: ['承認が必要です', '署名待ちの依頼が1件あります。内容を確認してください。'],
  received: ['署名を受領しました', '受領書を記録しました。実行の完了通知を待っています。'],
  completed: ['実行が完了しました', '承認された作業が完了しました。'],
  test: ['通知テスト', 'この端末への通知が有効です。'],
};
const GENERIC = ['確認があります', 'アプリを開いて確認してください。'];
const HEX64 = /^[0-9a-f]{64}$/;
// carried request cap (bytes). 2400 B -> payload 3324 B < the Site's 3500 B payload cap < 3993 B (4096 - 86 header - 17 delimiter/tag). MUST equal the Site's MAX_REQ_BYTES.
const MAX_REQ_BYTES = 2400;
const unb64u = (s) => { if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null; const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)); const u = Uint8Array.from(bin, (c) => c.charCodeAt(0)); return btoa(String.fromCharCode.apply(null, u)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === s ? u : null; };
const sha256Hex = async (u8) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', u8)), (x) => x.toString(16).padStart(2, '0')).join('');
// -> { ok, kind, id, req } | { ok:false }
async function parse(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o) || o.v !== 1 && o.v !== undefined) return { ok: false };
  if (!KINDS.includes(o.kind) || typeof o.id !== 'string' || !HEX64.test(o.id)) return { ok: false };
  if (o.kind === 'approve') { const b = unb64u(o.req); if (!b || b.length > MAX_REQ_BYTES || (await sha256Hex(b)) !== o.id) return { ok: false }; return { ok: true, kind: o.kind, id: o.id, req: o.req }; }
  if (o.req !== undefined && o.req !== null) return { ok: false };
  return { ok: true, kind: o.kind, id: o.id, req: null };
}
async function parsePayloadText(text) {
  let o; try { o = JSON.parse(text); } catch (e) { return { ok: false }; }
  if (!o || typeof o !== 'object' || Array.isArray(o) || o.v !== 1 || !Number.isFinite(o.ts)) return { ok: false };
  const keys = Object.keys(o).sort().join();
  if (keys !== (o.kind === 'approve' ? 'id,kind,req,ts,v' : 'id,kind,ts,v')) return { ok: false };
  return parse(o);
}
async function onPush(event) {
  let p = { ok: false };
  try { p = await parsePayloadText(event.data ? event.data.text() : ''); } catch (e) { p = { ok: false }; }
  // Safari revokes the permission if a push is not shown: ALWAYS show something, even for an undecryptable / malformed payload.
  if (!p.ok) { await self.registration.showNotification(GENERIC[0], { body: GENERIC[1], tag: 'xgate-generic', data: null }); await putRec('lastpush', { v: 1, t: Date.now(), kind: 'unparsed', id16: '', ok: false }); return; }
  const t = TEXTS[p.kind];
  await self.registration.showNotification(t[0], { body: t[1], tag: p.kind + '-' + p.id.slice(0, 16), renotify: false, data: { kind: p.kind, id: p.id, req: p.req } });
  // AFTER the notification is shown (never before): remember that a push reached this worker, and keep the verified approve request in an inbox so the app can load it even if the tap / window routing fails
  await putRec('lastpush', { v: 1, t: Date.now(), kind: p.kind, id16: p.id.slice(0, 16), ok: true });
  if (p.kind === 'approve') await putRec('inbox', { v: 1, kind: 'approve', id: p.id, req: p.req, ts: Date.now() });
  // best effort, AFTER showNotification resolved: tell an open app window that the notification really was displayed (the push service's HTTP 201 only means "accepted")
  try { for (const c of await clients.matchAll({ type: 'window', includeUncontrolled: true })) if (typeof c.url === 'string' && c.url.startsWith(self.registration.scope)) c.postMessage({ type: 'xgate-displayed', kind: p.kind, id: p.id }); } catch (e) { /* display already happened */ }
}
// the ONLY URLs this worker can produce: the app's own scope, optionally with ?r=<id16>#req=<verified request> or ?n=<kind>&r=<id16>
async function targetFor(data) {
  const scope = self.registration.scope;
  let p = { ok: false }; try { p = await parse(data); } catch (e) { p = { ok: false }; }
  if (!p.ok || p.kind === 'test') return { url: scope, message: null };
  const id16 = p.id.slice(0, 16);
  if (p.kind === 'approve') return { url: scope + '?r=' + id16 + '#req=' + p.req, message: { type: 'xgate-open', kind: p.kind, id: p.id, req: p.req } };
  return { url: scope + '?n=' + p.kind + '&r=' + id16, message: { type: 'xgate-open', kind: p.kind, id: p.id, req: null } };
}
// tap hand-off: one record, own database. Best effort (never blocks opening the app); the app re-verifies sha-256(req) == id and the strict request rules before using it.
function putRec(key, rec) {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => fin(false), 1500);          // bounded: a blocked / stuck IndexedDB must never delay focusing or opening the app
    try {
      const q = indexedDB.open('xgate-open', 1);
      q.onupgradeneeded = () => { q.result.createObjectStore('s'); };
      q.onblocked = () => fin(false);
      q.onerror = () => fin(false);
      q.onsuccess = () => {
        const db = q.result;
        db.onversionchange = () => { try { db.close(); } catch (e) { /* closing is best effort */ } };
        if (done) { try { db.close(); } catch (e) { /* late connection */ } return; }
        try { const tx = db.transaction('s', 'readwrite'); tx.objectStore('s').put(rec, key); tx.oncomplete = () => { db.close(); fin(true); }; tx.onerror = () => { db.close(); fin(false); }; tx.onabort = () => { db.close(); fin(false); }; } catch (e) { try { db.close(); } catch (e2) { /* ignore */ } fin(false); }
      };
    } catch (e) { fin(false); }
  });
}
async function onClick(event) {
  event.notification.close();
  const t = await targetFor(event.notification.data);
  if (t.message && t.message.kind === 'approve') await putRec('last', { v: 1, kind: 'approve', id: t.message.id, req: t.message.req, ts: Date.now() });
  const scope = self.registration.scope;
  const wins = (await clients.matchAll({ type: 'window', includeUncontrolled: true })).filter((c) => typeof c.url === 'string' && c.url.startsWith(scope));
  if (wins.length) {                       // the open app decides (it never swaps a target while a signing is in progress)
    const c = wins[0]; try { await c.focus(); } catch (e) { /* best effort */ }
    if (t.message) c.postMessage(t.message);
    return;
  }
  await clients.openWindow(t.url);
}
self.addEventListener('push', (event) => { event.waitUntil(onPush(event)); });
self.addEventListener('notificationclick', (event) => { event.waitUntil(onClick(event)); });
