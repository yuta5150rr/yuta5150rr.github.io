// fragment.js (v0.3l: + dot-probe/c5-keys-check-v1) (v0.3k: + dot-probe/chief-recovery-v1) (v0.3j: + dot-probe/chief-development-v1) (v0.3i: source 'file' for an explicit fixed-file refresh) (v0.3h: no lossy outbox) (v0.3g: durable signed receipt) (v0.3f: durable pending request) (v0.3d: + dot-probe/claude-resume-readonly) - pure helpers for the one-request transport. No DOM, no storage, no crypto, no network of its own:
// the caller passes the fetch function and this module only ever hands it ONE fixed same-origin path.
// IN : the exact request bytes the Sites authority issued, placed at ONE fixed same-origin file (public data only: no secret/receipt/token).
// OUT: top-level navigation to ONE fixed Sites page with the receipt in the URL fragment (never sent to a server by the browser).
import { rrFromRequest, RR_PREFIX } from './rr-codec.js';
export const SITES_ORIGIN = 'https://xgate-connector.tainakaritsu903729.chatgpt.site';
export const RECEIPT_URL = SITES_ORIGIN + '/receipt';
export const REQUEST_FILE = 'dotprobe-request.json';
export const FIXED_REPO = 'yuta5150rr/dot-probe';
export const README_REPO = 'yuta5150rr/autonomy-daemon';
export const README_PATHS = Object.freeze(['README.md']);
export const IMPORT_PATHS = Object.freeze(['.gitignore', '.npmrc', 'README.md', 'docs/**', 'package-lock.json', 'package.json', 'src/**', 'test/**', 'tsconfig.json', 'vitest.config.ts', 'wrangler.jsonc']);   // G6: the fixed import request (same repo as README)
const README_TITLE = 'リポジトリ ' + README_REPO + ' の README.md だけを変更するPRを、1回だけ承認する（他のファイル・workflow・設定は対象外）';
const PARSE_RE = /対象: .+ のPR#([1-9][0-9]{0,8})（mainのbase SHA ([0-9a-f]{40})）の、.*変更manifest SHA-256 ([0-9a-f]{64}) に一致/;
const importTitle = () => 'リポジトリ ' + README_REPO + ' に、検査済みの取り込み木（src・test・docs・設定ファイル）だけを入れるPRを、1回だけ承認する（.github・workflowは対象外）';
const importSummary = (digest, pr, base) => '許可する操作はこの1件だけ。対象: ' + README_REPO + ' のPR#' + pr + '（mainのbase SHA ' + base + '）の、取り込み木（README.md・.gitignore・.npmrc・package.json・package-lock.json・tsconfig.json・vitest.config.ts・wrangler.jsonc と、docs/・src/・test/ の中身）の追加・変更だけを含むPR（受領書 approvals/<work_id>.json を同じPRに載せる）を、承認ゲートが通してよい。承認する変更内容は、変更manifest SHA-256 ' + digest + ' に一致するものだけ（受領書自身は含まない）。上記以外のファイル・.github・approvals 以外の変更、実行、deploy、鍵や権限の変更、公開は許可しない。有効期限内に1つの対象にだけ使える（同じ受領書・同じnonceを別のPRやheadには使えない）。';
const readmeSummary = (digest, pr, base) => '許可する操作はこの1件だけ。対象: ' + README_REPO + ' のPR#' + pr + '（mainのbase SHA ' + base + '）の、README.md の内容変更を含むPR（受領書 approvals/<work_id>.json を同じPRに載せる）を、承認ゲートが通してよい。承認する変更内容は、変更manifest SHA-256 ' + digest + ' に一致するものだけ（受領書自身は含まない）。README.md 以外のファイル・.github・approvals 以外の変更、実行、deploy、鍵や権限の変更、公開は許可しない。有効期限内に1つの対象にだけ使える（同じ受領書・同じnonceを別のPRやheadには使えない）。';
export function readmeBoundOk(o) { const m = typeof o.summary === 'string' ? PARSE_RE.exec(o.summary) : null; return typeof o.work_id === 'string' && /^autonomy-readme-[0-9a-f]{8}$/.test(o.work_id) && o.title === README_TITLE && !!m && o.summary === readmeSummary(m[3], m[1], m[2]); }   // the REAL file the PR may change; pairs ONLY with README_REPO
export function importBoundOk(o) { const m = typeof o.summary === 'string' ? PARSE_RE.exec(o.summary) : null; return typeof o.work_id === 'string' && /^autonomy-import-[0-9a-f]{8}$/.test(o.work_id) && o.title === importTitle() && !!m && o.summary === importSummary(m[3], m[1], m[2]); }   // the BOUND import form: repo + PR + base + manifest digest in the signed text
export const FIXED_PATHS = Object.freeze(['dot-probe/readonly-status-check', 'dot-probe/enroll-key-binding', 'dot-probe/claude-resume-readonly', 'dot-probe/flex-readonly-report', 'dot-probe/chief-development-v1', 'dot-probe/chief-recovery-v1', 'dot-probe/c5-keys-check-v1']);
export const MAX_REQUEST_BYTES = 16384;
const MAX_FRAGMENT_RECEIPT_BYTES = 65536;

function bytesToB64u(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// bytes -> same bytes, or null. Strict: size cap, UTF-8 (no BOM), canonical JSON (parse->stringify must reproduce the exact text:
// no whitespace, no duplicate keys, no reordering), fixed repo, exactly one fixed path, no trailing newline.
export function acceptRequestFileBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2 || bytes.length > MAX_REQUEST_BYTES) return null;
  if (bytes[0] !== 0x7b || bytes[bytes.length - 1] !== 0x7d) return null;
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch (e) { return null; }
  let o;
  try { o = JSON.parse(text); } catch (e) { return null; }
  if (!o || typeof o !== 'object' || Array.isArray(o) || JSON.stringify(o) !== text) return null;
  if (typeof o.work_id === 'string' && o.work_id.startsWith(RR_PREFIX)) { try { rrFromRequest(o); return bytes; } catch (e) { return null; } }   // common RR: the whole record is re-derived from the signed summary and must equal every other field
  const isImport = Array.isArray(o.paths) && o.paths.length === IMPORT_PATHS.length && o.paths.every((p, i) => p === IMPORT_PATHS[i]);   // exactly the ONE fixed multi-path request
  if (!Array.isArray(o.paths) || (o.paths.length !== 1 && !isImport)) return null;
  if (isImport) return o.repo === README_REPO && importBoundOk(o) ? bytes : null;
  const okPair = (o.repo === FIXED_REPO && FIXED_PATHS.includes(o.paths[0])) || (o.repo === README_REPO && README_PATHS.includes(o.paths[0]));   // repo/path PAIRS, never a cross product
  if (!okPair) return null;
  if (o.repo === README_REPO && !readmeBoundOk(o)) return null;   // README requests must be the BOUND form (digest in the signed summary); the old unbound form is refused
  return bytes;
}

// fetchFn: the page's fetch. -> { status: 'none' | 'ok' | 'bad', bytes?, reason? }. 404 = nothing pending (not an error).
export async function loadFixedRequest(fetchFn) {
  let res;
  try { res = await fetchFn(REQUEST_FILE, { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' }); } catch (e) { return { status: 'bad', reason: 'fetch failed' }; }
  if (!res) return { status: 'bad', reason: 'no response' };
  if (res.status === 404) return { status: 'none' };
  if (res.status !== 200 || res.redirected === true) return { status: 'bad', reason: 'http ' + res.status };
  const len = Number(res.headers && res.headers.get ? res.headers.get('content-length') || 0 : 0);
  if (len > MAX_REQUEST_BYTES) return { status: 'bad', reason: 'too large' };
  const chunks = []; let total = 0;
  try {
    if (!res.body || !res.body.getReader) return { status: 'bad', reason: 'no body' };
    const reader = res.body.getReader();
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        total += part.value.length;
        if (total > MAX_REQUEST_BYTES) return { status: 'bad', reason: 'too large' };
        chunks.push(part.value);
      }
    } finally { try { await reader.cancel(); } catch (e) { /* already closed */ } }
  } catch (e) { return { status: 'bad', reason: 'read failed' }; }
  const bytes = new Uint8Array(total); let off = 0;
  for (const c of chunks) { bytes.set(c, off); off += c.length; }
  const ok = acceptRequestFileBytes(bytes);
  return ok ? { status: 'ok', bytes: ok } : { status: 'bad', reason: 'not a fixed canonical request' };
}

// #req=<base64url of the exact canonical request bytes> (issued by the owner's private Site /pending page) -> same strict acceptance as the fixed file.
// The fragment never reaches a server. Non-canonical base64url, wrong size, or any strictness failure => null.
export function requestFromFragment(hash) {
  const m = /^#req=([A-Za-z0-9_-]{2,22000})$/.exec(typeof hash === 'string' ? hash : '');
  if (!m || m[1].length % 4 === 1) return null;
  let bin;
  try { bin = atob(m[1].replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (m[1].length % 4)) % 4)); } catch (e) { return null; }
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if (bytesToB64u(bytes) !== m[1]) return null;
  return acceptRequestFileBytes(bytes);
}

// ---- durable pending request (v0.3f) ----
// A request imported from the owner's Site (#req=...) is kept as its EXACT bytes in scoped, non-credential browser storage so a reload / iOS suspension
// restores the SAME target instead of re-fetching the (older) public fixed file. Nothing here touches keys, crypto, core or the network.
export const PENDING_KEY = 'xgate-pending-request/v1';
const PENDING_KEYS = 'v,request_b64u,sha256,saved_ms,source,signed';
const TS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const SKEW_MS = 5 * 60 * 1000;
export function b64uToBytes(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) return null;
  let bin; try { bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)); } catch (e) { return null; }
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return bytesToB64u(bytes) === s ? bytes : null;
}
export function savePendingRequest(storage, bytes, sha256Hex, nowMs, source) {
  if (!storage || !acceptRequestFileBytes(bytes)) return { ok: false, reason: 'not-storable' };
  try { storage.setItem(PENDING_KEY, JSON.stringify({ v: 1, request_b64u: bytesToB64u(bytes), sha256: sha256Hex, saved_ms: nowMs, source, signed: false })); } catch (e) { return { ok: false, reason: 'storage-failed' }; }
  return { ok: true };
}
export function clearPendingRecord(storage) { try { storage && storage.removeItem(PENDING_KEY); return true; } catch (e) { return false; } }
// -> { status: 'none' | 'ok' | 'signed' | 'expired' | 'invalid' | 'storage-unavailable', bytes?, reason? }. Anything doubtful is NOT 'ok'.
export async function readPendingRequest(storage, nowMs, sha256Of) {
  if (!storage) return { status: 'storage-unavailable', reason: 'no storage' };
  let raw; try { raw = storage.getItem(PENDING_KEY); } catch (e) { return { status: 'storage-unavailable', reason: 'read failed' }; }
  if (raw === null || raw === undefined) return { status: 'none' };
  let rec; try { rec = JSON.parse(raw); } catch (e) { return { status: 'invalid', reason: 'not json' }; }
  if (!rec || typeof rec !== 'object' || Array.isArray(rec) || Object.keys(rec).sort().join() !== PENDING_KEYS.split(',').sort().join() || rec.v !== 1) return { status: 'invalid', reason: 'shape' };
  if (!['fragment', 'file'].includes(rec.source) || typeof rec.signed !== 'boolean' || !Number.isFinite(rec.saved_ms) || rec.saved_ms > nowMs + SKEW_MS || typeof rec.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(rec.sha256)) return { status: 'invalid', reason: 'fields' };
  const bytes = b64uToBytes(rec.request_b64u);
  if (!bytes) return { status: 'invalid', reason: 'encoding' };
  if (!acceptRequestFileBytes(bytes)) return { status: 'invalid', reason: 'not a fixed canonical request' };      // strict canonical bytes, fixed repo, allowed path only
  if ((await sha256Of(bytes)) !== rec.sha256) return { status: 'invalid', reason: 'hash mismatch' };
  let q; try { q = JSON.parse(new TextDecoder().decode(bytes)); } catch (e) { return { status: 'invalid', reason: 'json' }; }
  if (!TS.test(q.approve_by) || !TS.test(q.verify_by) || !TS.test(q.created_at)) return { status: 'invalid', reason: 'timestamps' };
  const approveBy = Date.parse(q.approve_by);
  if (rec.signed) return { status: 'signed', bytes };
  if (nowMs >= approveBy) return { status: 'expired', reason: 'approve_by passed', approve_by: q.approve_by };
  return { status: 'ok', bytes, record: rec };
}
// marks the stored record signed ONLY if it still holds exactly these bytes
export function markPendingSigned(storage, bytes) {
  try {
    const raw = storage.getItem(PENDING_KEY); if (!raw) return false;
    const rec = JSON.parse(raw); if (!rec || rec.request_b64u !== bytesToB64u(bytes)) return false;
    rec.signed = true; storage.setItem(PENDING_KEY, JSON.stringify(rec)); return true;
  } catch (e) { return false; }
}

// ---- durable signed receipt (v0.3g) ----
// The EXACT serialized receipt is stored, bound to the exact request bytes it signs, BEFORE any navigation, so a reload / suspension between
// serializeReceipt and the Site ingesting the fragment cannot lose the signature. Redelivery sends the same bytes to the ONE fixed Site URL;
// no new signature, no new nonce, no key material here. A receipt is dropped once its request's approve_by has passed (deadlines are never extended).
export const RECEIPT_KEY = 'xgate-pending-receipt/v1';
export const MAX_RECEIPT_BYTES = MAX_FRAGMENT_RECEIPT_BYTES;
export const MAX_RECEIPT_ITEMS = 3;
export const MAX_AUTO_REDELIVERIES = 5;
const ITEM_KEYS = 'id,request_b64u,receipt_text,receipt_sha256,saved_ms,approve_by_ms,attempts';
// receiptText must be canonical-shaped and its `request` must decode to EXACTLY requestBytes; -> { ok, approveByMs } | { ok:false, reason }
function checkReceiptBinding(requestBytes, receiptText) {
  if (typeof receiptText !== 'string') return { ok: false, reason: 'not-text' };
  const rb = new TextEncoder().encode(receiptText);
  if (rb.length < 2 || rb.length > MAX_RECEIPT_BYTES) return { ok: false, reason: 'size' };
  let r; try { r = JSON.parse(receiptText); } catch (e) { return { ok: false, reason: 'not-json' }; }
  if (!r || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).sort().join() !== 'device,passkey,request,v' || r.v !== 1) return { ok: false, reason: 'shape' };
  const bound = b64uToBytes(r.request);
  if (!bound || bound.length !== requestBytes.length || !bound.every((x, i) => x === requestBytes[i])) return { ok: false, reason: 'request-mismatch' };
  if (!acceptRequestFileBytes(requestBytes)) return { ok: false, reason: 'request-not-allowed' };
  let q; try { q = JSON.parse(new TextDecoder().decode(requestBytes)); } catch (e) { return { ok: false, reason: 'request-json' }; }
  const ap = TS.test(q.approve_by) ? Date.parse(q.approve_by) : NaN;
  if (!Number.isFinite(ap)) return { ok: false, reason: 'request-timestamps' };
  return { ok: true, approveByMs: ap };
}
function readReceiptItems(storage) { // -> array (possibly empty) | null when storage is unusable
  if (!storage) return null;
  let raw; try { raw = storage.getItem(RECEIPT_KEY); } catch (e) { return null; }
  if (raw === null || raw === undefined) return [];
  try { const j = JSON.parse(raw); return j && j.v === 1 && Array.isArray(j.items) ? j.items : []; } catch (e) { return []; }
}
function writeReceiptItems(storage, items) {
  try { if (items.length) storage.setItem(RECEIPT_KEY, JSON.stringify({ v: 1, items })); else storage.removeItem(RECEIPT_KEY); return true; } catch (e) { return false; }
}
// sha256Hex of the receipt text bytes is supplied by the caller (WebCrypto lives in the app). -> { ok } | { ok:false, reason }
export function saveReceipt(storage, requestBytes, receiptText, receiptSha256, nowMs) {
  const b = checkReceiptBinding(requestBytes, receiptText);
  if (!b.ok) return { ok: false, reason: b.reason };
  if (typeof receiptSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(receiptSha256)) return { ok: false, reason: 'hash' };
  const cur = readReceiptItems(storage); if (cur === null) return { ok: false, reason: 'storage-failed' };
  // Bounded outbox, never lossy: expired items can no longer be accepted by the Site and may go; an undelivered signed receipt is NEVER evicted.
  const live = cur.filter((x) => x && Number.isFinite(x.approve_by_ms) && x.approve_by_ms > nowMs);
  if (!live.some((x) => x.id === receiptSha256.slice(0, 16)) && live.length >= MAX_RECEIPT_ITEMS) return { ok: false, reason: 'outbox-full' };
  const item = { id: receiptSha256.slice(0, 16), request_b64u: bytesToB64u(requestBytes), receipt_text: receiptText, receipt_sha256: receiptSha256, saved_ms: nowMs, approve_by_ms: b.approveByMs, attempts: 0 };
  const items = [...live.filter((x) => x.id !== item.id), item];
  return writeReceiptItems(storage, items) ? { ok: true, id: item.id } : { ok: false, reason: 'storage-failed' };
}
// -> { status: 'none'|'ok'|'storage-unavailable', items: [{ id, requestBytes, receiptText, attempts, approveByMs }], dropped: [{ id, reason }] }
// Every item is re-validated (shape, size, hash, binding to its request, allowed path, deadline). Invalid / expired items are dropped from storage, never delivered.
export async function loadReceipts(storage, nowMs, sha256Of) {
  const raw = readReceiptItems(storage); if (raw === null) return { status: 'storage-unavailable', items: [], dropped: [] };
  const keep = [], items = [], dropped = [];
  for (const it of raw) {
    const id = it && typeof it.id === 'string' ? it.id : '?';
    try {
      if (!it || typeof it !== 'object' || Array.isArray(it) || Object.keys(it).sort().join() !== ITEM_KEYS.split(',').sort().join()) { dropped.push({ id, reason: 'shape' }); continue; }
      const requestBytes = b64uToBytes(it.request_b64u); if (!requestBytes) { dropped.push({ id, reason: 'encoding' }); continue; }
      const b = checkReceiptBinding(requestBytes, it.receipt_text); if (!b.ok) { dropped.push({ id, reason: b.reason }); continue; }
      if (typeof it.receipt_sha256 !== 'string' || (await sha256Of(new TextEncoder().encode(it.receipt_text))) !== it.receipt_sha256 || it.id !== it.receipt_sha256.slice(0, 16)) { dropped.push({ id, reason: 'hash-mismatch' }); continue; }
      if (it.approve_by_ms !== b.approveByMs || !Number.isInteger(it.attempts) || it.attempts < 0 || it.attempts > 99 || !Number.isFinite(it.saved_ms) || it.saved_ms > nowMs + SKEW_MS) { dropped.push({ id, reason: 'fields' }); continue; }
      if (nowMs >= b.approveByMs) { dropped.push({ id, reason: 'expired' }); continue; }
      keep.push(it); items.push({ id: it.id, requestBytes, receiptText: it.receipt_text, attempts: it.attempts, approveByMs: b.approveByMs });
    } catch (e) { dropped.push({ id, reason: 'error' }); }
  }
  if (dropped.length) writeReceiptItems(storage, keep);
  return { status: items.length ? 'ok' : 'none', items, dropped };
}
export function noteReceiptAttempt(storage, id) {
  const cur = readReceiptItems(storage); if (cur === null) return false;
  return writeReceiptItems(storage, cur.map((x) => (x && x.id === id ? { ...x, attempts: Math.min(99, (x.attempts | 0) + 1) } : x)));
}
export function clearReceipt(storage, id) { const cur = readReceiptItems(storage); return cur === null ? false : writeReceiptItems(storage, cur.filter((x) => !(x && x.id === id))); }

// ---- web push (candidate) ----
// The server's VAPID public key (applicationServerKey). null = push is inert (no permission request, no service worker). Set ONLY after the approved key generation.
export const VAPID_PUBLIC_B64U = "BI3-cEHkc3796SFQC-NiZ9VYm1JfpP353pB2wWPePHPITrOdcxEl1tbVZrKdcdFVcaSpQNwH8Sj53tZYLn_PXMU";
export const PUSH_ENROLL_URL = SITES_ORIGIN + '/push';
const PUSH_PATH = /^\/[A-Za-z0-9_-]{16,400}$/;
// PushSubscription.toJSON() -> the fixed Site enrollment URL (subscription in the fragment: never sent to a server by the browser), or null. The Site validates again.
export function buildEnrollmentUrl(sub) {
  try {
    if (!sub || typeof sub !== 'object' || Array.isArray(sub)) return null;
    const k = Object.keys(sub).sort().join(); if (k !== 'endpoint,keys' && k !== 'endpoint,expirationTime,keys') return null;
    if (sub.expirationTime !== undefined && sub.expirationTime !== null) return null;
    const u = new URL(sub.endpoint); if (u.protocol !== 'https:' || u.hostname !== 'web.push.apple.com' || u.port || u.username || u.password || u.search || u.hash || !PUSH_PATH.test(u.pathname) || u.href !== sub.endpoint) return null;
    if (!sub.keys || Object.keys(sub.keys).sort().join() !== 'auth,p256dh') return null;
    const p = b64uToBytes(sub.keys.p256dh), a = b64uToBytes(sub.keys.auth); if (!p || p.length !== 65 || p[0] !== 4 || !a || a.length !== 16) return null;
    return PUSH_ENROLL_URL + '#e=' + bytesToB64u(new TextEncoder().encode(JSON.stringify({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } })));
  } catch (e) { return null; }
}
// ?r=<id16>  |  ?n=received|completed&r=<id16>  -> { r, n }  (anything else is ignored: no route)
export function routeFromSearch(search) {
  const m = /^\?r=([0-9a-f]{16})$/.exec(search) || null; if (m) return { r: m[1], n: null };
  const n = /^\?n=(received|completed)&r=([0-9a-f]{16})$/.exec(search); return n ? { r: n[2], n: n[1] } : { r: null, n: null };
}
// a notification-opened URL names the request it is for: the carried bytes must hash to it. No route => nothing to compare.
export function routeMatchesRequest(search, sha256Hex) { const { r } = routeFromSearch(search); return r === null || (typeof sha256Hex === 'string' && sha256Hex.startsWith(r)); }
// message from the service worker (notification tapped while the app is open) -> { ok, kind, id, bytes } ; the id must be the hash of the carried request
export async function verifyOpenMessage(data, sha256Of) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.type !== 'xgate-open' || Object.keys(data).sort().join() !== 'id,kind,req,type') return { ok: false };
  if (!['approve', 'received', 'completed'].includes(data.kind) || typeof data.id !== 'string' || !/^[0-9a-f]{64}$/.test(data.id)) return { ok: false };
  if (data.kind !== 'approve') return data.req === null ? { ok: true, kind: data.kind, id: data.id, bytes: null } : { ok: false };
  const bytes = b64uToBytes(data.req); if (!bytes || !acceptRequestFileBytes(bytes) || (await sha256Of(bytes)) !== data.id) return { ok: false };
  return { ok: true, kind: 'approve', id: data.id, bytes, req: data.req };
}

// receipt text -> the fixed return URL. No other destination can be produced.
export function receiptReturnUrl(receiptText) {
  const bytes = new TextEncoder().encode(receiptText);
  if (bytes.length < 2 || bytes.length > MAX_FRAGMENT_RECEIPT_BYTES) return null;
  return RECEIPT_URL + '#r=' + bytesToB64u(bytes);
}

// ---- tap hand-off record (sw.js -> IndexedDB 'xgate-open' / store 's' / key 'last') ----
// The service worker stores the verified {id, req} of a tapped approve notification. This never signs or stores a request by itself: the app re-checks everything here,
// and loads it through the SAME strict path as a Site #req fragment. A tap is the owner's explicit choice, so a valid unexpired unsigned tapped request wins over the
// displayed / stored / public-file one; it never replaces a signing in progress and never revives an expired or signed one.
export const OPEN_DB = 'xgate-open', OPEN_STORE = 's', OPEN_KEY = 'last';
const OPEN_KEYS = 'id,kind,req,ts,v';
// -> { action: 'load' | 'consume' | 'defer' | 'keep', reason, bytes? }
//   load = show it (caller then deletes the record); consume = drop the record, change nothing; defer = signing in progress, try again later;
//   keep = cannot decide yet (signed-state unreadable): change nothing, keep the record
export async function decideOpenRecord(rec, nowMs, sha256Of, ctx) {
  if (rec === undefined || rec === null) return { action: 'none', reason: 'empty' };
  if (typeof rec !== 'object' || Array.isArray(rec) || Object.keys(rec).sort().join() !== OPEN_KEYS || rec.v !== 1 || rec.kind !== 'approve' || typeof rec.id !== 'string' || !/^[0-9a-f]{64}$/.test(rec.id) || !Number.isFinite(rec.ts) || rec.ts > nowMs + SKEW_MS) return { action: 'consume', reason: 'shape' };
  const bytes = b64uToBytes(rec.req);
  if (!bytes || !acceptRequestFileBytes(bytes)) return { action: 'consume', reason: 'not a fixed canonical request' };
  if ((await sha256Of(bytes)) !== rec.id) return { action: 'consume', reason: 'hash mismatch' };
  let q; try { q = JSON.parse(new TextDecoder().decode(bytes)); } catch (e) { return { action: 'consume', reason: 'json' }; }
  if (!TS.test(q.approve_by)) return { action: 'consume', reason: 'timestamps' };
  if (nowMs >= Date.parse(q.approve_by)) return { action: 'consume', reason: 'expired' };
  if (ctx.busy) return { action: 'defer', reason: 'signing in progress' };
  if (ctx.sameAsCurrent) return { action: 'consume', reason: 'already displayed' };
  if (ctx.signed === 'signed') return { action: 'consume', reason: 'already signed' };
  if (ctx.signed !== 'unsigned') return { action: 'keep', reason: 'signed state unknown' };
  return { action: 'load', reason: 'tapped', bytes };
}
