// fragment.js (v0.3c) - pure helpers for the one-request transport. No DOM, no storage, no crypto, no network of its own:
// the caller passes the fetch function and this module only ever hands it ONE fixed same-origin path.
// IN : the exact request bytes the Sites authority issued, placed at ONE fixed same-origin file (public data only: no secret/receipt/token).
// OUT: top-level navigation to ONE fixed Sites page with the receipt in the URL fragment (never sent to a server by the browser).
export const SITES_ORIGIN = 'https://xgate-connector.tainakaritsu903729.chatgpt.site';
export const RECEIPT_URL = SITES_ORIGIN + '/receipt';
export const REQUEST_FILE = 'dotprobe-request.json';
export const FIXED_REPO = 'yuta5150rr/dot-probe';
export const FIXED_PATHS = Object.freeze(['dot-probe/readonly-status-check', 'dot-probe/enroll-key-binding']);
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
  if (o.repo !== FIXED_REPO || !Array.isArray(o.paths) || o.paths.length !== 1 || !FIXED_PATHS.includes(o.paths[0])) return null;
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

// receipt text -> the fixed return URL. No other destination can be produced.
export function receiptReturnUrl(receiptText) {
  const bytes = new TextEncoder().encode(receiptText);
  if (bytes.length < 2 || bytes.length > MAX_FRAGMENT_RECEIPT_BYTES) return null;
  return RECEIPT_URL + '#r=' + bytesToB64u(bytes);
}
