// core.js - shared by the approval page (browser) and verify.mjs (Node >= 18).
// Pure functions only: no DOM, no network, no crypto. Callers do hashing and signatures,
// so the page and every verifier parse the same bytes with the same code.

export const FORMAT_VERSION = 1;
export const RP_ID = 'yuta5150rr.github.io';
export const ORIGIN = 'https://yuta5150rr.github.io';
export const CHALLENGE_PREFIX = 'approval/v1\n';        // challenge = SHA-256(prefix || R)
export const DEVICE_PREFIX = 'approval-device/v1\n';   // device key signs prefix || challenge
export const ALG_ES256 = -7;
export const MAX_APPROVE_WINDOW_MS = 7 * 24 * 3600 * 1000;   // approve_by - created_at
export const MAX_VERIFY_WINDOW_MS = 14 * 24 * 3600 * 1000;   // verify_by - created_at

const MAX_REQUEST_BYTES = 16384;
const MAX_RECEIPT_BYTES = 65536;
const MAX_KEYS_BYTES = 8192;
const MAX_CLIENT_DATA_BYTES = 4096;
const MAX_DEPTH = 8;

export class FormatError extends Error {
  constructor(code, detail) {
    super(detail ? code + ': ' + detail : code);
    this.name = 'FormatError';
    this.code = code;
  }
}
function fail(code, detail) { throw new FormatError(code, detail); }

// ---------- bytes ----------
const encoder = new TextEncoder();
export function utf8(str) { return encoder.encode(str); }

export function decodeUtf8Strict(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('BYTES_EXPECTED');
  try {
    // ignoreBOM:true keeps a leading BOM in the text, so the parser rejects it.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (e) {
    fail('UTF8_INVALID');
  }
}

export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function toHex(bytes) {
  let s = '';
  for (const x of bytes) s += x.toString(16).padStart(2, '0');
  return s;
}

// ---------- base64url (no padding, canonical only) ----------
const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64U_INDEX = (() => {
  const m = new Int16Array(128).fill(-1);
  for (let k = 0; k < 64; k++) m[B64U.charCodeAt(k)] = k;
  return m;
})();

export function b64uEncode(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63] + B64U[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63];
  }
  return out;
}

export function b64uDecode(str, field) {
  if (typeof str !== 'string' || str.length === 0 || str.length % 4 === 1) fail('B64_INVALID', field);
  const out = new Uint8Array(Math.floor((str.length * 3) / 4));
  let o = 0, buf = 0, bits = 0;
  for (let k = 0; k < str.length; k++) {
    const c = str.charCodeAt(k);
    const v = c < 128 ? B64U_INDEX[c] : -1;
    if (v < 0) fail('B64_INVALID', field);
    buf = ((buf << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (buf >> bits) & 0xff; }
  }
  if ((buf & ((1 << bits) - 1)) !== 0) fail('B64_INVALID', field); // non-canonical tail bits
  return out.slice(0, o);
}

// ---------- characters that must never appear in any parsed string ----------
// Controls, invisible/format characters, direction-changing characters and right-to-left
// scripts, line/paragraph separators, lone surrogates, private use, noncharacters.
// An explicit list (not \p{...}) so that Safari and Node give the same answer.
export function isForbiddenCodePoint(cp) {
  return (
    cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0xad || cp === 0x34f ||
    (cp >= 0x590 && cp <= 0x8ff) ||                 // Hebrew, Arabic, Syriac, Thaana, NKo, ... (RTL)
    cp === 0x115f || cp === 0x1160 || cp === 0x17b4 || cp === 0x17b5 ||
    (cp >= 0x180b && cp <= 0x180f) ||
    (cp >= 0x200b && cp <= 0x200f) ||               // zero width, LRM, RLM
    (cp >= 0x2028 && cp <= 0x202e) ||               // line/paragraph separators, bidi embeddings/overrides
    (cp >= 0x2060 && cp <= 0x206f) ||               // word joiner, invisible operators, bidi isolates
    cp === 0x3164 || cp === 0xffa0 ||               // Hangul fillers
    (cp >= 0xd800 && cp <= 0xdfff) ||               // lone surrogates
    (cp >= 0xe000 && cp <= 0xf8ff) ||               // private use
    (cp >= 0xfb1d && cp <= 0xfdff) ||               // Hebrew/Arabic presentation forms (RTL), noncharacters
    (cp >= 0xfe70 && cp <= 0xfeff) ||               // Arabic presentation forms B, BOM
    (cp >= 0xfff9 && cp <= 0xfffb) ||               // interlinear annotation
    (cp & 0xfffe) === 0xfffe ||                     // noncharacters U+xFFFE, U+xFFFF
    cp === 0x110bd || cp === 0x110cd ||
    (cp >= 0x10800 && cp <= 0x10fff) ||             // RTL scripts (SMP)
    (cp >= 0x13430 && cp <= 0x1343f) ||
    (cp >= 0x1bca0 && cp <= 0x1bca3) ||
    (cp >= 0x1d173 && cp <= 0x1d17a) ||
    (cp >= 0x1e800 && cp <= 0x1efff) ||             // RTL scripts (SMP)
    (cp >= 0xe0000 && cp <= 0xe0fff) ||             // tags, variation selectors supplement
    cp >= 0xf0000                                    // supplementary private use
  );
}

function checkText(s) {
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (isForbiddenCodePoint(cp)) fail('FORBIDDEN_CHAR', 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'));
  }
}

function codePointLength(s) {
  let n = 0;
  for (const _ of s) n++; // eslint-disable-line no-unused-vars
  return n;
}

// ---------- strict JSON (RFC 8259 + duplicate keys rejected + forbidden characters rejected) ----------
export function parseStrictJSON(text, maxLength) {
  if (typeof text !== 'string') fail('JSON_TEXT_EXPECTED');
  if (text.length > maxLength) fail('JSON_TOO_LONG');
  const n = text.length;
  let i = 0;
  const numberRe = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

  function ws() {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  }
  function value(depth) {
    if (depth > MAX_DEPTH) fail('JSON_TOO_DEEP');
    ws();
    if (i >= n) fail('JSON_SYNTAX', 'unexpected end');
    const c = text[i];
    if (c === '{') return object(depth);
    if (c === '[') return array(depth);
    if (c === '"') return string();
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    fail('JSON_SYNTAX', 'unexpected character at ' + i);
  }
  function object(depth) {
    i++;
    const obj = Object.create(null);
    const seen = new Set();
    ws();
    if (text[i] === '}') { i++; return obj; }
    for (;;) {
      ws();
      if (text[i] !== '"') fail('JSON_SYNTAX', 'expected key at ' + i);
      const key = string();
      if (seen.has(key)) fail('JSON_DUPLICATE_KEY', key);
      seen.add(key);
      ws();
      if (text[i] !== ':') fail('JSON_SYNTAX', 'expected : at ' + i);
      i++;
      const v = value(depth + 1);
      Object.defineProperty(obj, key, { value: v, enumerable: true, writable: false, configurable: false });
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return obj; }
      fail('JSON_SYNTAX', 'expected , or } at ' + i);
    }
  }
  function array(depth) {
    i++;
    const arr = [];
    ws();
    if (text[i] === ']') { i++; return arr; }
    for (;;) {
      arr.push(value(depth + 1));
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return arr; }
      fail('JSON_SYNTAX', 'expected , or ] at ' + i);
    }
  }
  function string() {
    i++; // opening quote
    let out = '';
    let start = i;
    for (;;) {
      if (i >= n) fail('JSON_SYNTAX', 'unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) { out += text.slice(start, i); i++; break; }
      if (c < 0x20) fail('JSON_SYNTAX', 'raw control character in string');
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        if (e === '"' || e === '\\' || e === '/') { out += e; i += 2; }
        else if (e === 'b') { out += '\b'; i += 2; }
        else if (e === 'f') { out += '\f'; i += 2; }
        else if (e === 'n') { out += '\n'; i += 2; }
        else if (e === 'r') { out += '\r'; i += 2; }
        else if (e === 't') { out += '\t'; i += 2; }
        else if (e === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail('JSON_SYNTAX', 'bad \\u escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
        } else fail('JSON_SYNTAX', 'bad escape');
        start = i;
        continue;
      }
      i++;
    }
    checkText(out); // escapes are decoded first, so "\u202e" is rejected like the raw character
    return out;
  }
  function number() {
    numberRe.lastIndex = i;
    const m = numberRe.exec(text);
    if (!m) fail('JSON_SYNTAX', 'bad number at ' + i);
    i += m[0].length;
    const v = Number(m[0]);
    if (!Number.isFinite(v)) fail('JSON_SYNTAX', 'number out of range');
    return v;
  }

  const result = value(0);
  ws();
  if (i !== n) fail('JSON_SYNTAX', 'trailing characters at ' + i);
  return result;
}

function parseJSONBytes(bytes, maxBytes, what) {
  if (!(bytes instanceof Uint8Array)) fail('BYTES_EXPECTED', what);
  if (bytes.length > maxBytes) fail('TOO_LONG', what);
  return parseStrictJSON(decodeUtf8Strict(bytes), maxBytes);
}

function isObject(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function has(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }

function exactKeys(obj, keys, what) {
  if (!isObject(obj)) fail('SCHEMA', what + ' must be an object');
  for (const k of Object.keys(obj)) if (!keys.includes(k)) fail('UNKNOWN_FIELD', what + '.' + k);
  for (const k of keys) if (!has(obj, k)) fail('MISSING_FIELD', what + '.' + k);
}

// ---------- timestamps: exactly YYYY-MM-DDTHH:MM:SSZ ----------
const TS_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;

export function parseTimestamp(s, field) {
  if (typeof s !== 'string') fail('TIME_FORMAT', field);
  const m = TS_RE.exec(s);
  if (!m) fail('TIME_FORMAT', field);
  const [y, mo, d, h, mi, se] = m.slice(1).map(Number);
  const t = Date.UTC(y, mo - 1, d, h, mi, se);
  const b = new Date(t);
  if (b.getUTCFullYear() !== y || b.getUTCMonth() !== mo - 1 || b.getUTCDate() !== d ||
      b.getUTCHours() !== h || b.getUTCMinutes() !== mi || b.getUTCSeconds() !== se) fail('TIME_FORMAT', field);
  return t;
}

export function formatTimestamp(ms) {
  return new Date(ms).toISOString().replace(/\.[0-9]{3}Z$/, 'Z');
}

// ---------- path globs: only '*' (inside one segment) and '**' (whole segments) ----------
const PATH_PATTERN_RE = /^[A-Za-z0-9._\-/*]+$/;

export function validatePathPattern(p) {
  if (typeof p !== 'string' || p.length < 1 || p.length > 200) fail('PATH_INVALID', 'length');
  if (!PATH_PATTERN_RE.test(p)) fail('PATH_INVALID', 'characters: ' + p);
  const segs = p.split('/');
  for (let k = 0; k < segs.length; k++) {
    const s = segs[k];
    if (s === '') fail('PATH_INVALID', 'empty segment: ' + p);       // leading, trailing or double '/'
    if (s === '.' || s === '..') fail('PATH_INVALID', 'dot segment: ' + p);
    if (s.includes('**') && s !== '**') fail('PATH_INVALID', '** must be a whole segment: ' + p);
    if (s === '**' && k > 0 && segs[k - 1] === '**') fail('PATH_INVALID', 'repeated **: ' + p);
  }
  return segs;
}

// '*' matches any run of characters (possibly empty) within one segment.
export function segmentMatch(pat, s) {
  let p = 0, t = 0, star = -1, mark = 0;
  while (t < s.length) {
    if (p < pat.length && pat[p] !== '*' && pat[p] === s[t]) { p++; t++; }
    else if (p < pat.length && pat[p] === '*') { star = p++; mark = t; }
    else if (star !== -1) { p = star + 1; t = ++mark; }
    else return false;
  }
  while (p < pat.length && pat[p] === '*') p++;
  return p === pat.length;
}

// '**' matches zero or more whole segments, except a trailing '**' matches one or more
// ('src/**' matches files under src/, not a file named 'src').
export function matchGlob(pattern, path) {
  const ps = validatePathPattern(pattern);
  if (typeof path !== 'string' || path.length === 0) return false;
  const ts = path.split('/');
  if (ts.some((s) => s === '')) return false;
  const memo = new Map();
  function m(i, j) {
    const key = i * (ts.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    let r;
    if (i === ps.length) r = j === ts.length;
    else if (ps[i] === '**') {
      r = false;
      for (let k = i === ps.length - 1 ? j + 1 : j; k <= ts.length && !r; k++) r = m(i + 1, k);
    } else r = j < ts.length && segmentMatch(ps[i], ts[j]) && m(i + 1, j + 1);
    memo.set(key, r);
    return r;
  }
  return m(0, 0);
}

export function matchesAny(patterns, path) {
  return patterns.some((p) => matchGlob(p, path));
}

// Fixed forbidden list (compared case-insensitively, so '.GitHub/' on a case-insensitive disk is caught).
// The caller allows exactly one addition under approvals/ (its own receipt); everything else here fails.
const FORBIDDEN_DIRS = ['.github', 'approvals'];
const FORBIDDEN_FILES = ['codeowners', 'docs/codeowners', '.gitmodules'];

export function isForbiddenPath(path) {
  const lower = String(path).toLowerCase();
  if (FORBIDDEN_DIRS.includes(lower.split('/')[0])) return true;
  return FORBIDDEN_FILES.includes(lower);
}

export function isBroadPattern(pattern) {
  return validatePathPattern(pattern).includes('**');
}

// True when some path matched by the pattern is on the forbidden list.
export function patternTouchesForbidden(pattern) {
  const p = pattern.toLowerCase();
  const segs = validatePathPattern(p);
  if (segs[0] === '**') return true;
  for (const d of FORBIDDEN_DIRS) if (segmentMatch(segs[0], d)) return true;
  for (const f of FORBIDDEN_FILES) if (matchGlob(p, f)) return true;
  return false;
}

// ---------- the request R ----------
const REQUEST_FIELDS = ['v', 'repo', 'work_id', 'title', 'summary', 'paths', 'approve_by', 'verify_by', 'created_at', 'nonce'];
const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]{1,100}$/;
const WORK_ID_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22,86}$/;

export function parseRequest(bytes) {
  const o = parseJSONBytes(bytes, MAX_REQUEST_BYTES, 'request');
  exactKeys(o, REQUEST_FIELDS, 'request');
  if (o.v !== FORMAT_VERSION) fail('REQUEST_VERSION');
  if (typeof o.repo !== 'string' || !REPO_RE.test(o.repo) || /\/\.{1,2}$/.test(o.repo)) fail('REPO_INVALID');
  if (typeof o.work_id !== 'string' || !WORK_ID_RE.test(o.work_id)) fail('WORK_ID_INVALID');
  if (typeof o.title !== 'string') fail('TITLE_INVALID');
  const tl = codePointLength(o.title);
  if (tl < 1 || tl > 120) fail('TITLE_INVALID', 'length');
  if (typeof o.summary !== 'string' || codePointLength(o.summary) > 2000) fail('SUMMARY_INVALID');
  if (!Array.isArray(o.paths) || o.paths.length < 1 || o.paths.length > 50) fail('PATHS_INVALID');
  const seen = new Set();
  for (const p of o.paths) {
    if (typeof p !== 'string') fail('PATH_INVALID', 'not a string');
    validatePathPattern(p);
    if (seen.has(p)) fail('PATH_INVALID', 'duplicate: ' + p);
    seen.add(p);
  }
  const created = parseTimestamp(o.created_at, 'created_at');
  const approveBy = parseTimestamp(o.approve_by, 'approve_by');
  const verifyBy = parseTimestamp(o.verify_by, 'verify_by');
  if (!(created < approveBy && approveBy <= verifyBy)) fail('TIME_ORDER');
  if (approveBy - created > MAX_APPROVE_WINDOW_MS) fail('TIME_WINDOW', 'approve_by');
  if (verifyBy - created > MAX_VERIFY_WINDOW_MS) fail('TIME_WINDOW', 'verify_by');
  if (typeof o.nonce !== 'string' || !NONCE_RE.test(o.nonce)) fail('NONCE_INVALID');
  return Object.freeze({
    v: o.v, repo: o.repo, work_id: o.work_id, title: o.title, summary: o.summary,
    paths: Object.freeze([...o.paths]),
    approve_by: o.approve_by, verify_by: o.verify_by, created_at: o.created_at,
    approve_by_ms: approveBy, verify_by_ms: verifyBy, created_at_ms: created,
    nonce: o.nonce,
  });
}

export function challengeMessage(requestBytes) {
  return concatBytes(utf8(CHALLENGE_PREFIX), requestBytes);
}

export function deviceMessage(challenge) {
  if (!(challenge instanceof Uint8Array) || challenge.length !== 32) fail('CHALLENGE_LENGTH');
  return concatBytes(utf8(DEVICE_PREFIX), challenge);
}

// ---------- WebAuthn pieces checked the same way on the page and in the verifier ----------
export function checkClientData(clientDataJSON, expectedChallenge) {
  const cd = parseJSONBytes(clientDataJSON, MAX_CLIENT_DATA_BYTES, 'clientDataJSON'); // unknown keys allowed (browsers add some)
  if (!isObject(cd)) fail('CLIENT_DATA_INVALID');
  if (cd.type !== 'webauthn.get') fail('CLIENT_TYPE');
  if (cd.challenge !== b64uEncode(expectedChallenge)) fail('CLIENT_CHALLENGE');
  if (cd.origin !== ORIGIN) fail('CLIENT_ORIGIN');
  if (has(cd, 'crossOrigin') && cd.crossOrigin !== false) fail('CLIENT_CROSS_ORIGIN');
  if (has(cd, 'topOrigin')) fail('CLIENT_TOP_ORIGIN');
}

export function checkAuthenticatorData(ad, rpIdHash) {
  if (!(ad instanceof Uint8Array) || ad.length !== 37) fail('AUTHDATA_LENGTH');
  if (!bytesEqual(ad.subarray(0, 32), rpIdHash)) fail('AUTHDATA_RP_ID');
  const flags = ad[32];
  if (!(flags & 0x01)) fail('AUTHDATA_UP');
  if (!(flags & 0x04)) fail('AUTHDATA_UV');
  if (flags & 0x40) fail('AUTHDATA_AT');
  if (flags & 0x80) fail('AUTHDATA_ED');
}

// ---------- keys.json ----------
// DER prefix of a P-256 public key in SubjectPublicKeyInfo form (uncompressed point follows).
const P256_SPKI_PREFIX = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04];

export function isP256Spki(b) {
  if (!(b instanceof Uint8Array) || b.length !== 91) return false;
  for (let k = 0; k < P256_SPKI_PREFIX.length; k++) if (b[k] !== P256_SPKI_PREFIX[k]) return false;
  return true;
}

export function serializeKeys({ credentialId, passkeyPublicKey, devicePublicKey, createdAtMs }) {
  const obj = {
    v: FORMAT_VERSION,
    rp_id: RP_ID,
    passkey: { credential_id: b64uEncode(credentialId), public_key: b64uEncode(passkeyPublicKey), alg: ALG_ES256 },
    device: { public_key: b64uEncode(devicePublicKey), alg: 'ES256' },
    created_at: formatTimestamp(createdAtMs),
  };
  const text = JSON.stringify(obj, null, 2) + '\n';
  parseKeys(utf8(text)); // never emit something the verifier would reject
  return text;
}

export function parseKeys(bytes) {
  const o = parseJSONBytes(bytes, MAX_KEYS_BYTES, 'keys');
  exactKeys(o, ['v', 'rp_id', 'passkey', 'device', 'created_at'], 'keys');
  if (o.v !== FORMAT_VERSION) fail('KEYS_VERSION');
  if (o.rp_id !== RP_ID) fail('KEYS_RP_ID');
  exactKeys(o.passkey, ['credential_id', 'public_key', 'alg'], 'keys.passkey');
  exactKeys(o.device, ['public_key', 'alg'], 'keys.device');
  if (o.passkey.alg !== ALG_ES256 || o.device.alg !== 'ES256') fail('KEYS_ALG');
  const credentialId = b64uDecode(o.passkey.credential_id, 'keys.passkey.credential_id');
  if (credentialId.length < 16 || credentialId.length > 1023) fail('KEYS_CREDENTIAL_ID');
  const passkeyPublicKey = b64uDecode(o.passkey.public_key, 'keys.passkey.public_key');
  const devicePublicKey = b64uDecode(o.device.public_key, 'keys.device.public_key');
  if (!isP256Spki(passkeyPublicKey) || !isP256Spki(devicePublicKey)) fail('KEYS_PUBLIC_KEY');
  if (bytesEqual(passkeyPublicKey, devicePublicKey)) fail('KEYS_PUBLIC_KEY', 'passkey and device key must differ');
  const createdAtMs = parseTimestamp(o.created_at, 'keys.created_at');
  return { credentialId, passkeyPublicKey, devicePublicKey, createdAtMs };
}

// ---------- receipt (approvals/<work_id>.json in the next stage) ----------
export function serializeReceipt({ requestBytes, credentialId, authenticatorData, clientDataJSON, passkeySignature, deviceSignature }) {
  const obj = {
    v: FORMAT_VERSION,
    request: b64uEncode(requestBytes),
    passkey: {
      credential_id: b64uEncode(credentialId),
      authenticator_data: b64uEncode(authenticatorData),
      client_data_json: b64uEncode(clientDataJSON),
      signature: b64uEncode(passkeySignature),
    },
    device: { signature: b64uEncode(deviceSignature) },
  };
  const text = JSON.stringify(obj, null, 2) + '\n';
  parseReceipt(utf8(text));
  return text;
}

export function parseReceipt(bytes) {
  const o = parseJSONBytes(bytes, MAX_RECEIPT_BYTES, 'receipt');
  exactKeys(o, ['v', 'request', 'passkey', 'device'], 'receipt');
  if (o.v !== FORMAT_VERSION) fail('RECEIPT_VERSION');
  exactKeys(o.passkey, ['credential_id', 'authenticator_data', 'client_data_json', 'signature'], 'receipt.passkey');
  exactKeys(o.device, ['signature'], 'receipt.device');
  const r = {
    requestBytes: b64uDecode(o.request, 'receipt.request'),
    credentialId: b64uDecode(o.passkey.credential_id, 'receipt.passkey.credential_id'),
    authenticatorData: b64uDecode(o.passkey.authenticator_data, 'receipt.passkey.authenticator_data'),
    clientDataJSON: b64uDecode(o.passkey.client_data_json, 'receipt.passkey.client_data_json'),
    passkeySignature: b64uDecode(o.passkey.signature, 'receipt.passkey.signature'),
    deviceSignature: b64uDecode(o.device.signature, 'receipt.device.signature'),
  };
  if (r.requestBytes.length > MAX_REQUEST_BYTES) fail('TOO_LONG', 'receipt.request');
  if (r.passkeySignature.length < 8 || r.passkeySignature.length > 72) fail('PASSKEY_SIGNATURE_FORMAT');
  if (r.deviceSignature.length !== 64) fail('DEVICE_SIGNATURE_FORMAT');
  return r;
}
