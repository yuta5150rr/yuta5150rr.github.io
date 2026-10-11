// Candidate: a separate authorization domain; existing PR v1 remains unchanged.
import {
  FormatError, utf8, concatBytes, decodeUtf8Strict, parseStrictJSON,
  parseTimestamp, b64uDecode, validatePathPattern,
} from './core.js';

export const MAX_DISCLOSURE_BYTES = 16384;
export const DISCLOSURE_PREFIX = 'xgate-disclosure/v1\n';
export const DISCLOSURE_DEVICE_PREFIX = 'xgate-disclosure-device/v1\n';
const FIELDS = ['v', 'kind', 'action', 'purpose', 'destination', 'repo', 'work_id',
  'head_sha', 'files', 'payloads', 'title', 'summary', 'created_at', 'approve_by', 'execute_by', 'nonce'];
const HEX64 = /^[a-f0-9]{64}$/;
const HEX40 = /^[a-f0-9]{40}$/;
export function reject(code, detail) { throw new FormatError(code, detail); }
export function exactKeys(o, keys, what) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) reject('SCHEMA', what);
  for (const k of Object.keys(o)) if (!keys.includes(k)) reject('UNKNOWN_FIELD', what + '.' + k);
  for (const k of keys) if (!Object.hasOwn(o, k)) reject('MISSING_FIELD', what + '.' + k);
}
export function parseDisclosureRequest(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_DISCLOSURE_BYTES) reject('REQUEST_SIZE');
  const o = parseStrictJSON(decodeUtf8Strict(bytes), MAX_DISCLOSURE_BYTES);
  exactKeys(o, FIELDS, 'disclosure');
  if (o.v !== 1 || o.kind !== 'external-disclosure' || o.action !== 'disclose'
      || o.purpose !== 'independent-design-code-critic') reject('DISCLOSURE_KIND');
  // A closed destination set. Never accept an AI-supplied callback or arbitrary URL.
  if (o.destination !== 'https://gemini.google.com') reject('DESTINATION');
  if (typeof o.repo !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(o.repo)
      || /\/\.{1,2}$/.test(o.repo)) reject('REPO');
  if (typeof o.work_id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/.test(o.work_id)) reject('WORK_ID');
  if (typeof o.head_sha !== 'string' || !HEX40.test(o.head_sha)) reject('HEAD_SHA');
  if (typeof o.title !== 'string' || [...o.title].length < 1 || [...o.title].length > 120
      || typeof o.summary !== 'string' || [...o.summary].length > 2000) reject('TEXT');
  if (!Array.isArray(o.files) || !o.files.length || o.files.length > 50) reject('FILES');
  const paths = new Set();
  for (const f of o.files) {
    exactKeys(f, ['path', 'sha256'], 'file');
    validatePathPattern(f.path);
    if (f.path.includes('*') || paths.has(f.path)) reject('FILE_PATH');
    paths.add(f.path);
    if (typeof f.sha256 !== 'string' || !HEX64.test(f.sha256)) reject('FILE_HASH');
    Object.freeze(f);
  }
  if (!Array.isArray(o.payloads) || !o.payloads.length || o.payloads.length > 10) reject('PAYLOADS');
  const names = new Set();
  for (const p of o.payloads) {
    exactKeys(p, ['name', 'sha256', 'size'], 'payload');
    if (typeof p.name !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(p.name) || names.has(p.name)) reject('PAYLOAD_NAME');
    names.add(p.name);
    if (typeof p.sha256 !== 'string' || !HEX64.test(p.sha256)) reject('PAYLOAD_HASH');
    if (!Number.isSafeInteger(p.size) || p.size < 1 || p.size > 10485760) reject('PAYLOAD_SIZE');
    Object.freeze(p);
  }
  const created_at_ms = parseTimestamp(o.created_at, 'created_at');
  const approve_by_ms = parseTimestamp(o.approve_by, 'approve_by');
  const execute_by_ms = parseTimestamp(o.execute_by, 'execute_by');
  if (!(created_at_ms < approve_by_ms && approve_by_ms <= execute_by_ms)
      || execute_by_ms - created_at_ms > 86400000) reject('TIME_WINDOW');
  if (typeof o.nonce !== 'string' || b64uDecode(o.nonce, 'nonce').length !== 32) reject('NONCE');
  return Object.freeze({ ...o, files: Object.freeze(o.files), payloads: Object.freeze(o.payloads),
    created_at_ms, approve_by_ms, execute_by_ms });
}
export function disclosureTimeBlock(q, nowMs, receiving = false) {
  if (!Number.isSafeInteger(nowMs) || q.created_at_ms > nowMs + 300000) return 'CLOCK';
  if (nowMs >= q.execute_by_ms) return 'EXECUTION_EXPIRED';
  if (receiving && nowMs >= q.approve_by_ms) return 'APPROVAL_EXPIRED';
  return null;
}
export const disclosureChallengeMessage = (bytes) => concatBytes(utf8(DISCLOSURE_PREFIX), bytes);
export function disclosureDeviceMessage(challenge) {
  if (!(challenge instanceof Uint8Array) || challenge.length !== 32) reject('CHALLENGE');
  return concatBytes(utf8(DISCLOSURE_DEVICE_PREFIX), challenge);
}
// The pinned page operator supplies this same-origin file after independent review.
// null disables all relay networking; request URLs never select an origin.
export function parseRelayConfig(bytes) {
  const o = parseStrictJSON(decodeUtf8Strict(bytes), 2048);
  exactKeys(o, ['v', 'relay_origin'], 'relay-config');
  if (o.v !== 1) reject('CONFIG_VERSION');
  if (o.relay_origin === null) return null;
  if (typeof o.relay_origin !== 'string') reject('CONFIG_ORIGIN');
  const u = new URL(o.relay_origin);
  if (u.protocol !== 'https:' || u.origin !== o.relay_origin || u.username || u.password) reject('CONFIG_ORIGIN');
  return u.origin;
}
export function parseRelayFragment(hash) {
  if (typeof hash !== 'string' || !hash.startsWith('#xgate=')) return null;
  if (!/^#xgate=[a-f0-9]{64}&cap=[A-Za-z0-9_-]{43}$/.test(hash)) reject('RELAY_FRAGMENT');
  const [id, cap] = hash.slice(1).split('&').map(s => s.split('=')[1]);
  if (b64uDecode(cap, 'cap').length !== 32) reject('RELAY_FRAGMENT');
  return Object.freeze({ id, cap });
}
