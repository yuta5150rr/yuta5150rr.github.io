// Common Request Record (RR) <-> the EXISTING signed request format (core.js parseRequest: v,repo,work_id,title,summary,paths,approve_by,verify_by,created_at,nonce).
// Dependency-free (browser + node) so the app's synchronous acceptRequestFileBytes can use it unchanged in spirit. NOTHING new is signed: the device key / passkey sign the SAME challenge over the SAME request bytes as today;
// the RR is carried INSIDE the signed summary, rendered field by field, so one signature covers target / version / operation + exact args / impact / exclusions / rollback / expiry / tier / nonce.
// PR-class scopes: the path patterns a signed pr_change may cover. Data only; the SAME table lives in the trust-root gate (adding a scope = a trust-root update, deliberately).
export const PATH_CLASSES = Object.freeze({ readme: Object.freeze(['README.md']), import: Object.freeze(['.gitignore', '.npmrc', 'README.md', 'docs/**', 'package-lock.json', 'package.json', 'src/**', 'test/**', 'tsconfig.json', 'vitest.config.ts', 'wrangler.jsonc']) });
export const RR_MAX_REQUEST_BYTES = 4096;   // = the mailbox Worker's MAX_REQ; the largest request any registered operation produces today is 2219 B (test)
export const VERIFY_EXTRA_MS = 2 * 3600e3;   // verify_by = expires_at + 2 h (the PR gate may run after the signing window; the signing deadline stays expires_at)
export const RR_REPO = 'yuta5150rr/autonomy-daemon', RR_PREFIX = 'xgate-rr-', MAX_SUMMARY = 2000, MAX_TTL_MS = 7 * 24 * 3600e3;
const K256 = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
export function sha256Hex(str) {   // pure JS (sync) so the browser-side acceptance stays synchronous; verified against node:crypto in the tests
  const b = new TextEncoder().encode(str), l = b.length, n = (((l + 9 + 63) >> 6) << 6), m = new Uint8Array(n); m.set(b); m[l] = 0x80; const dv = new DataView(m.buffer); dv.setUint32(n - 4, (l * 8) >>> 0); dv.setUint32(n - 8, Math.floor((l * 8) / 4294967296));
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64), rot = (x, k) => (x >>> k) | (x << (32 - k));
  for (let o = 0; o < n; o += 64) { for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4); for (let i = 16; i < 64; i++) { const s0 = rot(w[i-15],7) ^ rot(w[i-15],18) ^ (w[i-15] >>> 3), s1 = rot(w[i-2],17) ^ rot(w[i-2],19) ^ (w[i-2] >>> 10); w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0; }
    let [a,b2,c,d,e,f,g,h] = H; for (let i = 0; i < 64; i++) { const S1 = rot(e,6) ^ rot(e,11) ^ rot(e,25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0, S0 = rot(a,2) ^ rot(a,13) ^ rot(a,22), mj = (a & b2) ^ (a & c) ^ (b2 & c), t2 = (S0 + mj) >>> 0; h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b2; b2 = a; a = (t1 + t2) >>> 0; }
    H[0]+=a;H[1]+=b2;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h; }
  return [...H].map((x) => x.toString(16).padStart(8, '0')).join('');
}
const sortKeys = (o) => (Array.isArray(o) ? o.map(sortKeys) : o && typeof o === 'object' ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])])) : o);
export const canonical = (o) => JSON.stringify(sortKeys(o)), rrId = (rr) => sha256Hex(canonical(rr));
export const RR_FIELDS = ['v', 'kind', 'requester', 'executor', 'target', 'base', 'operation', 'impact', 'tier', 'rollback', 'excludes', 'created_at', 'expires_at', 'nonce'];   // the order of the rendered lines
// superset of core.js isForbiddenCodePoint (checked for parity in the tests): such text could not be signed anyway, so it is refused at the RR level with a clear reason.
export const forbidden = (cp) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || cp === 0xad || cp === 0x34f || (cp >= 0x590 && cp <= 0x8ff) || cp === 0x115f || cp === 0x1160 || cp === 0x17b4 || cp === 0x17b5 || (cp >= 0x180b && cp <= 0x180f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0x3164 || cp === 0xffa0 || (cp >= 0xd800 && cp <= 0xdfff) || (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xfb1d && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfeff) || (cp >= 0xfff9 && cp <= 0xfffb) || (cp & 0xfffe) === 0xfffe || cp === 0x110bd || cp === 0x110cd || (cp >= 0x10800 && cp <= 0x10fff) || (cp >= 0x13430 && cp <= 0x1343f) || (cp >= 0x1bca0 && cp <= 0x1bca3) || (cp >= 0x1d173 && cp <= 0x1d17a) || (cp >= 0x1e800 && cp <= 0x1efff) || (cp >= 0xe0000 && cp <= 0xe0fff) || cp >= 0xf0000;
const badText = (v) => (typeof v === 'string' ? [...v].some((c) => forbidden(c.codePointAt(0))) : Array.isArray(v) ? v.some(badText) : v && typeof v === 'object' ? Object.entries(v).some(([k, x]) => badText(k) || badText(x)) : false);
const isoRe = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/, plain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
export function validateRR(rr) {
  if (!plain(rr)) return 'not an object'; for (const k of Object.keys(rr)) if (!RR_FIELDS.includes(k)) return 'unknown field ' + k; for (const k of RR_FIELDS) if (!(k in rr)) return 'missing ' + k;
  if (rr.v !== 1 || rr.kind !== 'approval-request') return 'version/kind'; if (!['C', 'G'].includes(rr.tier)) return 'tier'; for (const k of ['requester', 'executor']) if (typeof rr[k] !== 'string' || !/^[a-z0-9-]{2,40}$/.test(rr[k])) return k;
  if (!plain(rr.target) || Object.keys(rr.target).sort().join() !== 'ref,system' || typeof rr.target.system !== 'string' || typeof rr.target.ref !== 'string' || !rr.target.system || !rr.target.ref || /[\n\r]/.test(rr.target.system + rr.target.ref)) return 'target';
  if (typeof rr.base !== 'string' || !/^[0-9a-f]{7,64}$|^none$/.test(rr.base)) return 'base';
  if (!plain(rr.operation) || Object.keys(rr.operation).sort().join() !== 'args,type' || typeof rr.operation.type !== 'string' || !/^[a-z_]{3,40}$/.test(rr.operation.type) || !plain(rr.operation.args)) return 'operation';
  if (typeof rr.impact !== 'string' || rr.impact.length < 20 || rr.impact.length > 800 || /[\n\r]/.test(rr.impact)) return 'impact (one line, 20..800)'; if (typeof rr.rollback !== 'string' || rr.rollback.length < 5 || /[\n\r]/.test(rr.rollback)) return 'rollback (one line)';
  if (!Array.isArray(rr.excludes) || rr.excludes.length < 1 || rr.excludes.some((x) => typeof x !== 'string' || !x || /[\n\r]/.test(x))) return 'excludes'; if (typeof rr.nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(rr.nonce)) return 'nonce';
  if (typeof rr.created_at !== 'string' || typeof rr.expires_at !== 'string' || !isoRe.test(rr.created_at) || !isoRe.test(rr.expires_at)) return 'timestamps'; const ttl = Date.parse(rr.expires_at) - Date.parse(rr.created_at); if (!(ttl > 0 && ttl <= MAX_TTL_MS)) return 'ttl (0..7 d)';
  if (rr.operation.type === 'pr_change' && !(Object.hasOwn(PATH_CLASSES, rr.operation.args.scope))) return 'pr_change scope';
  if (badText(rr)) return 'forbidden character (control/invisible/bidi) in a text field';
  return null;
}

// ---- canonical human-readable description: DERIVED from the typed operation, never free text. impact / rollback / excludes of an RR MUST equal it (a mismatch is refused by the Site, the gate, the Mac and the app),
// so the Japanese text the owner reads can never contradict the typed scope/args that the gate enforces. Free text is not accepted for these fields.
export const OP_TEXT = Object.freeze({
  pr_change: (rr) => { const a = rr.operation.args; return {
    impact: 'PR #' + a.pr + '（' + a.repo + '）を、main の版 ' + a.base_sha.slice(0, 12) + ' を基準に、変更内容の指紋 ' + a.manifest_digest.slice(0, 16) + ' と範囲「' + a.scope + '」に一致する場合だけ、承認ゲートが通してよい。ゲートは実際の変更を署名内容と照合する。このPRを main に merge すると、現行の仕組みでは deploy.yml が自動で本番へ deploy する。',
    rollback: 'merge 後に戻す場合は、元に戻す新しいPRを作り、同じ承認ゲートで承認する。この承認は PR #' + a.pr + ' に1回だけ使える。',
    excludes: ['他のPR・他の base 版・他の変更内容は承認しない', '範囲外のファイル、.github の workflow、trust root、ruleset、environment、secret は承認しない', 'merge の実行そのものは承認しない（既存の承認ゲートと実行手順が別に行う）'] }; },
  workflow_dispatch: (rr) => { const a = rr.operation.args; return {
    impact: a.repo + ' の ' + a.ref + ' で workflow ' + a.workflow + ' を1回だけ実行する。本番への deploy は行わない（deploy.yml などの保護 workflow は対象外）。',
    rollback: '実行は取り消せない。結果は実行記録（Actions）で確認し、必要なら新しい依頼で別の対処を承認する。',
    excludes: ['他の workflow・他のブランチの実行は承認しない', '2回目以降の実行は承認しない（1回だけ）'] }; },
});
export const canonicalText = (rr) => (rr && rr.operation && typeof rr.operation.type === 'string' && Object.hasOwn(OP_TEXT, rr.operation.type) && plain(rr.operation.args) ? OP_TEXT[rr.operation.type](rr) : null);
export function textMismatch(rr) { let c; try { c = canonicalText(rr); } catch { c = null; } return !c || rr.impact !== c.impact || rr.rollback !== c.rollback || JSON.stringify(rr.excludes) !== JSON.stringify(c.excludes); }
// The approval screen: rows generated ONLY from the signed RR (every field appears; nothing is cut), Japanese labels. The raw signed summary stays available next to it.
const jst = (iso) => new Date(Date.parse(iso) + 9 * 3600e3).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') + ' JST（' + iso + '）';
export function viewRows(rr) {
  const a = rr.operation.args, id = rrId(rr), pr = rr.operation.type === 'pr_change', rows = [];
  rows.push(['操作', pr ? 'PR の変更を承認する（pr_change）' : rr.operation.type === 'workflow_dispatch' ? 'workflow を1回だけ実行する（workflow_dispatch）' : rr.operation.type]);
  rows.push(['対象リポジトリ', a.repo]);
  if (pr) { rows.push(['対象PR', '#' + a.pr]); rows.push(['基準の main 版（base）', rr.base]); rows.push(['変更内容の指紋（manifest SHA-256）', a.manifest_digest]); rows.push(['変更を許す範囲（scope）', a.scope + '：' + PATH_CLASSES[a.scope].join('、')]); }
  else { rows.push(['実行する workflow', a.workflow]); rows.push(['実行するブランチ', a.ref]); rows.push(['対象の版（base）', rr.base]); }
  rows.push(['公開・本番への副作用', pr ? 'このPRを main に merge すると、現行の仕組みでは deploy.yml が自動で本番へ deploy する（merge の実行は別の手順）' : '本番への deploy は行わない（保護 workflow は対象外）']);
  rows.push(['承認しないもの', rr.excludes.join(' ／ ')]); rows.push(['戻し方', rr.rollback]);
  rows.push(['承認の期限', jst(rr.expires_at)]); rows.push(['検証の期限（署名の後にゲートが読める期限）', jst(new Date(Date.parse(rr.expires_at) + VERIFY_EXTRA_MS).toISOString().replace(/\.\d+Z$/, 'Z'))]);
  rows.push(['依頼者 → 実行者', rr.requester + ' → ' + rr.executor]); rows.push(['承認の重さ（tier）', rr.tier === 'G' ? 'G：保護された変更（署名が必須）' : 'C：保護外の操作']);
  rows.push(['影響の説明（上の項目から自動生成）', rr.impact]); rows.push(['依頼ID（sha256 全体）', id]); rows.push(['nonce', rr.nonce]);
  return rows.map(([label, value]) => ({ label, value }));
}
export function viewOfRequestBytes(bytes) {   // for the app: null = not a common RR; {error:true} = RR-prefixed but not a valid/canonical RR; {rows, raw, id} otherwise
  let o; try { o = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return null; }
  if (!plain(o) || typeof o.work_id !== 'string' || !o.work_id.startsWith(RR_PREFIX)) return null;
  try { const rr = rrFromRequest(o); return { rows: viewRows(rr), raw: o.summary, id: rrId(rr) }; } catch { return { error: true }; }
}
// The signed summary is ONE line (core.js forbids line separators): INTRO, then `【field】<JSON>` for every RR field in RR_FIELDS order, then `【id】<sha256>`. Injective (JSON values, markers only recognised after a value ended)
// and re-derivable from the RR alone => the verifier/app compare it BYTE FOR BYTE with the rendering of the RR they parsed out of it.
export const INTRO = '共通依頼レコード。次の内容だけを1回、承認する（内容が1つでも違えば別の依頼）。';
export const renderSummary = (rr) => INTRO + ' ' + RR_FIELDS.map((k) => '【' + k + '】' + JSON.stringify(rr[k])).join(' ') + ' 【id】' + rrId(rr);
function jsonEnd(s, i) {   // index just after the JSON value starting at s[i] (string-aware); throws if none
  const c = s[i]; if (c === '"') { for (let j = i + 1; j < s.length; j++) { if (s[j] === '\\') j++; else if (s[j] === '"') return j + 1; } throw new Error('unterminated string'); }
  if (c === '{' || c === '[') { let d = 0; for (let j = i; j < s.length; j++) { const ch = s[j]; if (ch === '"') j = jsonEnd(s, j) - 1; else if (ch === '{' || ch === '[') d++; else if (ch === '}' || ch === ']') { d--; if (d === 0) return j + 1; } } throw new Error('unterminated'); }
  const m = s.slice(i).match(/^(-?[0-9][0-9.eE+-]*|true|false|null)/); if (!m) throw new Error('no value'); return i + m[0].length;
}
export const titleOf = (rr) => ('共通依頼 RR-' + rrId(rr).slice(0, 8) + ' ' + rr.operation.type).slice(0, 120), workIdOf = (rr) => RR_PREFIX + rrId(rr).slice(0, 8);
export function rrToRequestObject(rr) {
  const why = validateRR(rr); if (why) throw new Error('RR_INVALID: ' + why); if (textMismatch(rr)) throw new Error('RR_TEXT_MISMATCH'); const summary = renderSummary(rr); if ([...summary].length > MAX_SUMMARY) throw new Error('RR_TOO_LARGE_FOR_SIGNED_SUMMARY');
  const id8 = rrId(rr).slice(0, 8), iso2 = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z'); return { v: 1, repo: RR_REPO, work_id: RR_PREFIX + id8, title: titleOf(rr), summary, paths: rr.operation.type === 'pr_change' ? [...PATH_CLASSES[rr.operation.args.scope]] : ['rr/' + id8], approve_by: rr.expires_at, verify_by: iso2(Date.parse(rr.expires_at) + VERIFY_EXTRA_MS), created_at: rr.created_at, nonce: rr.nonce };
}
export const rrToRequestBytes = (rr) => { const t = JSON.stringify(rrToRequestObject(rr)); if (new TextEncoder().encode(t).length > RR_MAX_REQUEST_BYTES) throw new Error('RR_TOO_LARGE'); return t; };   // key order = core.js REQUEST_FIELDS, no whitespace (the app's canonical form)
// request object (already parsed) -> the RR it carries, or throws. Every derived field must equal what the RR dictates; anything else is NOT an RR request.
export function rrFromRequest(o) {
  const fail = (c) => { throw new Error('NOT_AN_RR_REQUEST: ' + c); }; if (!plain(o) || typeof o.summary !== 'string') fail('shape'); const t = o.summary, rr = {}; if (!t.startsWith(INTRO + ' ')) fail('intro'); let pos = INTRO.length + 1;
  for (const k of RR_FIELDS) { const m = '【' + k + '】'; if (!t.startsWith(m, pos)) fail('field ' + k); pos += m.length; let end; try { end = jsonEnd(t, pos); rr[k] = JSON.parse(t.slice(pos, end)); } catch { fail('json ' + k); } pos = end; if (t[pos] !== ' ') fail('separator after ' + k); pos++; }
  if (!t.startsWith('【id】', pos)) fail('id marker'); if (validateRR(rr)) fail('rr invalid: ' + validateRR(rr)); if (textMismatch(rr)) fail('description differs from the typed operation'); const bytes = rrToRequestBytes(rr); if (JSON.stringify(o) !== bytes) fail('derived fields differ from the RR (repo/work_id/title/paths/deadlines/nonce/summary)'); return rr;
}
