#!/usr/bin/env node
// gate.mjs - stage 1: checks one pull request and sets the "human-approval" commit status on its head.
// Runs in .github/workflows/human-approval.yml (pull_request_target) from a pinned commit of this
// repository, next to core.js, verify.mjs, pr-check.mjs, keys.json and approver.json of that commit.
// It never fetches or runs pull-request code: the pull request is read as data through the REST API
// with the read-only GITHUB_TOKEN. The status is written only with a short-lived token of the approval
// App named in approver.json, narrowed to statuses:write on this one repository; the gate then tries to
// revoke that token (up to 3 times) and reports a failed revoke as revoke_failed.
// Node >= 20, no npm dependencies.
//
// Environment (set by the workflow): GITHUB_REPOSITORY, PR_NUMBER, HEAD_SHA, GITHUB_TOKEN,
// APPROVER_PRIVATE_KEY; optional GITHUB_SERVER_URL and GITHUB_RUN_ID for the link on the status.
// Exit code: 0 = success set, 1 = failure or error set, 2 = no status could be set,
//            3 = a status was set but the token could not be revoked (revoke_failed).

import { createHash, createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FormatError, b64uEncode, utf8, parseReceipt, parseRequest } from './core.js';
import { buildManifest, manifestDigest } from './manifest.mjs';
import { makeClaimClient, actionsIdToken } from './claim-client.mjs';
import { verifyReceipt } from './verify.mjs';
import {
  STATUS_CONTEXT, MAIN_REF, SHA_RE, REPO_RE, MAX_RECEIPT_BLOB_BYTES,
  parseApprover, checkPullRequest, checkUpToDate, readTree, diffTrees, splitChanges, checkScope,
  checkOtherWorkflows, describeSuccess, describeFailure,
} from './pr-check.mjs';

export class ApiError extends Error {
  constructor(message, status = 0) { super(message); this.name = 'ApiError'; this.code = 'API_ERROR'; this.status = status; }
}

// One line per event, ASCII only, never starting with "::" (a workflow command), so a path taken
// from the pull request cannot inject anything into the job log.
export function logLine(obj) {
  const s = JSON.stringify(obj).replace(/[^\x20-\x7e]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  return 'gate ' + s;
}

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeApi(base, fetchImpl, sleep) {
  return async function api(method, path, token, body) {
    const attempts = method === 'GET' ? 2 : 1;
    for (let k = 1; ; k++) {
      let res;
      try {
        res = await fetchImpl(base + path, {
          method,
          headers: {
            accept: 'application/vnd.github+json',
            authorization: 'Bearer ' + token,
            'x-github-api-version': '2022-11-28',
            'user-agent': 'approval-gate',
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          redirect: 'error',
          signal: AbortSignal.timeout(30000),
        });
      } catch (e) {
        if (k < attempts) { await sleep(2000); continue; }
        throw new ApiError(method + ' ' + path + ': ' + (e && e.name ? e.name : 'network error'));
      }
      const text = await res.text();
      if (res.status >= 500 && k < attempts) { await sleep(2000); continue; }
      if (res.status < 200 || res.status > 299) throw new ApiError(method + ' ' + path + ': HTTP ' + res.status, res.status);
      if (text === '') return null;
      try { return JSON.parse(text); } catch (e) { throw new ApiError(method + ' ' + path + ': not JSON', res.status); }
    }
  };
}

// The bytes of a blob, checked against its git object id (so they are exactly the tree's entry).
const README_REPO = 'yuta5150rr/autonomy-daemon', MAX_CONTENT_BYTES = 1048576;
const README_TITLE = 'リポジトリ ' + README_REPO + ' の README.md だけを変更するPRを、1回だけ承認する（他のファイル・workflow・設定は対象外）';
const PARSE_RE = /対象: .+ のPR#([1-9][0-9]{0,8})（mainのbase SHA ([0-9a-f]{40})）の、.*変更manifest SHA-256 ([0-9a-f]{64}) に一致/;
const readmeSummary = (digest, pr, base) => '許可する操作はこの1件だけ。対象: ' + README_REPO + ' のPR#' + pr + '（mainのbase SHA ' + base + '）の、README.md の内容変更を含むPR（受領書 approvals/<work_id>.json を同じPRに載せる）を、承認ゲートが通してよい。承認する変更内容は、変更manifest SHA-256 ' + digest + ' に一致するものだけ（受領書自身は含まない）。README.md 以外のファイル・.github・approvals 以外の変更、実行、deploy、鍵や権限の変更、公開は許可しない。有効期限内に1つの対象にだけ使える（同じ受領書・同じnonceを別のPRやheadには使えない）。';
const IMPORT_PATHS = Object.freeze(['.gitignore', '.npmrc', 'README.md', 'docs/**', 'package-lock.json', 'package.json', 'src/**', 'test/**', 'tsconfig.json', 'vitest.config.ts', 'wrangler.jsonc']);   // G6: the fixed import request
const importTitle = () => 'リポジトリ ' + README_REPO + ' に、検査済みの取り込み木（src・test・docs・設定ファイル）だけを入れるPRを、1回だけ承認する（.github・workflowは対象外）';
const importSummary = (digest, pr, base) => '許可する操作はこの1件だけ。対象: ' + README_REPO + ' のPR#' + pr + '（mainのbase SHA ' + base + '）の、取り込み木（README.md・.gitignore・.npmrc・package.json・package-lock.json・tsconfig.json・vitest.config.ts・wrangler.jsonc と、docs/・src/・test/ の中身）の追加・変更だけを含むPR（受領書 approvals/<work_id>.json を同じPRに載せる）を、承認ゲートが通してよい。承認する変更内容は、変更manifest SHA-256 ' + digest + ' に一致するものだけ（受領書自身は含まない）。上記以外のファイル・.github・approvals 以外の変更、実行、deploy、鍵や権限の変更、公開は許可しない。有効期限内に1つの対象にだけ使える（同じ受領書・同じnonceを別のPRやheadには使えない）。';
export const bound = { README_TITLE, readmeSummary, PARSE_RE, IMPORT_PATHS, importTitle, importSummary };

// ---- common RR (relay 82 candidate): PR-class form of the SAME request format. Only operation pr_change; everything else is BOUND_FORMAT. Inlined so no trust-root file list changes. ----
const RRC = (() => {
// Common Request Record (RR) <-> the EXISTING signed request format (core.js parseRequest: v,repo,work_id,title,summary,paths,approve_by,verify_by,created_at,nonce).
// Dependency-free (browser + node) so the app's synchronous acceptRequestFileBytes can use it unchanged in spirit. NOTHING new is signed: the device key / passkey sign the SAME challenge over the SAME request bytes as today;
// the RR is carried INSIDE the signed summary, rendered field by field, so one signature covers target / version / operation + exact args / impact / exclusions / rollback / expiry / tier / nonce.
// PR-class scopes: the path patterns a signed pr_change may cover. Data only; the SAME table lives in the trust-root gate (adding a scope = a trust-root update, deliberately).
const PATH_CLASSES = Object.freeze({ readme: Object.freeze(['README.md']), import: Object.freeze(['.gitignore', '.npmrc', 'README.md', 'docs/**', 'package-lock.json', 'package.json', 'src/**', 'test/**', 'tsconfig.json', 'vitest.config.ts', 'wrangler.jsonc']) });
const RR_MAX_REQUEST_BYTES = 4096;   // = the mailbox Worker's MAX_REQ; the largest request any registered operation produces today is 2219 B (test)
const VERIFY_EXTRA_MS = 2 * 3600e3;   // verify_by = expires_at + 2 h (the PR gate may run after the signing window; the signing deadline stays expires_at)
const RR_REPO = 'yuta5150rr/autonomy-daemon', RR_PREFIX = 'xgate-rr-', MAX_SUMMARY = 2000, MAX_TTL_MS = 24 * 3600e3;
const K256 = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function sha256Hex(str) {   // pure JS (sync) so the browser-side acceptance stays synchronous; verified against node:crypto in the tests
  const b = new TextEncoder().encode(str), l = b.length, n = (((l + 9 + 63) >> 6) << 6), m = new Uint8Array(n); m.set(b); m[l] = 0x80; const dv = new DataView(m.buffer); dv.setUint32(n - 4, (l * 8) >>> 0); dv.setUint32(n - 8, Math.floor((l * 8) / 4294967296));
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64), rot = (x, k) => (x >>> k) | (x << (32 - k));
  for (let o = 0; o < n; o += 64) { for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4); for (let i = 16; i < 64; i++) { const s0 = rot(w[i-15],7) ^ rot(w[i-15],18) ^ (w[i-15] >>> 3), s1 = rot(w[i-2],17) ^ rot(w[i-2],19) ^ (w[i-2] >>> 10); w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0; }
    let [a,b2,c,d,e,f,g,h] = H; for (let i = 0; i < 64; i++) { const S1 = rot(e,6) ^ rot(e,11) ^ rot(e,25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0, S0 = rot(a,2) ^ rot(a,13) ^ rot(a,22), mj = (a & b2) ^ (a & c) ^ (b2 & c), t2 = (S0 + mj) >>> 0; h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b2; b2 = a; a = (t1 + t2) >>> 0; }
    H[0]+=a;H[1]+=b2;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h; }
  return [...H].map((x) => x.toString(16).padStart(8, '0')).join('');
}
const sortKeys = (o) => (Array.isArray(o) ? o.map(sortKeys) : o && typeof o === 'object' ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])])) : o);
const canonical = (o) => JSON.stringify(sortKeys(o)), rrId = (rr) => sha256Hex(canonical(rr));
const RR_FIELDS = ['v', 'kind', 'requester', 'executor', 'target', 'base', 'operation', 'impact', 'tier', 'rollback', 'excludes', 'created_at', 'expires_at', 'nonce'];   // the order of the rendered lines
// superset of core.js isForbiddenCodePoint (checked for parity in the tests): such text could not be signed anyway, so it is refused at the RR level with a clear reason.
const forbidden = (cp) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || cp === 0xad || cp === 0x34f || (cp >= 0x590 && cp <= 0x8ff) || cp === 0x115f || cp === 0x1160 || cp === 0x17b4 || cp === 0x17b5 || (cp >= 0x180b && cp <= 0x180f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0x3164 || cp === 0xffa0 || (cp >= 0xd800 && cp <= 0xdfff) || (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xfb1d && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfeff) || (cp >= 0xfff9 && cp <= 0xfffb) || (cp & 0xfffe) === 0xfffe || cp === 0x110bd || cp === 0x110cd || (cp >= 0x10800 && cp <= 0x10fff) || (cp >= 0x13430 && cp <= 0x1343f) || (cp >= 0x1bca0 && cp <= 0x1bca3) || (cp >= 0x1d173 && cp <= 0x1d17a) || (cp >= 0x1e800 && cp <= 0x1efff) || (cp >= 0xe0000 && cp <= 0xe0fff) || cp >= 0xf0000;
const badText = (v) => (typeof v === 'string' ? [...v].some((c) => forbidden(c.codePointAt(0))) : Array.isArray(v) ? v.some(badText) : v && typeof v === 'object' ? Object.entries(v).some(([k, x]) => badText(k) || badText(x)) : false);
const isoRe = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/, plain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
function validateRR(rr) {
  if (!plain(rr)) return 'not an object'; for (const k of Object.keys(rr)) if (!RR_FIELDS.includes(k)) return 'unknown field ' + k; for (const k of RR_FIELDS) if (!(k in rr)) return 'missing ' + k;
  if (rr.v !== 1 || rr.kind !== 'approval-request') return 'version/kind'; if (!['C', 'G'].includes(rr.tier)) return 'tier'; for (const k of ['requester', 'executor']) if (typeof rr[k] !== 'string' || !/^[a-z0-9-]{2,40}$/.test(rr[k])) return k;
  if (!plain(rr.target) || Object.keys(rr.target).sort().join() !== 'ref,system' || typeof rr.target.system !== 'string' || typeof rr.target.ref !== 'string' || !rr.target.system || !rr.target.ref || /[\n\r]/.test(rr.target.system + rr.target.ref)) return 'target';
  if (typeof rr.base !== 'string' || !/^[0-9a-f]{7,64}$|^none$/.test(rr.base)) return 'base';
  if (!plain(rr.operation) || Object.keys(rr.operation).sort().join() !== 'args,type' || typeof rr.operation.type !== 'string' || !/^[a-z_]{3,40}$/.test(rr.operation.type) || !plain(rr.operation.args)) return 'operation';
  if (typeof rr.impact !== 'string' || rr.impact.length < 20 || rr.impact.length > 800 || /[\n\r]/.test(rr.impact)) return 'impact (one line, 20..800)'; if (typeof rr.rollback !== 'string' || rr.rollback.length < 5 || /[\n\r]/.test(rr.rollback)) return 'rollback (one line)';
  if (!Array.isArray(rr.excludes) || rr.excludes.length < 1 || rr.excludes.some((x) => typeof x !== 'string' || !x || /[\n\r]/.test(x))) return 'excludes'; if (typeof rr.nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(rr.nonce)) return 'nonce';
  if (typeof rr.created_at !== 'string' || typeof rr.expires_at !== 'string' || !isoRe.test(rr.created_at) || !isoRe.test(rr.expires_at)) return 'timestamps'; const ttl = Date.parse(rr.expires_at) - Date.parse(rr.created_at); if (!(ttl > 0 && ttl <= MAX_TTL_MS)) return 'ttl (0..24 h)';
  if (rr.operation.type === 'pr_change' && !(Object.hasOwn(PATH_CLASSES, rr.operation.args.scope))) return 'pr_change scope';
  if (badText(rr)) return 'forbidden character (control/invisible/bidi) in a text field';
  return null;
}

// ---- canonical human-readable description: DERIVED from the typed operation, never free text. impact / rollback / excludes of an RR MUST equal it (a mismatch is refused by the Site, the gate, the Mac and the app),
// so the Japanese text the owner reads can never contradict the typed scope/args that the gate enforces. Free text is not accepted for these fields.
const OP_TEXT = Object.freeze({
  pr_change: (rr) => { const a = rr.operation.args; return {
    impact: 'PR #' + a.pr + '（' + a.repo + '）を、main の版 ' + a.base_sha.slice(0, 12) + ' を基準に、変更内容の指紋 ' + a.manifest_digest.slice(0, 16) + ' と範囲「' + a.scope + '」に一致する場合だけ、承認ゲートが通してよい。ゲートは実際の変更を署名内容と照合する。このPRを main に merge すると、現行の仕組みでは deploy.yml が自動で本番へ deploy する。',
    rollback: 'merge 後に戻す場合は、元に戻す新しいPRを作り、同じ承認ゲートで承認する。この承認は PR #' + a.pr + ' に1回だけ使える。',
    excludes: ['他のPR・他の base 版・他の変更内容は承認しない', '範囲外のファイル、.github の workflow、trust root、ruleset、environment、secret は承認しない', 'merge の実行そのものは承認しない（既存の承認ゲートと実行手順が別に行う）'] }; },
  workflow_dispatch: (rr) => { const a = rr.operation.args; return {
    impact: a.repo + ' の ' + a.ref + ' で workflow ' + a.workflow + ' を1回だけ実行する。本番への deploy は行わない（deploy.yml などの保護 workflow は対象外）。',
    rollback: '実行は取り消せない。結果は実行記録（Actions）で確認し、必要なら新しい依頼で別の対処を承認する。',
    excludes: ['他の workflow・他のブランチの実行は承認しない', '2回目以降の実行は承認しない（1回だけ）'] }; },
});
const canonicalText = (rr) => (rr && rr.operation && typeof rr.operation.type === 'string' && Object.hasOwn(OP_TEXT, rr.operation.type) && plain(rr.operation.args) ? OP_TEXT[rr.operation.type](rr) : null);
function textMismatch(rr) { let c; try { c = canonicalText(rr); } catch { c = null; } return !c || rr.impact !== c.impact || rr.rollback !== c.rollback || JSON.stringify(rr.excludes) !== JSON.stringify(c.excludes); }
// The approval screen: rows generated ONLY from the signed RR (every field appears; nothing is cut), Japanese labels. The raw signed summary stays available next to it.
const jst = (iso) => new Date(Date.parse(iso) + 9 * 3600e3).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') + ' JST（' + iso + '）';
function viewRows(rr) {
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
function viewOfRequestBytes(bytes) {   // for the app: null = not a common RR; {error:true} = RR-prefixed but not a valid/canonical RR; {rows, raw, id} otherwise
  let o; try { o = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return null; }
  if (!plain(o) || typeof o.work_id !== 'string' || !o.work_id.startsWith(RR_PREFIX)) return null;
  try { const rr = rrFromRequest(o); return { rows: viewRows(rr), raw: o.summary, id: rrId(rr) }; } catch { return { error: true }; }
}
// The signed summary is ONE line (core.js forbids line separators): INTRO, then `【field】<JSON>` for every RR field in RR_FIELDS order, then `【id】<sha256>`. Injective (JSON values, markers only recognised after a value ended)
// and re-derivable from the RR alone => the verifier/app compare it BYTE FOR BYTE with the rendering of the RR they parsed out of it.
const INTRO = '共通依頼レコード。次の内容だけを1回、承認する（内容が1つでも違えば別の依頼）。';
const renderSummary = (rr) => INTRO + ' ' + RR_FIELDS.map((k) => '【' + k + '】' + JSON.stringify(rr[k])).join(' ') + ' 【id】' + rrId(rr);
function jsonEnd(s, i) {   // index just after the JSON value starting at s[i] (string-aware); throws if none
  const c = s[i]; if (c === '"') { for (let j = i + 1; j < s.length; j++) { if (s[j] === '\\') j++; else if (s[j] === '"') return j + 1; } throw new Error('unterminated string'); }
  if (c === '{' || c === '[') { let d = 0; for (let j = i; j < s.length; j++) { const ch = s[j]; if (ch === '"') j = jsonEnd(s, j) - 1; else if (ch === '{' || ch === '[') d++; else if (ch === '}' || ch === ']') { d--; if (d === 0) return j + 1; } } throw new Error('unterminated'); }
  const m = s.slice(i).match(/^(-?[0-9][0-9.eE+-]*|true|false|null)/); if (!m) throw new Error('no value'); return i + m[0].length;
}
const titleOf = (rr) => ('共通依頼 RR-' + rrId(rr).slice(0, 8) + ' ' + rr.operation.type).slice(0, 120), workIdOf = (rr) => RR_PREFIX + rrId(rr).slice(0, 8);
function rrToRequestObject(rr) {
  const why = validateRR(rr); if (why) throw new Error('RR_INVALID: ' + why); if (textMismatch(rr)) throw new Error('RR_TEXT_MISMATCH'); const summary = renderSummary(rr); if ([...summary].length > MAX_SUMMARY) throw new Error('RR_TOO_LARGE_FOR_SIGNED_SUMMARY');
  const id8 = rrId(rr).slice(0, 8), iso2 = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z'); return { v: 1, repo: RR_REPO, work_id: RR_PREFIX + id8, title: titleOf(rr), summary, paths: rr.operation.type === 'pr_change' ? [...PATH_CLASSES[rr.operation.args.scope]] : ['rr/' + id8], approve_by: rr.expires_at, verify_by: iso2(Date.parse(rr.expires_at) + VERIFY_EXTRA_MS), created_at: rr.created_at, nonce: rr.nonce };
}
const rrToRequestBytes = (rr) => { const t = JSON.stringify(rrToRequestObject(rr)); if (new TextEncoder().encode(t).length > RR_MAX_REQUEST_BYTES) throw new Error('RR_TOO_LARGE'); return t; };   // key order = core.js REQUEST_FIELDS, no whitespace (the app's canonical form)
// request object (already parsed) -> the RR it carries, or throws. Every derived field must equal what the RR dictates; anything else is NOT an RR request.
function rrFromRequest(o) {
  const fail = (c) => { throw new Error('NOT_AN_RR_REQUEST: ' + c); }; if (!plain(o) || typeof o.summary !== 'string') fail('shape'); const t = o.summary, rr = {}; if (!t.startsWith(INTRO + ' ')) fail('intro'); let pos = INTRO.length + 1;
  for (const k of RR_FIELDS) { const m = '【' + k + '】'; if (!t.startsWith(m, pos)) fail('field ' + k); pos += m.length; let end; try { end = jsonEnd(t, pos); rr[k] = JSON.parse(t.slice(pos, end)); } catch { fail('json ' + k); } pos = end; if (t[pos] !== ' ') fail('separator after ' + k); pos++; }
  if (!t.startsWith('【id】', pos)) fail('id marker'); if (validateRR(rr)) fail('rr invalid: ' + validateRR(rr)); if (textMismatch(rr)) fail('description differs from the typed operation'); const bytes = rrToRequestBytes(rr); if (JSON.stringify(o) !== bytes) fail('derived fields differ from the RR (repo/work_id/title/paths/deadlines/nonce/summary)'); return rr;
}

return { RR_PREFIX, PATH_CLASSES, rrFromRequest };
})();
function rrSchemaCheckArgs(spec, args) {
  if (!spec) return 'unsupported operation'; if (!args || typeof args !== 'object' || Array.isArray(args)) return 'args not an object';
  if (Object.keys(args).sort().join() !== Object.keys(spec.fields).sort().join()) return 'args keys differ from the schema';
  for (const [k, f] of Object.entries(spec.fields)) {
    const v = args[k];
    if (f.type === 'enum') { if (!f.values.includes(v)) return 'field ' + k; }
    else if (f.type === 'int') { if (!(Number.isSafeInteger(v) && v >= f.min && v <= f.max)) return 'field ' + k; }
    else if (f.type === 'hex') { if (!(typeof v === 'string' && v.length === f.len && /^[0-9a-f]+$/.test(v))) return 'field ' + k; }
    else return 'field type ' + k;
  }
  return null;
}
function rrSchemaCheckRR(schemas, rr) {
  const spec = Object.hasOwn(schemas, rr.operation.type) ? schemas[rr.operation.type] : null; if (!spec) return 'RR_OP_UNSUPPORTED'; if (!spec.tier.includes(rr.tier)) return 'RR_TIER';
  if (rrSchemaCheckArgs(spec, rr.operation.args)) return 'RR_ARGS_INVALID'; if (rr.target.system !== 'github' || rr.target.ref !== rr.operation.args.repo) return 'RR_TARGET_MISMATCH';
  if (spec.baseArg && rr.base !== rr.operation.args[spec.baseArg]) return 'RR_BASE_MISMATCH'; return null;
}
const RR_SCHEMAS = {"pr_change":{"executor":"gate","tier":["G"],"baseArg":"base_sha","fields":{"repo":{"type":"enum","values":["yuta5150rr/autonomy-daemon"]},"pr":{"type":"int","min":1,"max":999999999},"base_sha":{"type":"hex","len":40},"manifest_digest":{"type":"hex","len":64},"scope":{"type":"enum","values":["readme","import"]}}}};   // PR-class only; adding a scope or an operation here is a trust-root update (protected), on purpose
async function changesDigest(api, cfg, changes, receiptPath) {
  const items = [];
  for (const c of changes) {
    if (c.path === receiptPath) continue;                                                  // the receipt itself is the only excluded entry
    items.push({ path: c.path, before: c.before ? { mode: c.before.mode, bytes: await readBlob(api, cfg.repo, cfg.readToken, c.before, MAX_CONTENT_BYTES, c.path) } : null,
      after: c.after ? { mode: c.after.mode, bytes: await readBlob(api, cfg.repo, cfg.readToken, c.after, MAX_CONTENT_BYTES, c.path) } : null });
  }
  return manifestDigest(buildManifest(items));
}
// The signed RR must name repo + PR number + main base SHA + change-manifest digest + a scope (a path class of the table above); each is compared with the REAL value. The scope's path patterns are the request paths, so the existing checkScope /
// forbidden-path rules judge the real changes exactly as for the README/import forms. An RR of any other operation is NOT a PR approval.
async function rrBoundCheck(api, cfg, rq, requestBytes, changes, receiptPath, mainSha) {
  let rr; try { rr = RRC.rrFromRequest(JSON.parse(new TextDecoder().decode(requestBytes))); } catch (e) { throw new FormatError('BOUND_FORMAT'); }
  if (rr.operation.type !== 'pr_change' || rrSchemaCheckRR(RR_SCHEMAS, rr)) throw new FormatError('BOUND_FORMAT');
  const a = rr.operation.args, same = (x, y) => Array.isArray(x) && x.length === y.length && x.every((p, i) => p === y[i]);
  if (rq.repo !== README_REPO || a.repo !== cfg.repo || rr.target.ref !== cfg.repo || !same(rq.paths, RRC.PATH_CLASSES[a.scope])) throw new FormatError('BOUND_FORMAT');
  if (String(a.pr) !== String(cfg.prNumber)) throw new FormatError('PR_NUMBER_MISMATCH');
  if (a.base_sha !== mainSha) throw new FormatError('BASE_MISMATCH');
  const digest = await changesDigest(api, cfg, changes, receiptPath); if (a.manifest_digest !== digest) throw new FormatError('MANIFEST_MISMATCH');
  return { rq, digest };
}
// The signed text must name repo + PR number + main base SHA + change-manifest digest, all decided BEFORE signing; here each is compared with the REAL value.
async function boundCheck(api, cfg, receiptBytes, changes, receiptPath, mainSha) {
  const rq = parseRequest(parseReceipt(receiptBytes).requestBytes);
  if (typeof rq.work_id === 'string' && rq.work_id.startsWith(RRC.RR_PREFIX)) return rrBoundCheck(api, cfg, rq, parseReceipt(receiptBytes).requestBytes, changes, receiptPath, mainSha);
  const m = typeof rq.summary === 'string' ? PARSE_RE.exec(rq.summary) : null;
  const isImport = typeof rq.work_id === 'string' && /^autonomy-import-[0-9a-f]{8}$/.test(rq.work_id), samePaths = (a, b) => Array.isArray(a) && a.length === b.length && a.every((x, i) => x === b[i]);
  const formOk = !!m && rq.repo === README_REPO && (isImport
    ? rq.title === importTitle() && rq.summary === importSummary(m[3], m[1], m[2]) && samePaths(rq.paths, IMPORT_PATHS)
    : /^autonomy-readme-[0-9a-f]{8}$/.test(rq.work_id) && rq.title === README_TITLE && rq.summary === readmeSummary(m[3], m[1], m[2]) && samePaths(rq.paths, ['README.md']));
  if (!formOk) throw new FormatError('BOUND_FORMAT');   // old unbound form, a mixed form or other paths land here
  if (m[1] !== String(cfg.prNumber)) throw new FormatError('PR_NUMBER_MISMATCH');
  if (m[2] !== mainSha) throw new FormatError('BASE_MISMATCH');
  const items = [];
  for (const c of changes) {
    if (c.path === receiptPath) continue;                                                  // the receipt itself is the only excluded entry
    items.push({ path: c.path, before: c.before ? { mode: c.before.mode, bytes: await readBlob(api, cfg.repo, cfg.readToken, c.before, MAX_CONTENT_BYTES, c.path) } : null,
      after: c.after ? { mode: c.after.mode, bytes: await readBlob(api, cfg.repo, cfg.readToken, c.after, MAX_CONTENT_BYTES, c.path) } : null });
  }
  const digest = manifestDigest(buildManifest(items));
  if (m[3] !== digest) throw new FormatError('MANIFEST_MISMATCH');
  return { rq, digest };
}

async function readBlob(api, repo, token, entry, maxBytes, what) {
  if (entry.size !== null && entry.size > maxBytes) throw new FormatError('TOO_LONG', what);
  const b = await api('GET', '/repos/' + repo + '/git/blobs/' + entry.sha, token);
  if (!b || b.encoding !== 'base64' || typeof b.content !== 'string') throw new ApiError('blob ' + entry.sha + ': encoding');
  const bytes = new Uint8Array(Buffer.from(b.content.replace(/\n/g, ''), 'base64'));
  if (bytes.length > maxBytes) throw new FormatError('TOO_LONG', what);
  const id = createHash('sha1').update('blob ' + bytes.length + '\0').update(bytes).digest('hex');
  if (id !== entry.sha) throw new FormatError('BLOB_MISMATCH', what);
  return bytes;
}

async function readCommitTree(api, repo, token, commitSha) {
  const c = await api('GET', '/repos/' + repo + '/git/commits/' + commitSha, token);
  if (!c || c.sha !== commitSha || !c.tree || !SHA_RE.test(c.tree.sha)) throw new ApiError('commit ' + commitSha);
  return api('GET', '/repos/' + repo + '/git/trees/' + c.tree.sha + '?recursive=1', token);
}

// Every check of design 5, in a fixed order. Throws FormatError (a rule failed) or ApiError.
async function evaluate(api, cfg, approver, nowMs) {
  const { repo, prNumber, headSha, readToken } = cfg;
  const pr = await api('GET', '/repos/' + repo + '/pulls/' + prNumber, readToken);
  checkPullRequest(pr, repo, headSha);                                                       // (a)

  const ref = await api('GET', '/repos/' + repo + '/git/ref/heads/' + MAIN_REF, readToken);
  const mainSha = ref && ref.object && ref.object.type === 'commit' ? ref.object.sha : '';
  if (!SHA_RE.test(mainSha)) throw new ApiError('main ref');
  const cmp = await api('GET', '/repos/' + repo + '/compare/' + mainSha + '...' + headSha + '?per_page=1', readToken);
  checkUpToDate(cmp, mainSha);                                                               // (b)

  const mainTree = readTree(await readCommitTree(api, repo, readToken, mainSha), 'main');   // (i)
  const headTree = readTree(await readCommitTree(api, repo, readToken, headSha), 'head');   // (i)
  const changes = diffTrees(mainTree, headTree);
  const { receipt, paths } = splitChanges(changes, mainTree, headTree); // (b) (h)

  const receiptBytes = await readBlob(api, repo, readToken, receipt.entry, MAX_RECEIPT_BLOB_BYTES, receipt.path);
  const v = verifyReceipt({                                                                  // (c)-(g)
    receiptBytes, keysBytes: cfg.keysBytes, expectedRepo: repo, expectedWorkId: receipt.workId, nowMs,
  });
  checkScope(paths, v.paths);                                                                // (h)
  checkOtherWorkflows(mainTree, approver.otherWorkflows.get(repo));                          // (j)
  const b = await boundCheck(api, cfg, receiptBytes, changes, receipt.path, mainSha);       // NEW: content/PR/base binding against real values
  const pr2 = await api('GET', '/repos/' + repo + '/pulls/' + prNumber, readToken);          // NEW: the head we verified is still the head
  if (!pr2 || !pr2.head || pr2.head.sha !== headSha) throw new FormatError('PR_MOVED');
  const target = { repo, pr: Number(prNumber), base: mainSha, head: headSha, digest: b.digest };
  let claim;
  try { claim = await cfg.store.claim({ nonce: b.rq.nonce, requestHash: v.request_hash, target }); }   // NEW: one-time use, atomic, per nonce AND per request_hash
  catch (e) { if (e && e.name === 'ClaimError' && e.code === 'CLAIM_CONFLICT') throw new FormatError('CLAIM_CONFLICT'); throw e; }   // an unknown/unreachable store (ClaimUnknown, 5xx, timeout) is NOT a conflict: it becomes status error   // other store errors => state 'error' (fail-closed)
  return { mainSha, v, changed: paths.length, receipt: receipt.path, target, claim, requestHash: v.request_hash };
}

export function appJwt(appId, pem, nowSec) {
  const part = (o) => b64uEncode(utf8(JSON.stringify(o)));
  const head = part({ alg: 'RS256', typ: 'JWT' }) + '.' + part({ iat: nowSec - 60, exp: nowSec + 540, iss: appId });
  const key = createPrivateKey({ key: pem, format: 'pem' });
  if (key.asymmetricKeyType !== 'rsa') throw new Error('approval App key is not RSA');
  return head + '.' + b64uEncode(new Uint8Array(cryptoSign('sha256', Buffer.from(head), key)));
}

// The token must carry exactly statuses:write (metadata:read may be listed too) and reach only this
// repository. Returns what is wrong, or null.
export function tokenProblem(t, repo) {
  const perms = t.permissions;
  if (!perms || typeof perms !== 'object' || Array.isArray(perms)) return 'no permissions';
  if (perms.statuses !== 'write') return 'no statuses:write';
  for (const [k, v] of Object.entries(perms)) {
    if (k === 'statuses') continue;
    if (k === 'metadata' && v === 'read') continue;
    return 'extra permission ' + k;
  }
  if (t.repository_selection !== 'selected') return 'repository_selection';
  if (!Array.isArray(t.repositories) || t.repositories.length !== 1 || !t.repositories[0] || t.repositories[0].full_name !== repo) return 'repositories';
  return null;
}

// Sanitized installation facts for the log (names/levels from fixed alphabets only; nothing else of the response is printed).
export function installationFacts(inst) {
  const sel = inst && (inst.repository_selection === 'all' || inst.repository_selection === 'selected') ? inst.repository_selection : '?';
  const perms = {}; const src = inst && inst.permissions && typeof inst.permissions === 'object' && !Array.isArray(inst.permissions) ? inst.permissions : {};
  for (const k of Object.keys(src).sort().slice(0, 30)) if (/^[a-z_]{1,40}$/.test(k)) perms[k] = ['read', 'write', 'admin'].includes(src[k]) ? src[k] : '?';
  return { ok: true, stage: 'installation', repository_selection: sel, permissions: perms, events: Array.isArray(inst && inst.events) ? Math.min(inst.events.length, 99) : '?' };
}

// DELETE /installation/token, up to 3 tries. 204 = revoked; 401 = the token no longer works (expired
// or already revoked). Returns false when neither could be confirmed: that is revoke_failed.
async function revoke(api, token, sleep) {
  for (let k = 1; k <= 3; k++) {
    try { await api('DELETE', '/installation/token', token); return true; } catch (e) {
      if (e instanceof ApiError && e.status === 401) return true;
      if (k < 3) await sleep(1000 * k);
    }
  }
  return false;
}

// A token of the approval App that can only write commit statuses on this one repository.
async function approverToken(api, repo, approver, pem, nowSec, sleep, onInstallation) {
  const [owner, name] = repo.split('/');
  const jwt = appJwt(approver.appId, pem, nowSec);
  const inst = await api('GET', '/repos/' + repo + '/installation', jwt);
  if (!inst || inst.app_id !== approver.appId || !Number.isSafeInteger(inst.id) || !inst.account || inst.account.login !== owner) {
    throw new ApiError('installation of the approval App');
  }
  if (typeof onInstallation === 'function') onInstallation(inst);   // facts the gate already holds; logged sanitized, never used for a decision
  const t = await api('POST', '/app/installations/' + inst.id + '/access_tokens', jwt,
    { repositories: [name], permissions: { statuses: 'write' } });
  if (!t || typeof t.token !== 'string' || t.token.length < 20) throw new ApiError('approval App token');
  const problem = tokenProblem(t, repo);
  if (problem) {
    // a token we will not use is revoked at once rather than left valid until it expires
    const revoked = await revoke(api, t.token, sleep);
    const err = new ApiError('approval App token: ' + problem);
    err.revokeFailed = !revoked;
    throw err;
  }
  return t.token;
}

// cfg: { apiBase, repo, prNumber, headSha, readToken, approverKeyPem, keysBytes, approverBytes,
//        targetUrl?, nowMs(): number, fetch?, log?, sleep? }
export async function runGate(cfg) {
  const log = cfg.log || ((o) => console.log(logLine(o)));
  const sleep = cfg.sleep || realSleep;
  if (typeof cfg.repo !== 'string' || !REPO_RE.test(cfg.repo) || !/^[1-9][0-9]{0,9}$/.test(String(cfg.prNumber)) ||
      typeof cfg.headSha !== 'string' || !SHA_RE.test(cfg.headSha) || !cfg.readToken || !cfg.approverKeyPem || !cfg.store) {
    log({ ok: false, stage: 'input' });
    return 2;
  }
  let approver;
  try { approver = parseApprover(cfg.approverBytes); } catch (e) {
    log({ ok: false, stage: 'approver.json', code: e.code || 'ERROR' });
    return 2;
  }
  const api = makeApi(cfg.apiBase, cfg.fetch || fetch, sleep);
  const nowMs = cfg.nowMs();

  let state;
  let description;
  let ev = null;
  try {
    const r = await evaluate(api, cfg, approver, nowMs); ev = r;
    state = 'success';
    description = describeSuccess(r.v);
    log({ ok: true, work_id: r.v.work_id, request_hash: r.v.request_hash, main: r.mainSha, head: cfg.headSha,
      changed_paths: r.changed, receipt: r.receipt, verify_by: r.v.verify_by,
      passkey_key: r.v.passkey_key, device_key: r.v.device_key });
  } catch (e) {
    const rule = e instanceof FormatError;
    const code = rule ? e.code : (e instanceof ApiError ? 'API_ERROR' : 'INTERNAL');
    state = rule ? 'failure' : 'error';
    description = describeFailure(code);
    log({ ok: false, stage: 'check', code, detail: String(e && e.message ? e.message : e) });
  }

  let token = null;
  let exit = state === 'success' ? 0 : 1;
  try {
    token = await approverToken(api, cfg.repo, approver, cfg.approverKeyPem, Math.floor(cfg.nowMs() / 1000), sleep, (i) => log(installationFacts(i)));
    const body = { state, context: STATUS_CONTEXT, description };
    if (cfg.targetUrl) body.target_url = cfg.targetUrl;
    const readback = async () => { const l = await api('GET', '/repos/' + cfg.repo + '/commits/' + cfg.headSha + '/statuses', token);   // App token: the workflow read token cannot list statuses (403)
      const x = Array.isArray(l) ? l.find((y) => y && y.context === STATUS_CONTEXT) : null; return !!x && x.state === 'success' && x.description === description; };
    if (state === 'success' && ev) {
      // ONE run holds the send right (store.acquireSend is atomic); everyone else only reads the real status back. A send whose outcome is unknown is NEVER re-sent automatically.
      // GitHub statuses have no idempotency key, so exactly-once and automatic recovery cannot both be promised: retry happens ONLY after a failure that PROVES "not sent" (a definite HTTP 4xx); everything else is held for a person.
      const hold = (why) => { throw new ApiError('HELD:' + why); };
      const present = (st, extra) => log({ ok: true, stage: 'status', state, description, note: 'already present', ...extra });
      const seen = async (st) => { if (!(await readback())) return false; if (st === 'status_pending') await cfg.store.confirm(ev.requestHash, ev.target); return true; };
      let mayPost = false;
      if (ev.claim.state === 'confirmed') { if (!(await readback())) hold('CONFIRMED_NOT_VISIBLE'); present(); }
      else if (ev.claim.state === 'claimed' || ev.claim.state === 'send_refused') {
        const a = await cfg.store.acquireSend(ev.requestHash, ev.target); mayPost = a.acquired === true;
        if (!mayPost) { if (await seen(a.state)) present(); else hold(a.state === 'send_refused' ? 'SEND_ATTEMPTS_EXHAUSTED' : 'SEND_RIGHT_HELD_ELSEWHERE'); }
      } else { if (await seen(ev.claim.state)) present(); else hold('SEND_OUTCOME_UNKNOWN'); }   // status_pending left by an earlier run
      if (mayPost) {
        try { await api('POST', '/repos/' + cfg.repo + '/statuses/' + cfg.headSha, token, body); }
        catch (e) { if (e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 408) await cfg.store.markUnsent(ev.requestHash, ev.target); throw e; }   // only a definite 4xx returns the send right
        if (!(await readback())) throw new ApiError('status read-back');   // unknown: stays status_pending, held
        await cfg.store.confirm(ev.requestHash, ev.target);
        log({ ok: true, stage: 'status', state, description });
      }
    } else {
      await api('POST', '/repos/' + cfg.repo + '/statuses/' + cfg.headSha, token, body);
      log({ ok: true, stage: 'status', state, description });
    }
  } catch (e) {
    log({ ok: false, stage: 'status', detail: String(e && e.message ? e.message : e) });
    if (e && e.revokeFailed) log({ ok: false, stage: 'revoke', state: 'revoke_failed' });
    exit = 2;
  }
  if (token) {
    if (await revoke(api, token, sleep)) {
      log({ ok: true, stage: 'revoke' });
    } else {
      log({ ok: false, stage: 'revoke', state: 'revoke_failed' });
      if (exit !== 2) exit = 3;
    }
  }
  return exit;
}

function runUrl(env, repo) {
  if (env.GITHUB_SERVER_URL === 'https://github.com' && /^[0-9]{1,20}$/.test(env.GITHUB_RUN_ID || '') && REPO_RE.test(repo || '')) {
    return 'https://github.com/' + repo + '/actions/runs/' + env.GITHUB_RUN_ID;
  }
  return undefined;
}

async function main() {
  const major = Number(process.versions.node.split('.')[0]);
  if (!(major >= 20)) { console.log(logLine({ ok: false, stage: 'node', version: process.versions.node })); process.exit(2); }
  const env = process.env;
  const readToken = env.GITHUB_TOKEN;
  const approverKeyPem = env.APPROVER_PRIVATE_KEY;
  delete env.GITHUB_TOKEN;
  delete env.APPROVER_PRIVATE_KEY;
  const here = dirname(fileURLToPath(import.meta.url));
  let keysBytes;
  let approverBytes;
  try {
    keysBytes = new Uint8Array(readFileSync(join(here, 'keys.json')));
    approverBytes = new Uint8Array(readFileSync(join(here, 'approver.json')));
  } catch (e) {
    console.log(logLine({ ok: false, stage: 'files', detail: String(e && e.code ? e.code : e) }));
    process.exit(2);
  }
  const endpoint = env.XGATE_CLAIM_ENDPOINT; let store;
  try { store = makeClaimClient({ endpoint, getToken: () => actionsIdToken(env, fetch, 'xgate-claim'), fetch }); } catch (e) { console.log(logLine({ ok: false, stage: 'claim-store', detail: 'CLAIM_ENDPOINT' })); process.exit(2); }   // no endpoint => fail closed
  process.exit(await runGate({
    apiBase: 'https://api.github.com',
    repo: env.GITHUB_REPOSITORY,
    prNumber: env.PR_NUMBER,
    headSha: env.HEAD_SHA,
    readToken,
    approverKeyPem,
    keysBytes,
    approverBytes,
    targetUrl: runUrl(env, env.GITHUB_REPOSITORY),
    nowMs: () => Date.now(),
    store,
  }));
}

let invokedPath = '';
try { invokedPath = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : ''; } catch (e) { invokedPath = ''; }
if (invokedPath === import.meta.url) main();
