#!/usr/bin/env node
// deploy.mjs - deploys one Worker version to Cloudflare from the deploy job (job 2) of a repository's
// .github/workflows/deploy.yml. Design: x-gate "autonomy-daemon deploy gate" spec v0.3.1, section 4.3 (D5-D11)
// and section 4.4. Runs from a pinned commit of this repository (TRUST_SHA), next to core.js and the deploy
// manifests (deploy-<name>.json) of that commit. Node >= 20, no npm dependencies (Node built-ins, fetch
// and core.js of the same commit).
//
//   node <trust>/deploy.mjs <name> <bundle-dir>
//     <name>        selects deploy-<name>.json next to this file ([a-z0-9-], a literal in deploy.yml)
//     <bundle-dir>  a fresh, empty-before-download directory holding the artifact of job 1
//                   (one path segment relative to the working directory, a literal in deploy.yml)
//
// Environment (GitHub Actions): GITHUB_SHA, GITHUB_REF, GITHUB_EVENT_NAME, GITHUB_REPOSITORY,
// GITHUB_TOKEN (job 2's token, contents: read; used only to read the main ref = D11, only sent to
// api.github.com) and CLOUDFLARE_API_TOKEN (environment production; only sent to api.cloudflare.com).
// Both tokens are removed from process.env as soon as they are read.
//
// Steps; the first failure stops the run and nothing after it happens:
//   1 environment: a push to refs/heads/main, GITHUB_SHA is 40 hex                                  (D7)
//   2 manifest: strict JSON (core.js), exact fields; GITHUB_REPOSITORY must be the manifest's repo   (4.4)
//   3 input: exactly worker.js and build.json, both regular files (no symlink, no directory), size
//     limits, strict build.json whose size and sha256 match the bytes. worker.js is only read as
//     bytes and sent as one multipart part; it is never parsed, imported, evaluated or executed     (D6 D8 D9)
//   4 main HEAD == GITHUB_SHA, else stop (a newer run deploys the newer commit)                      (D11)
//   5 Version Upload (POST .../workers/scripts/<script>/versions?bindings_inherit=strict): bindings
//     exactly as the manifest, each secret inherited by name; annotations: workers/tag = GITHUB_SHA,
//     workers/message = "sha256:" + the hex SHA-256 of the uploaded bytes
//   6 read the version back before deploying it, through two documented GET endpoints, each checked
//     against the version id:
//       Scripts Version GET (.../workers/scripts/<script>/versions/<id>): resources.bindings and
//         resources.script_runtime compatibility (its documented result has no annotations)
//       Workers Version GET (.../workers/workers/<script>/versions/<id>): annotations, main_module,
//         compatibility and bindings
//   7 main HEAD == GITHUB_SHA, else stop before deploying                                           (D11)
//   8 Create Deployment: that version at 100 %, no force
//   9 read back: the first deployment (the one serving traffic) is this one, this version at 100 %
//  10 main HEAD == GITHUB_SHA after the deploy, else log "deployed commit is no longer the head of
//     main" and fail (a later run deploys the newer commit)                                         (D11)
// The race between step 7 and the deployment being created is outside the guarantee (spec D11).
// The sha256 match proves only that job 2 sends the bytes job 1 described (transfer integrity, D9),
// not that the bytes are correct or come from a trusted build.
//
// Exit code: 0 = deployed and read back, main unchanged
//            1 = stopped before the Create Deployment request was sent: this run deployed nothing
//                (a stale run may leave one uploaded, undeployed version; that is harmless)
//            2 = the run did not succeed, and the Create Deployment request was sent or it cannot be
//                ruled out (only an unexpected crash outside the stages, logged as stage "crash")
// The final log line always says what is known about the deployment ("deployment"): "none" (exit 1);
// "refused" = what was seen: Cloudflare answered the request with a 4xx and its error envelope (this
// is not proof that no deployment was made); "unknown" = no usable answer, a deployment may exist;
// "created" = the deployment exists (exit 0, or exit 2 when a later check failed). The request is
// never sent twice. After any exit 2 the final log line also says "before_rerun": read the
// deployments list (dashboard or API) before running again.

import { createHash } from 'node:crypto';
import { constants as FS, readFileSync, realpathSync } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FormatError, decodeUtf8Strict, parseStrictJSON } from './core.js';

export const CF_API = 'https://api.cloudflare.com/client/v4';
export const GH_API = 'https://api.github.com';
export const BUNDLE_FILE = 'worker.js';
export const BUILD_FILE = 'build.json';
export const MAX_MANIFEST_BYTES = 16384;
export const MAX_BUILD_JSON_BYTES = 1024;
export const MAX_BUNDLE_LIMIT = 64 * 1024 * 1024;
const UPLOAD_TIMEOUT_MS = 120000;
const API_TIMEOUT_MS = 30000;

const SHA_RE = /^[0-9a-f]{40}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]{1,100}$/;
const ACCOUNT_RE = /^[0-9a-f]{32}$/;
const SCRIPT_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const MODULE_RE = /^[A-Za-z0-9_-]{1,64}\.js$/;
const DATE_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;
const FLAG_RE = /^[a-z0-9_]{1,64}$/;
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOKEN_RE = /^[\x21-\x7e]{20,1000}$/;
export const MANIFEST_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
export const DIR_ARG_RE = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$/;
const MAX_LIST = 32;
const MAX_TEXT = 1024;

const MANIFEST_FIELDS = ['v', 'repo', 'account_id', 'script_name', 'main_module', 'compatibility_date',
  'compatibility_flags', 'bindings', 'inherit_secrets', 'max_bundle_bytes'];
const BUILD_FIELDS = ['v', 'file', 'size', 'sha256'];

export class DeployError extends Error {
  constructor(code, detail) { super(detail ? code + ': ' + detail : code); this.name = 'DeployError'; this.code = code; }
}
function fail(code, detail) { throw new DeployError(code, detail); }

// An API call that did not succeed. `refusal` is true only when Cloudflare answered with a 4xx and its
// error envelope (success: false). It records what was seen; it does not prove that the request had no
// effect. Anything else (no answer, a 5xx, a 4xx without the envelope, a 2xx without success: true)
// says even less: the request may have been applied.
export class ApiError extends Error {
  constructor(message, status, refusal) {
    super(message); this.name = 'ApiError'; this.code = 'API_ERROR'; this.status = status; this.refusal = refusal;
  }
}

// What the final log line says after any exit 2 (the run itself never sends the request again).
const BEFORE_RERUN = 'read the deployments list (dashboard or API) before running again';

// One line per event, ASCII only, never starting with "::" (a workflow command).
export function logLine(obj) {
  const s = JSON.stringify(obj).replace(/[^\x20-\x7e]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  return 'deploy ' + s;
}

function isObject(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function has(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
function exactKeys(obj, keys, code, what) {
  if (!isObject(obj)) fail(code, what + ' must be an object');
  for (const k of Object.keys(obj)) if (!keys.includes(k)) fail(code, 'unknown field ' + what + '.' + k);
  for (const k of keys) if (!has(obj, k)) fail(code, 'missing field ' + what + '.' + k);
}
function strict(bytes, maxBytes, code) {
  try {
    return parseStrictJSON(decodeUtf8Strict(bytes), maxBytes);
  } catch (e) {
    if (e instanceof FormatError) fail(code, e.message);
    throw e;
  }
}
function validDate(s) {
  const m = DATE_RE.exec(s);
  if (!m) return false;
  const y = Number(m[1]); const mo = Number(m[2]); const d = Number(m[3]);
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

// ---------- 1 environment (D7) ----------
export function checkEnv(env) {
  const sha = env.GITHUB_SHA;
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) fail('ENV', 'GITHUB_SHA');
  if (env.GITHUB_EVENT_NAME !== 'push') fail('ENV', 'GITHUB_EVENT_NAME');
  if (env.GITHUB_REF !== 'refs/heads/main') fail('ENV', 'GITHUB_REF');
  if (typeof env.GITHUB_REPOSITORY !== 'string' || !REPO_RE.test(env.GITHUB_REPOSITORY)) fail('ENV', 'GITHUB_REPOSITORY');
  return { sha, repo: env.GITHUB_REPOSITORY };
}

export function checkTokens(cfToken, ghToken) {
  if (typeof cfToken !== 'string' || !TOKEN_RE.test(cfToken)) fail('ENV', 'CLOUDFLARE_API_TOKEN');
  if (typeof ghToken !== 'string' || !TOKEN_RE.test(ghToken)) fail('ENV', 'GITHUB_TOKEN');
}

// ---------- 2 manifest (section 4.4) ----------
export function parseManifest(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('MANIFEST', 'bytes expected');
  if (bytes.length > MAX_MANIFEST_BYTES) fail('MANIFEST', 'too large');
  const m = strict(bytes, MAX_MANIFEST_BYTES, 'MANIFEST');
  exactKeys(m, MANIFEST_FIELDS, 'MANIFEST', 'manifest');
  if (m.v !== 1) fail('MANIFEST', 'v');
  const text = (x, re, field) => { if (typeof x !== 'string' || !re.test(x)) fail('MANIFEST', field); return x; };
  const list = (x, field) => { if (!Array.isArray(x) || x.length > MAX_LIST) fail('MANIFEST', field); return x; };
  const repo = text(m.repo, REPO_RE, 'repo');
  const accountId = text(m.account_id, ACCOUNT_RE, 'account_id');
  const scriptName = text(m.script_name, SCRIPT_RE, 'script_name');
  const mainModule = text(m.main_module, MODULE_RE, 'main_module');
  const compatibilityDate = text(m.compatibility_date, DATE_RE, 'compatibility_date');
  if (!validDate(compatibilityDate)) fail('MANIFEST', 'compatibility_date');
  const compatibilityFlags = list(m.compatibility_flags, 'compatibility_flags').map((f) => text(f, FLAG_RE, 'compatibility_flags'));
  if (new Set(compatibilityFlags).size !== compatibilityFlags.length) fail('MANIFEST', 'compatibility_flags repeated');
  const names = new Set();
  const named = (n, field) => {
    text(n, NAME_RE, field);
    if (names.has(n)) fail('MANIFEST', 'binding name repeated: ' + n);
    names.add(n);
    return n;
  };
  const bindings = list(m.bindings, 'bindings').map((b) => {
    if (!isObject(b)) fail('MANIFEST', 'bindings[] must be objects');
    if (b.type === 'd1') {
      exactKeys(b, ['type', 'name', 'id'], 'MANIFEST', 'bindings[]');
      return Object.freeze({ type: 'd1', name: named(b.name, 'bindings[].name'), id: text(b.id, UUID_RE, 'bindings[].id') });
    }
    if (b.type === 'plain_text') {
      exactKeys(b, ['type', 'name', 'text'], 'MANIFEST', 'bindings[]');
      if (typeof b.text !== 'string' || b.text.length > MAX_TEXT) fail('MANIFEST', 'bindings[].text');
      return Object.freeze({ type: 'plain_text', name: named(b.name, 'bindings[].name'), text: b.text });
    }
    return fail('MANIFEST', 'bindings[].type');
  });
  const inheritSecrets = list(m.inherit_secrets, 'inherit_secrets').map((n) => named(n, 'inherit_secrets'));
  const maxBundleBytes = m.max_bundle_bytes;
  if (!Number.isSafeInteger(maxBundleBytes) || maxBundleBytes < 1 || maxBundleBytes > MAX_BUNDLE_LIMIT) fail('MANIFEST', 'max_bundle_bytes');
  return Object.freeze({
    repo, accountId, scriptName, mainModule, compatibilityDate,
    compatibilityFlags: Object.freeze(compatibilityFlags),
    bindings: Object.freeze(bindings),
    inheritSecrets: Object.freeze(inheritSecrets),
    maxBundleBytes,
  });
}

// ---------- 3 input (D6 D8 D9) ----------
// The file's identity, size and change times (bigint stat: nanoseconds), before and after reading.
function fileState(st) {
  return [st.dev, st.ino, st.size, st.mtimeNs, st.ctimeNs].join(':');
}

// Reads one regular file without following a symlink, through the opened descriptor only (no
// check-then-open race), and rejects a file that is larger than maxBytes or that changes while being
// read: fewer bytes than its size, more bytes after the end, or a different identity, size, mtime or
// ctime between the stat before and the stat after the read. The kernel sets those times with a coarse
// clock (a few milliseconds), so a same-size rewrite within one tick can keep both times and is not
// detected. That cannot make the upload differ from the hash: the bytes sent are exactly the bytes that
// were read and hashed, and they must match build.json; job 2 runs no other process that writes there.
// `openFile` is fs.promises.open; the tests pass a stand-in that changes the state mid-read.
async function readRegular(path, maxBytes, what, openFile = open) {
  let fh;
  try {
    fh = await openFile(path, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK);
  } catch (e) {
    return fail('INPUT', what + ': cannot open (' + (e && e.code ? e.code : 'error') + ')');
  }
  try {
    const before = await fh.stat({ bigint: true });
    if (!before.isFile()) fail('INPUT', what + ': not a regular file');
    if (before.size > BigInt(maxBytes)) fail('INPUT', what + ': larger than ' + maxBytes + ' bytes');
    const size = Number(before.size);
    const buf = Buffer.alloc(size);
    let off = 0;
    while (off < size) {
      const { bytesRead } = await fh.read(buf, off, size - off, off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    if (off !== size) fail('INPUT', what + ': changed while reading');
    const more = await fh.read(Buffer.alloc(1), 0, 1, size);
    if (more.bytesRead !== 0) fail('INPUT', what + ': changed while reading');
    const after = await fh.stat({ bigint: true });
    if (fileState(after) !== fileState(before)) fail('INPUT', what + ': changed while reading');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
  } finally {
    await fh.close();
  }
}

export function checkBuildJson(bytes, size, sha256) {
  const b = strict(bytes, MAX_BUILD_JSON_BYTES, 'BUILD_JSON');
  exactKeys(b, BUILD_FIELDS, 'BUILD_JSON', 'build.json');
  if (b.v !== 1) fail('BUILD_JSON', 'v');
  if (b.file !== BUNDLE_FILE) fail('BUILD_JSON', 'file');
  if (!Number.isSafeInteger(b.size) || b.size !== size) fail('BUILD_JSON', 'size does not match worker.js');
  if (typeof b.sha256 !== 'string' || !HEX64_RE.test(b.sha256)) fail('BUILD_JSON', 'sha256 format');
  if (b.sha256 !== sha256) fail('BUILD_JSON', 'sha256 does not match worker.js');
}

export async function readInput(dir, maxBundleBytes, { openFile = open } = {}) {
  let st;
  try {
    st = await lstat(dir);
  } catch (e) {
    return fail('INPUT', 'bundle directory: ' + (e && e.code ? e.code : 'error'));
  }
  if (!st.isDirectory()) fail('INPUT', 'bundle directory: not a directory'); // lstat: a symlink is not a directory
  const entries = await readdir(dir, { withFileTypes: true });
  const names = entries.map((e) => e.name).sort();
  if (names.length !== 2 || names[0] !== BUILD_FILE || names[1] !== BUNDLE_FILE) {
    fail('INPUT', 'bundle directory must hold exactly ' + BUILD_FILE + ' and ' + BUNDLE_FILE + ' (found ' + names.length + ' entries)');
  }
  for (const e of entries) if (!e.isFile()) fail('INPUT', e.name + ': not a regular file');
  const bytes = await readRegular(join(dir, BUNDLE_FILE), maxBundleBytes, BUNDLE_FILE, openFile);
  if (bytes.length === 0) fail('INPUT', BUNDLE_FILE + ': empty');
  const build = await readRegular(join(dir, BUILD_FILE), MAX_BUILD_JSON_BYTES, BUILD_FILE, openFile);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  checkBuildJson(build, bytes.length, sha256);
  return { bytes, size: bytes.length, sha256 };
}

// ---------- API clients (each holds one token and talks to one fixed origin) ----------
const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Only numbers go to the log: the HTTP status (by the caller) and Cloudflare's numeric error codes.
// Cloudflare's free-text messages are never logged.
function errorCodes(j) {
  const errs = isObject(j) && Array.isArray(j.errors) ? j.errors : [];
  const codes = errs.map((e) => (isObject(e) && Number.isSafeInteger(e.code) ? e.code : '?')).slice(0, 5).join(',');
  return codes ? ' codes=' + codes : '';
}

export function makeCloudflare(fetchImpl, token, sleep = realSleep) {
  return async function cf(method, path, { form, json, query, timeoutMs = API_TIMEOUT_MS } = {}) {
    const label = method + ' ' + path;
    const attempts = method === 'GET' ? 2 : 1;
    for (let k = 1; ; k++) {
      let res;
      try {
        res = await fetchImpl(CF_API + path + (query ? '?' + query : ''), {
          method,
          headers: {
            authorization: 'Bearer ' + token,
            'user-agent': 'deploy-gate',
            ...(json === undefined ? {} : { 'content-type': 'application/json' }),
          },
          body: form !== undefined ? form : json !== undefined ? JSON.stringify(json) : undefined,
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (e) {
        if (k < attempts) { await sleep(2000); continue; }
        throw new ApiError(label + ': ' + (e && e.name ? e.name : 'network error'), 0, false);
      }
      const text = await res.text();
      if (res.status >= 500 && k < attempts) { await sleep(2000); continue; }
      let j = null;
      try { j = JSON.parse(text); } catch (e) { j = null; }
      if (res.status < 200 || res.status > 299 || !isObject(j) || j.success !== true) {
        const refusal = res.status >= 400 && res.status <= 499 && isObject(j) && j.success === false;
        throw new ApiError(label + ': HTTP ' + res.status + errorCodes(j), res.status, refusal);
      }
      return j.result;
    }
  };
}

export function makeMainHead(fetchImpl, token, repo, sleep = realSleep) {
  if (!REPO_RE.test(repo)) fail('ENV', 'repo');
  const path = '/repos/' + repo + '/git/ref/heads/main';
  return async function mainHead() {
    for (let k = 1; ; k++) {
      let res;
      try {
        res = await fetchImpl(GH_API + path, {
          method: 'GET',
          headers: {
            accept: 'application/vnd.github+json',
            authorization: 'Bearer ' + token,
            'x-github-api-version': '2022-11-28',
            'user-agent': 'deploy-gate',
          },
          redirect: 'error',
          signal: AbortSignal.timeout(API_TIMEOUT_MS),
        });
      } catch (e) {
        if (k < 2) { await sleep(2000); continue; }
        throw new ApiError('GET main ref: ' + (e && e.name ? e.name : 'network error'), 0, false);
      }
      const text = await res.text();
      if (res.status >= 500 && k < 2) { await sleep(2000); continue; }
      if (res.status !== 200) throw new ApiError('GET main ref: HTTP ' + res.status, res.status, false);
      let j = null;
      try { j = JSON.parse(text); } catch (e) { j = null; }
      const sha = isObject(j) && isObject(j.object) && j.object.type === 'commit' ? j.object.sha : '';
      if (typeof sha !== 'string' || !SHA_RE.test(sha)) throw new ApiError('GET main ref: unexpected body', res.status, false);
      return sha;
    }
  };
}

// ---------- 5 and 6 the version ----------
export function versionMetadata(manifest, sha, sha256) {
  return {
    main_module: manifest.mainModule,
    compatibility_date: manifest.compatibilityDate,
    compatibility_flags: [...manifest.compatibilityFlags],
    bindings: [
      ...manifest.bindings.map((b) => (b.type === 'd1'
        ? { type: 'd1', name: b.name, id: b.id }
        : { type: 'plain_text', name: b.name, text: b.text })),
      ...manifest.inheritSecrets.map((name) => ({ type: 'inherit', name })),
    ],
    annotations: { 'workers/tag': sha, 'workers/message': 'sha256:' + sha256 },
  };
}

// The bindings the uploaded version must have: the manifest's, and every inherited secret as secret_text.
export function expectedBindings(manifest) {
  const m = new Map();
  for (const b of manifest.bindings) m.set(b.name, b);
  for (const name of manifest.inheritSecrets) m.set(name, { type: 'secret_text', name });
  return m;
}

const sorted = (a) => [...a].sort();
const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const shown = (s) => (typeof s === 'string' ? s.slice(0, 64) : '?');

// Exactly the expected set of bindings: no extra, no missing, none twice; type, D1 id and plain text equal.
function checkBindings(got, expect, where) {
  if (!Array.isArray(got)) fail('VERSION', where + ': bindings');
  const seen = new Set();
  for (const b of got) {
    if (!isObject(b) || typeof b.name !== 'string' || typeof b.type !== 'string') fail('VERSION', where + ': binding shape');
    if (seen.has(b.name)) fail('VERSION', where + ': binding listed twice: ' + shown(b.name));
    seen.add(b.name);
    const want = expect.get(b.name);
    if (!want) fail('VERSION', where + ': unexpected binding: ' + shown(b.name));
    if (b.type !== want.type) fail('VERSION', where + ': binding ' + want.name + ': type ' + shown(b.type));
    if (want.type === 'd1' && b.id !== want.id) fail('VERSION', where + ': binding ' + want.name + ': id');
    if (want.type === 'plain_text' && b.text !== want.text) fail('VERSION', where + ': binding ' + want.name + ': text');
  }
  if (seen.size !== expect.size) {
    const missing = [...expect.keys()].filter((n) => !seen.has(n));
    fail('VERSION', where + ': missing binding: ' + missing.join(','));
  }
}

function checkCompat(date, flags, expect, where) {
  if (date !== expect.compatibilityDate) fail('VERSION', where + ': compatibility_date');
  const got = flags === undefined ? [] : flags;
  if (!Array.isArray(got) || !sameList(sorted(got), sorted(expect.compatibilityFlags))) fail('VERSION', where + ': compatibility_flags');
}

// Scripts Version GET, documented result: { id, number, metadata, resources: { bindings, script, script_runtime } }.
export function checkScriptVersion(v, expect) {
  const where = 'scripts version';
  if (!isObject(v)) fail('VERSION', where + ': not an object');
  if (v.id !== expect.id) fail('VERSION', where + ': id');
  if (!isObject(v.resources)) fail('VERSION', where + ': resources');
  const rt = v.resources.script_runtime;
  if (!isObject(rt)) fail('VERSION', where + ': script_runtime');
  checkCompat(rt.compatibility_date, rt.compatibility_flags, expect, where);
  checkBindings(v.resources.bindings, expect.bindings, where);
}

// Workers Version GET, documented result: { id, number, created_on, annotations, bindings,
// compatibility_date, compatibility_flags, main_module, ... }.
export function checkWorkerVersion(w, expect) {
  const where = 'workers version';
  if (!isObject(w)) fail('VERSION', where + ': not an object');
  if (w.id !== expect.id) fail('VERSION', where + ': id');
  const a = w.annotations;
  if (!isObject(a) || a['workers/tag'] !== expect.tag) fail('VERSION', where + ': annotation workers/tag is not GITHUB_SHA');
  if (a['workers/message'] !== expect.message) fail('VERSION', where + ': annotation workers/message is not the sha256 of the uploaded bytes');
  if (w.main_module !== expect.mainModule) fail('VERSION', where + ': main_module');
  checkCompat(w.compatibility_date, w.compatibility_flags, expect, where);
  checkBindings(w.bindings, expect.bindings, where);
}

function onlyThisVersion(versions, versionId) {
  return Array.isArray(versions) && versions.length === 1 && isObject(versions[0]) &&
    versions[0].version_id === versionId && versions[0].percentage === 100;
}

// Which part of the Create Deployment answer failed the check above, without logging any value of it (the answer itself is never logged).
// Only: types, an array length, key NAMES that look like plain identifiers (at most 20, at most 30 characters each) and booleans.
function describeDeployResponse(dep, versionId) {
  const names = (o) => (isObject(o) ? Object.keys(o).filter((k) => /^[A-Za-z_]{1,30}$/.test(k)).sort().slice(0, 20) : null);
  const vs = isObject(dep) && Array.isArray(dep.versions) ? dep.versions : null;
  const v0 = vs && vs.length ? vs[0] : undefined;
  return {
    dep_type: dep === null ? 'null' : Array.isArray(dep) ? 'array' : typeof dep,
    dep_keys: names(dep),
    id_type: isObject(dep) ? typeof dep.id : null,
    id_is_uuid: isObject(dep) && typeof dep.id === 'string' && UUID_RE.test(dep.id),
    versions_type: isObject(dep) ? (Array.isArray(dep.versions) ? 'array' : typeof dep.versions) : null,
    versions_len: vs ? vs.length : null,
    v0_keys: names(v0),
    v0_version_id_is_uploaded: isObject(v0) && v0.version_id === versionId,
    v0_percentage_type: isObject(v0) ? typeof v0.percentage : null,
    v0_percentage_is_100: isObject(v0) && v0.percentage === 100,
  };
}

// ---------- the whole run ----------
// cfg: { env, cfToken, ghToken, manifestBytes, inputDir, fetch, sleep?, log, openFile? }
// Returns { exit, outcome, deployment, ... } and logs one line per stage. Never logs a token, the bundle
// or Cloudflare's error text. An unexpected error (a bug, not a rule) ends the run like a rule failure of
// the same stage: exit 1 before the Create Deployment request is sent, exit 2 (deployment "unknown")
// from then on.
export async function runDeploy(cfg) {
  const log = cfg.log;
  const sleep = cfg.sleep || realSleep;
  const stop = (exit, outcome, deployment, extra) => {
    log({ ok: exit === 0, stage: 'done', outcome, deployment, ...extra, ...(exit === 2 ? { before_rerun: BEFORE_RERUN } : {}) });
    return { exit, outcome, deployment, ...extra };
  };
  const notSent = (outcome, extra) => stop(1, outcome, 'none', extra);
  const unexpected = (exit, at, e) => stop(exit, 'error', exit === 1 ? 'none' : 'unknown', { at, detail: String(e && e.name ? e.name : 'error') });
  let sha;
  let manifest;
  let input;
  try {
    ({ sha } = checkEnv(cfg.env));
    checkTokens(cfg.cfToken, cfg.ghToken);
    manifest = parseManifest(cfg.manifestBytes);
    if (cfg.env.GITHUB_REPOSITORY !== manifest.repo) fail('ENV', 'GITHUB_REPOSITORY is not the manifest repo');
    log({ ok: true, stage: 'env', commit: sha, repo: manifest.repo, script: manifest.scriptName });
    input = await readInput(cfg.inputDir, manifest.maxBundleBytes, cfg.openFile ? { openFile: cfg.openFile } : {});
    log({ ok: true, stage: 'input', size: input.size, sha256: input.sha256 });
  } catch (e) {
    if (e instanceof DeployError) return notSent('rejected', { detail: e.message });
    return unexpected(1, 'checks', e);
  }

  const cf = makeCloudflare(cfg.fetch, cfg.cfToken, sleep);
  const mainHead = makeMainHead(cfg.fetch, cfg.ghToken, manifest.repo, sleep);
  const account = '/accounts/' + manifest.accountId;
  const script = account + '/workers/scripts/' + manifest.scriptName;

  // 4 D11 before the upload
  try {
    const head = await mainHead();
    if (head !== sha) return notSent('stale', { at: 'before_upload', commit: sha, main: head });
  } catch (e) {
    if (e instanceof ApiError) return notSent('api_error', { at: 'main_before_upload', detail: e.message });
    return unexpected(1, 'main_before_upload', e);
  }

  // 5 upload and 6 read back through both GET endpoints
  let versionId;
  try {
    const metadata = versionMetadata(manifest, sha, input.sha256);
    const form = new FormData();
    form.append('metadata', JSON.stringify(metadata));
    form.append(manifest.mainModule, new Blob([input.bytes], { type: 'application/javascript+module' }), manifest.mainModule);
    const up = await cf('POST', script + '/versions', { form, query: 'bindings_inherit=strict', timeoutMs: UPLOAD_TIMEOUT_MS });
    versionId = isObject(up) ? up.id : undefined;
    if (typeof versionId !== 'string' || !UUID_RE.test(versionId)) return notSent('api_error', { at: 'upload', detail: 'no version id' });
    log({ ok: true, stage: 'upload', version_id: versionId, size: input.size, sha256: input.sha256 });
    const expect = {
      id: versionId,
      tag: sha,
      message: 'sha256:' + input.sha256,
      mainModule: manifest.mainModule,
      compatibilityDate: manifest.compatibilityDate,
      compatibilityFlags: manifest.compatibilityFlags,
      bindings: expectedBindings(manifest),
    };
    checkScriptVersion(await cf('GET', script + '/versions/' + versionId), expect);
    checkWorkerVersion(await cf('GET', account + '/workers/workers/' + manifest.scriptName + '/versions/' + versionId), expect);
    log({ ok: true, stage: 'version', version_id: versionId });
  } catch (e) {
    if (e instanceof ApiError) return notSent('api_error', { at: 'version', version_id: versionId, detail: e.message });
    if (e instanceof DeployError) return notSent('version_mismatch', { version_id: versionId, detail: e.message });
    return unexpected(1, 'version', e);
  }

  // 7 D11 before the deployment
  try {
    const head = await mainHead();
    if (head !== sha) return notSent('stale', { at: 'before_deploy', commit: sha, main: head, undeployed_version_id: versionId });
  } catch (e) {
    if (e instanceof ApiError) return notSent('api_error', { at: 'main_before_deploy', detail: e.message });
    return unexpected(1, 'main_before_deploy', e);
  }

  // 8 the deployment: from here on every failure is exit 2, with what is known about the deployment
  let deploymentId;
  try {
    const dep = await cf('POST', script + '/deployments', {
      json: {
        strategy: 'percentage',
        versions: [{ version_id: versionId, percentage: 100 }],
        annotations: { 'workers/message': 'commit ' + sha },
      },
    });
    deploymentId = isObject(dep) ? dep.id : undefined;
    // Plan A: Create Deployment may answer with just { id } (seen in production, run #4). The id must still be a UUID. When `versions` is absent it is not
    // evidence either way, so step 9 (the list read back: first entry = this id, only the uploaded version, 100 %) is the check. When `versions` IS present it must match exactly as before.
    const versionsAbsent = isObject(dep) && !has(dep, 'versions');
    if (typeof deploymentId !== 'string' || !UUID_RE.test(deploymentId) || (!versionsAbsent && !onlyThisVersion(dep.versions, versionId))) {
      log({ ok: false, stage: 'deploy_response_shape', ...describeDeployResponse(dep, versionId) });   // diagnostics only: types, lengths, key NAMES and booleans; never a value, never the body
      return stop(2, 'readback_failed', 'unknown', { at: 'deploy_response', version_id: versionId });
    }
    log({ ok: true, stage: 'deploy', deployment_id: deploymentId, version_id: versionId, ...(versionsAbsent ? { response_versions: 'absent_checked_at_readback' } : {}) });
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.refusal) return stop(2, 'deploy_refused', 'refused', { version_id: versionId, detail: e.message });
      return stop(2, 'deploy_unknown', 'unknown', { version_id: versionId, detail: e.message });
    }
    return unexpected(2, 'deploy', e);
  }

  // 9 read back and 10 D11 after the deployment
  try {
    const list = await cf('GET', script + '/deployments');
    const first = isObject(list) && Array.isArray(list.deployments) ? list.deployments[0] : undefined;
    if (!isObject(first) || first.id !== deploymentId || !onlyThisVersion(first.versions, versionId)) {
      return stop(2, 'readback_failed', 'created', { at: 'deployments', deployment_id: deploymentId, version_id: versionId });
    }
    log({ ok: true, stage: 'readback', deployment_id: deploymentId, version_id: versionId });
    const head = await mainHead();
    if (head !== sha) {
      log({ ok: false, stage: 'main_after_deploy', note: 'deployed commit is no longer the head of main', commit: sha, main: head });
      return stop(2, 'main_moved', 'created', { commit: sha, main: head, deployment_id: deploymentId, version_id: versionId });
    }
  } catch (e) {
    if (e instanceof ApiError) return stop(2, 'readback_failed', 'created', { deployment_id: deploymentId, version_id: versionId, detail: e.message });
    return unexpected(2, 'readback', e);
  }
  return stop(0, 'deployed', 'created', { commit: sha, version_id: versionId, deployment_id: deploymentId, size: input.size, sha256: input.sha256 });
}

async function main() {
  const out = (o) => console.log(logLine(o));
  const major = Number(process.versions.node.split('.')[0]);
  if (!(major >= 20)) { out({ ok: false, stage: 'node', version: process.versions.node }); process.exit(1); }
  const env = process.env;
  const cfToken = env.CLOUDFLARE_API_TOKEN;
  const ghToken = env.GITHUB_TOKEN;
  delete env.CLOUDFLARE_API_TOKEN;
  delete env.GITHUB_TOKEN;
  const args = process.argv.slice(2);
  if (args.length !== 2 || !MANIFEST_NAME_RE.test(args[0]) || !DIR_ARG_RE.test(args[1])) {
    out({ ok: false, stage: 'usage', detail: 'node deploy.mjs <name> <bundle-dir>' });
    process.exit(1);
  }
  const here = dirname(fileURLToPath(import.meta.url));
  let manifestBytes;
  try {
    manifestBytes = new Uint8Array(readFileSync(join(here, 'deploy-' + args[0] + '.json')));
  } catch (e) {
    out({ ok: false, stage: 'manifest', detail: String(e && e.code ? e.code : e) });
    process.exit(1);
  }
  let r;
  try {
    r = await runDeploy({
      env: {
        GITHUB_SHA: env.GITHUB_SHA,
        GITHUB_REF: env.GITHUB_REF,
        GITHUB_EVENT_NAME: env.GITHUB_EVENT_NAME,
        GITHUB_REPOSITORY: env.GITHUB_REPOSITORY,
      },
      cfToken,
      ghToken,
      manifestBytes,
      inputDir: resolve(process.cwd(), args[1]),
      fetch: globalThis.fetch,
      log: out,
    });
  } catch (e) {
    crash(e);
  }
  process.exit(r.exit);
}

// Unexpected (a bug, not a rule): exit 2, because we cannot tell how far the run got. Even if writing
// the log line fails, the exit code stays 2 (an uncaught error would exit 1, which means "not sent").
function crash(e) {
  try {
    console.log(logLine({ ok: false, stage: 'crash', deployment: 'unknown', detail: String(e && e.name ? e.name : 'error'), before_rerun: BEFORE_RERUN }));
  } catch (e2) {
    // nothing more to do; the exit code carries the result
  }
  process.exit(2);
}

let invokedPath = '';
try { invokedPath = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : ''; } catch (e) { invokedPath = ''; }
if (invokedPath === import.meta.url) main().catch(crash);
