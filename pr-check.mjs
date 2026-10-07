// pr-check.mjs - stage 1: the pull-request side of the human-approval check (design 5: a, b, h, i, j).
// Pure functions over data (tree listings, refs): no network and no hashing here, so the gate
// (GitHub API data, gate.mjs) and the applier of stage 4 (git data) run the same rules.
// Imports only core.js, which stage 1 leaves byte-for-byte unchanged.

import { FormatError, parseStrictJSON, decodeUtf8Strict, matchesAny, isForbiddenPath } from './core.js';

function fail(code, detail) { throw new FormatError(code, detail); }

export const STATUS_CONTEXT = 'human-approval';
export const MAIN_REF = 'main';
export const SELF_WORKFLOW = '.github/workflows/human-approval.yml';
export const MAX_RECEIPT_BLOB_BYTES = 65536;          // = core.js MAX_RECEIPT_BYTES

export const SHA_RE = /^[0-9a-f]{40}$/;
export const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]{1,100}$/;   // = core.js
const RECEIPT_PATH_RE = /^approvals\/([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)\.json$/;            // work_id rule of core.js
const CHANGED_PATH_RE = /^[A-Za-z0-9._\/-]+$/;   // the characters a request path pattern may use
const WORKFLOW_PATH_RE = /^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/;
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,32}[a-z0-9])?$/;
const MAX_APPROVER_BYTES = 16384;
const MAX_REPOS = 20;
const MAX_WORKFLOWS_PER_REPO = 50;
const FILE_MODES = ['100644', '100755'];
const MODE_TYPES = { '100644': 'blob', '100755': 'blob', '120000': 'blob', '040000': 'tree', '160000': 'commit' };

function has(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
function isPlainObject(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }

// ---------- approver.json: the gate's settings in the trust root (the applier reads it too) ----------
// { "v": 1, "app_id": <the approval App>, "slug": "<its name>",
//   "other_workflows": { "<owner>/<repo>": { ".github/workflows/<name>.yml": "<git blob id>", ... }, ... } }
// other_workflows lists, per repository the gate serves, every workflow file other than the gate's own
// that may exist on main, with its exact bytes (blob id). An empty list means: no other workflow at all.
export function parseApprover(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('BYTES_EXPECTED', 'approver');
  if (bytes.length > MAX_APPROVER_BYTES) fail('TOO_LONG', 'approver');
  const o = parseStrictJSON(decodeUtf8Strict(bytes), MAX_APPROVER_BYTES);
  if (!isPlainObject(o)) fail('SCHEMA', 'approver');
  const keys = ['v', 'app_id', 'slug', 'other_workflows'];
  for (const k of Object.keys(o)) if (!keys.includes(k)) fail('UNKNOWN_FIELD', 'approver.' + k);
  for (const k of keys) if (!has(o, k)) fail('MISSING_FIELD', 'approver.' + k);
  if (o.v !== 1) fail('APPROVER_VERSION');
  if (!Number.isSafeInteger(o.app_id) || o.app_id < 1) fail('APPROVER_APP_ID');
  if (typeof o.slug !== 'string' || !SLUG_RE.test(o.slug)) fail('APPROVER_SLUG');
  const ow = o.other_workflows;
  if (!isPlainObject(ow)) fail('APPROVER_WORKFLOWS', 'not an object');
  const repos = Object.keys(ow);
  if (repos.length < 1 || repos.length > MAX_REPOS) fail('APPROVER_WORKFLOWS', 'number of repositories');
  const byRepo = new Map();
  for (const repo of repos) {
    if (!REPO_RE.test(repo)) fail('APPROVER_WORKFLOWS', 'repository name');
    const list = ow[repo];
    if (!isPlainObject(list)) fail('APPROVER_WORKFLOWS', repo + ': not an object');
    const paths = Object.keys(list);
    if (paths.length > MAX_WORKFLOWS_PER_REPO) fail('APPROVER_WORKFLOWS', repo + ': too many');
    const allowed = new Map();
    for (const p of paths) {
      if (!WORKFLOW_PATH_RE.test(p) || p === SELF_WORKFLOW) fail('APPROVER_WORKFLOWS', repo + ': path ' + p);
      if (typeof list[p] !== 'string' || !SHA_RE.test(list[p])) fail('APPROVER_WORKFLOWS', repo + ': blob id of ' + p);
      allowed.set(p, list[p]);
    }
    byRepo.set(repo, allowed);
  }
  return Object.freeze({ appId: o.app_id, slug: o.slug, otherWorkflows: byRepo });
}

// ---------- (a) the pull request: same repository, into main, still at the head the event named ----------
export function checkPullRequest(pr, repo, headSha) {
  if (!pr || typeof pr !== 'object') fail('PR_INVALID');
  if (pr.state !== 'open') fail('PR_NOT_OPEN');
  if (!pr.base || pr.base.ref !== MAIN_REF || !pr.base.repo || pr.base.repo.full_name !== repo) fail('PR_BASE');
  if (!pr.head || !pr.head.repo || pr.head.repo.full_name !== repo) fail('PR_HEAD_REPO');
  if (pr.head.sha !== headSha) fail('PR_MOVED');
}

// ---------- (b) the head contains the latest main (compare main...head) ----------
export function checkUpToDate(cmp, mainSha) {
  if (!cmp || cmp.status !== 'ahead' || cmp.behind_by !== 0 || !(cmp.ahead_by >= 1) ||
      !cmp.merge_base_commit || cmp.merge_base_commit.sha !== mainSha) fail('NOT_UP_TO_DATE');
}

// ---------- (i) a recursive tree listing -> Map(path -> entry); a listing cut short fails ----------
export function readTree(listing, what) {
  if (!listing || typeof listing !== 'object') fail('TREE_INVALID', what);
  if (listing.truncated !== false) fail('TREE_TRUNCATED', what);
  if (!Array.isArray(listing.tree)) fail('TREE_INVALID', what);
  const map = new Map();
  for (const e of listing.tree) {
    if (!e || typeof e.path !== 'string' || e.path.length === 0) fail('TREE_INVALID', what);
    const type = MODE_TYPES[e.mode];
    if (!type || e.type !== type) fail('TREE_INVALID', what + ': mode/type');
    if (typeof e.sha !== 'string' || !SHA_RE.test(e.sha)) fail('TREE_INVALID', what + ': sha');
    if (map.has(e.path)) fail('TREE_INVALID', what + ': duplicate path');
    map.set(e.path, Object.freeze({ mode: e.mode, type, sha: e.sha, size: Number.isSafeInteger(e.size) ? e.size : null }));
  }
  return map;
}

// Files, symlinks and submodules that differ between two trees (directories are implied by them).
// When the head contains the latest main, every merge method leaves main with the head's tree,
// so this list is exactly what merging the pull request changes on main.
export function diffTrees(mainTree, headTree) {
  const paths = new Set();
  for (const [p, e] of mainTree) if (e.type !== 'tree') paths.add(p);
  for (const [p, e] of headTree) if (e.type !== 'tree') paths.add(p);
  const out = [];
  for (const p of [...paths].sort()) {
    const a = mainTree.get(p);
    const b = headTree.get(p);
    const before = a && a.type !== 'tree' ? a : null;
    const after = b && b.type !== 'tree' ? b : null;
    if (before && after && before.mode === after.mode && before.sha === after.sha) continue;
    out.push(Object.freeze({ path: p, before, after }));
  }
  return out;
}

// One key for paths that a case-insensitive disk (the Mac applier) would treat as the same name.
export function foldKey(path) {
  return path.normalize('NFKC').toUpperCase().toLowerCase();
}

function checkPathShape(p) {
  if (!CHANGED_PATH_RE.test(p)) fail('PATH_CHARSET', p);
  for (const s of p.split('/')) {
    if (s === '' || s === '.' || s === '..' || s.toLowerCase() === '.git') fail('PATH_INVALID', p);
  }
}

function checkEntryMode(e, p) {
  if (e.mode === '120000') fail('SYMLINK', p);
  if (e.mode === '160000') fail('SUBMODULE', p);
  if (!FILE_MODES.includes(e.mode) || e.type !== 'blob') fail('MODE_INVALID', p);
}

// A collision fails when one of the two names is new in the head; one already on main is left alone.
function checkCaseCollisions(mainTree, headTree) {
  const seen = new Map();
  for (const p of headTree.keys()) {
    const k = foldKey(p);
    const first = seen.get(k);
    if (first === undefined) { seen.set(k, p); continue; }
    if (!mainTree.has(p) || !mainTree.has(first)) fail('CASE_COLLISION', first + ' / ' + p);
  }
}

// (b) the head adds exactly one receipt approvals/<work_id>.json that main does not have, and
// (h, first half) every changed path is plain: ASCII pattern characters, regular files only.
// Returns the receipt entry and the other changed paths (both sides of a rename are separate entries).
export function splitChanges(changes, mainTree, headTree) {
  let receipt = null;
  const paths = [];
  for (const c of changes) {
    checkPathShape(c.path);
    if (c.before) checkEntryMode(c.before, c.path);
    if (c.after) checkEntryMode(c.after, c.path);
    if (c.path.split('/')[0].toLowerCase() === 'approvals') {
      const m = RECEIPT_PATH_RE.exec(c.path);
      if (!m) fail('RECEIPT_PATH', c.path);
      if (c.before || !c.after) fail('APPROVALS_TOUCHED', c.path);  // only an addition: never a change or a removal
      if (c.after.mode !== '100644') fail('RECEIPT_MODE', c.path);
      if (receipt) fail('APPROVALS_TOUCHED', 'more than one receipt');
      receipt = Object.freeze({ path: c.path, workId: m[1], entry: c.after });
    } else {
      paths.push(c.path);
    }
  }
  if (!receipt) fail('NO_RECEIPT');
  const key = foldKey(receipt.path);
  for (const p of mainTree.keys()) if (foldKey(p) === key) fail('RECEIPT_ON_MAIN', receipt.path);
  checkCaseCollisions(mainTree, headTree);
  return { receipt, paths };
}

// (h, second half) every other changed path is inside the approved patterns and off the fixed list.
export function checkScope(paths, requestPaths) {
  for (const p of paths) {
    if (isForbiddenPath(p)) fail('FORBIDDEN_PATH', p);
    if (!matchesAny(requestPaths, p)) fail('OUT_OF_SCOPE', p);
  }
}

// ---------- (j) the other workflows on main ----------
// A job that names the approver environment gets the approval App key, and so does a job of a workflow
// it calls. What a workflow names is only known by reading its YAML the way GitHub does (escapes, flow
// mappings, anchors), so the gate reads no workflow text at all: every file under .github/workflows/ on
// main (any letter case, any depth) other than the gate's own must be listed for this repository in
// approver.json with its exact blob id. The owner reviews a workflow before it is listed.
export function checkOtherWorkflows(mainTree, allowed) {
  if (!(allowed instanceof Map)) fail('REPO_NOT_LISTED');
  for (const [p, e] of mainTree) {
    if (e.type === 'tree' || p === SELF_WORKFLOW) continue;
    if (!foldKey(p).startsWith('.github/workflows/')) continue;
    const want = allowed.get(p);
    if (want === undefined) fail('OTHER_WORKFLOW_NOT_ALLOWED', p);
    if (e.type !== 'blob' || !FILE_MODES.includes(e.mode) || e.sha !== want) fail('OTHER_WORKFLOW_CHANGED', p);
  }
}

// ---------- the status text (ASCII, at most 140 characters; never a path from the pull request) ----------
export function describeSuccess(v) {
  return ('ok ' + v.work_id + ' pk ' + v.passkey_key.slice(0, 8) + ' dev ' + v.device_key.slice(0, 8)).slice(0, 140);
}

export function describeFailure(code) {
  return ('NG ' + (/^[A-Z0-9_]{1,60}$/.test(code) ? code : 'INTERNAL')).slice(0, 140);
}
