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
import { FormatError, b64uEncode, utf8 } from './core.js';
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
  const { receipt, paths } = splitChanges(diffTrees(mainTree, headTree), mainTree, headTree); // (b) (h)

  const receiptBytes = await readBlob(api, repo, readToken, receipt.entry, MAX_RECEIPT_BLOB_BYTES, receipt.path);
  const v = verifyReceipt({                                                                  // (c)-(g)
    receiptBytes, keysBytes: cfg.keysBytes, expectedRepo: repo, expectedWorkId: receipt.workId, nowMs,
  });
  checkScope(paths, v.paths);                                                                // (h)
  checkOtherWorkflows(mainTree, approver.otherWorkflows.get(repo));                          // (j)
  return { mainSha, v, changed: paths.length, receipt: receipt.path };
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
async function approverToken(api, repo, approver, pem, nowSec, sleep) {
  const [owner, name] = repo.split('/');
  const jwt = appJwt(approver.appId, pem, nowSec);
  const inst = await api('GET', '/repos/' + repo + '/installation', jwt);
  if (!inst || inst.app_id !== approver.appId || !Number.isSafeInteger(inst.id) || !inst.account || inst.account.login !== owner) {
    throw new ApiError('installation of the approval App');
  }
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
      typeof cfg.headSha !== 'string' || !SHA_RE.test(cfg.headSha) || !cfg.readToken || !cfg.approverKeyPem) {
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
  try {
    const r = await evaluate(api, cfg, approver, nowMs);
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
    token = await approverToken(api, cfg.repo, approver, cfg.approverKeyPem, Math.floor(cfg.nowMs() / 1000), sleep);
    const body = { state, context: STATUS_CONTEXT, description };
    if (cfg.targetUrl) body.target_url = cfg.targetUrl;
    await api('POST', '/repos/' + cfg.repo + '/statuses/' + cfg.headSha, token, body);
    log({ ok: true, stage: 'status', state, description });
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
  }));
}

let invokedPath = '';
try { invokedPath = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : ''; } catch (e) { invokedPath = ''; }
if (invokedPath === import.meta.url) main();
