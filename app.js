// app.js - approval page, stage 0: setup (device key + passkey), keys.json, and test signing.
// Nothing is loaded from other origins. Every dynamic text goes through textContent.
import {
  RP_ID, ORIGIN, ALG_ES256, FormatError,
  utf8, toHex, bytesEqual, b64uEncode, isP256Spki, formatTimestamp,
  parseRequest, parseKeys, serializeKeys, serializeReceipt,
  challengeMessage, deviceMessage, checkClientData, checkAuthenticatorData,
  isBroadPattern, patternTouchesForbidden, signingBlock,
} from './core.js';
import { loadFixedRequest, receiptReturnUrl, requestFromFragment, savePendingRequest, readPendingRequest, clearPendingRecord, markPendingSigned, decideOpenRecord, OPEN_DB, OPEN_STORE, OPEN_KEY, saveReceipt, loadReceipts, noteReceiptAttempt, MAX_AUTO_REDELIVERIES, VAPID_PUBLIC_B64U, b64uToBytes, buildEnrollmentUrl, routeFromSearch, routeMatchesRequest, verifyOpenMessage } from './fragment.js?v=3n'; // versioned: a cached v0.3c module would reject the resume path

const PAGE_VERSION = 'stage 0 / v0.2 (2026-10-04)';
const TEST_REPO = 'yuta5150rr/probe';
const DAY_MS = 24 * 3600 * 1000;
const DB_NAME = 'approval';
const STORE = 'keys';
const RECORD_KEY = 'v1';

const $ = (id) => document.getElementById(id);
const state = {
  record: null,            // { v, createdAt, deviceKeyPair, devicePublicKey, credentialId, passkeyPublicKey, passkeyCreatedAt }
  published: null,         // parsed keys.json from this origin
  publishedStatus: 'unknown',
  publishedDetail: '',
  current: null,           // { bytes, request, challenge } - bytes are the exact bytes that get signed
  currentBlock: null,
  receiptText: null,
  receiptName: null,
  imported: false,         // true only when the shown request came from the fixed same-origin request file
  busy: false,
};

// ---------- small helpers ----------
function log(msg, kind) {
  const li = document.createElement('li');
  li.textContent = new Date().toLocaleTimeString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false }) + '  ' + msg;
  if (kind) li.className = kind;
  $('log').prepend(li);
}

function errText(e) {
  if (e instanceof FormatError) return e.message;
  if (e && e.name) return e.name + ': ' + e.message;
  return String(e);
}

function jst(ms) {
  return new Date(ms).toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  }) + '（日本時間）';
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function fingerprint(spki) {
  return toHex(await sha256(spki)).slice(0, 16);
}

function isStandalone() {
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}

function environmentProblems() {
  const p = [];
  if (location.origin !== ORIGIN) p.push('このページの場所が違う（' + location.origin + '）');
  if (!window.isSecureContext) p.push('安全な接続ではない');
  if (!window.PublicKeyCredential || !navigator.credentials) p.push('passkey が使えない');
  if (!window.crypto || !crypto.subtle) p.push('WebCrypto が使えない');
  if (!window.indexedDB) p.push('IndexedDB が使えない');
  return p;
}

// ---------- IndexedDB (the device key lives only here, non-extractable) ----------
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('IndexedDB blocked'));
  });
}

async function withStore(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result;
      const r = fn(tx.objectStore(STORE));
      r.onsuccess = () => { result = r.result; };
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('transaction aborted'));
    });
  } finally {
    db.close();
  }
}

const dbGet = () => withStore('readonly', (s) => s.get(RECORD_KEY)).then((v) => v || null);
const dbPut = (v) => withStore('readwrite', (s) => s.put(v, RECORD_KEY));
const dbDelete = () => withStore('readwrite', (s) => s.delete(RECORD_KEY));

// ---------- files out (share sheet: "Save to Files"; no clipboard) ----------
function saveFile(name, text) {
  const file = new File([text], name, { type: 'application/json' });
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    navigator.share({ files: [file] })
      .then(() => log(name + ' を渡した（「ファイルに保存」を選んだかを確かめる）', 'good'))
      .catch((e) => log(e && e.name === 'AbortError'
        ? name + ' の保存を取りやめた'
        : name + ' を保存できなかった: ' + errText(e), 'bad'));
    return;
  }
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  log(name + ' をダウンロードに回した');
}

// ---------- status ----------
async function renderStatus() {
  const r = state.record;
  const standalone = isStandalone();
  $('st-mode').textContent = standalone ? 'ホーム画面アプリ' : 'ブラウザ（ホーム画面アプリではない）';
  $('st-device').textContent = r && r.deviceKeyPair
    ? 'あり（作成 ' + jst(r.createdAt) + '・指紋 ' + await fingerprint(r.devicePublicKey) + '）'
    : 'なし';
  $('st-passkey').textContent = r && r.credentialId
    ? '登録済み（指紋 ' + await fingerprint(r.passkeyPublicKey) + '）'
    : 'なし';
  const label = {
    unknown: '未照合', missing: 'まだ公開されていない', match: '✓ この端末の鍵と一致',
    mismatch: '✗ この端末の鍵と違う', error: '読めない',
  }[state.publishedStatus];
  $('st-published').textContent = label + (state.publishedDetail ? '（' + state.publishedDetail + '）' : '');

  $('btn-device').disabled = state.busy || !standalone || !!r;
  $('btn-passkey').disabled = state.busy || !standalone || !(r && r.deviceKeyPair) || !!(r && r.credentialId);
  $('btn-save-keys').disabled = state.busy || !(r && r.deviceKeyPair && r.credentialId);
  $('btn-check-device').disabled = state.busy;
  $('btn-check-published').disabled = state.busy;
  $('btn-test-request').disabled = state.busy;
  $('btn-approve').disabled = state.busy || !state.current || !!state.currentBlock;
  $('btn-save-receipt').hidden = !state.receiptText;
  $('btn-reset').disabled = state.busy || !r;
}

async function loadPublished() {
  try {
    const res = await fetch('keys.json', { cache: 'no-store', credentials: 'omit', redirect: 'error' });
    if (res.status === 404) {
      state.published = null;
      state.publishedStatus = 'missing';
      state.publishedDetail = '';
      return;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const keys = parseKeys(new Uint8Array(await res.arrayBuffer()));
    state.published = keys;
    const r = state.record;
    if (!r || !r.credentialId) {
      state.publishedStatus = 'mismatch';
      state.publishedDetail = 'この端末に鍵が無い';
      return;
    }
    const diffs = [];
    if (!bytesEqual(keys.credentialId, r.credentialId)) diffs.push('passkey の ID');
    if (!bytesEqual(keys.passkeyPublicKey, r.passkeyPublicKey)) diffs.push('passkey の公開鍵');
    if (!bytesEqual(keys.devicePublicKey, r.devicePublicKey)) diffs.push('端末の鍵');
    state.publishedStatus = diffs.length ? 'mismatch' : 'match';
    state.publishedDetail = diffs.join('・');
  } catch (e) {
    state.published = null;
    state.publishedStatus = 'error';
    state.publishedDetail = errText(e);
  }
}

// ---------- setup 1: device key (non-extractable, stays in this app's storage) ----------
async function onCreateDeviceKey() {
  if (!isStandalone()) { log('ホーム画面アプリで開いてから作る（Safari のタブでは作らない）', 'bad'); return; }
  if (state.record || state.busy) return;
  state.busy = true;
  await renderStatus();
  try {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    if (pair.privateKey.extractable !== false) throw new Error('秘密鍵が取り出せる設定になっている');
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    if (!isP256Spki(spki)) throw new Error('公開鍵の形が想定と違う');
    await dbPut({
      v: 1, createdAt: Date.now(), deviceKeyPair: pair, devicePublicKey: spki,
      credentialId: null, passkeyPublicKey: null, passkeyCreatedAt: null,
    });
    const back = await dbGet();
    if (!back || !back.deviceKeyPair || !bytesEqual(back.devicePublicKey, spki)) throw new Error('保存の読み戻しが一致しない');
    state.record = back;
    let persisted = false;
    try {
      persisted = navigator.storage && navigator.storage.persist ? await navigator.storage.persist() : false;
    } catch (e) {
      persisted = false;
    }
    log('端末の鍵を作った（取り出し不可・保存の永続化の許可 ' + (persisted ? 'あり' : 'なし') + '）', 'good');
  } catch (e) {
    log('端末の鍵を作れなかった: ' + errText(e), 'bad');
  }
  state.busy = false;
  runDeferredIncoming();
  await renderStatus();
}

// ---------- setup 2: passkey with user verification (WebAuthn UV, usually Face ID). create() is called directly in the tap handler ----------
function onCreatePasskey() {
  const r = state.record;
  if (!isStandalone() || !r || !r.deviceKeyPair || r.credentialId || state.busy) return;
  state.busy = true;
  let promise;
  try {
    promise = navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: '承認' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'approval', displayName: '承認' },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: ALG_ES256 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform', residentKey: 'required',
          requireResidentKey: true, userVerification: 'required',
        },
        attestation: 'none',
        timeout: 120000,
      },
    });
  } catch (e) {
    promise = Promise.reject(e);
  }
  renderStatus();
  promise.then(async (cred) => {
    if (!cred || cred.type !== 'public-key') throw new Error('passkey が返ってこなかった');
    const resp = cred.response;
    if (typeof resp.getPublicKey !== 'function' || typeof resp.getPublicKeyAlgorithm !== 'function') {
      throw new Error('このブラウザでは passkey の公開鍵を取り出せない');
    }
    if (resp.getPublicKeyAlgorithm() !== ALG_ES256) throw new Error('鍵の方式が ES256 ではない');
    const raw = resp.getPublicKey();
    const spki = raw ? new Uint8Array(raw) : null;
    if (!spki || !isP256Spki(spki)) throw new Error('passkey の公開鍵の形が想定と違う');
    if (typeof resp.getAuthenticatorData === 'function') {
      const ad = new Uint8Array(resp.getAuthenticatorData());
      if (ad.length < 37 || !(ad[32] & 0x04)) throw new Error('本人確認（UV）が立っていない');
    }
    const updated = { ...r, credentialId: new Uint8Array(cred.rawId), passkeyPublicKey: spki, passkeyCreatedAt: Date.now() };
    await dbPut(updated);
    const back = await dbGet();
    if (!back || !back.credentialId || !bytesEqual(back.credentialId, updated.credentialId)) throw new Error('保存の読み戻しが一致しない');
    state.record = back;
    log('passkey を作った（本人確認つき）', 'good');
  }).catch((e) => log('passkey を作れなかった: ' + errText(e), 'bad'))
    .finally(() => { state.busy = false; renderStatus(); runDeferredIncoming(); });
}

// ---------- setup 3: keys.json out ----------
function onSaveKeys() {
  const r = state.record;
  if (!r || !r.credentialId) return;
  let text;
  try {
    text = serializeKeys({
      credentialId: r.credentialId, passkeyPublicKey: r.passkeyPublicKey,
      devicePublicKey: r.devicePublicKey, createdAtMs: r.passkeyCreatedAt,
    });
  } catch (e) {
    log('keys.json を作れなかった: ' + errText(e), 'bad');
    return;
  }
  saveFile('keys.json', text);
}

async function onCheckPublished() {
  await loadPublished();
  await renderStatus();
  log('公開の keys.json: ' + $('st-published').textContent, state.publishedStatus === 'match' ? 'good' : 'bad');
}

// ---------- device key check (A4: still there after a restart / days without use) ----------
async function onCheckDevice() {
  try {
    const r = await dbGet();
    state.record = r;
    if (!r || !r.deviceKeyPair) {
      log('端末の鍵: なし', 'bad');
    } else {
      const msg = crypto.getRandomValues(new Uint8Array(32));
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, r.deviceKeyPair.privateKey, msg);
      const pub = await crypto.subtle.importKey('spki', r.devicePublicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, msg);
      log(ok
        ? '✓ 端末の鍵で署名できる（作成 ' + jst(r.createdAt) + '・取り出し不可 ' + (r.deviceKeyPair.privateKey.extractable === false ? 'はい' : 'いいえ') + '）'
        : '✗ 端末の鍵の署名が合わない', ok ? 'good' : 'bad');
    }
  } catch (e) {
    log('端末の鍵を確かめられなかった: ' + errText(e), 'bad');
  }
  await renderStatus();
}

// ---------- the request: parse the exact bytes, show machine values apart from the AI text ----------
const BLOCK_TEXT = {
  NOW_INVALID: '端末の時刻が読めない（署名しない）',
  CREATED_IN_FUTURE: '作成時刻が未来になっている（署名しない）',
  APPROVE_BY_PASSED: '承認の締切を過ぎている（署名しない）',
  VERIFY_BY_PASSED: '検証の締切を過ぎている（署名しない）',
};

function timeBlock(q, now) {
  const code = signingBlock(q, now);
  return code ? BLOCK_TEXT[code] : null;
}

function addRow(dl, label, value, cls) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  if (typeof value === 'string') dd.textContent = value;
  else dd.append(value);
  if (cls) dd.className = cls;
  dl.append(dt, dd);
}

function renderRequest() {
  const cur = state.current;
  $('request').hidden = !cur;
  if (!cur) return;
  const q = cur.request;
  const dl = $('req-machine');
  dl.replaceChildren();
  addRow(dl, 'リポジトリ', q.repo, 'mono');
  addRow(dl, '作業 ID', q.work_id, 'mono');
  const ul = document.createElement('ul');
  for (const p of q.paths) {
    const li = document.createElement('li');
    li.className = 'mono';
    const notes = [];
    if (isBroadPattern(p)) notes.push('** を含む（広い）');
    if (patternTouchesForbidden(p)) notes.push('禁止の場所に当たりうる（そこを変えると検証で必ず落ちる）');
    li.textContent = notes.length ? p + '  ← ' + notes.join('・') : p;
    if (notes.length) li.classList.add('bad');
    ul.append(li);
  }
  addRow(dl, '変えてよい場所', ul);
  addRow(dl, '承認の締切', jst(q.approve_by_ms) + ' / ' + q.approve_by);
  addRow(dl, '検証の締切', jst(q.verify_by_ms) + ' / ' + q.verify_by);
  addRow(dl, '作成', jst(q.created_at_ms) + ' / ' + q.created_at);

  const ai = $('req-ai');
  ai.replaceChildren();
  const t = document.createElement('p');
  t.className = 'ai-title';
  t.dir = 'ltr';
  t.textContent = q.title;
  const s = document.createElement('p');
  s.dir = 'ltr';
  s.textContent = q.summary || '（なし）';
  ai.append(t, s);

  $('req-hash').textContent = '依頼の指紋 ' + toHex(cur.challenge).slice(0, 16);
  state.currentBlock = timeBlock(q, Date.now());
  $('req-block').hidden = !state.currentBlock;
  $('req-block').textContent = state.currentBlock || '';
}

async function loadRequest(bytes) {
  state.current = null;
  state.currentBlock = null;
  state.receiptText = null;
  state.imported = false;
  const request = parseRequest(bytes); // strict: unknown/duplicate keys, bad characters, bad paths all throw
  const challenge = await sha256(challengeMessage(bytes));
  state.current = { bytes, request, challenge };
  renderRequest();
  await renderStatus();
}

async function onMakeTestRequest() {
  try {
    const now = Math.floor(Date.now() / 1000) * 1000;
    const stamp = formatTimestamp(now);
    const workId = 'test-' + stamp.slice(0, 10).replace(/-/g, '') + '-' + stamp.slice(11, 19).replace(/:/g, '');
    const req = {
      v: 1,
      repo: TEST_REPO,
      work_id: workId,
      title: '署名の試験',
      summary: '署名の試験用の依頼。この依頼で変わるものは無い。',
      paths: ['docs/approval-test.txt'],
      approve_by: formatTimestamp(now + 7 * DAY_MS),
      verify_by: formatTimestamp(now + 14 * DAY_MS),
      created_at: stamp,
      nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
    };
    await loadRequest(utf8(JSON.stringify(req)));
    log('試験用の依頼を作った（' + workId + '）');
  } catch (e) {
    log('依頼を作れなかった: ' + errText(e), 'bad');
    await renderStatus();
  }
}

// ---------- approve: passkey with UV + device key over the same challenge ----------
function onApprove() {
  const cur = state.current;
  if (!cur || state.busy) return;
  const block = timeBlock(cur.request, Date.now());
  if (block) { log(block, 'bad'); return; }
  const r = state.record;
  const credId = (r && r.credentialId) || (state.published && state.published.credentialId) || null;
  state.busy = true;
  state.receiptText = null;
  let promise;
  try {
    promise = navigator.credentials.get({
      publicKey: {
        challenge: cur.challenge,
        rpId: RP_ID,
        allowCredentials: credId ? [{ type: 'public-key', id: credId }] : [],
        userVerification: 'required',
        timeout: 120000,
      },
    });
  } catch (e) {
    promise = Promise.reject(e);
  }
  renderStatus();
  promise.then(async (assertion) => {
    if (state.current !== cur) throw new Error('表示中の依頼が変わった。やり直す');
    if (!assertion || assertion.type !== 'public-key') throw new Error('passkey の署名が返ってこなかった');
    const resp = assertion.response;
    const authenticatorData = new Uint8Array(resp.authenticatorData);
    const clientDataJSON = new Uint8Array(resp.clientDataJSON);
    const passkeySignature = new Uint8Array(resp.signature);
    const credentialId = new Uint8Array(assertion.rawId);
    checkClientData(clientDataJSON, cur.challenge);
    checkAuthenticatorData(authenticatorData, await sha256(utf8(RP_ID)));
    const rec = await dbGet();
    if (!rec || !rec.deviceKeyPair) {
      log('passkey の署名は取れた。端末の鍵がこのブラウザに無いので、受領書は作らない', 'bad');
      return;
    }
    if (!rec.credentialId || !bytesEqual(rec.credentialId, credentialId)) throw new Error('この端末で登録した passkey ではない');
    // Check the deadline again right before the device key signs: the prompt may have ended after approve_by.
    const late = timeBlock(cur.request, Date.now());
    if (late) {
      state.currentBlock = late;
      $('req-block').hidden = false;
      $('req-block').textContent = late;
      log('本人確認が終わった時には締切を過ぎていた。受領書は作らない', 'bad');
      return;
    }
    const deviceSignature = new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, rec.deviceKeyPair.privateKey, deviceMessage(cur.challenge)));
    state.receiptText = serializeReceipt({
      requestBytes: cur.bytes, credentialId, authenticatorData, clientDataJSON, passkeySignature, deviceSignature,
    });
    state.receiptName = 'receipt-' + cur.request.work_id + '.json';
    await persistSignedReceipt(cur);   // BEFORE any navigation: exact receipt, bound to this request, durable; the target is marked signed (never offered again)
    log('受領書を作った（' + cur.request.work_id + '）。「受領書を保存」で渡す', 'good');
    if (state.imported) returnToSites();
  }).catch((e) => log('承認できなかった: ' + errText(e), 'bad'))
    .finally(() => { state.busy = false; renderStatus(); runDeferredIncoming(); });
}

// One-way return: top-level navigation to ONE fixed Sites page, receipt in the fragment. No return trip to this app is needed.
// Interrupt point: a reload right after this returns (before location.assign) must still be able to re-deliver the exact signed receipt.
async function persistSignedReceipt(cur) {
  const kept = saveReceipt(pendingStorage(), cur.bytes, state.receiptText, await pendingHash(utf8(state.receiptText)), Date.now());
  markPendingSigned(pendingStorage(), cur.bytes);
  if (!kept.ok) log('受領書をこの端末に保存できなかった（' + kept.reason + '）。' + (kept.reason === 'outbox-full' ? '未返送の署名済み受領書が上限まで残っている（消さずに保持）。先にそれらを返す。' : '') + 'Siteへ返す前に閉じると失われる。すぐに「Sitesへ受領書を返す」を押す', 'bad');
  return kept;
}
function prepareReturnLink() {
  const url = state.receiptText ? receiptReturnUrl(state.receiptText) : null;
  if (!url) return null;
  let a = $('lnk-return');
  if (!a) {
    a = document.createElement('a');
    a.id = 'lnk-return';
    a.rel = 'noreferrer';
    a.textContent = 'Sitesへ受領書を返す';
    $('btn-save-receipt').after(a);
  }
  a.href = url;
  return url;
}
function returnToSites() {
  const url = prepareReturnLink();
  if (!url) { log('Sitesへ返せる形ではない（受領書を保存で渡す）', 'bad'); return; }
  log('Sitesへ自動で返す。進まない時は「Sitesへ受領書を返す」を押す', 'good');
  location.assign(url);
}

// Re-delivers the stored signed receipt(s), byte for byte, to the ONE fixed Site URL. Same bytes -> the Site is idempotent; no new signature is ever made.
// Automatic navigation is bounded (MAX_AUTO_REDELIVERIES per receipt); after that only the explicit link remains. Expired / invalid items were dropped by loadReceipts.
async function routeAllows(bytes) { return routeMatchesRequest(location.search, await pendingHash(bytes)); }
function noteNotificationRoute() { const r = routeFromSearch(location.search); if (r.n === 'received') log('通知から開いた: 署名の受領書が記録された（依頼 ' + r.r + '）。実行の完了を待つ', 'good'); else if (r.n === 'completed') log('通知から開いた: 読取専用の確認が完了した（依頼 ' + r.r + '）', 'good'); }
// Web push (candidate). INERT until VAPID_PUBLIC_B64U is set. The permission request MUST run inside the click handler (user gesture); nothing here signs, stores a receipt or reads keys.
function pushSupported() { return typeof navigator !== 'undefined' && 'serviceWorker' in navigator && typeof window !== 'undefined' && 'PushManager' in window && 'Notification' in window; }
function onEnablePush() {
  if (!pushSupported()) { log('このブラウザは通知に未対応（ホーム画面に追加したアプリで使える）', 'bad'); return; }
  const key = VAPID_PUBLIC_B64U ? b64uToBytes(VAPID_PUBLIC_B64U) : null;
  if (!key || key.length !== 65) { log('通知の公開鍵が未設定のため通知を有効にできない（承認後に設定）', 'bad'); return; }
  Notification.requestPermission().then(async (perm) => {        // called synchronously from the tap
    if (perm !== 'granted') { log('通知が許可されなかった。設定アプリの通知から許可できる', 'bad'); return; }
    const reg = (await navigator.serviceWorker.getRegistration()) || (await navigator.serviceWorker.register('sw.js', { scope: './' }));
    await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (sub && !sameBytes(new Uint8Array(sub.options.applicationServerKey), key)) {   // an existing subscription for ANOTHER key is never replaced automatically
      showPushReset();
      log('この端末は別の公開鍵で通知を登録済み。自動では置き換えない。鍵を替える場合だけ、下の「通知の登録をリセット」を意図して押す', 'bad');
      return;
    }
    sub = sub || (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }));
    const url = buildEnrollmentUrl(sub.toJSON());
    if (!url) { log('購読情報が想定外の形のため登録しない', 'bad'); return; }
    log('通知を許可した。Siteへこの端末の通知設定を登録する', 'good');
    location.assign(url);
  }).catch((e) => log('通知を有効にできなかった: ' + errText(e), 'bad'));
}
// The message must come from THIS origin's own registered sw.js (any of its installing/waiting/active workers: right after the first installation the page is not controlled yet,
// so navigator.serviceWorker.controller may be null and is NOT required). Foreign sources / origins / scripts are dropped before the payload is even looked at.
async function swMessageTrusted(ev) {
  if (!ev || ev.origin !== location.origin || !ev.source || typeof ev.source !== 'object') return false;
  let reg = null; try { reg = await navigator.serviceWorker.getRegistration(); } catch (e) { return false; }
  if (!reg) return false;
  const workers = [reg.installing, reg.waiting, reg.active].filter(Boolean);
  return workers.includes(ev.source) && ev.source.scriptURL === new URL('sw.js', location.href).href;
}
async function onSwMessage(ev) {
  if (!(await swMessageTrusted(ev))) { log('通知アプリ以外からのメッセージを無視した', 'bad'); return; }
  const d = ev.data;
  if (d && typeof d === 'object' && d.type === 'xgate-displayed') {   // the worker really called showNotification: this is the only "displayed" evidence the app can have
    if (Object.keys(d).sort().join() === 'id,kind,type' && ['approve', 'received', 'completed', 'test'].includes(d.kind) && /^[0-9a-f]{64}$/.test(d.id)) log('通知が端末に表示された（' + d.kind + '）', 'good'); else log('不正な表示メッセージを無視した', 'bad');
    return;
  }
  const m = await verifyOpenMessage(d, async (b) => pendingHash(b));
  if (!m.ok) { log('通知アプリからの不正なメッセージを無視した', 'bad'); return; }
  if (m.kind === 'approve') { history.replaceState(null, '', location.pathname + '?r=' + m.id.slice(0, 16) + '#req=' + m.req); await drainIncoming(); }   // busy-safe: never swaps a target while signing
  else log(m.kind === 'received' ? '通知: 署名の受領書が記録された' : '通知: 読取専用の確認が完了した', 'good');
}
// explicit, deliberate: only the button the user presses after the mismatch message
function showPushReset() { const b = $('btn-reset-push'); if (b) b.hidden = false; }
async function onResetPush() {
  try { const reg = await navigator.serviceWorker.getRegistration(); const sub = reg && (await reg.pushManager.getSubscription()); if (sub) await sub.unsubscribe(); log('この端末の通知の登録をリセットした。もう一度「通知を有効にする」を押す', 'good'); const b = $('btn-reset-push'); if (b) b.hidden = true; }
  catch (e) { log('リセットできなかった: ' + errText(e), 'bad'); }
}
// device-local display check: shows a test notification through the SAME service worker code path, with NO push service, key or server involved (needs the permission only)
async function onLocalDisplayTest() {
  try {
    if (!pushSupported() || Notification.permission !== 'granted') { log('先に「通知を有効にする」で通知を許可してください', 'bad'); return; }
    const reg = await navigator.serviceWorker.getRegistration(); if (!reg) { log('通知用ワーカーが未登録', 'bad'); return; }
    await reg.showNotification('通知テスト', { body: 'この端末内の表示テストです（Siteは経由しません）。', tag: 'xgate-local-test', data: { kind: 'test', id: '0'.repeat(64), req: null } });
    log('端末内の表示テストを出した。通知が表示されたか確認してください', 'good');
  } catch (e) { log('表示テストを出せなかった: ' + errText(e), 'bad'); }
}
function setupPush() {
  if (!pushSupported() || !VAPID_PUBLIC_B64U) return;            // inert: no worker, no button
  navigator.serviceWorker.register('sw.js', { scope: './' }).then((reg) => { if (reg.waiting) log('通知用ワーカーの新しい版が待機中（アプリを一度閉じると切り替わる。それまでの通知は今のワーカーで扱う）'); }).catch((e) => log('通知用ワーカーを登録できなかった: ' + errText(e), 'bad'));
  navigator.serviceWorker.addEventListener('message', (ev) => { onSwMessage(ev); });
  if (typeof navigator.serviceWorker.startMessages === 'function') navigator.serviceWorker.startMessages();   // addEventListener (unlike onmessage) does not start the message queue
  const b = document.createElement('button'); b.type = 'button'; b.id = 'btn-enable-push'; b.textContent = '通知を有効にする（この端末）';
  b.addEventListener('click', () => { onEnablePush(); });
  const lt = document.createElement('button'); lt.type = 'button'; lt.id = 'btn-local-notify-test'; lt.textContent = '通知の表示テスト（この端末内）'; lt.addEventListener('click', () => { onLocalDisplayTest(); });
  const rs = document.createElement('button'); rs.type = 'button'; rs.id = 'btn-reset-push'; rs.hidden = true; rs.textContent = '通知の登録をリセット（意図して押す）'; rs.addEventListener('click', () => { onResetPush(); });
  $('btn-test-request').before(b, document.createElement('br'), lt, document.createElement('br'), rs, document.createElement('br'));
}

// Startup. The #req fragment is scrubbed ONLY after its exact bytes are durably saved (or when it cannot be used at all);
// if saving failed the original fragment stays in the URL, so a reload re-imports the very same target instead of falling back to the old public file.
async function startupLoad() {
  const fromHash = requestFromFragment(location.hash);
  const hadFragment = location.hash.startsWith('#req=');
  const raw0 = location.hash;
  if (fromHash && !(await routeAllows(fromHash))) {   // a notification/Site URL names its request (?r=<id16>): the bytes must be that request, else nothing is loaded
    scrubIf(raw0); log('開いたURLの依頼IDと依頼の内容が一致しない。読み込まない', 'bad'); await restoreSavedPending(false, false);
  } else if (fromHash) {
    const out = await loadRequestFromFragment(fromHash);
    if (out.saved || !out.shown) scrubIf(raw0);
  } else if (hadFragment) {
    scrubIf(raw0);       // unusable fragment: nothing to keep
    log('Siteから受け取った依頼が正しい形式ではなかった。保存済みの依頼があればそれを使う', 'bad'); await restoreSavedPending(false, false);
  } else await restoreSavedPending(true, false);
  await redeliverPendingReceipts();
  noteNotificationRoute();
}

// An unrelated old receipt is NEVER auto-delivered over a target the user is looking at: automatic re-delivery is only for the receipt that matches the
// signed stored target while nothing else is shown. Every other undelivered receipt stays stored and is offered as an explicit recovery link.
function offerRecoveryLink(item) {
  let a = $('lnk-recover-' + item.id);
  if (!a) { a = document.createElement('a'); a.id = 'lnk-recover-' + item.id; a.rel = 'noreferrer'; $('btn-save-receipt').after(a); }
  a.textContent = '署名済みで未返送の前の受領書をSiteへ返す（' + item.id.slice(0, 8) + '）';
  a.href = receiptReturnUrl(item.receiptText);
  a.onclick = () => { noteReceiptAttempt(pendingStorage(), item.id); };
}
// Incoming #req while this document is ALREADY open (hashchange, pageshow / back-forward cache restore). Serialized; the latest URL wins (the hash is read when the
// run starts, never captured earlier); never swaps the target while a signing is in progress (deferred until it ends); an invalid fragment changes nothing but says so.
let incomingRunning = false, incomingDirty = false, incomingDeferred = false;
// removes the fragment only if it is still the one that was processed: a newer #req that arrived meanwhile must survive for the follow-up run
function scrubIf(raw) { if (location.hash === raw) history.replaceState(null, '', location.pathname + location.search); }
async function applyIncomingFragment() {
  const raw = location.hash;
  if (!raw.startsWith('#req=')) return;
  const bytes = requestFromFragment(raw);
  if (!bytes) { scrubIf(raw); log('Siteから受け取った依頼が正しい形式ではない。表示中の依頼は変えない', 'bad'); return; }
  if (state.current && state.current.bytes.length === bytes.length && state.current.bytes.every((x, i) => x === bytes[i])) return;   // already the displayed target
  const out = await loadRequestFromFragment(bytes);
  if (out.saved || !out.shown) scrubIf(raw);
  await redeliverPendingReceipts();
}

// ---- tap hand-off (sw.js stores the verified tapped request; see fragment.js decideOpenRecord) ----
function openHandoffDb() { return new Promise((res, rej) => { const q = indexedDB.open(OPEN_DB, 1); q.onupgradeneeded = () => { q.result.createObjectStore(OPEN_STORE); }; q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); }
async function openRecordOp(mode, fn) { const db = await openHandoffDb(); try { return await new Promise((res, rej) => { const tx = db.transaction(OPEN_STORE, mode); const r = fn(tx.objectStore(OPEN_STORE)); tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); tx.onabort = () => rej(tx.error); }); } finally { db.close(); } }
// delete the record ONLY if it is still exactly the one that was processed (a newer tap written meanwhile must survive); one readwrite transaction = compare + delete
function dropOpenRecordIf(rec) {
  return openHandoffDb().then((db) => new Promise((res, rej) => {
    const tx = db.transaction(OPEN_STORE, 'readwrite'); const st = tx.objectStore(OPEN_STORE); const g = st.get(OPEN_KEY);
    g.onsuccess = () => { const c = g.result; if (c && typeof c === 'object' && c.id === rec.id && c.req === rec.req && c.ts === rec.ts) st.delete(OPEN_KEY); };
    tx.oncomplete = () => { db.close(); res(); }; tx.onerror = () => { db.close(); rej(tx.error); }; tx.onabort = () => { db.close(); rej(tx.error); };
  }));
}
async function applyOpenRecord() {
  let rec; try { rec = await openRecordOp('readonly', (st) => st.get(OPEN_KEY)); } catch (e) { return; }
  if (rec === undefined) return;
  const now = Date.now();
  let bytes = null; try { bytes = rec && typeof rec.req === 'string' ? b64uToBytes(rec.req) : null; } catch (e) { bytes = null; }
  const ctx = { busy: state.busy, sameAsCurrent: !!(bytes && state.current && sameBytes(state.current.bytes, bytes)), signed: bytes ? await signedState(bytes) : 'unsigned' };
  const d = await decideOpenRecord(rec, now, pendingHash, ctx);
  let drop = true;
  if (d.action === 'defer') { incomingDeferred = true; return; }
  if (d.action === 'keep') { log('通知で開いた依頼が署名済みか確認できない。何も変えていない', 'bad'); return; }
  if (d.action === 'load') {
    const out = await loadRequestFromFragment(d.bytes);
    log(out.shown ? '通知で開いた依頼（' + workIdOf(d.bytes) + '）を表示した' : '通知で開いた依頼を表示できなかった。記録は残す', out.shown ? 'good' : 'bad');
    await redeliverPendingReceipts();
    drop = out.shown && out.saved;   // not shown / not saved on this device: keep the hand-off so a reload or the next resume re-imports the very same request (same intent as keeping an unsaved #req in the URL)
  } else if (d.action === 'consume') {
    if (d.reason === 'already displayed' && unsavedMarked()) {   // shown but never saved on this device: keep the hand-off until a save succeeds
      const sv = savePendingRequest(pendingStorage(), bytes, await pendingHash(bytes), Date.now(), 'fragment');
      if (sv.ok) { setUnsavedMark(false); log('通知で開いた依頼をこの端末に保存できた', 'good'); } else drop = false;
    }
    else if (d.reason !== 'already displayed') log('通知で開いた依頼は使わなかった（' + d.reason + '）', d.reason === 'expired' || d.reason === 'already signed' ? undefined : 'bad');
  }
  if (drop) { try { await dropOpenRecordIf(rec); } catch (e) { /* a leftover record is re-checked next time */ } }
}
async function drainIncoming() {
  if (incomingRunning) { incomingDirty = true; return; }
  incomingRunning = true;
  try {
    do {
      incomingDirty = false;
      if (state.busy) { incomingDeferred = true; return; }
      await applyIncomingFragment();
      await applyOpenRecord();
    } while (incomingDirty);
  } finally { incomingRunning = false; }
}
function runDeferredIncoming() { if (incomingDeferred) { incomingDeferred = false; return drainIncoming(); } }

// Explicit refresh (the button): same intake as above, but with the stale state cleared BEFORE the I/O and gated against signing / incoming #req races.
async function refreshFromFixedFile() {
  if (state.busy) { log('署名などの処理中は読み込み直せない。終わってからもう一度押す', 'bad'); return; }
  if (incomingRunning) { log('依頼を取り込み中。少し待ってからもう一度押す', 'bad'); return; }
  incomingRunning = true;
  try { clearPendingRequest(); setUnsavedMark(false); await intakeFixedFile(true); } finally { incomingRunning = false; }
  if (incomingDirty || location.hash.startsWith('#req=')) await drainIncoming();
}

async function redeliverPendingReceipts() {
  const r = await loadReceipts(pendingStorage(), Date.now(), pendingHash);
  for (const d of r.dropped) log('保存した受領書を使わない（' + d.reason + '）', d.reason === 'expired' ? undefined : 'bad');
  if (r.status === 'storage-unavailable') { log('保存した受領書を確認できない（保存領域を読めない）。署名済みの受領書が残っていても再送できない', 'bad'); return; }
  if (!r.items.length) return;
  const signed = state.current ? null : await readPendingRequest(pendingStorage(), Date.now(), pendingHash);
  const same = (b) => signed && signed.status === 'signed' && signed.bytes && signed.bytes.length === b.length && signed.bytes.every((x, i) => x === b[i]);
  const auto = r.items.find((it) => same(it.requestBytes) && it.attempts < MAX_AUTO_REDELIVERIES);
  for (const it of r.items) if (it !== auto) offerRecoveryLink(it);
  const others = r.items.filter((it) => it !== auto).length;
  if (others) log('署名済みで未返送の前の受領書が' + others + '件ある（保持している）。現在の依頼はそのまま。必要なら表示のリンクから返す', 'bad');
  if (!auto) return;
  state.receiptText = auto.receiptText; state.receiptName = 'receipt-redelivery.json';
  noteReceiptAttempt(pendingStorage(), auto.id);
  log('署名済みの受領書がまだSiteへ返っていない可能性がある。同じ受領書を再送する（新しい署名はしない）', 'good');
  returnToSites();
}

// Drops everything a previously shown request left behind and redraws, so a stale request can never stay signable.
function clearPendingRequest() {
  state.current = null;
  state.currentBlock = null;
  state.receiptText = null;
  state.imported = false;
  renderRequest();
  renderStatus().catch(() => {});
}

// A request handed over by the owner's private Site (/pending) in the URL fragment; the app's own strict parseRequest still decides whether it can be signed.
function pendingStorage() { try { return window.localStorage; } catch (e) { return null; } }
async function pendingHash(bytes) { return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))); }
function workIdOf(bytes) { try { return String(JSON.parse(new TextDecoder().decode(bytes)).work_id).slice(0, 40); } catch (e) { return '?'; } }
async function loadRequestFromFragment(bytes) {
  const saved = savePendingRequest(pendingStorage(), bytes, await pendingHash(bytes), Date.now(), 'fragment');
  try {
    await loadRequest(bytes);
    state.imported = true;
    if (saved.ok) { setUnsavedMark(false); log('Siteから署名待ちの依頼（' + workIdOf(bytes) + '）を受け取り、この端末に保存した。機械の値を確かめてから承認する', 'good'); }
    else { setUnsavedMark(true); log('Siteから署名待ちの依頼を受け取ったが、この端末に保存できなかった（' + saved.reason + '）。URLの依頼は消さずに残す（再読込しても同じ依頼を読み直す）。古い公開ファイルは自動では読まない。機械の値を確かめてから承認する', 'bad'); }
    return { shown: true, saved: saved.ok };
  } catch (e) {
    clearPendingRecord(pendingStorage());
    clearPendingRequest();
    log('Siteから受け取った依頼を表示できなかった: ' + errText(e), 'bad');
    return { shown: false, saved: false };
  }
}

// Restores the stored target (reload / suspension). The public fixed file is read ONLY when nothing was ever imported
// (or on the explicit button when nothing is stored) - never in the background behind a newer imported target.
const UNSAVED_MARK = 'xgate-unsaved-import';
function unsavedMarked() { try { return window.name === UNSAVED_MARK; } catch (e) { return false; } }
function setUnsavedMark(on) { try { window.name = on ? UNSAVED_MARK : ''; } catch (e) { /* best effort; the on-screen warning is the primary signal */ } }
async function restoreSavedPending(allowFile, explicit) {
  const r = await readPendingRequest(pendingStorage(), Date.now(), pendingHash);
  if (r.status === 'ok') {
    try { await loadRequest(r.bytes); state.imported = true; log('この端末に保存した署名待ちの依頼を復元した。機械の値を確かめてから承認する', 'good'); }
    catch (e) { clearPendingRequest(); log('保存した依頼を表示できなかった（署名は止めた）: ' + errText(e), 'bad'); }
    return;
  }
  if (r.status === 'none') {
    if (!explicit && unsavedMarked()) { clearPendingRequest(); log('保存できなかった依頼を受け取った後に再読込された。最新の依頼を確認できないため署名を止めた（古い公開ファイルは自動では読まない）。新しい依頼を開き直すか、読み込み直しを押す', 'bad'); return; }
    if (allowFile) { setUnsavedMark(false); await loadPendingRequest(); } else { clearPendingRequest(); log('署名待ちの依頼は保存されていない'); }
    return;
  }
  clearPendingRequest();
  if (r.status === 'signed') { log('保存した依頼は署名済み。再署名はしない。新しい依頼を待つ（古い公開ファイルは自動では読まない）', 'bad'); return; }
  if (r.status === 'expired') {
    clearPendingRecord(pendingStorage()); log('保存した依頼は承認の締切（' + r.approve_by + '）を過ぎた。署名できない', 'bad');
    if (allowFile) await loadPendingRequest();   // a newer valid fixed-file target may be picked; the app's strict parse + deadline check still decide (failure/expired => nothing signable)
    return;
  }
  if (r.status === 'invalid') { clearPendingRecord(pendingStorage()); log('保存した依頼が正しい形式ではない（' + r.reason + '）。署名を止めた', 'bad'); return; }
  log('この端末の保存領域を読めないため、最新の依頼を確認できない。署名を止めた。「署名待ちの依頼を読み込み直す」で公開ファイルを明示的に読める', 'bad');   // storage-unavailable
}

// Reads the ONE fixed same-origin file (connect-src 'self'); the app's own strict parseRequest still decides whether it can be signed.
// The ONLY path that reads the fixed public file (startup 'none' / 'expired' fallback AND the explicit button). One set of rules for all of it:
//  fetch (no-store) -> strict canonical acceptance (fragment.js) -> signature state must be KNOWABLE and unsigned -> not older than a newer valid unsigned stored target ->
//  the app's strict parseRequest + deadline check (loadRequest) -> persist (source 'file') only when signable. Anything else leaves NOTHING signable and never touches the stored state.
function sameBytes(a, b) { return a.length === b.length && a.every((x, i) => x === b[i]); }
const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
function createdMs(bytes) { try { const q = JSON.parse(new TextDecoder().decode(bytes)); return TS_RE.test(q.created_at) ? Date.parse(q.created_at) : NaN; } catch (e) { return NaN; } }
// -> 'signed' | 'unsigned' | 'unknown'. Unreadable stored state is UNKNOWN (never silently "unsigned").
async function signedState(bytes) {
  const p = await readPendingRequest(pendingStorage(), Date.now(), pendingHash);
  if (p.status === 'storage-unavailable') return 'unknown';
  if (p.status === 'signed' && p.bytes && sameBytes(p.bytes, bytes)) return 'signed';
  const r = await loadReceipts(pendingStorage(), Date.now(), pendingHash);
  if (r.status === 'storage-unavailable') return 'unknown';
  return r.items.some((it) => sameBytes(it.requestBytes, bytes)) ? 'signed' : 'unsigned';
}
async function intakeFixedFile(explicit) {
  const r = await loadFixedRequest((u, init) => fetch(u, init));
  if (r.status === 'none') { clearPendingRequest(); log(explicit ? '公開の署名待ちファイルは置かれていない。署名できる依頼はない' : '署名待ちの依頼は置かれていない', explicit ? 'bad' : undefined); return; }
  if (r.status === 'bad') { clearPendingRequest(); log('公開の署名待ちファイルを読めなかった（' + r.reason + '）。署名を止めた', 'bad'); return; }
  const sig = await signedState(r.bytes);
  if (sig === 'unknown') { clearPendingRequest(); log('署名済みかどうかを確認できない（この端末の保存領域を読めない）。署名を止めた。保存済みの依頼と受領書は変えていない', 'bad'); return; }
  if (sig === 'signed') { clearPendingRequest(); log('公開ファイルの依頼は署名済み。再署名はしない', 'bad'); return; }
  const stored = await readPendingRequest(pendingStorage(), Date.now(), pendingHash);
  if (stored.status === 'ok' && !sameBytes(stored.bytes, r.bytes)) {
    const fc = createdMs(r.bytes), sc = createdMs(stored.bytes);
    if (!Number.isFinite(fc)) { clearPendingRequest(); log('公開ファイルの依頼の作成時刻を確認できない。署名を止めた', 'bad'); return; }
    if (Number.isFinite(sc) && fc < sc) { clearPendingRequest(); log('公開ファイルの依頼（' + workIdOf(r.bytes) + '）は、保存済みのより新しい依頼（' + workIdOf(stored.bytes) + '）より古い。署名を止めた。保存済みの依頼は残してある（再読込で復元）', 'bad'); return; }   // equal second = distinct requests: the explicit file intent is followed
  }
  try {
    await loadRequest(r.bytes); state.imported = true;
    if (state.currentBlock) { log('公開ファイルの依頼は署名できない: ' + state.currentBlock + '。最新の依頼は通知をタップするか、Site /c5check の「未承認の check 依頼を開く」から開く。', 'bad'); return; }
    const sv = savePendingRequest(pendingStorage(), r.bytes, await pendingHash(r.bytes), Date.now(), 'file');
    log(sv.ok ? '公開ファイルの最新の依頼（' + workIdOf(r.bytes) + '）を読み込み、この端末に保存した。機械の値を確かめてから承認する' : '公開ファイルの最新の依頼（' + workIdOf(r.bytes) + '）を読み込んだが、この端末に保存できなかった（' + sv.reason + '）', sv.ok ? 'good' : 'bad');
  } catch (e) { clearPendingRequest(); log('公開ファイルの依頼を表示できなかった（署名は止めた）: ' + errText(e), 'bad'); }
}
async function loadPendingRequest() { await intakeFixedFile(false); }

function onSaveReceipt() {
  if (state.receiptText) saveFile(state.receiptName, state.receiptText);
}

function onReset() {
  if (!state.record || state.busy) return;
  const ok = window.confirm('この端末の鍵を消す？\n消すと公開中の keys.json と合わなくなり、セットアップからやり直しになる（passkey は「パスワード」アプリから別に消す）。');
  if (!ok) return;
  dbDelete()
    .then(() => { state.record = null; state.receiptText = null; log('この端末の鍵を消した'); })
    .catch((e) => log('消せなかった: ' + errText(e), 'bad'))
    .finally(() => { loadPublished().then(renderStatus); });
}

// ---------- start ----------
// Listeners are registered FIRST and the serializer stays gated (incomingRunning) for the whole startup (dbGet, loadPublished, startupLoad), so a #req that arrives
// meanwhile is never lost and never applied before initialization is safe; whatever is still pending is drained exactly once afterwards.
async function init() {
  incomingRunning = true;
  window.addEventListener('hashchange', () => { drainIncoming(); });
  window.addEventListener('pageshow', () => { drainIncoming(); });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') drainIncoming(); });
  try { await initInner(); } finally { incomingRunning = false; }
  await drainIncoming();   // also picks up a tap hand-off left by the service worker when the URL / message did not reach this page
}
async function initInner() {
  if (window.top !== window.self) return; // never run inside a frame; the page stays blank
  $('app').hidden = false;
  $('ver').textContent = PAGE_VERSION;
  const problems = environmentProblems();
  if (problems.length) {
    for (const b of document.querySelectorAll('button')) b.disabled = true;
    log('この環境では使えない: ' + problems.join('・'), 'bad');
    return;
  }
  $('btn-device').addEventListener('click', onCreateDeviceKey);
  $('btn-passkey').addEventListener('click', onCreatePasskey);
  $('btn-save-keys').addEventListener('click', onSaveKeys);
  $('btn-check-published').addEventListener('click', onCheckPublished);
  $('btn-check-device').addEventListener('click', onCheckDevice);
  $('btn-test-request').addEventListener('click', onMakeTestRequest);
  $('btn-approve').addEventListener('click', onApprove);
  $('btn-save-receipt').addEventListener('click', onSaveReceipt);
  $('btn-reset').addEventListener('click', onReset);
  try {
    state.record = await dbGet();
  } catch (e) {
    log('保存領域を読めない: ' + errText(e), 'bad');
  }
  await loadPublished();
  await renderStatus();
  const reload = document.createElement('button');
  reload.type = 'button';
  reload.id = 'btn-reload-pending';
  reload.textContent = '署名待ちの依頼を読み込み直す';
  reload.addEventListener('click', () => { refreshFromFixedFile(); });
  $('btn-test-request').before(reload, document.createElement('br'));
  setupPush();
  await startupLoad();
  if (!isStandalone()) log('ホーム画面アプリではない。セットアップは「ホーム画面に追加」した方で行う。');
}

init();
