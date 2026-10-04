// app.js - approval page, stage 0: setup (device key + passkey), keys.json, and test signing.
// Nothing is loaded from other origins. Every dynamic text goes through textContent.
import {
  RP_ID, ORIGIN, ALG_ES256, FormatError,
  utf8, toHex, bytesEqual, b64uEncode, isP256Spki, formatTimestamp,
  parseRequest, parseKeys, serializeKeys, serializeReceipt,
  challengeMessage, deviceMessage, checkClientData, checkAuthenticatorData,
  isBroadPattern, patternTouchesForbidden, signingBlock,
} from './core.js';

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
    .finally(() => { state.busy = false; renderStatus(); });
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
    log('受領書を作った（' + cur.request.work_id + '）。「受領書を保存」で渡す', 'good');
  }).catch((e) => log('承認できなかった: ' + errText(e), 'bad'))
    .finally(() => { state.busy = false; renderStatus(); });
}

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
async function init() {
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
  if (!isStandalone()) log('ホーム画面アプリではない。セットアップは「ホーム画面に追加」した方で行う。');
}

init();
