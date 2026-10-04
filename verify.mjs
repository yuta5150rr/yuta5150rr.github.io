#!/usr/bin/env node
// verify.mjs - checks one approval receipt against keys.json (Node >= 18, no npm dependencies).
// Stage 0 covers the receipt itself (design 5: c, d, e, f, g). The pull-request checks
// (a, b, h, i, j) are added in the next stage and reuse matchGlob/isForbiddenPath from core.js.
//
//   node verify.mjs --keys keys.json --receipt receipt.json --repo owner/name --work-id id [--now 2026-10-05T00:00:00Z]
//
// Prints one JSON line. Exit code: 0 = valid, 1 = invalid, 2 = usage error.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  RP_ID, FormatError, utf8, toHex, bytesEqual, concatBytes,
  parseKeys, parseReceipt, parseRequest, parseTimestamp,
  challengeMessage, deviceMessage, checkClientData, checkAuthenticatorData,
} from './core.js';

const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());

export function fingerprint(spki) {
  return toHex(sha256(spki)).slice(0, 16);
}

function p256PublicKey(spki, what) {
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch (e) {
    throw new FormatError('PUBLIC_KEY_INVALID', what);
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new FormatError('PUBLIC_KEY_INVALID', what);
  }
  return key;
}

function ecdsaVerify(message, key, signature, dsaEncoding) {
  try {
    return cryptoVerify('sha256', Buffer.from(message), { key, dsaEncoding }, Buffer.from(signature));
  } catch (e) {
    return false; // malformed signatures count as invalid, never as an exception path that skips a check
  }
}

// All arguments are required: there is no "skip this check" mode.
export function verifyReceipt({ receiptBytes, keysBytes, expectedRepo, expectedWorkId, nowMs }) {
  if (typeof expectedRepo !== 'string' || typeof expectedWorkId !== 'string') throw new FormatError('EXPECTATION_MISSING');
  if (!Number.isFinite(nowMs)) throw new FormatError('NOW_MISSING');

  const keys = parseKeys(keysBytes);
  const receipt = parseReceipt(receiptBytes);
  const request = parseRequest(receipt.requestBytes);

  // (c) the request belongs to this repo and this work, and new success may still be issued
  if (request.repo !== expectedRepo) throw new FormatError('REPO_MISMATCH', request.repo);
  if (request.work_id !== expectedWorkId) throw new FormatError('WORK_ID_MISMATCH', request.work_id);
  if (!(nowMs < request.verify_by_ms)) throw new FormatError('VERIFY_BY_PASSED', request.verify_by);

  // (d) clientDataJSON: type, challenge = SHA-256("approval/v1\n" || R), origin
  const challenge = sha256(challengeMessage(receipt.requestBytes));
  checkClientData(receipt.clientDataJSON, challenge);

  // (e) authenticatorData: rpIdHash, user present, user verified
  checkAuthenticatorData(receipt.authenticatorData, sha256(utf8(RP_ID)));

  // (f) the registered passkey signed authenticatorData || SHA-256(clientDataJSON)
  if (!bytesEqual(receipt.credentialId, keys.credentialId)) throw new FormatError('CREDENTIAL_MISMATCH');
  const passkeyKey = p256PublicKey(keys.passkeyPublicKey, 'passkey');
  const signed = concatBytes(receipt.authenticatorData, sha256(receipt.clientDataJSON));
  if (!ecdsaVerify(signed, passkeyKey, receipt.passkeySignature, 'der')) throw new FormatError('PASSKEY_SIGNATURE');

  // (g) the device key (only in the home-screen app on the iPhone) signed the same challenge
  const deviceKey = p256PublicKey(keys.devicePublicKey, 'device');
  if (!ecdsaVerify(deviceMessage(challenge), deviceKey, receipt.deviceSignature, 'ieee-p1363')) {
    throw new FormatError('DEVICE_SIGNATURE');
  }

  return {
    ok: true,
    repo: request.repo,
    work_id: request.work_id,
    paths: request.paths,
    approve_by: request.approve_by,
    verify_by: request.verify_by,
    created_at: request.created_at,
    request_hash: toHex(challenge),
    passkey_key: fingerprint(keys.passkeyPublicKey),
    device_key: fingerprint(keys.devicePublicKey),
  };
}

function parseArgs(argv) {
  const out = {};
  for (let k = 0; k < argv.length; k += 2) {
    const name = argv[k];
    const val = argv[k + 1];
    if (!['--keys', '--receipt', '--repo', '--work-id', '--now'].includes(name) || val === undefined) return null;
    if (out[name] !== undefined) return null;
    out[name] = val;
  }
  if (!out['--keys'] || !out['--receipt'] || !out['--repo'] || !out['--work-id']) return null;
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    console.error('usage: node verify.mjs --keys keys.json --receipt receipt.json --repo owner/name --work-id id [--now YYYY-MM-DDTHH:MM:SSZ]');
    process.exit(2);
  }
  let result;
  try {
    const nowMs = args['--now'] ? parseTimestamp(args['--now'], '--now') : Date.now();
    result = verifyReceipt({
      receiptBytes: new Uint8Array(readFileSync(args['--receipt'])),
      keysBytes: new Uint8Array(readFileSync(args['--keys'])),
      expectedRepo: args['--repo'],
      expectedWorkId: args['--work-id'],
      nowMs,
    });
  } catch (e) {
    const code = e instanceof FormatError ? e.code : 'ERROR';
    console.log(JSON.stringify({ ok: false, code, detail: e.message }));
    process.exit(1);
  }
  console.log(JSON.stringify(result));
  process.exit(0);
}

let invokedPath = '';
try { invokedPath = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : ''; } catch (e) { invokedPath = ''; }
if (invokedPath === import.meta.url) main();
