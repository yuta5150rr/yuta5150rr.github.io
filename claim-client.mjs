// claim-client.mjs (trust-root layout): gate-side client of the claim endpoint. The server (handler, service, OIDC verifier) lives in the Site worker, not in the trust root.
export class ClaimError extends Error { constructor(code) { super(code); this.name = 'ClaimError'; this.code = code; } }
export class ClaimUnknown extends Error { constructor(why) { super('CLAIM_UNKNOWN: ' + why); this.name = 'ClaimUnknown'; this.code = 'CLAIM_UNKNOWN'; } }
export function makeClaimClient({ endpoint, getToken, fetch: f = fetch, timeoutMs = 10_000 }) {
  if (!/^https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._-]+)*$/.test(endpoint)) throw new Error('CLAIM_ENDPOINT');
  const call = async (op, body) => {
    let res; try { res = await f(endpoint + '/' + op, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + await getToken() }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' }); } catch (e) { throw new ClaimUnknown('network'); }
    let o; try { o = await res.json(); } catch { throw new ClaimUnknown('answer'); }
    if (res.status === 200 && o && o.ok === true) return o;
    if (res.status === 409) throw new ClaimError(o && o.code === 'CLAIM_STATE' ? 'CLAIM_STATE' : 'CLAIM_CONFLICT');
    if (res.status >= 500) throw new ClaimUnknown('server ' + res.status);
    throw new ClaimError(o && o.code ? 'CLAIM_REFUSED_' + String(o.code).slice(0, 40) : 'CLAIM_REFUSED');   // 4xx: definite refusal (auth, args)
  };
  return { claim: ({ nonce, requestHash, target }) => call('claim', { nonce, request_hash: requestHash, target }), acquireSend: (h, t) => call('send', { request_hash: h, target: t }), markUnsent: (h, t) => call('unsent', { request_hash: h, target: t }), confirm: (h, t) => call('confirm', { request_hash: h, target: t }), get: (h) => call('get', { request_hash: h }) };
}
// inside GitHub Actions (permissions: id-token: write): the OIDC token for the claim audience
export async function actionsIdToken(env, f, audience) { const u = env.ACTIONS_ID_TOKEN_REQUEST_URL, t = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN; if (!u || !t || !/^https:\/\//.test(u)) throw new Error('NO_OIDC'); const r = await f(u + (u.includes('?') ? '&' : '?') + 'audience=' + encodeURIComponent(audience), { headers: { authorization: 'Bearer ' + t } }); const o = await r.json(); if (!o || typeof o.value !== 'string') throw new Error('NO_OIDC'); return o.value; }
