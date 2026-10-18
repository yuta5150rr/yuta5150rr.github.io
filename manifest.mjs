// Change manifest of a PR (everything except the receipt itself, repo, PR number and base SHA), canonical and hashed.
// entry = [path, op, beforeSha256|null, afterSha256|null, beforeMode|null, afterMode|null]; op in add|modify|delete|mode; entries sorted by path (code-unit order), no duplicates.
import { createHash } from 'node:crypto';
export const MANIFEST_PREFIX = 'approval-manifest/v1\n';
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
// change = { path, before: { mode, bytes } | null, after: { mode, bytes } | null }
export function buildManifest(changes) {
  const out = []; const seen = new Set();
  for (const c of changes) {
    if (typeof c.path !== 'string' || c.path === '' || seen.has(c.path)) throw new Error('MANIFEST_PATH');
    seen.add(c.path);
    const b = c.before ? { mode: String(c.before.mode), h: sha256(c.before.bytes) } : null, a = c.after ? { mode: String(c.after.mode), h: sha256(c.after.bytes) } : null;
    if (!b && !a) throw new Error('MANIFEST_EMPTY_CHANGE');
    const op = !b ? 'add' : !a ? 'delete' : b.h !== a.h ? 'modify' : b.mode !== a.mode ? 'mode' : null;
    if (op === null) continue;                                         // unchanged: not a change
    out.push([c.path, op, b ? b.h : null, a ? a.h : null, b ? b.mode : null, a ? a.mode : null]);
  }
  return out.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
}
export const manifestDigest = (entries) => sha256(Buffer.concat([Buffer.from(MANIFEST_PREFIX), Buffer.from(JSON.stringify(entries))]));
// owner-side helper: digest of "README before -> after" content (what the person reviews before the request is issued)
export const digestOfFiles = (before, after) => manifestDigest(buildManifest(Object.keys({ ...before, ...after }).map((p) => ({
  path: p, before: p in before ? { mode: '100644', bytes: Buffer.from(before[p]) } : null, after: p in after ? { mode: '100644', bytes: Buffer.from(after[p]) } : null }))));
