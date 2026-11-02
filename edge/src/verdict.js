'use strict';

/**
 * THE VERDICT ON A COPY OF A KEY'S CHAIN - one answer for every host (the structure track S4 step 2, 2026-11-02; R27
 * "what counts as verified"; PROPOSAL-edge-chain-gold.md "check once, keep the verdict"). It was the ok-edge app's alone
 * (edgeStore evaluateWith), and its kept state lived in that app's memory only: every restart checked the whole chain
 * again. Here it is pure - no key, no storage, no time - and its STATE is plain data a host may keep (memory, a file, the
 * device's store), so the next check after a restart is as short as the next one in the same session.
 *
 *   verdict(copy, head, key, {held, prev, noFull, say}) -> {verdict, unverified, state, path} | null
 *
 *   copy     {deviceId, links: [{link, head, reveal?}] (bytes, by seq), anchor?: {seq, head}, seals?: [{seq, head,
 *            signature}], lastSeen?: {seq, head}}
 *   head     the key's head now: {seq, head: bytes, ringFrom} - or null / no head bytes (a host that holds no copy yet
 *            knows the seq, not the head): 'not-synced'
 *   key      what the key gave this session: {publicKey, publicKeyPq, checkpoint?: {seq, head, signature, signaturePq},
 *            openings?} - the checkpoint is the HYBRID ANCHOR: verified with both halves, or nothing is "verified"
 *   held     the links the key's ring still holds (pickup)
 *   prev     the state an earlier verdict returned (or null): what lets a check skip, or check only the new links
 *   noFull   the quick path only: null when only the full check would do (the caller runs it with the ring)
 *   say      a log line (the host's; nothing sensitive is said)
 *
 *   verdict     {kind: 'not-synced'} | {kind: 'verified', through, lost?, notHere?} | {kind: 'unsigned', through}
 *               | {kind: 'gap', through, from, to} | {kind: 'tampered', seq, reason}
 *   unverified  the seqs not drawn as checked (what is really missing; at or before an anchor)
 *   state       what to keep for the next check, or null: nothing is kept (a checkpoint that does not verify, or an
 *               unsigned result, is checked in full again, with the checkpoint asked afresh)
 *   path        'skipped' | 'new-links' | 'sealed' | 'full' | null (not-synced)
 *
 * THE STATE compares copies by a DIGEST of their links (SHA-256 over each link and its head, in order), not by the
 * records' identity in memory - so it survives a restart: {seq, head, count, lastSeq, lastHead, digest, verdict,
 * unverified} (hex and numbers only).
 */
const chain = require('./chain');
const codes = require('./codes');
const copy = require('./copy');
const { toHex, fromHex } = require('../../src/bytes');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');

const seqOf = (r) => chain.decodeLink(r.link).seq;
/* a key with no link yet signs its checkpoint at this seq (no link) */
const NO_SEQ = 0xffffffff;

/**
 * The digest of a copy's first n links (each link and its head, in order).
 * @param {Array<{link: Uint8Array, head: Uint8Array}>} links
 * @param {number} [n]
 * @returns {string}
 */
function digestOf(links, n = links.length) {
  const h = sha256.create();
  for (let i = 0; i < n; i++) { h.update(links[i].link); h.update(links[i].head); }
  return toHex(h.digest());
}

/*
 * THE ANCHOR A CHECK STARTS FROM, or null: a fresh copy is anchored at the key's checkpoint (no history read before it),
 * but once it holds the chain from its start the anchor no longer stands in for anything: the check runs from genesis
 * and every link is checked (seq 0, or a CONTINUE; or a LOSS in the copy covering everything before its first link -
 * the key accepted those as gone, and the full check verifies that LOSS like any link).
 */
function anchorOf(c) {
  if (!c.anchor) return null;
  /* re-anchored at a LOSS this copy holds: nothing before the lost range welds to what follows - checked from the LOSS */
  const at = c.anchor.seq;
  if (c.links.some((l) => seqOf(l) === at && chain.decodeLink(l.link).op === codes.OP.LOSS)) return c.anchor;
  const first = c.links[0];
  if (!first) return c.anchor;
  const f = chain.decodeLink(first.link);
  if (f.seq === 0 || f.op === codes.OP.CONTINUE) return null;
  const covered = copy.lossesIn(c.links).some((l) => l.from === 0 && l.to >= f.seq - 1);
  return covered ? null : c.anchor;
}

/*
 * THE SEALED START (BLOCKS.md): with nothing verified before, the newest seal at or below the copy's end, its signature
 * checked (P-256: an older checkpoint) with the public key the key gave this session, whose device id must be this
 * copy's. copy.assess then welds the stored links to it like any anchor. Anything that does not fit -> null (full check).
 */
function sealedStart(c, head, key, say) {
  if (!c.seals || !c.seals.length || !c.links.length) return null;
  const no = (why) => { say(`sealed start not used: ${why}`); return null; };
  if (!key || !key.publicKey) return no('the key gave no public key this session');
  let deviceId;
  try { deviceId = chain.deviceIdOf(key.publicKey); } catch { return no('the public key is not an Edge key'); }
  if (toHex(deviceId) !== toHex(c.deviceId)) return no('the public key is another device\'s');
  const lastSeq = seqOf(c.links[c.links.length - 1]);
  const seal = [...c.seals].reverse().find((x) => x.seq <= lastSeq && x.seq <= head.seq);
  if (!seal) return no('no seal at or below the end of the copy');
  if (!chain.verifyCheckpointP256({ deviceId, seq: seal.seq, head: seal.head }, seal.signature, key.publicKey)) return no(`the seal at #${seal.seq} does not verify`);
  return { seq: seal.seq, head: seal.head };
}

/**
 * @param {{deviceId: Uint8Array, links: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, anchor?: {seq: number, head: Uint8Array}|null, seals?: Array<{seq: number, head: Uint8Array, signature: Uint8Array}>, lastSeen?: {seq: number, head: Uint8Array}|null}} c
 * @param {{seq: number, head: Uint8Array|null, ringFrom: number}|null} head
 * @param {{publicKey?: Uint8Array|null, publicKeyPq?: Uint8Array|null, checkpoint?: {seq: number, head: Uint8Array, signature: Uint8Array, signaturePq?: Uint8Array|null}|null, openings?: any}|null} key
 * @param {{held?: Array<{link: Uint8Array, head: Uint8Array}>, prev?: any, noFull?: boolean, say?: (t: string) => void}} [opts]
 * @returns {{verdict: any, unverified: number[], state: any, path: string|null} | null}
 */
function verdict(c, head, key, { held = [], prev = null, noFull = false, say = () => {} } = {}) {
  /* no head bytes: the same as not synced, until a copy arrives - nothing kept changes */
  if (!head || !head.head) return { verdict: { kind: 'not-synced' }, unverified: [], state: prev, path: null };
  const id = toHex(c.deviceId).slice(0, 8);
  const headHex = toHex(head.head);
  const links = c.links;
  const last = links[links.length - 1];
  const digest = digestOf(links);
  const stateOf = (v, unverified) => ({
    seq: head.seq, head: headHex, count: links.length, lastSeq: last ? seqOf(last) : -1, lastHead: last ? toHex(last.head) : '',
    digest, verdict: v, unverified: [...unverified],
  });
  const done = (v, unverified, path, keep = true) => ({ verdict: v, unverified: [...unverified], state: keep ? stateOf(v, unverified) : null, path });
  /* prev's links are this copy's first prev.count links (and prev.count ones in all: the same copy) */
  const samePrefix = prev && prev.count <= links.length && (prev.count === links.length ? prev.digest === digest : digestOf(links, prev.count) === prev.digest);
  const sameCopy = samePrefix && prev.count === links.length;

  /*
   * ONE MOMENT OF THE KEY: the head and the checkpoint are separate reads, and a link that lands between them gives a
   * checkpoint for a NEWER head than the one checked. It is only one anchor: checked without it; the next check has both.
   */
  const emptyChain = key && key.checkpoint && key.checkpoint.seq === NO_SEQ;
  const cp = key && key.checkpoint && !emptyChain && key.checkpoint.seq <= head.seq ? key.checkpoint : null;
  if (key && key.checkpoint && !cp && !emptyChain) say(`verify ${id}: the key's checkpoint is for #${key.checkpoint.seq}, the head read was #${head.seq} - a link landed meanwhile; checked without it`);

  if (prev && prev.seq === head.seq && prev.head === headHex && sameCopy) {
    say(`verify ${id}: skipped (same head #${head.seq}, same copy)`);
    return { verdict: prev.verdict, unverified: prev.unverified.slice(), state: prev, path: 'skipped' };
  }
  /*
   * A verified copy may carry losses the person accepted (R24) - older history, unchanged while its records are: they and
   * the seqs they leave unverified carry over, and only the links after the copy's last verified one are new. A gap or a
   * red verdict always goes to the full check.
   */
  const grew = prev && (links.length > prev.count || head.seq > prev.seq);
  if (grew && prev.verdict.kind === 'verified' && prev.count > 0 && samePrefix) {
    const a = copy.assess(
      { links, openings: (key && key.openings) || {} },
      { publicKey: key && key.publicKey, publicKeyPq: (key && key.publicKeyPq) || null, deviceId: c.deviceId, head: { seq: head.seq, head: head.head }, held, checkpoint: cp },
      { from: { seq: prev.lastSeq, head: fromHex(prev.lastHead) }, ringFrom: head.ringFrom },
    );
    if (a.chain.ok && !a.chain.gaps.length && !a.open.length && !a.missing.length) {
      const { lost, notHere } = prev.verdict;
      say(`verify ${id}: new links #${prev.lastSeq + 1}..#${head.seq} only`);
      return done({ kind: 'verified', through: head.seq, ...(lost ? { lost } : {}), ...(notHere ? { notHere } : {}) }, prev.unverified, 'new-links');
    }
    say(`verify ${id}: new links not clean (${a.chain.failure ? `${a.chain.failure.reason} at #${a.chain.failure.seq}` : `${a.chain.gaps.length} gap(s), ${a.open.length} open, ${a.missing.length} missing`}) - full check`);
  }
  if (noFull) return null;

  /*
   * THE HYBRID ANCHOR (one ML-DSA anchor per copy, 2026-10-10): the key's live checkpoint must verify with both halves -
   * the older checkpoints (seals, openings) are checked by P-256 alone and are quantum-safe only through the welds up to
   * it. No fallback: a checkpoint without its ML-DSA-65 half, or a key that gave no ML-DSA-65 key, fails here.
   */
  let hybridOk = false;
  if (cp && key && key.publicKey) {
    try {
      hybridOk = chain.verifyCheckpoint({ deviceId: chain.deviceIdOf(key.publicKey), seq: cp.seq, head: cp.head }, cp.signature, key.publicKey, cp.signaturePq || null, key.publicKeyPq || null);
    } catch { hybridOk = false; }
    if (!hybridOk) {
      say(`verify ${id}: the key's checkpoint at #${cp.seq} does not verify with both halves (P-256 + ML-DSA-65)`);
      return done({ kind: 'tampered', seq: cp.seq, reason: 'bad-checkpoint' }, [], 'full', false);
    }
  }
  /* an anchored copy is checked from its anchor (the welds to the signed head prove it) */
  const anchor = anchorOf(c);
  const sealed = prev || anchor ? null : sealedStart(c, head, key, say);
  const assessWith = (seal) => copy.assess(
    { links, openings: (key && key.openings) || {} },
    { publicKey: key && key.publicKey, publicKeyPq: (key && key.publicKeyPq) || null, deviceId: c.deviceId, head: { seq: head.seq, head: head.head }, held, checkpoint: cp },
    anchor
      ? { from: { seq: anchor.seq, head: anchor.head }, ringFrom: head.ringFrom }
      : { ringFrom: head.ringFrom, ...(c.lastSeen ? { lastSeen: c.lastSeen } : {}), ...(seal ? { sealed: seal } : {}) },
  );
  let a = sealed ? assessWith(sealed) : null;
  let path = 'full';
  if (a && sealed && !a.chain.failure && !a.open.length) {
    path = 'sealed';
    say(`verify ${id}: sealed through #${sealed.seq}, full checks after it through #${head.seq}`);
  } else {
    if (a) say(`verify ${id}: the sealed start was not clean (${a.chain.failure ? `${a.chain.failure.reason} at #${a.chain.failure.seq}` : `${a.chain.gaps.length} gap(s), ${a.open.length} open`}) - full check`);
    say(`verify ${id}: full check through #${head.seq}${prev && prev.seq === head.seq && !sameCopy ? ' (the copy changed under the same head)' : ''}`);
    a = assessWith(null);
  }
  const result = a.chain;
  /* unverified is what is really missing (copy.assess `missing`), and nothing at or before the anchor was checked */
  const unverified = new Set();
  for (const g of a.missing) for (let s = g.from; s <= g.to; s++) unverified.add(s);
  if (anchor) for (const l of links) if (seqOf(l) <= anchor.seq) unverified.add(seqOf(l));
  const open = a.open;
  const lost = a.missing;
  let v;
  if (result.failure) v = { kind: 'tampered', seq: result.failure.seq, reason: result.failure.reason };
  /*
   * A GAP BENEATH A CONFIRMED CHECKPOINT: the key signed its head with both halves, the links after the gap weld up to it
   * - the missing links are history this device does not hold (notHere), and the copy counts as verified. Without that
   * signature a gap is still a gap.
   */
  else if (open.length && hybridOk) v = { kind: 'verified', through: head.seq, notHere: open, ...(lost.length ? { lost } : {}) };
  else if (open.length) v = { kind: 'gap', through: result.verifiedThrough, from: open[0].from, to: open[0].to };
  else if (lost.length) v = { kind: 'verified', through: head.seq, lost };
  else v = { kind: 'verified', through: result.verifiedThrough };
  /* VERIFIED NEEDS A SIGNATURE: no checkpoint verified with both halves in this check -> unsigned, never kept */
  if (v.kind === 'verified' && !hybridOk && head.seq >= 0) {
    say(`verify ${id}: no checkpoint of the key verified in this check - not checked yet (unsigned)`);
    return done({ kind: 'unsigned', through: v.through }, unverified, path, false);
  }
  return done(v, unverified, path);
}

/**
 * May links offered for a key's OWN chain be taken into its copy? (S4 step 6 - one set of rules for every host: the
 * desktop taking this computer's shared records, a CLI taking a copy it was given.) In: what merging them gave
 * (sync.merge: added, conflicts), the copy WITH them checked like any copy (its verdict, the seqs that check verified),
 * and its accepted losses (copy.lossesIn). Out: {ok: true} or {ok: false, refusal, detail}.
 *
 *   a fork (a link that disagrees with one the copy holds): refused - never chosen between
 *   the copy would not verify with them (other than a gap): refused
 *   EVERY LINK TAKEN IS A CHECKED ONE (Brad, 2026-10-11: "checking every field in a token means nothing if we never
 *   check the signature"): a link the check did not verify - welded to the key's signed checkpoint - is refused, unless
 *   it lies inside a range the key accepted as lost (a LOSS link, R24: the LOSS accounts for it, and the link after it
 *   welds to it - key 1, 2026-10-24). A gap verdict alone once let links inside the gap in unchecked; the real links at
 *   those seqs were refused later as a fork.
 *
 * @param {{added: Array<{link: Uint8Array}>, conflicts: number[], verdict: {kind: string}, verifiedSeqs: Set<number> | number[], losses?: Array<{from: number, to: number}>}} o
 * @returns {{ok: true} | {ok: false, refusal: string, detail: string}}
 */
function takeOwn({ added, conflicts, verdict: v, verifiedSeqs, losses = [] }) {
  if (conflicts.length) {
    return { ok: false, refusal: 'invalid', detail: `a fork: this copy holds different links at #${conflicts.join(', #')} - nothing taken; settle it in the app` };
  }
  if (added.length && v.kind !== 'verified' && v.kind !== 'gap') {
    return { ok: false, refusal: 'copy_unverified', detail: `with those links this copy would not verify (${v.kind}) - nothing taken` };
  }
  const verified = verifiedSeqs instanceof Set ? verifiedSeqs : new Set(verifiedSeqs);
  const lost = (seq) => losses.some((l) => l.from <= seq && seq <= l.to);
  const unchecked = added.map((r) => chain.decodeLink(r.link).seq).filter((seq) => !verified.has(seq) && !lost(seq));
  if (unchecked.length) {
    return { ok: false, refusal: 'copy_unverified', detail: `#${unchecked.slice(0, 5).join(', #')}${unchecked.length > 5 ? '…' : ''} cannot be checked against the key - nothing taken` };
  }
  return { ok: true };
}

module.exports = { verdict, digestOf, anchorOf, sealedStart, takeOwn, NO_SEQ };
