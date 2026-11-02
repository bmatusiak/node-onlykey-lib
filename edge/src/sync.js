'use strict';

/**
 * Merging and checking copies of a key's chain - what is left of `onlykey-js edge sync` (removed 2026-11-02, Brad: "in
 * favor of bucket sync, because that handles more than just Edge, and it does the same thing"). Copies of a chain now
 * travel as the bucket's sealed rows through the room (bucket/src/sealedcopy.js); what every holder of a copy still needs
 * is here. Pure: no device, no Node built-ins.
 *
 *   merge(have, offered)    a copy's records + more, by seq; a seq on both sides with other bytes is a FORK - reported,
 *                           never chosen between
 *   anchorCheck({...})      another device's chain against its key's signed checkpoint and the heads seen before
 *   NO_SEQ                  the checkpoint seq of a key with no link yet
 *
 * The signed EDGE_SYNC_* messages (HAVE / LINKS / COMMIT / GIVE / OFFER), the computer-to-phone sync and the held
 * offers went with the command.
 */

const { toHex } = require('../../src/bytes');
const chain = require('./chain');

/* "no seq": a checkpoint of a key with no link yet (anchorCheck) */
const NO_SEQ = 0xffffffff;

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * A copy's records + the offered ones, by seq. A seq on both sides with different bytes is a FORK - reported, never
 * chosen between.
 * -> {links (sorted by seq), added: [records], conflicts: [seq]}
 */
function merge(have, offered) {
  const bySeq = new Map(have.map((r) => [chain.decodeLink(r.link).seq, r]));
  const added = [];
  const conflicts = [];
  for (const r of offered) {
    const seq = chain.decodeLink(r.link).seq;
    const mine = bySeq.get(seq);
    if (mine) {
      if (!sameBytes(mine.link, r.link) || !sameBytes(mine.head, r.head)) conflicts.push(seq);
      continue;
    }
    bySeq.set(seq, r);
    added.push(r);
  }
  const links = [...bySeq.entries()].sort((a, b) => a[0] - b[0]).map(([, r]) => r);
  added.sort((a, b) => chain.decodeLink(a.link).seq - chain.decodeLink(b.link).seq);
  return { links, added, conflicts };
}

/**
 * Before another device's log is kept, that chain must hold up - no I/O (devices.classify runs it). (Named for the
 * anchors it served until 2026-10-08; the check itself is unchanged.)
 *   records:    the copy of that chain merged with what came
 *   publicKey:  that device's checkpoint key (X || Y), as its statement names it
 *   publicKeyPq: its ML-DSA-65 twin (1952 bytes), as its statement names it
 *   checkpoint: {seq, head, signature, signaturePq} read from that device's key
 *   anchors:    [{seq, head}] the points of that chain kept before
 * ALARMS:
 *   bad-checkpoint - not signed by that device's keys (both halves of the hybrid);
 *   rollback       - that device's head is now older than one kept before;
 *   changed        - at a seq kept before, that device's chain now holds another head;
 *   tampered       - the links do not verify up to the signed checkpoint.
 * -> {ok: true, verifiedThrough, open} | {ok: false, alarm, seq?, detail?}
 *
 * @param {{records: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, publicKey: Uint8Array, publicKeyPq: Uint8Array,
 *   checkpoint: {seq: number, head: Uint8Array, signature: Uint8Array, signaturePq: Uint8Array}, anchors?: Array<{seq: number, head: Uint8Array}>}} o
 * @returns {{ok: boolean, alarm?: string, seq?: number, detail?: string, verifiedThrough?: number, open?: any[]}}
 */
function anchorCheck({ records, publicKey, publicKeyPq, checkpoint, anchors = [] }) {
  const copyLib = require('./copy');
  const deviceId = chain.deviceIdOf(publicKey);
  const cp = { seq: checkpoint.seq, head: Uint8Array.from(checkpoint.head) };
  if (!chain.verifyCheckpoint({ deviceId, ...cp }, checkpoint.signature, publicKey, checkpoint.signaturePq, publicKeyPq)) return { ok: false, alarm: 'bad-checkpoint', seq: cp.seq };
  /*
   * A key with no link yet signs NO_SEQ (0xffffffff): an empty chain, checked at once. Read as a seq, the check counted
   * toward four billion and hung (a new Pixel's first sync, 2026-10-08). A link past an empty checkpoint is not this chain's.
   */
  if (cp.seq === NO_SEQ) return records.length ? { ok: false, alarm: 'tampered', seq: cp.seq, detail: 'links offered past an empty checkpoint' } : { ok: true, verifiedThrough: -1, open: false };
  const newest = anchors.reduce((m, a) => (m === null || a.seq > m.seq ? a : m), null);
  if (newest && cp.seq < newest.seq) return { ok: false, alarm: 'rollback', seq: newest.seq, detail: `its head is #${cp.seq}, older than #${newest.seq} anchored before` };
  const upTo = records.filter((r) => chain.decodeLink(r.link).seq <= cp.seq);
  const bySeq = new Map(upTo.map((r) => [chain.decodeLink(r.link).seq, r]));
  for (const a of anchors) {
    const at = a.seq === cp.seq ? cp.head : bySeq.get(a.seq) ? bySeq.get(a.seq).head : null;
    if (at && toHex(at) !== toHex(a.head)) return { ok: false, alarm: 'changed', seq: a.seq, detail: `#${a.seq} holds another head than the one anchored` };
  }
  const v = copyLib.assess({ links: upTo }, { publicKey, publicKeyPq, head: cp, held: [], checkpoint: { ...cp, signature: checkpoint.signature, signaturePq: checkpoint.signaturePq } });
  if (v.chain.failure) return { ok: false, alarm: 'tampered', seq: v.chain.failure.seq, detail: v.chain.failure.reason };
  return { ok: true, verifiedThrough: v.chain.verifiedThrough, open: v.open };
}

module.exports = { NO_SEQ, merge, anchorCheck };
