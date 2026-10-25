'use strict';

/**
 * THE BUCKET TRADE between two paired devices of one bucket identity (ok-edge plan S3; Brad, 2026-10-25: "the desktop
 * app/cli has what's paired with this computer, so we trade with them - it could be ble or web-app remote"; "the stale
 * mobile device will most likely talk to the desktop at one point, so they trade when they can").
 *
 * A COMPUTER asks, the PEER (the phone, a remote) answers - three rounds over whatever carries their messages (the
 * cli pair over Bluetooth, the relay), each a message and its answer:
 *
 *   1. hello   computer -> {nonce, identity}            peer -> {nonce, proof of the computer's nonce}
 *   2. prove   computer -> {proof of the peer's nonce, HAVE}   peer -> {HAVE, GIVE}   (only after checking the proof)
 *   3. give    computer -> {GIVE}                        peer -> {taken}
 *
 * NOTHING BEFORE PROOF, AND NO HINT (Brad, 2026-10-24: "only replicate after proving identity, i dont want to fish for
 * buckets"). A proof is the device's BUCKET KEY signing the other side's fresh nonce (bucket-identity.js 'proof'),
 * with the certificate the bucket identity made for that key on the key itself - so only a device that held the key
 * of this bucket identity can make one. A peer shows no HAVE, no GIVE, nothing about its bucket until the computer's
 * proof checks; anything wrong - another identity, a bad proof, a replayed nonce, an out-of-order message - is the
 * same plain refusal, which says nothing about whether a bucket exists.
 *
 * WHAT IS TRADED is bucket/src/replicate.js's HAVE and GIVE: each side imports the other's changes into its own open
 * bucket by the store rules (the newer wins, archived values travel, entries join). The carrier is the caller's - it
 * must be the paired, encrypted channel (the cli pair) - and a GIVE inside it is the bucket's own records: the labels
 * and encrypted forms a bucket may hold, never a secret (bucket.js).
 *
 * Pure: no device, no wire; the caller passes its open bucket, its bucket key and certificate, and randomness.
 */

const rep = require('./replicate');
const bid = require('./bucket-identity');
const { toHex, fromHex } = require('../../src/bytes');

const TYPES = { HELLO: 'okbucket.hello', PROVE: 'okbucket.prove', GIVE: 'okbucket.give' };
const NONCE = 32;
const REFUSED = { ok: false, refusal: 'no' };

const enc = (b) => toHex(b);
const dec = (h) => fromHex(String(h));

/* what a proof signs: the other side's nonce, which side signs it, and the bucket identity - never valid elsewhere */
const proofBytes = (nonce, side, identity) => new Uint8Array([...nonce, ...new TextEncoder().encode(`|${side}|${identity}`)]);

/**
 * A device's proof of its bucket identity over the other side's nonce.
 * @param {{identityPublicKey: Uint8Array, bucketKey: {secretKey: Uint8Array, publicKey: Uint8Array}, certificate: Uint8Array, id: string}} me
 */
function prove(me, nonce, side) {
  return {
    identityPublicKey: enc(me.identityPublicKey),
    bucketPublicKey: enc(me.bucketKey.publicKey),
    certificate: enc(me.certificate),
    signature: enc(bid.sign(me.bucketKey, 'proof', proofBytes(nonce, side, me.id))),
  };
}

/* does this proof show a device of bucket identity `id`, over `nonce`, from `side`? Never throws. */
function checks(proof, nonce, side, id) {
  try {
    const identityPublicKey = dec(proof.identityPublicKey);
    if (bid.identityIdOf(identityPublicKey) !== id) return false;
    return bid.verify({
      identityPublicKey, bucketPublicKey: dec(proof.bucketPublicKey), certificate: dec(proof.certificate),
      purpose: 'proof', bytes: proofBytes(nonce, side, id), signature: dec(proof.signature),
    });
  } catch {
    return false;
  }
}

/**
 * The computer's side of one trade, round by round.
 * @param {{bucket: object, me: object, randomBytes: (n: number) => Uint8Array, rules?: object}} o
 *   bucket: this computer's open bucket (changed in place by take); me: its bucket identity, bucket key, certificate
 * @returns {{hello(): object, prove(answer: object): object|null, give(answer: object): object|null, finish(answer: object): {taken: object}|null}}
 */
function computerSide({ bucket, me, randomBytes, rules = {} }) {
  const nonce = randomBytes(NONCE);
  let mine = null;
  let theirs = null;
  let peerProven = false;
  return {
    hello: () => ({ type: TYPES.HELLO, v: 1, nonce: enc(nonce), identity: me.id }),
    /* the peer's answer to hello: its proof over our nonce - only then do we prove ourselves and show our HAVE */
    prove(answer) {
      if (!answer || !answer.ok || !answer.proof || !checks(answer.proof, nonce, 'peer', me.id)) return null;
      peerProven = true;
      mine = rep.summarize(bucket);
      return { type: TYPES.PROVE, v: 1, identity: me.id, proof: prove(me, dec(answer.nonce), 'computer'), have: mine };
    },
    /* the peer's HAVE and GIVE: take its GIVE, then give what it lacks */
    give(answer) {
      if (!peerProven || !answer || !answer.ok || !answer.have || !answer.give) return null;
      theirs = answer.have;
      const out = rep.give(bucket, mine, theirs);
      const taken = rep.take(bucket, answer.give, { rules });
      return { message: { type: TYPES.GIVE, v: 1, identity: me.id, give: out }, taken: taken.taken };
    },
    finish: (answer) => (answer && answer.ok ? { taken: answer.taken || {} } : null),
  };
}

/**
 * The peer's side (the phone, a remote): answers each round, holding a trade per computer between rounds.
 * @param {{bucket: () => object|null, me: () => object|null, randomBytes: (n: number) => Uint8Array, rules?: object, seen?: Set<string>}} o
 *   bucket / me: the open bucket and this device's bucket identity, bucket key and certificate - null while the bucket
 *   is not open (then every round is refused, the same way); seen: nonces already answered (no replay)
 * @returns {(message: object, from: string) => object|null} null for a message that is not a trade
 */
function peerSide({ bucket, me, randomBytes, rules = {}, seen = new Set() }) {
  const trades = new Map(); /* from -> {nonce, computerNonce, proven, theirs, mine} */
  return (message, from) => {
    if (!message || !Object.values(TYPES).includes(message.type)) return null;
    const b = bucket();
    const m = me();
    if (!b || !m || message.identity !== m.id) { trades.delete(from); return REFUSED; }
    if (message.type === TYPES.HELLO) {
      const theirNonce = String(message.nonce || '');
      if (theirNonce.length !== NONCE * 2 || seen.has(theirNonce)) return REFUSED;
      seen.add(theirNonce);
      const nonce = randomBytes(NONCE);
      trades.set(from, { nonce, proven: false });
      return { ok: true, nonce: enc(nonce), proof: prove(m, dec(theirNonce), 'peer') };
    }
    const t = trades.get(from);
    if (message.type === TYPES.PROVE) {
      if (!t || t.proven || !message.proof || !checks(message.proof, t.nonce, 'computer', m.id) || !message.have) {
        trades.delete(from);
        return REFUSED;
      }
      t.proven = true;
      t.mine = rep.summarize(b);
      return { ok: true, have: t.mine, give: rep.give(b, t.mine, message.have) };
    }
    /* GIVE: only after this computer's proof, once */
    if (!t || !t.proven || !message.give) { trades.delete(from); return REFUSED; }
    trades.delete(from);
    const r = rep.take(b, message.give, { rules });
    return { ok: true, taken: r.taken };
  };
}

module.exports = { TYPES, computerSide, peerSide, prove, checks };
