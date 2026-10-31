'use strict';

/**
 * edge/src/certify.js - WHAT THE OWNER KEY CERTIFIES, and how a host checks it (Brad, 2026-10-30: certify "can be used
 * to certify things used by the blockchain lib, so its generic, and that frees us from doing firmware changes for things
 * that need to be certified"). The firmware certifies an opaque 32-byte subject at a press - or, for a kind that accepts
 * it, under a budget - writes a link for it and signs (grants.certifyDigest). This registry is the only place that says
 * what a subject means: its tag, how it is built, and which approvals each kind accepts. A new certified kind is an
 * entry here and a bucket store, never a firmware change.
 *
 *   nametag     a device's name                       press only   grants.verifyStatement (its own shape)
 *   login-card  a device's LOGIN IDENTITY CARD         press only   below
 *   agent       an agent identity's creation info     press, or a budget ("the agent identity info is the only stuff it
 *                                                                    can autopress") - built with the agent identities
 *   revoke      an agent identity's revocation         press only
 *
 * THE LOGIN IDENTITY CARD (Brad, 2026-10-30: a manual login gets into the app, then "an edge certify that produces a bucket
 * login agent identity card that has the bucket identity the manual flow used ... then the card can be rebuilt with cert
 * and used for 1 press login after"; "each unique restored backup salt device id has its own card"). One per device: the
 * device id, the bucket identity, the key's site and exactly the requests a login makes - the bucket's derive and the
 * bucket key's derive (by label), the identity's signatures on slot 201 (its label, a cap). Everything in it is read
 * with no press, so any host rebuilds it; the certification (its link's seq, both owner signatures) is kept with the
 * bucket. The certification signs the device id and both checkpoint keys too: a device with a card is a device of
 * this owner - its log is yours, named or not.
 */

const crypto = require('../../src/crypto/provider');
const { utf8ToBytes, toHex, fromHex } = require('../../src/bytes');
const grants = require('./grants');
const chain = require('./chain');

const TAGS = Object.freeze({
  nametag: 'OKEDGE-NAMETAG-v1',
  'login-card': 'OKEDGE-CARD-v1',
  agent: 'OKEDGE-AGENT-v1',
  revoke: 'OKEDGE-AGENT-REVOKE-v1',
});
/* the approvals each kind accepts (grants.APPROVAL) */
const ACCEPTS = Object.freeze({
  nametag: [grants.APPROVAL.PRESS],
  'login-card': [grants.APPROVAL.PRESS],
  agent: [grants.APPROVAL.PRESS, grants.APPROVAL.BUDGET],
  revoke: [grants.APPROVAL.PRESS],
});

const HEX = (n) => new RegExp(`^[0-9a-f]{${n}}$`);
const isHex = (s, n) => typeof s === 'string' && HEX(n).test(s);

/**
 * A login card, canonical: the fields in one fixed order, hex lower-case, the derive labels sorted - so every host that
 * rebuilds it gets the same bytes. Throws on a malformed one.
 * @param {{device: string, identity: string, site: string, derives: string[], signs: {slot: number, label: string, cap: number}}} c
 */
function loginCard(c) {
  const device = String(c && c.device || '').toLowerCase();
  const identity = String(c && c.identity || '').toLowerCase();
  if (!isHex(device, 32)) throw new TypeError('certify: a login card names its device id (16 bytes, hex)');
  if (!isHex(identity, 64)) throw new TypeError('certify: a login card names its bucket identity public key (32 bytes, hex)');
  if (typeof c.site !== 'string' || !c.site) throw new TypeError('certify: a login card names the key\'s site');
  const derives = [...new Set((c.derives || []).map(String))].sort();
  if (!derives.length || derives.length > 3 || derives.some((d) => !d)) throw new TypeError('certify: a login card names 1 to 3 derive labels');
  const s = c.signs || {};
  const label = String(s.label || '').toLowerCase();
  if (s.slot !== 201 || !isHex(label, 64) || !Number.isInteger(s.cap) || s.cap < 1 || s.cap > 8) {
    throw new TypeError('certify: a login card\'s signs are {slot: 201, label (32 bytes hex), cap 1..8}');
  }
  return { v: 1, kind: 'login-card', device, identity, site: c.site, derives, signs: { slot: 201, label, cap: s.cap } };
}

/*
 * AN AGENT IDENTITY'S CREATION INFO (Brad, 2026-10-30: "we sign the creation info for the certs including time-creation /
 * expire and label/name (that cant change), then generate the pubcerts, and store it to sync"; "identities provide the
 * derivation labels that the agent can ask for"). Canonical: label (unique in the list, fixed for good), created and
 * expires (seconds; 0 = never), the derivation labels by kind ({ssh: 'ssh://user@host', gpg: '<user id>'}), the committer.
 * The public certificates are made from it afterwards (the gpg one with this created time) and travel beside it.
 */
const LABEL_MAX = 64;
function agentCard(c) {
  const label = String(c && c.label || '').trim();
  if (!label || [...label].length > LABEL_MAX || !/^[ -~]+$/.test(label)) throw new TypeError(`certify: an agent identity's label is 1 to ${LABEL_MAX} printable characters`);
  const u32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
  if (!u32(c.created) || c.created === 0) throw new TypeError('certify: an agent identity names when it was created (seconds)');
  if (!u32(c.expires)) throw new TypeError('certify: an agent identity\'s expires is seconds after created (0 = never)');
  const d = c.derive || {};
  const derive = {};
  if (d.ssh !== undefined) { if (!/^ssh:\/\/\S+$/.test(String(d.ssh))) throw new TypeError('certify: derive.ssh is ssh://user@host'); derive.ssh = String(d.ssh); }
  if (d.gpg !== undefined) { if (!String(d.gpg).trim()) throw new TypeError('certify: derive.gpg is a user ID'); derive.gpg = String(d.gpg); }
  if (!Object.keys(derive).length) throw new TypeError('certify: an agent identity provides at least one derivation label');
  const committer = c.committer ? { name: String(c.committer.name), email: String(c.committer.email) } : null;
  return { v: 1, kind: 'agent', label, created: c.created, expires: c.expires, derive, committer };
}

/** The 32 bytes the key certifies for a thing of this kind (the card's canonical JSON; a nametag its hash). */
function subjectOf(kind, thing) {
  if (kind === 'nametag') return grants.nametagHash(thing);
  if (kind === 'login-card') return crypto.sha256(utf8ToBytes(TAGS[kind] + JSON.stringify(loginCard(thing))));
  if (kind === 'agent') return crypto.sha256(utf8ToBytes(TAGS[kind] + JSON.stringify(agentCard(thing))));
  /* a revocation names the identity it ends: its label and its created time (the two that make it that one) */
  if (kind === 'revoke') return crypto.sha256(utf8ToBytes(TAGS[kind] + JSON.stringify({ label: String(thing.label), created: thing.created })));
  throw new TypeError(`certify: no subject builder for "${kind}" yet`);
}

/* a certification as the plugin returns it (bytes) -> as a host keeps it (hex), and back */
const BYTES = ['deviceId', 'publicKey', 'publicKeyPq', 'subject', 'ownerKey', 'ownerKeyPq', 'signature', 'signaturePq'];
const toStored = (c) => Object.fromEntries(Object.entries(c).map(([k, v]) => [k, BYTES.includes(k) ? toHex(v) : v]));
const fromStored = (c) => Object.fromEntries(Object.entries(c).map(([k, v]) => [k, BYTES.includes(k) && typeof v === 'string' ? fromHex(v) : v]));

/**
 * A certified thing as hosts keep and sync it: {kind, thing, certification (hex)}.
 * @param {string} kind @param {object} thing @param {object} certification edge.certify()'s answer
 */
function record(kind, thing, certification) {
  const canonical = kind === 'login-card' ? loginCard(thing) : kind === 'agent' ? agentCard(thing) : thing;
  /* the checkpoint OPS_CHECKPOINT firmware adds is not the certification's: a login card carries it as its top */
  const { checkpoint, ...cert } = certification;
  const rec = { v: 1, kind, thing: canonical, certification: toStored(cert) };
  if (kind === 'login-card' && checkpoint && checkpoint.head) rec.top = top(checkpoint);
  return rec;
}

/*
 * THE TOP (Brad, 2026-10-31: "provide it the top of the head between a checkpoint to the head, for edge to unlock
 * itself ... the top of the head needs to be carried in the login card"): the newest checkpoint the key signed (a
 * receipt's, a certify's, a budget start's or a proven head) and the links after it, as far as this host's copy goes.
 * A card carries it beside the owner-signed part (rec.top), so it is rebuilt on every sync without a press; verify()
 * below never reads it. A host that never used the key warms Edge from it (edge.warmUp): the key's own signatures
 * stand behind the checkpoint, the links weld on from its head, and the key confirms the head they reach.
 */
/* how far back a top's checkpoint may be from the key's head, in links ("the 1024 limits how far back a checkpoint may be") */
const TOP_REACH = 1024;

/**
 * The top as a card keeps it (hex). checkpoint: {seq, head, signature, signaturePq} with the head this host welded;
 * links: the raw links after it, oldest first.
 * @param {{seq: number, head: Uint8Array, signature: Uint8Array, signaturePq: Uint8Array}} checkpoint
 * @param {Uint8Array[]} links
 */
function top(checkpoint, links = []) {
  if (!checkpoint || !(checkpoint.head instanceof Uint8Array) || checkpoint.head.length !== 32) throw new TypeError('certify.top: a checkpoint with the 32-byte head this host welded');
  if (links.length > TOP_REACH) throw new RangeError(`certify.top: at most ${TOP_REACH} links after the checkpoint, not ${links.length}`);
  return {
    checkpoint: { seq: checkpoint.seq, head: toHex(checkpoint.head), signature: toHex(checkpoint.signature), signaturePq: toHex(checkpoint.signaturePq) },
    links: links.map((l) => toHex(l)),
  };
}

/**
 * Does this top stand? Both checkpoint signatures under the key's checkpoint keys (READ from the key, never from the
 * card), every link welding on from the checkpoint's head in order, and the checkpoint at most TOP_REACH links behind
 * the key's head. -> {ok: true, checkpoint, newest: {seq, head}, links: [{link, head}]} | {ok: false, reason}
 * @param {object} t a card's top @param {{deviceId: Uint8Array, publicKey: Uint8Array, publicKeyPq: Uint8Array, keySeq: number}} key
 */
function verifyTop(t, key) {
  const fail = (reason) => ({ ok: false, reason });
  try {
    if (!t || !t.checkpoint || !Array.isArray(t.links)) return fail('no-top');
    const cp = { seq: t.checkpoint.seq, head: fromHex(t.checkpoint.head), signature: fromHex(t.checkpoint.signature), signaturePq: fromHex(t.checkpoint.signaturePq) };
    if (!Number.isInteger(cp.seq) || cp.seq < 0 || cp.head.length !== 32) return fail('malformed');
    if (!Number.isInteger(key.keySeq) || cp.seq > key.keySeq) return fail('ahead-of-key');
    if (key.keySeq - cp.seq > TOP_REACH) return fail('too-far-back');
    if (!chain.verifyCheckpoint({ deviceId: key.deviceId, seq: cp.seq, head: cp.head }, cp.signature, key.publicKey, cp.signaturePq, key.publicKeyPq)) return fail('checkpoint-signature');
    let at = { seq: cp.seq, head: cp.head };
    const links = [];
    for (const hex of t.links) {
      const link = fromHex(hex);
      if (chain.decodeLink(link).seq !== at.seq + 1) return fail('links-out-of-order');
      at = { seq: at.seq + 1, head: chain.weld(at.head, link) };
      links.push({ link, head: at.head });
    }
    if (at.seq > key.keySeq) return fail('ahead-of-key');
    return { ok: true, checkpoint: cp, newest: at, links };
  } catch {
    return fail('malformed');
  }
}

/**
 * Is this record certified by MY owner keys, for exactly this thing, with an approval its kind accepts - and (a login
 * card) by the device it names? -> boolean (false on anything malformed).
 * @param {{kind: string, thing: object, certification: object}} rec
 * @param {Uint8Array} ownerKey @param {Uint8Array} ownerKeyPq the owner keys READ from the key (never from the record)
 */
function verify(rec, ownerKey, ownerKeyPq) {
  try {
    const c = fromStored(rec.certification || {});
    const subject = subjectOf(rec.kind, rec.thing);
    if (rec.kind === 'login-card' && toHex(c.deviceId) !== loginCard(rec.thing).device) return false;
    return grants.verifyCertification({ ...c, subject }, ownerKey, ownerKeyPq, ACCEPTS[rec.kind] || []);
  } catch {
    return false;
  }
}

/**
 * MAY THIS BUDGET OPEN? (Brad, 2026-10-30: Edge auto-presses only what is inside a certified card picked from the list.)
 * Every scope inside the card: a derive scope on one of its labels (cap 1), a sign scope on slot 201 with its label and
 * no more than its cap. The HOSTS enforce this today; `keyEnforces` (the firmware checking its own signature over the card
 * at GRANT_CREATE) is the gate for later - off, and a host never relies on it being on.
 * @param {{thing: object}} rec a verified login-card record @param {Array<object>} scopes as grants.encodeScopes takes them
 * -> {ok: true} | {ok: false, why}
 */
function budgetAllowed(rec, scopes) {
  let card;
  try { card = loginCard(rec && rec.thing); } catch (e) { return { ok: false, why: e.message }; }
  for (const s of scopes || []) {
    if (s.op === 17 && s.slot === 128) {
      if (!card.derives.includes(String(s.derive)) || s.cap !== 1) return { ok: false, why: `derive "${s.derive}" is not on the card` };
    } else if (s.op === 1 && s.slot === 201) {
      const label = s.label instanceof Uint8Array ? toHex(s.label) : String(s.label || '').toLowerCase();
      if (label !== card.signs.label || s.cap > card.signs.cap) return { ok: false, why: 'the sign is not the card\'s, or more than its cap' };
    } else {
      return { ok: false, why: `scope op ${s.op} slot ${s.slot} is not a login's` };
    }
  }
  return { ok: true };
}
const keyEnforces = false;

module.exports = { TAGS, ACCEPTS, TOP_REACH, loginCard, agentCard, subjectOf, record, top, verifyTop, verify, budgetAllowed, keyEnforces, toStored, fromStored };
