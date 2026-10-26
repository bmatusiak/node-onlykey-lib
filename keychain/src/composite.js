'use strict';

/**
 * The composite post-quantum PGP identity, kept in Key Chain.
 *
 * One OpenPGP v6 key whose signatures are ML-DSA-65 + Ed25519 and whose
 * encryption is ML-KEM-768 + X25519: safe while either half holds, so a
 * future quantum computer breaking X25519/Ed25519 does not open it. The
 * firmware (3.1.0+) holds the four private seeds in an RSA slot (key type
 * 0x67) and answers decrypt and sign there; nothing else of it is on the key.
 *
 * WHY KEY CHAIN KEEPS THE CERTIFICATE. The device cannot give the public
 * certificate back - the slot holds 160 bytes of seeds, not the packets and
 * self-signatures a PGP certificate is made of. The phone makes the key, so
 * the phone is the only place the certificate ever exists; lose it and the
 * key in the slot still decrypts, but nobody can encrypt to it any more. So
 * the entry carries it (`pgp`), and it is backed up and exported with the
 * rest of the list.
 *
 * THE PRIVATE HALF exists once, in memory, between make() and load(): the
 * blob is zeroed the moment the device has it, and discard() zeroes one
 * that is never loaded. It is never in an entry - createEntry refuses one.
 *
 * openpgp is passed in (the vendored PQC fork), as pgp-import and cert take
 * it: this module stays plain.
 */

const compositePgp = require('../../src/crypto/composite_pgp');
const list = require('./list');

/**
 * Make a composite key on the host. The blob is the private half: load() it
 * into a slot, or discard() it.
 * @param {object} openpgp the vendored PQC openpgp.js
 * @param {{name?: string, email?: string}} [who] the user ID on the certificate
 * @returns {Promise<{blob: Uint8Array, pgp: string, pgpFingerprint: string, userId: string}>}
 */
async function make(openpgp, { name, email } = {}) {
  const who = {};
  if (name) who.name = name;
  if (email) who.email = email;
  const { armoredPublicKey, blob } = await compositePgp.generateCompositeKey(openpgp, {
    userId: Object.keys(who).length ? who : undefined,
  });
  const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const userId = key.getUserIDs()[0] || '';
  return { blob, pgp: armoredPublicKey, pgpFingerprint: key.getFingerprint(), userId };
}

/** Zero a made key's private half; it can no longer be loaded. */
function discard(made) {
  if (made && made.blob) made.blob.fill(0);
  if (made) made.blob = null;
}

/**
 * Load a made key into an RSA slot (1-4), in config mode as OKSETPRIV
 * requires, then zero the blob. On a refusal the blob is kept, so the same
 * key can be loaded again once the reason is fixed - discard() it to give up.
 * @param {{loadKey: Function}} device the lib's device service
 * @param {number} slot
 * @param {object} made from make()
 * @param {{label?: string|null}} [opts] passed to loadKey: the slot's label tag
 * @returns {Promise<object>} the Key Chain entry for the slot
 */
async function load(device, slot, made, opts = {}) {
  if (!made || !made.blob) throw new Error('this composite key was already loaded or discarded');
  if (!Number.isInteger(slot) || slot < 1 || slot > 4) throw new Error(`a composite key goes in an RSA slot (1-4); got ${slot}`);
  await device.loadKey(slot, { type: compositePgp.PQC_KEY_TYPE_BYTE, key: made.blob }, opts);
  discard(made);
  return entry({ slot, pgp: made.pgp, pgpFingerprint: made.pgpFingerprint, name: made.userId });
}

/**
 * The Key Chain entry for a composite key in a slot: its certificate, its
 * fingerprint (what tells two composite keys in one slot apart - there is no
 * raw public key to hash), no public key bytes.
 */
function entry({ slot, pgp, pgpFingerprint, name, ...rest }) {
  if (!pgpFingerprint) throw new Error('a composite entry needs its PGP fingerprint');
  return list.createEntry({
    ...rest,
    kind: 'slot',
    slot,
    /* as a PGP key made in the App records them: Remove on the slot finds this entry */
    slots: [slot],
    type: 'composite',
    publicKey: new Uint8Array(0),
    pgp,
    pgpFingerprint,
    ...(name ? { name } : {}),
  });
}

/* ------------------------------------------------------------------ where a key is, now */
/*
 * KEY MANAGEMENT IS DYNAMIC (Brad, 2026-10-25: "i want the key management to be dymanic, its possible the user may
 * already be using the slot"). A composite key is loaded into an RSA slot once, in config mode - an advanced step,
 * and one the user may take with any tool. So no feature keeps a slot number as the truth: the Key Chain list says
 * where the key was, the key says what each slot holds now, and the slot used is worked out from both, every time.
 * Found by the Windows desktop and the A13 (testnet): the list said slot 4, a test had since put an RSA key there and
 * the composite key was in slot 3 - Cryptobox asked RSA slot 4 for a composite signature and the firmware refused.
 *
 * Nothing here writes to the key: reading the slots is OKGETLABELS and OKGETPUBKEY, out of config mode, no press.
 */
const tag = require('./tag');

const RSA_SLOTS = [1, 2, 3, 4];
const fpOf = (x) => String((x && x.pgpFingerprint) || '').toUpperCase();
const slotsOf = (e) => (Array.isArray(e.slots) && e.slots.length ? e.slots : [e.slot]).filter((n) => Number.isInteger(n));

/**
 * What RSA slots 1-4 hold, with their labels: probeKeySlot's answer per slot (empty / composite / rsa).
 * @param {{probeKeySlot: Function, readKeyLabels?: Function}} device the lib's device service
 * @returns {Promise<Array<{slot: number, kind: string, label: string}>>}
 */
async function readRsaSlots(device) {
  const labels = new Map();
  try {
    const { keys } = await device.readKeyLabels();
    for (const k of keys) labels.set(k.slot, k.label || '');
  } catch {
    /* labels only order the guesses; the probe is the answer */
  }
  const out = [];
  for (const slot of RSA_SLOTS) out.push({ ...(await device.probeKeySlot(slot)), label: labels.get(slot) || '' });
  return out;
}

/**
 * The slot to ask for this composite key, from the list and what the slots hold now. In order: a composite slot the
 * list has this key in; a composite slot labelled with its name; any other composite slot. A composite slot the list
 * gives to ANOTHER key is never chosen - the user is using it. The choice is a guess until the key answers: the
 * signature hook checks the answer against the certificate (composite_pgp registerCompositeHooks).
 * @param {object[]} entries the Key Chain list
 * @param {{pgpFingerprint: string, name?: string}} key the certificate's fingerprint and name
 * @param {Array<{slot: number, kind: string, label?: string}>} slots readRsaSlots()
 * @returns {{slot: number|null, candidates: number[], why: string|null}}
 */
function locate(entries, key, slots) {
  const fp = fpOf(key);
  const composites = slots.filter((p) => p.kind === 'composite').map((p) => p.slot);
  const here = (e) => e.type === 'composite' && list.present(e);
  const listed = new Set(entries.filter((e) => here(e) && fpOf(e) === fp).flatMap(slotsOf));
  const others = new Set(entries.filter((e) => here(e) && fpOf(e) !== fp).flatMap(slotsOf));
  const name = String(key.name || '');
  const labelled = (n) => {
    const t = tag.parseTag((slots.find((p) => p.slot === n) || {}).label);
    return Boolean(t && t.kind === 'pqc' && name && (name === t.name || name.startsWith(t.name)));
  };
  const free = composites.filter((n) => !others.has(n) || listed.has(n));
  const candidates = [
    ...free.filter((n) => listed.has(n)),
    ...free.filter((n) => !listed.has(n) && labelled(n)),
    ...free.filter((n) => !listed.has(n) && !labelled(n)),
  ];
  if (candidates.length) return { slot: candidates[0], candidates, why: null };
  const why = composites.length
    ? `every composite key on this OnlyKey (${composites.map((n) => `RSA${n}`).join(', ')}) is another key in your Key Chain`
    : 'this OnlyKey holds no composite key in RSA slots 1-4';
  return { slot: null, candidates, why };
}

/**
 * The list after a slot read: an entry whose slot now holds a different kind of key (or none) is marked gone - never
 * dropped (list.present). Returns null when nothing changed.
 * @param {object[]} entries
 * @param {Array<{slot: number, kind: string}>} slots probes of some slots (only those are judged)
 * @param {string} [when] ISO time
 * @returns {object[]|null}
 */
function reconcile(entries, slots, when = new Date().toISOString()) {
  /* only an answer that is sure: a slot that is empty, or holds a known type - an 'unknown' reply judges nothing */
  const kindAt = new Map(slots.filter((p) => p.kind === 'empty' || list.TYPES.includes(p.kind)).map((p) => [p.slot, p.kind]));
  let changed = false;
  const next = entries.map((e) => {
    if (e.kind !== 'slot' || !list.present(e)) return e;
    const judged = slotsOf(e).filter((n) => kindAt.has(n));
    if (!judged.length || judged.some((n) => kindAt.get(n) === e.type)) return e;
    changed = true;
    return { ...e, gone: when };
  });
  return changed ? next : null;
}

/**
 * The list after the key PROVED this composite key is in `slot` (a signature that checked against the certificate,
 * a message it decrypted): an entry for the key at that slot, last seen now - made from the certificate the list
 * already holds when the key was listed elsewhere.
 * @param {object[]} entries
 * @param {{pgp: string, pgpFingerprint: string, name?: string}} key
 * @param {number} slot
 * @param {string} [when]
 * @returns {object[]}
 */
function seen(entries, key, slot, when = new Date().toISOString()) {
  const fp = fpOf(key);
  const at = entries.find((e) => e.type === 'composite' && fpOf(e) === fp && slotsOf(e).includes(slot));
  if (at) return entries.map((e) => (e === at ? { ...e, lastSeen: when } : e));
  const made = entry({ slot, pgp: key.pgp, pgpFingerprint: key.pgpFingerprint, name: key.name, firstSeen: when, lastSeen: when });
  return list.merge(entries, [made]).entries;
}

/* ------------------------------------------------------------------ adopting a key already on the key */
/*
 * THE USER DECIDES (Brad, 2026-10-26: "they may want to adopt or create a new one, there choice"). A composite key can
 * be on the OnlyKey with no certificate in the Key Chain - loaded by another tool, made on another device, or its
 * entry lost. Make a new one (make + load) or ADOPT this one: a certificate the user picks (from Guest Book, an old
 * Key Chain entry, a paste) becomes the slot's entry once the slot proves it holds that key's private half - one press,
 * an Ed25519 signature over a fresh random challenge that must verify against the certificate's own Ed25519 key
 * (okpqc_sign signs exactly the bytes after the selector). Nothing is written to the key.
 */
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');

/**
 * A composite certificate's facts, or null when the text is not a composite (+PQC) public key.
 * @param {object} openpgp the vendored PQC openpgp.js
 * @param {string} pgp armored public key
 * @returns {Promise<{pgpFingerprint: string, name: string, eccPublicKey: Uint8Array}|null>}
 */
async function certificate(openpgp, pgp) {
  let key;
  try { key = await openpgp.readKey({ armoredKey: pgp }); } catch { return null; }
  const packet = key.keyPacket;
  const composite = openpgp.enums.publicKey.pqc_mldsa_ed25519;
  if (!packet || packet.algorithm !== composite || !packet.publicParams || !packet.publicParams.eccPublicKey) return null;
  if (key.isPrivate()) throw new Error('that is a PRIVATE key - Key Chain keeps public certificates only');
  return {
    pgpFingerprint: key.getFingerprint().toUpperCase(),
    name: key.getUserIDs()[0] || 'composite key',
    eccPublicKey: Uint8Array.from(packet.publicParams.eccPublicKey),
  };
}

/**
 * Prove that `slot` holds the private half of this certificate, and return its Key Chain entry. One press.
 * @param {{composite_sign: Function}} okcrypto
 * @param {object} openpgp
 * @param {{slot: number, pgp: string, randomBytes: (n: number) => Uint8Array, opts?: object, when?: string}} args
 * @returns {Promise<object>} the entry (merge it into the list)
 */
async function adopt(okcrypto, openpgp, { slot, pgp, randomBytes, opts = {}, when = new Date().toISOString() }) {
  if (!RSA_SLOTS.includes(slot)) throw new Error(`a composite key is in an RSA slot (1-4); got ${slot}`);
  const cert = await certificate(openpgp, pgp);
  if (!cert) throw new Error('that is not a composite (+PQC) public key');
  const challenge = randomBytes(32);
  const signature = await okcrypto.composite_sign(slot, compositePgp.HALF_ECC, challenge, opts);
  if (!ed25519.verify(signature, challenge, cert.eccPublicKey)) {
    throw Object.assign(new Error(`RSA${slot} holds a different composite key than ${cert.name}`), { code: 'EWRONGSLOT', slot });
  }
  return entry({ slot, pgp, pgpFingerprint: cert.pgpFingerprint, name: cert.name, firstSeen: when, lastSeen: when });
}

module.exports = { make, discard, load, entry, RSA_SLOTS, readRsaSlots, locate, reconcile, seen, certificate, adopt };
