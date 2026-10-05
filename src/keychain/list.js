'use strict';

/**
 * The Key Chain list - PUBLIC data only, by construction (owner, 2026-10-01).
 *
 * What a 16-byte key label cannot hold lives here: derived keys (no slot at
 * all), PGP certificates (user ID + the device's self-signatures), the
 * composite key's public certificate (the device cannot read it back), and
 * public keys the owner made to use elsewhere. The label tag on the key stays
 * the truth for slots; an entry for a slot is a cache of what it shows.
 *
 * Kept by the host (ok-rn: AsyncStorage) and exported/imported as a file, so it
 * moves to another phone or the desktop App. NEVER a private key: parse() and
 * createEntry() refuse anything that looks like one, because a list that is
 * shared and backed up casually is exactly where a private key must not land.
 *
 * File: {"format": "onlykey-keychain", "version": 1, "entries": [...]}, public
 * keys as hex.
 */

const { toHex, fromHex } = require('../bytes');
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const artifacts = require('./artifacts');

const FORMAT = 'onlykey-keychain';
const VERSION = 1;
const KINDS = ['slot', 'derived', 'external'];
const TYPES = ['ed25519', 'x25519', 'p256', 'secp256k1', 'rsa', 'mlkem768', 'xwing', 'composite'];

/* Field names a private key travels under, and text that only a private key carries. */
const PRIVATE_FIELDS = ['secret', 'privateKey', 'private', 'scalar', 'seed', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'blob'];
/* the own-identities mark, under any spelling an entry might bring it */
const OWN_FIELDS = ['yours', 'own', 'mine', 'ownIdentity'];
const PRIVATE_TEXT = /PRIVATE KEY|AGE-SECRET-KEY-|-----BEGIN PGP PRIVATE/i;

function refusePrivate(value, where) {
  if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
    for (const [k, v] of Object.entries(value)) {
      if (PRIVATE_FIELDS.includes(k)) {
        throw new Error(`the Key Chain list holds public data only - "${where}.${k}" looks like a private key`);
      }
      refusePrivate(v, `${where}.${k}`);
    }
  } else if (typeof value === 'string' && PRIVATE_TEXT.test(value)) {
    throw new Error(`the Key Chain list holds public data only - "${where}" contains private key text`);
  }
}

/** A stable id: the same key from the same place is the same entry. */
function entryId(e) {
  const where = e.kind === 'slot' ? `slot${e.slot}` : e.kind === 'derived' ? `${e.scheme}:${e.label}` : (e.name || '');
  return `${e.kind}:${where}:${e.type}:${toHex(sha256(e.publicKey)).slice(0, 16)}`;
}

/**
 * Validate and normalise one entry. publicKey may be bytes or hex.
 * @param {object} fields
 * @returns {object}
 */
function createEntry(fields) {
  refusePrivate(fields, 'entry');
  const e = { ...fields };
  /*
   * "Yours" (the own-identities mark behind the phone's red warning) is the
   * phone's alone - set and removed only there, with its confirm (spec session,
   * 2026-10-03). No entry carries it: not one a CLI or an agent records, not one
   * a file brings in. Dropped, so it can be neither set nor cleared this way.
   */
  for (const k of OWN_FIELDS) delete e[k];
  if (!KINDS.includes(e.kind)) throw new Error(`entry kind is one of ${KINDS.join(', ')}; got "${e.kind}"`);
  if (!TYPES.includes(e.type)) throw new Error(`entry type is one of ${TYPES.join(', ')}; got "${e.type}"`);
  e.publicKey = typeof e.publicKey === 'string' ? fromHex(e.publicKey) : Uint8Array.from(e.publicKey || []);
  if (!e.publicKey.length && e.type !== 'composite') throw new Error('an entry needs its public key');
  if (e.kind === 'slot' && !(Number.isInteger(e.slot))) throw new Error('a slot entry needs its slot number');
  if (e.kind === 'derived' && (!e.scheme || !e.label)) throw new Error('a derived entry needs its scheme and label');
  if (e.pgp !== undefined && (typeof e.pgp !== 'string' || !/BEGIN PGP PUBLIC KEY BLOCK/.test(e.pgp))) {
    throw new Error('an entry\'s pgp is an armored PUBLIC key block');
  }
  if (e.revocation !== undefined && (typeof e.revocation !== 'string' || !/BEGIN PGP PUBLIC KEY BLOCK/.test(e.revocation))) {
    throw new Error('an entry revocation is an armored PUBLIC key block');
  }
  if (!e.artifacts && e.publicKey.length) {
    try { e.artifacts = artifacts.forKey({ type: e.type, publicKey: e.publicKey }); } catch (_) { e.artifacts = {}; }
  }
  e.created = e.created || new Date().toISOString();
  e.id = entryId(e);
  return e;
}

/** The file. */
function serialize(entries) {
  return JSON.stringify({
    format: FORMAT,
    version: VERSION,
    entries: entries.map((e) => ({ ...e, publicKey: toHex(e.publicKey) })),
  }, null, 2);
}

/** Read a file back; every entry is checked again - a file is not trusted for being ours. */
function parse(text) {
  let doc;
  try {
    doc = JSON.parse(String(text));
  } catch (err) {
    throw new Error(`not a Key Chain file (${err.message})`);
  }
  if (!doc || doc.format !== FORMAT) throw new Error('not a Key Chain file (no "onlykey-keychain" format)');
  if (doc.version !== VERSION) throw new Error(`Key Chain file version ${doc.version}; this reads ${VERSION}`);
  if (!Array.isArray(doc.entries)) throw new Error('a Key Chain file has an entries list');
  return doc.entries.map(createEntry);
}

/**
 * Add `incoming` to `existing`. An entry with an id already present gets the
 * fields only the incoming copy has (`joined`) - nothing either side knew is
 * dropped. Keeping the existing copy as it was lost the computer's PGP
 * certificate on every okedge sync, and the next agent start put it back, so
 * every sync "moved" it again and asked for a press (the A13, 2026-10-05).
 * A twin (the same derived key under a hash and a name) becomes one entry.
 * @returns {{entries: object[], added: number, paired: number, joined: number, kept: number}}
 */
function merge(existing, incoming) {
  const byId = new Map(existing.map((e) => [e.id, e]));
  let added = 0;
  let paired = 0;
  let joined = 0;
  for (const e of incoming) {
    if (byId.has(e.id)) {
      const cur = byId.get(e.id);
      const one = combine(cur, e);
      if (sameEntry(one, cur)) continue;
      byId.set(one.id, one);
      joined += 1;
      continue;
    }
    const twin = findTwin([...byId.values()], e);
    if (twin) {
      const one = combine(twin, e);
      byId.delete(twin.id);
      byId.set(one.id, one);
      paired += 1;
      continue;
    }
    byId.set(e.id, e);
    added += 1;
  }
  return { entries: [...byId.values()], added, paired, joined, kept: incoming.length - added - paired - joined };
}

/*
 * ONE ENTRY PER KEY (spec session, 2026-10-03). The phone records a derive by
 * the label HASH it saw (`hash:…` - the firmware never has the text); a
 * computer records the same derive by its NAME (`ssh://…`, `gpg://…`). Same type
 * and the same public key = the same key: they become one entry under the name.
 */
const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/* the same entry, ignoring when it was last used (that moves by itself) */
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.keys(v).sort().reduce((o, k) => { o[k] = canonical(v[k]); return o; }, {});
  return v;
}
function sameEntry(a, b) {
  const text = (e) => { const o = JSON.parse(serialize([e])).entries[0]; delete o.lastSeen; return JSON.stringify(canonical(o)); };
  return text(a) === text(b);
}

/** The entry in `entries` holding the same derived key as `e` (type + public key), or null. */
function findTwin(entries, e) {
  if (e.kind !== 'derived' || !e.publicKey || !e.publicKey.length) return null;
  return entries.find((x) => x !== e && x.kind === 'derived' && x.type === e.type
    && x.publicKey && bytesEqual(x.publicKey, e.publicKey)) || null;
}

/** Two entries of one key -> one: the name over the hash, first seen earliest, last seen latest, everything each one knew. */
function combine(a, b) {
  const named = (x) => x.label && !String(x.label).startsWith('hash:');
  const [base, other] = named(b) && !named(a) ? [b, a] : [a, b];
  const one = { ...other, ...base };
  const hashOf = [a, b].map((x) => x.labelHash || (String(x.label).startsWith('hash:') ? String(x.label).slice(5) : null)).find(Boolean);
  if (hashOf) one.labelHash = hashOf;
  const times = (k, pick) => [a[k], b[k]].filter(Boolean).sort()[pick === 'min' ? 0 : 1] || a[k] || b[k];
  if (a.firstSeen || b.firstSeen) one.firstSeen = times('firstSeen', 'min');
  if (a.lastSeen || b.lastSeen) one.lastSeen = [a.lastSeen, b.lastSeen].filter(Boolean).sort().pop();
  const tools = [...new Set([...(a.tools || []), ...(b.tools || [])])];
  /* no tools on either side: none here either - an empty list would read as a change */
  if (tools.length) one.tools = tools; else delete one.tools;
  for (const k of ['pgp', 'pgpFingerprint', 'certCreated', 'certExpires', 'revocation', 'transport', 'rpIdHash', 'rpId', 'code']) {
    if (one[k] === undefined) one[k] = a[k] !== undefined ? a[k] : b[k];
  }
  return createEntry(one);
}

/** A short fingerprint to show beside an entry. */
const fingerprint = (publicKey) => toHex(sha256(publicKey)).slice(0, 16).match(/.{4}/g).join(' ');

module.exports = { FORMAT, VERSION, KINDS, TYPES, createEntry, serialize, parse, merge, findTwin, combine, fingerprint };
