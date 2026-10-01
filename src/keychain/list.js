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
  if (!KINDS.includes(e.kind)) throw new Error(`entry kind is one of ${KINDS.join(', ')}; got "${e.kind}"`);
  if (!TYPES.includes(e.type)) throw new Error(`entry type is one of ${TYPES.join(', ')}; got "${e.type}"`);
  e.publicKey = typeof e.publicKey === 'string' ? fromHex(e.publicKey) : Uint8Array.from(e.publicKey || []);
  if (!e.publicKey.length && e.type !== 'composite') throw new Error('an entry needs its public key');
  if (e.kind === 'slot' && !(Number.isInteger(e.slot))) throw new Error('a slot entry needs its slot number');
  if (e.kind === 'derived' && (!e.scheme || !e.label)) throw new Error('a derived entry needs its scheme and label');
  if (e.pgp !== undefined && (typeof e.pgp !== 'string' || !/BEGIN PGP PUBLIC KEY BLOCK/.test(e.pgp))) {
    throw new Error('an entry\'s pgp is an armored PUBLIC key block');
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
 * Add `incoming` to `existing`: an entry with an id already present is kept as
 * it was (the same key from the same place), everything else is added.
 * @returns {{entries: object[], added: number, kept: number}}
 */
function merge(existing, incoming) {
  const byId = new Map(existing.map((e) => [e.id, e]));
  let added = 0;
  for (const e of incoming) {
    if (byId.has(e.id)) continue;
    byId.set(e.id, e);
    added += 1;
  }
  return { entries: [...byId.values()], added, kept: incoming.length - added };
}

/** A short fingerprint to show beside an entry. */
const fingerprint = (publicKey) => toHex(sha256(publicKey)).slice(0, 16).match(/.{4}/g).join(' ');

module.exports = { FORMAT, VERSION, KINDS, TYPES, createEntry, serialize, parse, merge, fingerprint };
