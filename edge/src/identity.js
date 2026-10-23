'use strict';

/**
 * THE AGENT IDENTITY, kept by the phone with the chain (SPEC H7; Brad, 2026-10-20:
 * "edge should hold the identity (on the app side) with the block chain", shown in the
 * Edge Management drawer, "computer sets, phone keeps").
 *
 * One record per net (live / testnet):
 *
 *   {ssh: 'ssh://claude@nitro16', gpgUid: 'Claude (nitro16) <…>', committer: {name, email} | null,
 *    expires: <seconds after created, 0 = never>,
 *    cert: {armored, fingerprint, created, expires, signPublic}}
 *
 * The labels are what the key derives the agent's ssh and gpg keys from (agent derivation
 * v2); the certificate binds the derived gpg key to the user ID, and its creation time is
 * part of its fingerprint - so the record, not a file on one computer, is what makes every
 * computer the same agent with the same keys on GitHub.
 *
 * Two messages on the paired channel (as EDGE_NOTE / EDGE_REQUEST - from a PAIRED computer,
 * inside its encrypted session; the pairing says who sends):
 *
 *   {type: 'EDGE_IDENTITY_SET', v: 1, nonce, record}   -> {ok: true} once the person
 *        approved it on the phone's sheet, or {ok: false, refusal: 'refused'|'busy'|'invalid', detail}
 *   {type: 'EDGE_IDENTITY_GET', v: 1, nonce}           -> {ok: true, record: <record> | null}
 *
 * Pure: no storage and no I/O here. ok-rn keeps the record in AsyncStorage; for a hard key on USB
 * (no phone) the CLI keeps it in its bucket, per net (edge/cli/local-host.js, 2026-10-23); both use
 * these checks and these words.
 */
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');

const SET_TYPE = 'EDGE_IDENTITY_SET';
const GET_TYPE = 'EDGE_IDENTITY_GET';
const TYPES = [SET_TYPE, GET_TYPE];

const MAX_LABEL = 256;
const MAX_NAME = 128;
const MAX_ARMORED = 8192;

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);
const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const text = (v, max) => typeof v === 'string' && v.trim() !== '' && utf8ToBytes(v).length <= max;

/**
 * A record well formed? -> {ok: true} or {ok: false, reason}. The reason names the field,
 * because the computer that built a bad one is told exactly which.
 * @param {any} r
 * @returns {{ok: boolean, reason?: string}}
 */
function checkRecord(r) {
  const no = (reason) => ({ ok: false, reason });
  if (!r || typeof r !== 'object') return no('no record');
  if (!text(r.ssh, MAX_LABEL) || !/^ssh:\/\/\S+$/.test(r.ssh)) return no('ssh: an ssh://user@host label');
  if (!text(r.gpgUid, MAX_LABEL)) return no('gpgUid: a user ID such as "Name <email>"');
  if (r.committer !== null && r.committer !== undefined) {
    const c = r.committer;
    if (typeof c !== 'object' || !text(c.name, MAX_NAME) || !text(c.email, MAX_NAME)) return no('committer: {name, email}');
  }
  if (!isU32(r.expires)) return no('expires: seconds, 0 = never');
  const c = r.cert;
  if (!c || typeof c !== 'object') return no('cert: the certificate');
  if (typeof c.armored !== 'string' || !c.armored.includes('BEGIN PGP PUBLIC KEY BLOCK') || c.armored.length > MAX_ARMORED) return no('cert.armored: an armored public key');
  if (!isHex(c.fingerprint, 20)) return no('cert.fingerprint: 40 hex digits');
  if (!isU32(c.created) || c.created === 0) return no('cert.created: a unix time');
  if (!isU32(c.expires) || c.expires !== r.expires) return no('cert.expires: the record\'s expires');
  if (!isHex(c.signPublic, 32)) return no('cert.signPublic: the derived ed25519 key, 64 hex digits');
  return { ok: true };
}

/** Only the record's own fields, in a fixed order (a stored or sent record carries nothing else). */
function clean(r) {
  return {
    ssh: r.ssh,
    gpgUid: r.gpgUid,
    committer: r.committer ? { name: r.committer.name, email: r.committer.email } : null,
    expires: r.expires,
    cert: {
      armored: r.cert.armored,
      fingerprint: r.cert.fingerprint.toUpperCase(),
      created: r.cert.created,
      expires: r.cert.expires,
      signPublic: r.cert.signPublic.toLowerCase(),
    },
  };
}

/** The computer: "keep this identity" (the phone asks the person). */
function buildSet({ record, nonce = randomBytes(16) }) {
  const ok = checkRecord(record);
  if (!ok.ok) throw new RangeError(`edge identity: ${ok.reason}`);
  return { type: SET_TYPE, v: 1, nonce: toHex(nonce), record: clean(record) };
}

/** The computer: "which identity do you keep?" */
function buildGet({ nonce = randomBytes(16) } = {}) {
  return { type: GET_TYPE, v: 1, nonce: toHex(nonce) };
}

/**
 * The phone: a message well formed and new. seen: nonces already taken. -> {ok} or
 * {ok: false, reason: 'malformed' | 'replayed' | <the record's reason>}.
 * @param {any} msg
 * @param {{seen?: Set<string>}} [o]
 * @returns {{ok: boolean, reason?: string}}
 */
function verify(msg, { seen } = {}) {
  if (!msg || !TYPES.includes(msg.type) || msg.v !== 1 || !isHex(msg.nonce, 16)) return { ok: false, reason: 'malformed' };
  if (msg.type === SET_TYPE) {
    const r = checkRecord(msg.record);
    if (!r.ok) return r;
  }
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/** "7FBF 276C …" - a fingerprint the way the sheet and the drawer show it. */
function spacedFingerprint(fp) {
  return String(fp || '').toUpperCase().replace(/(.{4})/g, '$1 ').trim();
}

/**
 * The rows the phone's sheet and Edge Management show, and the CLI prints: the same words
 * everywhere (no screen invents its own).
 * @param {any} record
 * @returns {Array<[string, string]>}
 */
function rows(record) {
  if (!record) return [];
  /** @type {Array<[string, string]>} */
  const out = [
    ['ssh', record.ssh],
    ['gpg', record.gpgUid],
  ];
  if (record.committer) out.push(['committer', `${record.committer.name} <${record.committer.email}>`]);
  out.push(['certificate', spacedFingerprint(record.cert.fingerprint)]);
  out.push(['made', new Date(record.cert.created * 1000).toISOString().slice(0, 10)]);
  out.push(['expires', record.expires ? new Date((record.cert.created + record.expires) * 1000).toISOString().slice(0, 10) : 'never']);
  return out;
}

/** Two records the same identity (same labels, same certificate)? */
function same(a, b) {
  if (!a || !b) return false;
  return JSON.stringify(clean(a)) === JSON.stringify(clean(b));
}

module.exports = { SET_TYPE, GET_TYPE, TYPES, checkRecord, clean, buildSet, buildGet, verify, rows, same, spacedFingerprint };
