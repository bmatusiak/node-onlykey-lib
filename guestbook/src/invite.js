'use strict';

/**
 * The invite a phone shows as a QR to swap keys in person (GUEST-BOOK-SPEC.md, "The QR +
 * Bluetooth key swap"; Brad, 2026-10-12: "only 1 user snap a qr, and both phones go into a
 * pubkey exchange prompt or sheet").
 *
 *   okrn://connect?v=2&id=<16 bytes>&t=<16 bytes>&b=<8 bytes>
 *
 *   id  names the showing phone's contact identity: the derived X-Wing key under
 *       "okrn-contact:v1" on its OnlyKey. The 1216-byte key itself is too big for a QR
 *       anyone can scan, so it comes over the link and must hash to this.
 *   t   a random token that lives only while the QR is open. Only someone who saw the QR has
 *       it, and the swap refuses a peer that cannot prove it - before anyone's OnlyKey is asked
 *       for a press.
 *   b   the link id: the showing phone advertises a Bluetooth service named by it, so the
 *       scanner connects to THIS phone, not any phone nearby.
 *
 * Nothing in it is secret for long and nothing in it is private: it is the in-person check
 * that replaces comparing codes. A QR that is photographed and used later finds no phone
 * advertising its `b`.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
/* Uint8Array helpers, never Buffer: Hermes has none, and the phone reads these invites */
const { toBase64Url: b64url, fromBase64Url, toHex, fromHex } = require('../../src/bytes');

const VERSION = 2;
const ID_LEN = 16;
const TOKEN_LEN = 16;
const LINK_LEN = 8;
const LABEL = 'okrn-contact:v1';

const te = new TextEncoder();
const fromB64url = (s) => { try { return fromBase64Url(String(s)); } catch { return new Uint8Array(0); } };

/** The id of a contact identity: SHA-256("okrn-contact/id/v1" || X-Wing public key), first 16 bytes. */
function idOf(publicKey) {
  const tag = te.encode('okrn-contact/id/v1');
  const all = new Uint8Array(tag.length + publicKey.length);
  all.set(tag, 0);
  all.set(publicKey, tag.length);
  return sha256(all).slice(0, ID_LEN);
}

/**
 * A new invite for this phone's contact identity.
 * @param {{publicKey: Uint8Array, randomBytes: (n: number) => Uint8Array}} p
 * @returns {{id: Uint8Array, token: Uint8Array, link: Uint8Array, url: string}}
 */
function makeInvite({ publicKey, randomBytes }) {
  if (!publicKey || publicKey.length !== 1216) throw new Error('an invite names a 1216-byte X-Wing contact key');
  const id = idOf(publicKey);
  const token = randomBytes(TOKEN_LEN);
  const link = randomBytes(LINK_LEN);
  const url = `okrn://connect?v=${VERSION}&id=${b64url(id)}&t=${b64url(token)}&b=${toHex(link)}`;
  return { id, token, link, url };
}

/**
 * Read an invite from what a QR scan or a link gave. Throws naming what is wrong.
 * @param {string} text
 * @returns {{id: Uint8Array, token: Uint8Array, link: Uint8Array}}
 */
function readInvite(text) {
  const m = /^okrn:\/\/connect\?(.+)$/.exec(String(text || '').trim());
  if (!m) throw new Error('not an OnlyKey contact invite (okrn://connect?...)');
  const q = {};
  for (const part of m[1].split('&')) {
    const [k, v] = part.split('=');
    if (k) q[k] = v || '';
  }
  if (q.v !== String(VERSION)) throw new Error(`an invite of version ${q.v || '?'}; this app reads version ${VERSION}`);
  const id = fromB64url(q.id || '');
  const token = fromB64url(q.t || '');
  const link = /^[0-9a-f]{16}$/.test(q.b || '') ? fromHex(q.b) : new Uint8Array(0);
  if (id.length !== ID_LEN || token.length !== TOKEN_LEN || link.length !== LINK_LEN) {
    throw new Error('this invite is damaged: its id, token or link id has the wrong length');
  }
  return { id, token, link };
}

module.exports = { VERSION, LABEL, ID_LEN, TOKEN_LEN, LINK_LEN, idOf, makeInvite, readInvite, toHex };
