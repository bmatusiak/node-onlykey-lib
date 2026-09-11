'use strict';

/**
 * OpenSSH private keys, read without sshpk.
 *
 * The desktop app parses an SSH key with sshpk, a Node library it loads
 * through a runtime `require` precisely because it will not bundle
 * (ok-app-rewrite src/api/device/sshpkNode.ts:14). keys.js#fromSshpk was
 * written against sshpk's OUTPUT and has sat unreachable from mobile ever
 * since, waiting for a parser that runs under Hermes. This is that parser,
 * and it produces sshpk's shape on purpose - `{type, curve, part: {k|d|p,q:
 * {data}}}` - so fromSshpk is fed exactly what it was written for and no
 * second converter exists.
 *
 * One format: the "openssh-key-v1" container that ssh-keygen has written by
 * default since OpenSSH 7.8 (PROTOCOL.key in the OpenSSH source), which is
 * SSH wire encoding all the way down:
 *
 *     "openssh-key-v1\0"
 *     string ciphername   string kdfname   string kdfoptions   uint32 nkeys
 *     string publickey[nkeys]
 *     string private:  uint32 check  uint32 check  (equal when the key opens)
 *                      per key: string keytype, its fields, string comment
 *                      padding 1, 2, 3 … to the cipher block
 *
 * Per-type fields (the private half repeats the public one first):
 *     ssh-ed25519            string pub(32)  string priv(64 = seed ‖ pub)
 *     ecdsa-sha2-nistp256    string curve    string Q(65)  mpint d
 *     ssh-rsa                mpint n e d iqmp p q
 *
 * NOT handled, and said so rather than half-done:
 *  - a passphrase-protected key (ciphername other than "none"). Opening one
 *    needs bcrypt_pbkdf, which nothing in this package carries; the error
 *    names `ssh-keygen -p -N ""` so the caller can strip it first.
 *  - the older PEM forms ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"),
 *    which are ASN.1 and a different parser. `ssh-keygen -p -o` rewrites
 *    them into this container.
 *  - X25519 does not exist as an SSH key type, so the curve list is shorter
 *    than the PGP one by design.
 */

const { fromBase64 } = require('../bytes');

const MAGIC = 'openssh-key-v1\0';

/** A cursor over SSH wire encoding: uint32 lengths, big-endian. */
class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.at = 0;
  }
  uint32() {
    if (this.at + 4 > this.bytes.length) throw new Error('OpenSSH key is truncated');
    const b = this.bytes;
    const v = ((b[this.at] << 24) | (b[this.at + 1] << 16) | (b[this.at + 2] << 8) | b[this.at + 3]) >>> 0;
    this.at += 4;
    return v;
  }
  string() {
    const n = this.uint32();
    if (this.at + n > this.bytes.length) throw new Error('OpenSSH key is truncated');
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  text() {
    return String.fromCharCode(...this.string());
  }
}

/**
 * A fixed-width scalar from an SSH mpint: drop the sign-padding zero a
 * high-bit value carries, and left-pad one that was shortened by a leading
 * zero byte. OKSETPRIV takes exactly 32 bytes for an ECC key (prepareKey
 * checks), and an mpint is not fixed width.
 */
function fixedScalar(mpint, width) {
  let start = 0;
  while (start < mpint.length - 1 && mpint[start] === 0) start += 1;
  const trimmed = mpint.subarray(start);
  if (trimmed.length > width) throw new Error(`scalar is ${trimmed.length} bytes, wider than ${width}`);
  const out = new Uint8Array(width);
  out.set(trimmed, width - trimmed.length);
  return out;
}

/**
 * Parse an OpenSSH private key (the armoured text) into sshpk's shape.
 *
 * @param {string} text  "-----BEGIN OPENSSH PRIVATE KEY-----" … "-----END …"
 * @returns {{type: 'ed25519'|'ecdsa'|'rsa', curve?: string, comment: string, part: object}}
 */
function parsePrivateKey(text) {
  const src = String(text).trim();
  if (/-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/.test(src)) {
    throw new Error(
      'this is the older PEM form of an SSH key, which this port does not read; ' +
      'rewrite it with `ssh-keygen -p -o -f <file>` and load the result',
    );
  }
  if (/-----BEGIN PGP/.test(src)) {
    throw new Error('this is a PGP key, not an SSH key - use the PGP loader');
  }
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(src);
  if (!m) throw new Error('not an OpenSSH private key: no "BEGIN OPENSSH PRIVATE KEY" block');

  const blob = fromBase64(m[1].replace(/\s+/g, ''));
  const magic = String.fromCharCode(...blob.subarray(0, MAGIC.length));
  if (magic !== MAGIC) throw new Error('not an OpenSSH private key: bad magic');

  const r = new Reader(blob);
  r.at = MAGIC.length;
  const cipher = r.text();
  const kdf = r.text();
  r.string(); // kdf options
  const nkeys = r.uint32();
  if (nkeys !== 1) throw new Error(`OpenSSH key holds ${nkeys} keys; one was expected`);
  r.string(); // the public key, repeated inside the private section anyway

  if (cipher !== 'none' || kdf !== 'none') {
    throw new Error(
      `this key is protected with a passphrase (${cipher}/${kdf}), and opening one needs ` +
      'bcrypt_pbkdf, which this port does not carry; remove it first with ' +
      '`ssh-keygen -p -N "" -f <file>` and load the result',
    );
  }

  const priv = new Reader(r.string());
  const check1 = priv.uint32();
  const check2 = priv.uint32();
  if (check1 !== check2) throw new Error('OpenSSH key check values differ: the key is corrupt');

  const keytype = priv.text();
  let out;
  if (keytype === 'ssh-ed25519') {
    priv.string(); // pub
    const sk = priv.string(); // seed ‖ pub
    if (sk.length !== 64) throw new Error(`ed25519 private part is ${sk.length} bytes, expected 64`);
    out = { type: 'ed25519', part: { k: { data: Uint8Array.from(sk.subarray(0, 32)) } } };
  } else if (keytype === 'ecdsa-sha2-nistp256') {
    const curve = priv.text();
    if (curve !== 'nistp256') throw new Error(`ecdsa curve ${curve} does not match its key type`);
    priv.string(); // Q
    out = { type: 'ecdsa', curve: 'nistp256', part: { d: { data: fixedScalar(priv.string(), 32) } } };
  } else if (keytype === 'ssh-rsa') {
    priv.string(); // n
    priv.string(); // e
    priv.string(); // d
    priv.string(); // iqmp
    const p = priv.string();
    const q = priv.string();
    out = { type: 'rsa', part: { p: { data: Uint8Array.from(p) }, q: { data: Uint8Array.from(q) } } };
  } else if (/^ecdsa-sha2-nistp(384|521)$/.test(keytype)) {
    throw new Error(`${keytype} is not a curve the device holds (P-256 and Ed25519 are)`);
  } else {
    throw new Error(`unsupported SSH key type: ${keytype}`);
  }
  out.comment = priv.text();
  return out;
}

module.exports = { parsePrivateKey };
