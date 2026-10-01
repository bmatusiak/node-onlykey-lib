/*
 * src/crypto/ssh-pub.js - SSH public keys as an authorized_keys line, built
 * on any host: Node, a browser, React Native (Hermes).
 *
 * WHERE IT CAME FROM. cli/ssh-wire.js held these for the ssh-agent, on
 * Buffer, and said in its header that if a GUI ever wanted to SHOW an
 * authorized_keys line the byte helpers would move to src/ with Uint8Array
 * and the CLI would re-export them. Key Chain is that GUI, so they moved:
 * cli/ssh-wire.js now wraps these, and an Ed25519 or P-256 line from ok-rn is
 * the same line `onlykey-js agent` prints (test/ssh-pub.test.js holds both
 * against vectors frozen from the CLI before the move).
 *
 * WHERE THE RULES COME FROM. RFC 4251 5 (uint32, string, mpint), RFC 4253
 * 6.6 (ssh-rsa), RFC 5656 3.1 (ECDSA), RFC 8709 (Ed25519). The line layout -
 * type, base64 blob, comment - is OpenSSH's authorized_keys / .pub format.
 *
 * DEPENDENCY-LESS on purpose, as the agent was: a public key line is the
 * thing a server decides who you are by, so everything in it is here to be
 * read.
 */
'use strict';

const { utf8ToBytes, toBase64, concat } = require('../bytes');

/*
 * The two derived key types, by the names each side uses for them.
 *
 *   curve    lib-agent's name (`-e ed25519`, `-e nist256p1`), which is also
 *            what it prints in the key comment `<ssh://u@h|ed25519>`
 *   sshName  the SSH key-type string that opens every blob
 *   keyType  the OnlyKey's derivation key type (src/protocol/agent.js)
 *
 * secp256k1 and X25519 are derivable too, but ssh has no key type for either.
 * RSA is not here: it is not DERIVED - it is a key the user loaded into a
 * slot - so it has its own builder (rsaPublicKeyLine) below, and the agent's
 * identity grammar, which looks curves up in this table, does not grow an
 * entry it cannot derive.
 */
const CURVES = {
  ed25519: { curve: 'ed25519', sshName: 'ssh-ed25519', keyType: 1 },
  nist256p1: { curve: 'nist256p1', sshName: 'ecdsa-sha2-nistp256', keyType: 2, sshCurve: 'nistp256' },
};

const RSA_NAME = 'ssh-rsa';

/* ------------------------------------------------------------ primitives */

const toBytes = (v) => (typeof v === 'string' ? utf8ToBytes(v) : Uint8Array.from(v));

/** RFC 4251 uint32: four bytes, big-endian. */
function uint32(n) {
  const v = n >>> 0;
  return Uint8Array.of((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
}

/** RFC 4251 string: a uint32 length, then the bytes (a JS string is UTF-8). */
function string(v) {
  const bytes = toBytes(v);
  return concat([uint32(bytes.length), bytes]);
}

/**
 * RFC 4251 mpint, from an UNSIGNED big-endian magnitude.
 *
 * The rules that make this more than `string()`: two's complement, so a
 * positive number whose top bit is set gets a 0x00 in front, or it would read
 * as negative - every RSA modulus, whose top bit is set by construction,
 * gets one; and no UNNECESSARY leading bytes - "0x00 or 0xff are not
 * allowed" beyond that one - with zero as the empty string.
 *
 * lib-agent does not follow the second rule. formats.py ecdsa_verifier()
 * frames `b'\x00' + r` and `b'\x00' + s` unconditionally, so half its
 * signatures carry a redundant zero and any r below 2^248 keeps its own
 * leading zero bytes too. OpenSSH's sshbuf_get_bignum2_bytes_direct() strips
 * leading zeros and so accepts both; a stricter verifier (RFC 4251 says the
 * encoding is canonical) need not. This one emits the canonical form.
 */
function mpint(magnitude) {
  let b = toBytes(magnitude);
  let i = 0;
  while (i < b.length && b[i] === 0) i += 1;
  b = b.subarray(i);
  if (b.length && (b[0] & 0x80)) b = concat([Uint8Array.of(0), b]);
  return string(b);
}

/* ------------------------------------------------------------ blobs */

function curveInfo(curve) {
  const info = CURVES[curve];
  if (!info) throw new Error(`the SSH agent offers ${Object.keys(CURVES).join(' and ')}, not ${curve}`);
  return info;
}

/**
 * The SSH public-key blob for a key the OnlyKey returned.
 *
 *   ssh-ed25519          string "ssh-ed25519", string key(32)      RFC 8709
 *   ecdsa-sha2-nistp256  string name, string "nistp256",
 *                        string 0x04 || X || Y                     RFC 5656 3.1
 *
 * The device's P-256 reply is X||Y with no prefix (src/protocol/agent.js), so
 * the uncompressed-point 0x04 is added here.
 *
 * @param {'ed25519'|'nist256p1'} curve
 * @param {Uint8Array} raw
 * @returns {Uint8Array}
 */
function publicKeyBlob(curve, raw) {
  const info = curveInfo(curve);
  const key = toBytes(raw);
  if (info.keyType === 1) {
    if (key.length !== 32) throw new Error(`an Ed25519 public key is 32 bytes, not ${key.length}`);
    return concat([string(info.sshName), string(key)]);
  }
  if (key.length !== 64) throw new Error(`a P-256 public key from the device is X||Y, 64 bytes, not ${key.length}`);
  return concat([string(info.sshName), string(info.sshCurve), string(concat([Uint8Array.of(4), key]))]);
}

/*
 * type, base64 blob, comment - lib-agent's and OpenSSH's layout. No comment,
 * no trailing space: ssh-keygen writes a bare `type blob` the same way.
 */
function line(type, blob, comment) {
  const head = `${type} ${toBase64(blob)}`;
  return comment === undefined || comment === null || comment === '' ? head : `${head} ${comment}`;
}

/**
 * An authorized_keys line for a derived Ed25519 or P-256 key.
 *
 * @param {'ed25519'|'nist256p1'} curve
 * @param {Uint8Array} raw  the device's public key (32 bytes, or X||Y)
 * @param {string} [comment]
 * @returns {string}
 */
function publicKeyLine(curve, raw, comment) {
  return line(curveInfo(curve).sshName, publicKeyBlob(curve, raw), comment);
}

/* ------------------------------------------------------------ RSA */

/** An exponent as its big-endian magnitude, from a number or the bytes. */
function exponentBytes(e) {
  if (typeof e !== 'number') return toBytes(e);
  if (!Number.isSafeInteger(e) || e < 3) throw new Error(`an RSA public exponent is an integer of at least 3, not ${e}`);
  const out = [];
  for (let v = e; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return Uint8Array.from(out);
}

/**
 * The ssh-rsa public-key blob (RFC 4253 6.6):
 *
 *   string "ssh-rsa", mpint e, mpint n
 *
 * e BEFORE n - the reverse of PKCS#1's order, and the classic way to build a
 * blob that parses and names the wrong key. Both are mpints, so the modulus,
 * whose top bit is always set, carries the 0x00 sign byte (mpint above).
 *
 * @param {Uint8Array} modulus  n, unsigned big-endian (a slot's public key)
 * @param {{exponent?: number|Uint8Array}} [opts]  e, 65537 by default - what
 *   the OnlyKey and every mainstream generator use
 * @returns {Uint8Array}
 */
function rsaPublicKeyBlob(modulus, { exponent = 65537 } = {}) {
  const n = toBytes(modulus);
  let first = 0;
  while (first < n.length && n[first] === 0) first += 1;
  if (first === n.length) throw new Error('an RSA modulus cannot be zero');
  if (!(n[n.length - 1] & 1)) throw new Error('an RSA modulus is odd; these bytes are not one');
  const e = exponentBytes(exponent);
  if (!e.some((b) => b !== 0)) throw new Error('an RSA public exponent cannot be zero');
  return concat([string(RSA_NAME), mpint(e), mpint(n)]);
}

/**
 * An authorized_keys line for an RSA key.
 *
 * @param {Uint8Array} modulus
 * @param {string} [comment]
 * @param {{exponent?: number|Uint8Array}} [opts]
 * @returns {string}
 */
function rsaPublicKeyLine(modulus, comment, opts) {
  return line(RSA_NAME, rsaPublicKeyBlob(modulus, opts), comment);
}

module.exports = {
  CURVES,
  RSA_NAME,
  uint32,
  string,
  mpint,
  curveInfo,
  publicKeyBlob,
  publicKeyLine,
  rsaPublicKeyBlob,
  rsaPublicKeyLine,
};
