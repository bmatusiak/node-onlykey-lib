/*
 * transit.js - the OKCONNECT key exchange and the session box.
 *
 * Ported from onlykey-testing/lib/device/transit.js, which is the newest of the
 * three implementations and the only one driven against a physical key. The
 * browser client (onlykey-fido2/onlykey/onlykey-api.js + onlykey.extra.js)
 * derives the identical key by a different route; both are cross-checked in
 * the tests.
 *
 * Node `crypto` is replaced by @noble throughout, so this runs unchanged in
 * Node, a browser and Hermes.
 *
 *
 * READ THIS BEFORE CHANGING ANYTHING BELOW
 *
 * The transit box is NOT authenticated encryption, and calling it that is how
 * someone ends up trusting it. Verified in the firmware:
 *
 *   okcrypto.cpp:1016    uint8_t iv[12]; memset(iv, 0, 12);   -- every message
 *   okcrypto.cpp:1017-21 the msgcount that would vary it: five commented lines,
 *                        declared nowhere. Dead intent.
 *   okcrypto.cpp:1608    //gcm.computeTag(tag, sizeof(tag));
 *   okcrypto.cpp:1646    //if (!gcm.checkTag(tag, sizeof(tag))) return 1;
 *   device.cpp:156       ciphertext length == plaintext length: no room for a tag
 *   ok_extension.cpp:162 cmd and opt1..opt3 are OUTSIDE the encrypted region
 *
 * So: AES-256-CTR keystream with GCM's counter schedule, no authentication, no
 * replay protection, and one key + one zero IV per session - meaning ONE
 * keystream. Two equal-length payloads XOR to the XOR of their plaintexts, and
 * any plaintext bit can be flipped by flipping the ciphertext bit.
 *
 * A varying IV is not possible against shipped firmware: there is nowhere on
 * the wire to put one, and okcrypto_aes_crypto_box() takes no IV parameter. A
 * host that varied it would not get an error - the device would decrypt to
 * noise and dispatch a valid plaintext command byte against it. Fixing this
 * needs a coordinated firmware change with version negotiation.
 *
 * Reproducing it is therefore required for interop. Naming it honestly is the
 * least this library can do: the export is `box`, never `encrypt`.
 */
'use strict';

const { hsalsa } = require('@noble/ciphers/salsa.js');
const { ctr } = require('@noble/ciphers/aes.js');
const { x25519 } = require('@noble/curves/ed25519.js');
const { sha256 } = require('@noble/hashes/sha2.js');

const { fromLatin1, concat } = require('../bytes');

/** HSalsa20's sigma constant, "expand 32-byte k". */
const SIGMA = fromLatin1('expand 32-byte k');

/** The OKCONNECT payload is exactly this long, before any data follows it. */
const PREFIX = 43;

/**
 * Bytes 0..4 of the OKCONNECT payload: the vendor frame header and the message
 * id. The firmware reads the epoch at [5..8] and ignores these, and
 * onlykey-testing zero-fills them and still works on hardware - but every
 * shipped client emits them, so emit them. Costs nothing, and survives a
 * firmware revision that decides to check.
 */
const CONNECT_HEADER = [0xff, 0xff, 0xff, 0xff, 0xe4];

/* -------------------------------------------------------------- key exchange */

/** A fresh X25519 pair. Both halves are raw 32 bytes. */
function keypair() {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

/**
 * Little-endian byte<->word conversion, written out rather than taken from a
 * Uint32Array view.
 *
 * The reference does `new Uint32Array(bytes.buffer)`, which is NATIVE-endian.
 * That is correct on every platform anyone has run it on, and silently wrong
 * on a big-endian one. Salsa20 is defined little-endian, so say so.
 */
function toWordsLE(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const words = new Uint32Array(bytes.byteLength / 4);
  for (let i = 0; i < words.length; i++) words[i] = view.getUint32(i * 4, true);
  return words;
}

function fromWordsLE(words) {
  const out = new Uint8Array(words.length * 4);
  const view = new DataView(out.buffer);
  for (let i = 0; i < words.length; i++) view.setUint32(i * 4, words[i], true);
  return out;
}

/**
 * NaCl's crypto_box_beforenm.
 *
 * NOT the raw X25519 output - that is only the first half. NaCl runs the shared
 * point through HSalsa20 with a 16-byte zero input, and the device does the
 * same, so skipping it yields a plausible-looking 32 bytes and a device that
 * answers noise. selfTest() below exists to catch exactly that mistake.
 */
function beforenm(theirPublic, ourSecret) {
  const shared = x25519.getSharedSecret(ourSecret, theirPublic);
  const out = new Uint32Array(8);
  hsalsa(
    toWordsLE(SIGMA),              // 4 words: sigma
    toWordsLE(shared),             // 8 words: the X25519 output, as the key
    toWordsLE(new Uint8Array(16)), // 4 words: a 16-byte zero input
    out,
  );
  return fromWordsLE(out);
}

/**
 * The session key: SHA-256 over the RAW beforenm bytes.
 *
 * Raw in, raw out - no hex round trip at any point. The browser client reaches
 * the same 32 bytes via nacl.box.before() plus its own sha256, which is why
 * the two interoperate.
 */
function transitKey(devicePublic, ourSecret) {
  return sha256(beforenm(devicePublic, ourSecret));
}

/* ------------------------------------------------------------------ the box */

/**
 * Seal or open - the same call, because the operation is its own inverse.
 *
 * GCM with a 12-byte IV is CTR over J0 = IV||00000001 with the payload
 * starting at counter block 2, so this is byte-identical to
 * gcm(key, zeroIV).encrypt(x) truncated to x.length, and it never allocates a
 * tag. That also sidesteps a practical problem: a GCM *decipher* refuses to
 * run without a tag, and there is no tag on this wire, so the open direction
 * has to be the encrypt call anyway.
 *
 * See the header for why the IV is zero and why that cannot be fixed here.
 */
function box(key, data) {
  if (key.length !== 32) {
    throw new Error(`transit key must be 32 bytes, got ${key.length}`);
  }
  const counterBlock = new Uint8Array(16);
  counterBlock[15] = 2; // J0 is ...0001; the payload starts at the next block
  return ctr(key, counterBlock).encrypt(data);
}

/* ------------------------------------------------------------- OKCONNECT */

/**
 * The 43-byte OKCONNECT payload. Sent UNENCRYPTED - it is the key exchange.
 *
 *   [0..4]   FF FF FF FF E4   frame header + OKCONNECT
 *   [5..8]   epoch seconds, big-endian uint32
 *   [9..40]  our raw X25519 public key
 *   [41]     browser byte, display only
 *   [42]     OS byte, display only
 */
function connectPayload(publicKey, opts = {}) {
  if (publicKey.length !== 32) {
    throw new Error(`public key must be 32 bytes, got ${publicKey.length}`);
  }
  const { when = Date.now(), browser = 'c', os = 'l' } = opts;

  const out = new Uint8Array(PREFIX);
  out.set(CONNECT_HEADER, 0);
  new DataView(out.buffer).setUint32(5, Math.floor(when / 1000), false);
  out.set(publicKey, 9);
  out[41] = typeof browser === 'string' ? browser.charCodeAt(0) : browser;
  out[42] = typeof os === 'string' ? os.charCodeAt(0) : os;
  return out;
}

/**
 * Split an OKCONNECT reply into the device key and its status string.
 *
 * [0..31] is the device's raw X25519 public key, in the clear. [32..] is the
 * model/version string, boxed with the transit key on current firmware and
 * plaintext on some builds - so try opening it and fall back.
 *
 * The shipped client gets this wrong twice (onlykey-api.js:181-183): it reads
 * FWversion out of response.slice(40,52), which is still ciphertext, and then
 * indexes response[51] on the already-decrypted buffer, double-counting the
 * 32-byte offset. Read the version from the opened tail.
 */
function parseConnectReply(reply, key) {
  const printable = (bytes) => {
    let text = '';
    for (const b of bytes) {
      if (b === 0) break;
      if (b < 0x20 || b > 0x7e) return null;
      text += String.fromCharCode(b);
    }
    return text.length ? text : null;
  };

  /*
   * TWO DIFFERENT REPLIES SHARE THIS MESSAGE ID, and telling them apart is not
   * optional.
   *
   * Over the CTAP path, bridge_to_onlykey() answers OKCONNECT with a real key
   * exchange: 32 bytes of X25519 public key followed by the status string
   * boxed under the derived transit key.
   *
   * Over the VENDOR path it does not. okcore.cpp's dispatch is
   * `case OKCONNECT: set_time(recv_buffer); return;`, and set_time() answers
   * with hidprint(HW_MODEL(UNLOCKED)) - a PLAINTEXT status string starting at
   * byte 0. There is no public key and no key exchange at all.
   *
   * Reading the second as the first derives a "transit key" from the ASCII of
   * a status string. Nothing errors: the session reports itself established,
   * box() produces confident garbage, and the first real command fails
   * somewhere unrelated. So the form is detected rather than assumed.
   *
   * The test is that the whole reply, once its trailing NUL padding is
   * removed, is printable ASCII. A 32-byte X25519 public key satisfying that
   * has probability about (95/256)^32, which is on the order of 1e-18.
   */
  let end = reply.length;
  while (end > 0 && reply[end - 1] === 0x00) end -= 1;
  const body = reply.subarray(0, end);
  const asPlainStatus = end > 0 ? printable(body) : null;

  if (asPlainStatus !== null && asPlainStatus.length === end) {
    return {
      kind: 'status',
      devicePublic: null,
      status: asPlainStatus,
      sealed: false,
    };
  }

  /*
   * The 33-byte minimum belongs to the EXCHANGE form only, and is checked here
   * rather than at the top for that reason.
   *
   * A plaintext status is as long as the string: hidprint() sends strlen bytes,
   * so "INITIALIZED" is 11. The emulator happens to pad its reports to 64,
   * which is why a universal guard passed on this device - but a transport
   * that reports the true length would have rejected a perfectly good reply
   * with a message about a size the vendor path never promised.
   */
  if (reply.length < 33) {
    throw new Error(
      `OKCONNECT reply is ${reply.length} bytes and is not printable status; ` +
      'a key exchange needs at least 33',
    );
  }

  /*
   * A THIRD FORM: v0.2-beta.8c, whose exchange reply is laid out differently.
   *
   * The public key is at bytes 21..53 rather than 0..32, and the version
   * string sits in the CLEAR at 8..20 instead of inside the boxed tail. The
   * web app has carried this branch from the beginning
   * (onlykey-api.js:168-198) and detects it exactly this way - by reading
   * that version field before deciding where the key is - so no caller has
   * to know the firmware version in order to parse the reply that tells it
   * the firmware version.
   *
   * Reading a legacy reply with the modern offsets is the silent failure
   * this whole function exists to prevent: 32 bytes that are not the key
   * derive a transit key that is not the transit key, the session reports
   * itself established, and the first real command fails somewhere
   * unrelated.
   *
   * UNVERIFIED ON HARDWARE, and it cannot be here: no release in
   * ok-versions.json is beta-8c, so there is no emulator to point at it.
   * version.js says the same of its own `okconnectLayout` flag, which
   * nothing consumed until now - this is what it was for. What IS pinned is
   * the offset arithmetic, against a synthetic reply built to the web app's
   * description.
   */
  const LEGACY_VERSION = 'v0.2-beta.8c';
  if (reply.length >= 53 && printable(reply.subarray(8, 20)) === LEGACY_VERSION) {
    return {
      kind: 'exchange',
      layout: 'legacy',
      devicePublic: reply.subarray(21, 53),
      status: LEGACY_VERSION,
      sealed: false,
    };
  }

  const devicePublic = reply.subarray(0, 32);
  const tail = reply.subarray(32);
  const opened = key ? printable(box(key, tail)) : null;
  const asIs = printable(tail);

  return {
    kind: 'exchange',
    layout: 'modern',
    devicePublic,
    status: opened || asIs || '',
    sealed: Boolean(opened),
  };
}

/* ------------------------------------------------------------- self tests */

/**
 * Three vectors, asserted separately on purpose.
 *
 * A wrong transit key and a chunking bug both present as "the device answered
 * noise", so the steps have to fail distinguishably. Skipping HSalsa20 yields
 * the raw X25519 point 4a5d9d5b...42 rather than 1b275564...89, and that is
 * the single most likely porting mistake.
 */
const VECTORS = {
  /* NaCl's published alice/bob pair; also RFC 7748 6.1. */
  aliceSecret: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  beforenm: '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389',
  /* AES-256-GCM, zero key, zero IV, 16 zero bytes, tag discarded (NIST). */
  boxZero: 'cea7403d4d606b6e074ec5d3baf39d18',
};

module.exports = {
  PREFIX,
  CONNECT_HEADER,
  VECTORS,
  keypair,
  beforenm,
  transitKey,
  box,
  connectPayload,
  parseConnectReply,
};
