/*
 * okconnect.js - the OKCONNECT key exchange.
 *
 * This is the exchange every DERIVED secret rides on: the per-site password
 * generator, the vault's encryption key, and the device half of an X-Wing age
 * identity are all `derive_public_key` / `derive_shared_secret` with a
 * different key type. Until it exists none of them can work, which is why
 * plugins/okcrypto reported `deriveXwing: false` with "the OKCONNECT key
 * exchange it rides on is not written yet".
 *
 * Transcribed from onlykey.github.io's onlykey-3rd-party.js (derive_public_key
 * :277, derive_shared_secret:368, xwing_derive:507) and onlykey.extra.js
 * (aesgcm_decrypt:301). Everything here is FRAMING AND KEY AGREEMENT - no
 * transport. The caller sends the message over the CTAP tunnel with the key
 * action, key type and encrypt-response flag as opt1/opt2/opt3, because those
 * three bytes are read by bridge_to_onlykey() in ok_extension.cpp and exist
 * nowhere in the vendor path.
 *
 * ## Three details that are not guessable from the firmware alone
 *
 * THE AES KEY IS A HASH OF THE SHARED SECRET, not the shared secret. The
 * derive functions hold a raw `nacl.box.before` result and pass it to
 * aesgcm_decrypt, which does `sha256(shared_sec)` on the way in
 * (onlykey.extra.js:304). Reading only the caller suggests the raw secret.
 *
 * THE RESPONSE CARRIES NO GCM TAG. `tagLength: 0` (onlykey.extra.js:313) turns
 * forge's AES-GCM into a stream cipher with no authentication, so the
 * ciphertext is exactly as long as the plaintext. A normal GCM implementation
 * will refuse it, because there is no tag to check - decryption here is
 * therefore AES-CTR at GCM's own starting counter block. This is NOT a
 * hardening opportunity to take unilaterally: the firmware decides the format,
 * and a tag we invent is a tag it will not produce.
 *
 * THE IV IS TWELVE ZERO BYTES. `counter` is initialised to 0 and never
 * incremented (onlykey.extra.js:295), and `IntToByteArray(0)` is four zeroes
 * padded to twelve.
 */
'use strict';

const nacl = require('tweetnacl');
const { sha256 } = require('@noble/hashes/sha2.js');
const { ctr, gcm } = require('@noble/ciphers/aes.js');
const { concat, utf8ToBytes } = require('../bytes');

/** OnlyKey's vendor command for the connect/derive exchange. */
const OKCONNECT = 228;

/** Which curve the derivation runs on. */
const KEYTYPE = {
  NACL: 0,
  /** P-256, the only one derive_public_key/derive_shared_secret really use. */
  P256R1: 1,
  P256K1: 2,
  CURVE25519: 3,
  /** Not in the reference's own table; used by the X-Wing path. */
  XWING: 5,
};

/** What the device should do. The REQ_PRESS variants demand a button. */
const KEYACTION = {
  DERIVE_PUBLIC_KEY: 1,
  DERIVE_SHARED_SECRET: 2,
  DERIVE_PUBLIC_KEY_REQ_PRESS: 3,
  DERIVE_SHARED_SECRET_REQ_PRESS: 4,
};

/** The four 0xFF bytes every vendor message opens with. */
const HEADER = [0xff, 0xff, 0xff, 0xff];

/** X-Wing hands back two 32-byte halves together, for either action. */
const XWING_PAIR = 64;

/** An ECC private/shared value is 32 bytes for every supported key type. */
const SECRET_BYTES = 32;

/** AES-GCM's IV here, fixed. See the note at the top of this file. */
const IV = new Uint8Array(12);

/**
 * The derivation label, as bytes.
 *
 * `Uint8Array.from()` IS NOT A STRING ENCODER. Given a string it treats it as
 * an iterable of characters and coerces each with Number(), which is NaN for
 * any letter and stores as 0 - so every passphrase collapsed to a run of zero
 * bytes whose only distinguishing feature was its LENGTH, and two different
 * labels of equal length derived the SAME key. That bug is documented in the
 * reference at onlykey-3rd-party.js:54-66, confirmed three ways, and is the
 * reason this is a named function rather than an inline cast.
 */
function derivationInputBytes(label) {
  if (typeof label === 'string') return utf8ToBytes(label);
  return Uint8Array.from(label);
}

/**
 * The 32-byte hash the device derives from.
 *
 * An ABSENT label is not the same as an empty one: the reference hashes 32
 * ZERO BYTES when no label is given, not the empty string. Those are different
 * keys, and treating them as one would silently move every unlabelled
 * derivation.
 */
function derivationHash(label) {
  const input = label === undefined || label === null || label === ''
    ? new Uint8Array(32)
    : derivationInputBytes(label);
  return sha256(input);
}

/**
 * The current time, as the four bytes the firmware expects.
 *
 * The reference formats the epoch as hex and splits it into byte pairs, which
 * is big-endian and four bytes wide until the year 2106. Written as shifts
 * here because a hex round trip through `Number` is not clearer for being
 * closer to the original.
 */
function epochBytes(seconds = Math.round(Date.now() / 1000)) {
  const n = Math.floor(seconds);
  return Uint8Array.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Build an OKCONNECT message.
 *
 *   [header(4) | OKCONNECT | epoch(4) | transit pubkey(32) | env(2) | hash(32)]
 *
 * @param {Uint8Array} transitPublicKey  this host's ephemeral NaCl box pubkey
 * @param {string} label                 what to derive from; '' means none
 * @param {string} browser  one character, echoed by the device untouched
 * @param {string} os       one character
 * @param {Uint8Array} [publicKey]  a peer public key, appended for
 *   DERIVE_SHARED_SECRET. Its absence is what makes the same frame a
 *   DERIVE_PUBLIC_KEY request - the key action in opt1 says which, and the
 *   trailing key is simply not read for the first.
 *
 *   FRAMED HERE, by peerKeyWire, rather than by the caller. A caller holding a
 *   65-byte SEC1 point has no reason to suspect it needs reshaping, and the
 *   consequence of not reshaping it is a wrong secret rather than an error -
 *   so the conversion belongs at the one place every request passes through.
 * @param {number} [keytype]  which curve, so the peer key can be framed for it
 */
function buildMessage({
  transitPublicKey, label, browser = 'C', os = 'L', epochSeconds, publicKey = null,
  keytype = KEYTYPE.P256R1,
} = {}) {
  if (!(transitPublicKey instanceof Uint8Array) || transitPublicKey.length !== 32) {
    throw new Error('transitPublicKey must be 32 bytes');
  }
  return concat([
    Uint8Array.from(HEADER),
    Uint8Array.from([OKCONNECT]),
    epochBytes(epochSeconds),
    transitPublicKey,
    Uint8Array.from([browser.charCodeAt(0) & 0xff, os.charCodeAt(0) & 0xff]),
    derivationHash(label),
    publicKey ? peerKeyWire(publicKey, keytype) : new Uint8Array(0),
  ]);
}

/** A fresh ephemeral box keypair for one exchange. */
function newTransitKeypair() {
  return nacl.box.keyPair();
}

/**
 * The AES key for this exchange.
 *
 * `nacl.box.before` is X25519 followed by HSalsa20, not a bare scalar
 * multiplication - using raw X25519 here produces a different key and decrypts
 * to noise. Then the hash, which happens inside the reference's aesgcm_decrypt
 * rather than at its call site.
 */
function transitKey(devicePublicKey, appSecretKey) {
  const shared = nacl.box.before(
    Uint8Array.from(devicePublicKey),
    Uint8Array.from(appSecretKey),
  );
  return sha256(Uint8Array.from(shared));
}

/**
 * Undo the device's AES-GCM-without-a-tag.
 *
 * GCM is CTR mode over blocks starting at J0 + 1, and for a 12-byte IV
 * J0 is `IV || 00000001` - so the first keystream block is `IV || 00000002`.
 * With no tag to verify, decryption is exactly that CTR stream.
 */
function decryptBody(key, body) {
  const counterBlock = concat([IV, Uint8Array.from([0, 0, 0, 2])]);
  return ctr(Uint8Array.from(key), counterBlock).decrypt(Uint8Array.from(body));
}

/**
 * TRANSIT V2 - the framing firmware 3.0.5 and later speaks.
 *
 * v1 used AES-GCM as a stream cipher: a fixed all-zero IV, a counter that was
 * never incremented, and the tag thrown away. That is decryptBody() above, and
 * it is why this file's header describes GCM-without-authentication. v2 gives
 * each message its own IV and actually verifies the tag.
 *
 *     frame = [ counter(4, big-endian) | ciphertext | tag(16) ]
 *     iv    = [ dir | counter(4, big-endian) | 0 x 7 ]      (12 bytes)
 *     key   = sha256(NaCl shared secret)                    (unchanged)
 *
 * `dir` is 1 for host->device and 0 for device->host, so the two directions
 * can use the same counter value without ever sharing an IV under one key.
 *
 * WHICH ONE TO SPEAK IS NOT NEGOTIATED. onlykey.h states the contract: the
 * host reads the firmware version out of the PLAIN OKCONNECT response - that
 * one is unencrypted, so it is readable before any of this applies - and picks
 * its framing from it. Below 3.0.5 is v1, 3.0.5 and above is v2. There is no
 * flag in the frame saying which it is, and no way to tell them apart by
 * looking: a v1 body and a v2 frame are both just bytes. Guessing wrong yields
 * plausible noise rather than an error, which is what the tag now prevents in
 * one direction and what the version gate prevents in both.
 *
 * ONLY THE DEVICE->HOST DIRECTION IS IMPLEMENTED, because it is the only one
 * this library uses: requests go out in the clear and `opt3` asks for the
 * RESPONSE to be encrypted. The reference implementation has a matching
 * transit_seal() for hosts that encrypt their requests; if this library ever
 * does, that is the other half, and it needs the outgoing counter state and a
 * reset on every key replacement - including every derive, because a derive is
 * itself an OKCONNECT and the device rolls its key on each one.
 *
 * Ported from onlykey.extra.js (0c-coder/onlykey.github.io), which carries the
 * matching TRANSIT_V2_MIN and was measured on hardware against v3.0.5-test.
 */

/** Host->device is 1, device->host is 0. */
const TRANSIT_DIR_FROM_DEVICE = 0;

/** counter(4) + tag(16) around the ciphertext. */
const TRANSIT_V2_OVERHEAD = 20;

function transitIv(dir, counter) {
  const iv = new Uint8Array(12);
  iv[0] = dir;
  iv[1] = (counter >>> 24) & 0xff;
  iv[2] = (counter >>> 16) & 0xff;
  iv[3] = (counter >>> 8) & 0xff;
  iv[4] = counter & 0xff;
  return iv;
}

/**
 * Open a device->host v2 frame, or throw.
 *
 * NO PARTIAL ACCEPTANCE. A frame whose tag does not verify did not come from
 * something holding the transit key, and returning its plaintext "as far as it
 * got" would hand a caller attacker-chosen bytes that look like a key. That is
 * the whole reason v2 exists, so the failure is an exception and never a
 * shorter result.
 */
function openTransitV2(key, frame) {
  const bytes = Uint8Array.from(frame);
  if (bytes.length < TRANSIT_V2_OVERHEAD) {
    throw new Error(
      `transit v2 frame is ${bytes.length} bytes; the counter and tag alone are ` +
      `${TRANSIT_V2_OVERHEAD}`);
  }
  const counter = ((bytes[0] << 24) >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
  /*
   * @noble's gcm wants [ciphertext || tag] as one buffer, which is exactly the
   * frame minus its counter prefix - so this is a slice, not a concat.
   */
  const sealed = bytes.subarray(4);
  try {
    return gcm(Uint8Array.from(key), transitIv(TRANSIT_DIR_FROM_DEVICE, counter))
      .decrypt(sealed);
  } catch (err) {
    throw new Error(
      'transit v2 message failed authentication - the reply did not come from '
      + 'something holding the transit key, or the framing is being read as the '
      + `wrong version (counter ${counter}, ${sealed.length - 16} ciphertext bytes)`,
      { cause: err });
  }
}

/**
 * Split a decrypted response into the device's status line and its payload.
 *
 *   [ status string, NUL-terminated ("UNLOCKEDvX.Y.Z-xxxx\0") | payload ]
 *
 * The NUL is LOCATED rather than an offset assumed, because the status string
 * grows and shrinks with the firmware version string - a fixed offset works
 * until the version number gains a digit.
 */
function splitStatus(plaintext) {
  const nul = plaintext.indexOf(0);
  if (nul < 0) return { status: '', payload: plaintext };
  let status = '';
  for (let i = 0; i < nul; i++) status += String.fromCharCode(plaintext[i]);
  return { status, payload: plaintext.subarray(nul + 1) };
}

/**
 * A whole response: transit pubkey, then everything else encrypted.
 *
 *   [ device transit pubkey(32) | AES-GCM( status NUL payload ) ]
 *
 * Confirmed live rather than read off the firmware
 * (onlykey-3rd-party.js:498-506): with the encrypt-response flag set,
 * EVERYTHING after the transit public key is one encrypted blob -
 * ok_extension.cpp forces any truthy opt3 to that mode.
 *
 * @returns {{devicePublicKey: Uint8Array, status: string, payload: Uint8Array}}
 */
function openResponse(response, appSecretKey, { encrypted = true, transitV2 = false } = {}) {
  const bytes = Uint8Array.from(response);
  if (bytes.length < 32) {
    throw new Error(`OKCONNECT response is ${bytes.length} bytes; the transit key alone is 32`);
  }

  const devicePublicKey = bytes.subarray(0, 32);
  const body = bytes.subarray(32);
  if (!encrypted) {
    return { devicePublicKey, ...splitStatus(body) };
  }

  const key = transitKey(devicePublicKey, appSecretKey);
  /*
   * `transitV2` is the CALLER's, from the firmware version - see openTransitV2.
   * Defaulted false so a caller that has not been taught about it keeps the
   * behaviour it had, rather than silently changing how it reads every reply.
   */
  const plaintext = transitV2 ? openTransitV2(key, body) : decryptBody(key, body);
  return { devicePublicKey, ...splitStatus(plaintext) };
}

/** How wide a public key is, per key type. */
function publicKeyWidth(keytype) {
  /*
   * X-Wing is neither of the usual widths: it returns 64 bytes,
   * [pk_X(32) | mlkem_seed(32)] for a public-key derive and
   * [ss_X(32) | mlkem_seed(32)] for a shared secret
   * (ok_extension.cpp:275-281).
   */
  if (keytype === KEYTYPE.XWING) return 64;
  if (keytype === KEYTYPE.CURVE25519 || keytype === KEYTYPE.NACL) return 32;
  return 65;
}

/**
 * A peer public key in the form the FIRMWARE reads it.
 *
 * The device hands the key straight to micro-ecc:
 *
 *     uECC_shared_secret(pub, ecc_private_key, secret, curve)   okcrypto.cpp:955
 *
 * and micro-ecc's convention is a RAW 64-byte point, `x || y`, with no 0x04
 * prefix. Everything else about this is a consequence of that one fact.
 *
 * It matters because the device emits its OWN derived key the other way round.
 * ok_extension.cpp:330 does
 *
 *     memmove(ecc_public_key+1, ecc_public_key, 64);
 *     ecc_public_key[0] = 4;
 *
 * so what comes back is SEC1 uncompressed, `04 || x || y`. Echoing that 65-byte
 * value back as the peer key hands micro-ecc `04 || x[0..62]` - a point shifted
 * one byte along, which is still a valid-looking point and still produces a
 * perfectly stable 32-byte answer. It is simply the wrong answer, and no test
 * that checks determinism can see it. That is what this project shipped, and
 * __e2e_tests__/13-deriveParity.e2e.js is what caught it: an ECDH computed
 * host-side from a scalar we hold disagreed with the device's.
 *
 * The trailing byte matches the reference. onlykey-3rd-party.js:102 builds the
 * peer key as `x || y || 04` - the 0x04 at the END - which reads like a typo
 * and is not: micro-ecc takes the first 64 bytes and never looks at the 65th.
 * Emitting the same 65 bytes keeps us byte-identical to the client that is
 * proven against hardware, rather than merely equivalent.
 *
 * Only SEC1 (65 bytes, leading 0x04) and raw (64 bytes) are accepted. A 65-byte
 * value with 0x04 at the end would be ambiguous against a SEC1 point whose x
 * happens to start with 0x04, so it is refused rather than guessed at.
 *
 * @param {Uint8Array} publicKey
 * @param {number} keytype
 * @returns {Uint8Array} the bytes to append to the OKCONNECT message
 */
function peerKeyWire(publicKey, keytype) {
  const key = Uint8Array.from(publicKey);

  // The 32-byte curves are passed through: Curve25519::eval and
  // crypto_box_beforenm both take a bare 32-byte key, so there is no framing.
  if (keytype === KEYTYPE.CURVE25519 || keytype === KEYTYPE.NACL) {
    if (key.length !== 32) {
      throw new Error(`peer key for keytype ${keytype} must be 32 bytes, got ${key.length}`);
    }
    return key;
  }

  // X-Wing does not take a peer key at all; its second half is a seed.
  if (keytype === KEYTYPE.XWING) return key;

  let raw;
  if (key.length === 65 && key[0] === 0x04) {
    raw = key.subarray(1);
  } else if (key.length === 64) {
    raw = key;
  } else {
    throw new Error(
      `peer key must be 65 bytes starting 0x04, or 64 bytes raw - got ${key.length} ` +
      `bytes starting 0x${key[0]?.toString(16) ?? '??'}`,
    );
  }

  return concat([raw, Uint8Array.of(0x04)]);
}

/**
 * The derived public key out of a DERIVE_PUBLIC_KEY payload.
 *
 * P-256 comes back uncompressed at 65 bytes; the 32-byte curves come back
 * bare. Taken from the END of the payload, as the reference does - the device
 * appends it after whatever else the status blob carried.
 */
function publicKeyFrom(payload, keytype) {
  const width = publicKeyWidth(keytype);
  if (payload.length < width) {
    throw new Error(
      `payload is ${payload.length} bytes; a keytype-${keytype} public key is ${width}`,
    );
  }
  return payload.subarray(payload.length - width);
}

/**
 * A DERIVE_SHARED_SECRET payload, which is TWO values and not one.
 *
 * It ends with the public key AND THEN the secret:
 *
 *   [ ... | sharedPub(65 for P-256, 32 for the 25519 curves) | secret(32) ]
 *
 * so the secret is the LAST 32 BYTES and the public key sits in front of it
 * (onlykey-3rd-party.js:441-448). Reading this payload with publicKeyFrom -
 * which takes the last `width` bytes, correct for a public-key derive - hands
 * back 33 bytes of public key with the secret glued to the end of it. That is
 * not a truncated secret, it is a DIFFERENT VALUE that happens to contain the
 * right one: it looks like a plausible hex blob, it is stable per label, and
 * it does not match what any other OnlyKey client derives for that label.
 *
 * The private half is 32 bytes for every supported EC key type, so this width
 * does not vary the way the public one does.
 */
function sharedSecretFrom(payload, keytype) {
  /*
   * X-Wing is a THIRD layout, not a variation on this one. It returns 64 bytes
   * for both actions and the halves keep their positions
   * (ok_extension.cpp:275-281):
   *
   *   DERIVE_PUBLIC_KEY -> [ pk_X(32) | mlkem_seed(32) ]
   *   DERIVE_SHAREDSEC  -> [ ss_X(32) | mlkem_seed(32) ]
   *
   * so the secret is the FIRST half and the seed is the second - there is no
   * public key appended in front of it, and the seed is not a secret to
   * return in its place. Falling through to the EC reading below would demand
   * 96 bytes and throw, which is at least safe, but it would also be wrong
   * about why.
   */
  if (keytype === KEYTYPE.XWING) {
    if (payload.length < XWING_PAIR) {
      throw new Error(
        `payload is ${payload.length} bytes; an X-Wing pair is ${XWING_PAIR}`,
      );
    }
    const pair = payload.subarray(payload.length - XWING_PAIR);
    return {
      secret: pair.subarray(0, SECRET_BYTES),
      mlkemSeed: pair.subarray(SECRET_BYTES),
      publicKey: pair,
    };
  }

  const width = publicKeyWidth(keytype);
  if (payload.length < SECRET_BYTES + width) {
    throw new Error(
      `payload is ${payload.length} bytes; a keytype-${keytype} shared-secret `
      + `response carries ${width} + ${SECRET_BYTES}`,
    );
  }
  return {
    secret: payload.subarray(payload.length - SECRET_BYTES),
    publicKey: payload.subarray(
      payload.length - SECRET_BYTES - width,
      payload.length - SECRET_BYTES,
    ),
  };
}
module.exports = {
  OKCONNECT,
  KEYTYPE,
  KEYACTION,
  IV,
  derivationInputBytes,
  derivationHash,
  epochBytes,
  buildMessage,
  newTransitKeypair,
  transitKey,
  decryptBody,
  openTransitV2,
  TRANSIT_V2_OVERHEAD,
  splitStatus,
  openResponse,
  publicKeyWidth,
  publicKeyFrom,
  sharedSecretFrom,
  peerKeyWire,
  SECRET_BYTES,
  XWING_PAIR,
};
