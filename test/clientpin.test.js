/*
 * CTAP2 clientPin, protocol 1 - the wire bytes, pinned.
 *
 * ## Why this file is unusually literal
 *
 * Every wrong PIN attempt is one of EIGHT before the key's FIDO2 side is
 * locked for good (PIN_LOCKOUT_ATTEMPTS, ctap.h:170), and three per boot.
 * There is no way to test "did that work" cheaply against a real key: a bug
 * in any byte here does not produce a retry, it produces a spent life. So the
 * bytes are fixed here first, and nothing reaches a device until they are.
 *
 * ## The oracle is node:crypto, not our own code
 *
 * Asserting that our AES agrees with our AES proves nothing. Node's own
 * `aes-256-cbc` and `hmac` stand in for the firmware's crypto, and one test
 * goes further and REIMPLEMENTS the firmware's verification path -
 * ctap_update_pin_if_verified, including the backwards zero-count that
 * recovers the PIN length - so a round trip is checked against what the C
 * actually does rather than against what the spec says it should.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const cose = require('../src/protocol/cose');
const cp = require('../src/protocol/clientpin');
const cbor = require('../src/protocol/cbor');
const { toHex, utf8ToBytes } = require('../src/bytes');

/* ---- oracles: what the firmware does, written out again -------------- */

const ZERO_IV = Buffer.alloc(16);

function aesDecrypt(key, data) {
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), ZERO_IV);
  d.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([d.update(Buffer.from(data)), d.final()]));
}

function aesEncrypt(key, data) {
  const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), ZERO_IV);
  c.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([c.update(Buffer.from(data)), c.final()]));
}

function sha256(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}

function hmac16(key, ...parts) {
  const h = crypto.createHmac('sha256', Buffer.from(key));
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest()).subarray(0, 16);
}

/** trailing_zeros(buf, 63), ctap.cpp:2007-2016 - the PIN length field. */
function firmwarePinLength(plain) {
  let indx = 63;
  let c = 0;
  while (plain[indx] === 0 && indx) {
    indx--;
    c++;
  }
  return 64 - c;
}

/* ------------------------------------------------------------------ COSE */

test('a P-256 COSE_Key encodes in the canonical order the firmware demands', () => {
  const x = new Uint8Array(32).fill(0xaa);
  const y = new Uint8Array(32).fill(0xbb);
  const key = new Uint8Array(65);
  key[0] = 0x04;
  key.set(x, 1);
  key.set(y, 33);

  const bytes = cbor.encode(cose.encodeP256(key));

  /*
   * 1, 3, -1, -2, -3 - the NEGATIVE labels last, even though they are the
   * smaller numbers. tinycbor's CborValidateCanonicalFormat orders by the
   * ENCODED key bytes (0x01, 0x03, 0x20, 0x21, 0x22), not by value. Get this
   * wrong and the device rejects the request as invalid CBOR.
   */
  assert.equal(toHex(bytes.subarray(0, 11)), 'a501020338182001215820');
  assert.equal(bytes.length, 1 + 2 + 3 + 2 + 35 + 35);
});

test('a COSE_Key round-trips, and the 64-byte form is accepted too', () => {
  const raw = new Uint8Array(64);
  for (let i = 0; i < 64; i++) raw[i] = i + 1;

  const back = cose.decodeP256(cbor.decode(cbor.encode(cose.encodeP256(raw))));
  assert.equal(toHex(back.x), toHex(raw.subarray(0, 32)));
  assert.equal(toHex(back.y), toHex(raw.subarray(32)));
  assert.equal(back.uncompressed[0], 0x04);
  assert.equal(back.alg, cose.ALG_ECDH_ES_HKDF_256);
});

test('a COSE_Key that is not P-256 is refused rather than used anyway', () => {
  const ok = cose.encodeP256(new Uint8Array(64));

  const wrongCurve = new Map(ok);
  wrongCurve.set(cose.LABEL.CRV, 2);
  assert.throws(() => cose.decodeP256(wrongCurve), /crv is 2/);

  const wrongType = new Map(ok);
  wrongType.set(cose.LABEL.KTY, 1);
  assert.throws(() => cose.decodeP256(wrongType), /kty is 1/);

  const shortX = new Map(ok);
  shortX.set(cose.LABEL.X, new Uint8Array(31));
  assert.throws(() => cose.decodeP256(shortX), /x is not a 32-byte/);
});

test('a compressed point is refused, not silently truncated', () => {
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  assert.throws(() => cose.encodeP256(compressed), /64 or 65 bytes/);

  const badPrefix = new Uint8Array(65);
  badPrefix[0] = 0x03;
  assert.throws(() => cose.encodeP256(badPrefix), /must start with 0x04/);
});

/* ------------------------------------------------------- shared secret */

test('both sides derive the same shared secret, and it is SHA-256 of x', () => {
  const a = cp.newPlatformKey();
  const b = cp.newPlatformKey();

  const ours = cp.sharedSecret(a.secretKey, b.coseKey);
  const theirs = cp.sharedSecret(b.secretKey, a.coseKey);
  assert.equal(toHex(ours), toHex(theirs));
  assert.equal(ours.length, 32);

  /*
   * The oracle: node's ECDH gives the raw 32-byte x, and the secret is a
   * plain SHA-256 of it. No HKDF, no salt, no info - protocol 1 really is
   * this bare (ctap.cpp:2044-2048).
   */
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(a.secretKey));
  const x = new Uint8Array(ecdh.computeSecret(Buffer.from(b.publicKey)));
  assert.equal(x.length, 32);
  assert.equal(toHex(ours), toHex(sha256(x)));
});

/* ----------------------------------------------------------- the PIN */

test('the PIN is padded to 64 bytes, because the padding IS the length', () => {
  const padded = cp.padPin('1234');
  assert.equal(padded.length, 64);
  assert.equal(toHex(padded.subarray(0, 4)), '31323334');
  assert.ok(padded.subarray(4).every((b) => b === 0));
  assert.equal(firmwarePinLength(padded), 4);
});

test('the firmware length rules are enforced here, not discovered there', () => {
  assert.throws(() => cp.padPin('123'), /4\.\.63 bytes/);
  assert.throws(() => cp.padPin('x'.repeat(64)), /4\.\.63 bytes/);
  /* 63 is the last accepted length: ret >= NEW_PIN_MAX_SIZE fails at 64. */
  assert.equal(cp.padPin('x'.repeat(63)).length, 64);
  assert.equal(firmwarePinLength(cp.padPin('x'.repeat(63))), 63);
});

test('a multi-byte PIN is measured in BYTES, the way the device counts', () => {
  /* Four characters, twelve bytes of UTF-8. */
  const pin = '你好世界';
  const padded = cp.padPin(pin);
  assert.equal(firmwarePinLength(padded), 12);
});

test('newPinEnc decrypts, under an independent AES, to PIN plus zeros', () => {
  const secret = sha256(utf8ToBytes('a secret that is not random for the test'));
  const enc = cp.newPinEnc(secret, '246813');

  assert.equal(enc.length, 64, 'exactly four blocks - padding would make it five');

  const plain = aesDecrypt(secret, enc);
  assert.equal(firmwarePinLength(plain), 6);
  assert.equal(Buffer.from(plain.subarray(0, 6)).toString(), '246813');
});

test('pinHashEnc is one block of SHA-256(PIN) truncated to 16', () => {
  const secret = sha256(utf8ToBytes('another fixed secret'));
  const enc = cp.pinHashEnc(secret, '1234');
  assert.equal(enc.length, 16);
  assert.equal(toHex(aesDecrypt(secret, enc)), toHex(sha256(utf8ToBytes('1234')).subarray(0, 16)));
});

/* ------------------------------------------------------- the requests */

test('setPin carries exactly the five fields the firmware requires', () => {
  const secret = sha256(utf8ToBytes('set pin secret'));
  const platform = cp.newPlatformKey();
  const params = cp.setPinParams({ secret, platformKey: platform, newPin: '1234' });

  assert.equal([...params.keys()].join(','), '1,2,3,4,5');
  assert.equal(params.get(cp.PARAM.PIN_PROTOCOL), 1);
  assert.equal(params.get(cp.PARAM.SUB_COMMAND), cp.SUB.SET_PIN);

  /* pinAuth covers newPinEnc and NOTHING else for setPin (ctap.cpp:2050). */
  const enc = params.get(cp.PARAM.NEW_PIN_ENC);
  assert.equal(toHex(params.get(cp.PARAM.PIN_AUTH)), toHex(hmac16(secret, enc)));

  /* It has to survive a canonical encode, which is what the device parses. */
  const round = cbor.decode(cbor.encode(params));
  assert.equal(toHex(round.get(cp.PARAM.NEW_PIN_ENC)), toHex(enc));
});

test('changePin authenticates newPinEnc FOLLOWED BY pinHashEnc, in order', () => {
  const secret = sha256(utf8ToBytes('change pin secret'));
  const platform = cp.newPlatformKey();
  const params = cp.changePinParams({
    secret, platformKey: platform, currentPin: '1234', newPin: '567890',
  });

  assert.equal([...params.keys()].join(','), '1,2,3,4,5,6');
  const enc = params.get(cp.PARAM.NEW_PIN_ENC);
  const hash = params.get(cp.PARAM.PIN_HASH_ENC);

  assert.equal(toHex(params.get(cp.PARAM.PIN_AUTH)), toHex(hmac16(secret, enc, hash)));
  /* The other order is a valid HMAC of the wrong message - so assert it differs. */
  assert.notEqual(toHex(params.get(cp.PARAM.PIN_AUTH)), toHex(hmac16(secret, hash, enc)));
});

test('getPinToken sends the hash and NO pinAuth', () => {
  const secret = sha256(utf8ToBytes('token secret'));
  const params = cp.pinTokenParams({
    secret, platformKey: cp.newPlatformKey(), pin: '1234',
  });
  assert.equal([...params.keys()].join(','), '1,2,3,6');
  assert.equal(params.get(cp.PARAM.PIN_AUTH), undefined);
});

test('getRetries asks for nothing else at all', () => {
  const params = cp.retriesParams();
  assert.equal([...params.keys()].join(','), '1,2');
  assert.equal(toHex(cbor.encode(params)), 'a201010201');
});

test('getKeyAgreement is two fields, and must be re-sent per attempt', () => {
  assert.equal(toHex(cbor.encode(cp.keyAgreementParams())), 'a201010202');
});

/* ------------------------------------------------------- the answers */

test('the pinToken comes back as one encrypted block and decrypts', () => {
  const secret = sha256(utf8ToBytes('pin token round trip'));
  const token = new Uint8Array(16).fill(0x5a);
  const response = new Map([[cp.RESP.PIN_TOKEN, aesEncrypt(secret, token)]]);

  assert.equal(toHex(cp.readPinToken(response, secret)), toHex(token));
});

test('a pinToken of the wrong size is reported, not decrypted anyway', () => {
  const secret = sha256(utf8ToBytes('x'));
  assert.throws(
    () => cp.readPinToken(new Map([[cp.RESP.PIN_TOKEN, new Uint8Array(32)]]), secret),
    /returned 32 bytes/,
  );
  assert.throws(() => cp.readPinToken(new Map(), secret), /returned no bytes/);
});

test('retries and the key agreement key are read off their own labels', () => {
  assert.equal(cp.readRetries(new Map([[cp.RESP.RETRIES, 8]])), 8);
  assert.throws(() => cp.readRetries(new Map()), /no count/);

  const device = cp.newPlatformKey();
  const read = cp.readKeyAgreement(new Map([[cp.RESP.KEY_AGREEMENT, device.coseKey]]));
  assert.equal(toHex(read.uncompressed), toHex(device.publicKey));
});

test('pinTokenAuth is keyed by the token, for the commands that use one', () => {
  const token = new Uint8Array(16).fill(7);
  const message = new Uint8Array(32).fill(9);
  assert.equal(toHex(cp.pinTokenAuth(token, message)), toHex(hmac16(token, message)));
});

/* --------------------------------------- the firmware path, end to end */

test('a setPin request passes ctap_update_pin_if_verified, reimplemented', () => {
  /*
   * The firmware's own sequence, with node doing the crypto:
   *   1. shared secret from ITS private key and OUR public key
   *   2. HMAC(shared, newPinEnc) compared against our pinAuth, first 16 bytes
   *   3. AES-CBC decrypt newPinEnc in place, IV zero
   *   4. PIN length = 64 - trailing zeros counted back from index 63
   *   5. accept if 4 <= length < 64
   * If all five hold for bytes we generated, the exchange works.
   */
  const device = crypto.createECDH('prime256v1');
  device.generateKeys();
  const devicePublic = new Uint8Array(device.getPublicKey());

  const platform = cp.newPlatformKey();
  const secret = cp.sharedSecret(platform.secretKey, devicePublic);

  const params = cp.setPinParams({ secret, platformKey: platform, newPin: 'hunter2!' });

  /* The device side, from the request as it arrives over the wire. */
  const arrived = cbor.decode(cbor.encode(params));
  assert.equal(arrived.get(cp.PARAM.PIN_PROTOCOL), 1, 'protocol 1 or CTAP1_ERR_OTHER');

  const theirKey = cose.decodeP256(arrived.get(cp.PARAM.KEY_AGREEMENT));
  const theirSecret = sha256(
    new Uint8Array(device.computeSecret(Buffer.from(theirKey.uncompressed))),
  );
  assert.equal(toHex(theirSecret), toHex(secret));

  const newPinEncBytes = arrived.get(cp.PARAM.NEW_PIN_ENC);
  assert.ok(newPinEncBytes.length >= 64, 'NEW_PIN_ENC_MIN_SIZE, or CTAP1_ERR_OTHER');
  assert.equal(
    toHex(arrived.get(cp.PARAM.PIN_AUTH)),
    toHex(hmac16(theirSecret, newPinEncBytes)),
    'pinAuth must match or the device answers CTAP2_ERR_PIN_AUTH_INVALID',
  );

  const plain = aesDecrypt(theirSecret, newPinEncBytes);
  const length = firmwarePinLength(plain);
  assert.equal(length, 8);
  assert.ok(length >= 4 && length < 64, 'or CTAP2_ERR_PIN_POLICY_VIOLATION');
  assert.equal(Buffer.from(plain.subarray(0, length)).toString(), 'hunter2!');
});

test('a changePin request passes the same path, with the current PIN checked', () => {
  const device = crypto.createECDH('prime256v1');
  device.generateKeys();

  const platform = cp.newPlatformKey();
  const secret = cp.sharedSecret(platform.secretKey, new Uint8Array(device.getPublicKey()));

  const params = cp.changePinParams({
    secret, platformKey: platform, currentPin: '1234', newPin: '999999',
  });
  const arrived = cbor.decode(cbor.encode(params));

  const theirKey = cose.decodeP256(arrived.get(cp.PARAM.KEY_AGREEMENT));
  const theirSecret = sha256(
    new Uint8Array(device.computeSecret(Buffer.from(theirKey.uncompressed))),
  );

  const enc = arrived.get(cp.PARAM.NEW_PIN_ENC);
  const hashEnc = arrived.get(cp.PARAM.PIN_HASH_ENC);
  assert.equal(toHex(arrived.get(cp.PARAM.PIN_AUTH)), toHex(hmac16(theirSecret, enc, hashEnc)));

  /* Its own AES call, its own zero IV - NOT a continuation of the one above. */
  const currentHash = aesDecrypt(theirSecret, hashEnc);
  assert.equal(toHex(currentHash), toHex(sha256(utf8ToBytes('1234')).subarray(0, 16)));

  const plain = aesDecrypt(theirSecret, enc);
  assert.equal(Buffer.from(plain.subarray(0, firmwarePinLength(plain))).toString(), '999999');
});
