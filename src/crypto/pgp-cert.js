/*
 * src/crypto/pgp-cert.js - the OpenPGP certificate an OnlyKey-derived key
 * is, built on any host: Node, a browser, React Native (Hermes).
 *
 * WHERE IT CAME FROM. cli/gpg-key.js built this for `onlykey-js gpg init`
 * with Node's crypto (SHA-1 keygrips) and Buffer. Key Chain needs the same
 * certificate from a phone, so the builder moved here, byte for byte, onto
 * Uint8Array and the vendored @noble SHA-1 - and cli/gpg-key.js now imports
 * it. One builder: a certificate made by the CLI and one made by ok-rn for
 * the same (device, user ids, curve, time) are the same bytes, and the same
 * fingerprint. test/pgp-cert.test.js holds that against vectors frozen from
 * the CLI's code before the move.
 *
 * WHAT IT REPLACES. lib-agent's gpg/protocol.py + encode.py: `onlykey-gpg
 * init` asks the device for two public keys derived from "gpg://<user id>" -
 * a signing key and an ECDH key - and wraps them in an OpenPGP certificate
 * whose self-signatures the DEVICE makes. gpg imports that certificate and
 * from then on believes it has a key; the private halves never exist
 * anywhere but inside the OnlyKey.
 *
 * WHOSE ENCODING. The packets are the vendored openpgp fork's - the same
 * openpgp.js the web app and ok-rn use, so there is one OpenPGP encoder in
 * this library, not two. The fork's hardware hook (setHardwareHooks
 * `signer`) is what lets openpgp.js make a self-signature with a key it has
 * no private half for: it hashes and encodes, the hook gets the digest, the
 * device signs it.
 *
 * THE FORK IS AN ARGUMENT, not a require - the composite_pgp / classic_pgp /
 * pgp_messages pattern. This module sits on the `node-onlykey-lib/crypto`
 * barrel, and that barrel must not cost the 1.2 MB fork (test/package.test.js
 * "the crypto subpath does load post-quantum, and still not openpgp"); a
 * caller that builds a certificate already holds the fork from
 * `node-onlykey-lib/crypto/pgp`.
 *
 * ONE PIECE IS HAND-ENCODED: the public-key packet BODY (keyPacketBody). The
 * fork builds that body from an OID object it does not export, so a key
 * cannot be constructed from its raw point through the public API. The body
 * is RFC 4880 5.5.2 + RFC 6637 9 - version, creation time, algorithm, OID,
 * the point as an MPI, and for ECDH the KDF parameters - about fifteen bytes
 * of layout; it is then READ by openpgp.js (PublicKeyPacket.read), which
 * computes the fingerprint, and written back out by it. The test holds
 * read-then-write to the identical bytes, so the packet gpg imports is
 * openpgp.js's own encoding.
 *
 * THE FINGERPRINT IS A FUNCTION OF (device, user id, curve, creation time).
 * A v4 fingerprint is SHA-1 over the key packet body, so the same device and
 * user id give the same fingerprint every time IF the creation time is the
 * same. That is why lib-agent's `--time` defaults to 0 (the epoch), not
 * "now": re-running init on a new machine gives back the key the world
 * already has. `created` defaults to 0 here for the same reason; a caller
 * that wants "now" passes it.
 */
'use strict';

const { sha1 } = require('../vendor/exports/@noble/hashes/legacy.js');
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { utf8ToBytes, fromHex, toHex, concat } = require('../bytes');

const ALGO = { ECDH: 18, ECDSA: 19, EDDSA_LEGACY: 22 };

/*
 * The curve OIDs, DER body without tag and length (RFC 6637 11; the Ed25519
 * and Curve25519 ones are GnuPG's, now RFC 9580 9.2's "legacy" entries) -
 * byte for byte lib-agent's protocol.SUPPORTED_CURVES.
 */
const OID = {
  ed25519: fromHex('2B06010401DA470F01'),
  cv25519: fromHex('2B060104019755010501'),
  p256: fromHex('2A8648CE3D030107'),
};

/*
 * ECDH's KDF parameters (RFC 6637 9): length 3, reserved 1, then SHA-256 (8)
 * and AES-128 (7) - lib-agent's `\x03\x01\x08\x07`, and what gpg and
 * openpgp.js choose for these curves themselves. Part of the key packet, so
 * part of the fingerprint: they have to match lib-agent's for the same
 * fingerprint to come out.
 */
const KDF_SHA256_AES128 = Uint8Array.of(0x03, 0x01, 0x08, 0x07);

/*
 * lib-agent's -e names, and what each means on both halves. The device's key
 * types are src/protocol/agent.js's: 1 Ed25519, 2 P-256, 4 X25519. P-256's
 * ECDH key is a P-256 key; Ed25519's is X25519 (lib-agent
 * formats.get_ecdh_curve_name).
 */
const CURVES = {
  ed25519: {
    sign: { algo: ALGO.EDDSA_LEGACY, oid: OID.ed25519, keyType: 1, grip: 'ed25519' },
    ecdh: { algo: ALGO.ECDH, oid: OID.cv25519, keyType: 4, grip: 'cv25519' },
  },
  nist256p1: {
    sign: { algo: ALGO.ECDSA, oid: OID.p256, keyType: 2, grip: 'p256' },
    ecdh: { algo: ALGO.ECDH, oid: OID.p256, keyType: 2, grip: 'p256' },
  },
};

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/*
 * The point as OpenPGP carries it: the 25519 curves in "native" form, 0x40
 * then the 32 bytes (RFC 9580 11.2.1's legacy prefix); P-256 uncompressed,
 * 0x04 || X || Y. The device returns the bare 32 or 64 bytes.
 */
function openpgpPoint(raw) {
  const r = Uint8Array.from(raw);
  if (r.length === 32) return concat([Uint8Array.of(0x40), r]);
  if (r.length === 64) return concat([Uint8Array.of(0x04), r]);
  throw new Error(`a device public key is 32 or 64 bytes, not ${r.length}`);
}

/** An OpenPGP MPI: the bit length, then the bytes without leading zeros (RFC 4880 3.2). */
function mpi(bytes) {
  let b = Uint8Array.from(bytes);
  let i = 0;
  while (i < b.length && b[i] === 0) i += 1;
  b = b.subarray(i);
  const bits = b.length ? (b.length - 1) * 8 + (32 - Math.clz32(b[0])) : 0;
  return concat([Uint8Array.of((bits >>> 8) & 0xff, bits & 0xff), b]);
}

/** Seconds since the epoch, from a number of seconds or a Date. */
function toSeconds(t, what) {
  const s = t instanceof Date ? Math.floor(t.getTime() / 1000) : t;
  if (!Number.isInteger(s) || s < 0 || s > 0xffffffff) {
    throw new Error(`${what} is seconds since the epoch (0 .. 2^32-1) or a Date, not ${t}`);
  }
  return s;
}

/**
 * A v4 ECC public-key packet body (RFC 4880 5.5.2, RFC 6637 9) - the one
 * hand-encoded piece, see the top of the file.
 *
 * @param {{algo: number, oid: Uint8Array}} kind  CURVES[..].sign or .ecdh
 * @param {Uint8Array} raw  the device's public key, 32 or 64 bytes
 * @param {number} created  seconds since the epoch
 * @returns {Uint8Array}
 */
function keyPacketBody(kind, raw, created) {
  const t = created >>> 0;
  return concat([
    Uint8Array.of(4, (t >>> 24) & 0xff, (t >>> 16) & 0xff, (t >>> 8) & 0xff, t & 0xff, kind.algo),
    Uint8Array.of(kind.oid.length), kind.oid,
    mpi(openpgpPoint(raw)),
    kind.algo === ALGO.ECDH ? KDF_SHA256_AES128 : new Uint8Array(0),
  ]);
}

/* ------------------------------------------------------------ keygrips */

/*
 * THE KEYGRIP is how gpg names a key to its agent: SHA-1 over the key's
 * parameters as a libgcrypt S-expression, `(1:p32:...)(1:a..)...(1:q..)`
 * (libgcrypt's compute_keygrip). It is not the fingerprint - it does not
 * cover the creation time or the algorithm id, only the math - and gpg sends
 * it in HAVEKEY, SIGKEY and SETKEY, so an agent has to compute exactly what
 * gpg computes or it holds "no secret key" for its own key.
 *
 * The parameter values are lib-agent's (protocol.py keygrip_ed25519,
 * keygrip_curve25519, keygrip_nist256), which gpg has agreed with for years;
 * test/gpg-agent.test.js pins them against keygrips gpg itself printed
 * (--with-keygrip). `q` is the bare 32 bytes for the 25519 curves -
 * libgcrypt strips the 0x40 before hashing - and 04||X||Y for P-256.
 */
const GRIP_PARAMS = {
  ed25519: {
    p: '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED',
    a: '01',
    b: '2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A',
    g: '04216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A6666666666666666666666666666666666666666666666666666666666666658',
    n: '1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED',
  },
  cv25519: {
    p: '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED',
    a: '01DB41',
    b: '01',
    g: '04000000000000000000000000000000000000000000000000000000000000000920AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9',
    n: '1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED',
  },
  p256: {
    p: 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    a: 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
    b: '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    g: '046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
    n: 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
  },
};

/**
 * The 20-byte keygrip, as upper-case hex (how gpg sends it).
 *
 * @param {'ed25519'|'cv25519'|'p256'} grip
 * @param {Uint8Array} raw  the device's public key, 32 or 64 bytes
 * @returns {string}
 */
function keygrip(grip, raw) {
  const params = GRIP_PARAMS[grip];
  if (!params) throw new Error(`no keygrip for curve ${grip}`);
  const q = grip === 'p256' ? openpgpPoint(raw) : Uint8Array.from(raw);
  const parts = [...Object.entries(params).map(([k, v]) => [k, fromHex(v)]), ['q', q]];
  const h = sha1.create();
  for (const [name, value] of parts) {
    h.update(utf8ToBytes(`(${name.length}:${name}${value.length}:`));
    h.update(value);
    h.update(utf8ToBytes(')'));
  }
  return toHex(h.digest()).toUpperCase();
}

/* ------------------------------------------------------------ verifying */

/**
 * Does a device signature over an OpenPGP digest verify?
 *
 * Ed25519 (legacy EdDSA in OpenPGP) signs the digest bytes AS THE MESSAGE.
 * ECDSA signs the digest as the hash, truncated to the curve's 256 bits -
 * which is what the device is given (lib-agent client.py sign() cuts it to
 * 32 bytes) and what gpg verifies against. lowS is off: ECDSA has no low-S
 * rule and the device does not normalise S.
 *
 * @param {number} keyType  1 Ed25519, 2 P-256
 * @returns {boolean}
 */
function verifyDigest(keyType, raw, digest, sig) {
  try {
    if (keyType === 1) return ed25519.verify(Uint8Array.from(sig), Uint8Array.from(digest), Uint8Array.from(raw));
    return p256.verify(Uint8Array.from(sig), Uint8Array.from(digest).subarray(0, 32),
      openpgpPoint(raw), { prehash: false, lowS: false });
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------ the certificate */

/*
 * The self-signature subpackets, lib-agent's (encode.py create_primary):
 * preferred symmetric AES-256; hashes SHA-256, -384, -512; compression ZIP,
 * ZLIB, ZIP-uncompressed order 2,3,1; key server "no-modify"; features MDC.
 * openpgp.js adds the issuer key id and fingerprint in the hashed area, as
 * gpg itself does.
 */
const PRIMARY_PREFS = {
  preferredSymmetricAlgorithms: [9],
  preferredHashAlgorithms: [8, 9, 10],
  preferredCompressionAlgorithms: [2, 3, 1],
  keyServerPreferences: [0x80],
  features: [0x01],
};

/*
 * lib-agent's mark on "our" certificates: an unhashed Policy URI subpacket
 * (26) reading ONLYKEY-GPG (protocol.CUSTOM_SUBPACKET). lib-agent's
 * `--subkey` path reads it to decide whether a primary key's signatures are
 * made by the device or must go through the real gpg-agent, so a key made
 * here carries it too - one set of homes, whichever tool made them.
 * Unhashed: added after signing, covered by nothing, as lib-agent does.
 */
const CUSTOM_SUBPACKET = { type: 26, critical: false, body: utf8ToBytes('ONLYKEY-GPG') };

/**
 * The public certificate: primary signing key, then per user id the user id
 * and the device's positive certification (0x13), then the ECDH subkey and
 * the device's subkey binding (0x18) - lib-agent's create_primary +
 * create_subkey, one device signature per user id plus one, in that order.
 *
 * @param {object} openpgp  the vendored fork (`node-onlykey-lib/crypto/pgp`)
 * @param {object} opts
 * @param {string} [opts.userId]  one user id, or:
 * @param {string[]} [opts.userIds]  several; the first is the primary. At
 *   least one is required. The device keys are derived from ONE of them -
 *   the first, by lib-agent's rule - and that derivation is the caller's.
 * @param {'ed25519'|'nist256p1'} opts.curve
 * @param {number|Date} [opts.created=0]  key AND signature time, seconds
 *   since the epoch (or a Date). 0 is lib-agent's default, see the top.
 * @param {number|Date} [opts.expires]  absent: the key never expires, and no
 *   Key Expiration Time subpacket is written (lib-agent's certificate). A
 *   number is seconds after `created` (the subpacket's own unit); a Date is
 *   the moment it expires. Written into every self-signature, so the primary
 *   and the subkey expire together.
 * @param {Uint8Array} opts.signPublic  the device's signing public key
 * @param {Uint8Array} opts.ecdhPublic  the device's ECDH public key
 * @param {(digest: Uint8Array, what: string) => Promise<Uint8Array>} opts.sign
 *   the device's 64-byte r||s over `digest` with the signing key
 * @returns {Promise<{armored: string, bytes: Uint8Array, fingerprint: string,
 *   subkeyFingerprint: string, keygrips: {sign: string, ecdh: string}}>}
 */
async function buildCertificate(openpgp, {
  userId, userIds, curve, created = 0, expires, signPublic, ecdhPublic, sign,
} = {}) {
  if (!openpgp || typeof openpgp.setHardwareHooks !== 'function') {
    throw new TypeError('buildCertificate needs the openpgp fork (node-onlykey-lib/crypto/pgp) as its first argument');
  }
  const kinds = CURVES[curve];
  if (!kinds) throw new Error(`no GPG key for curve ${curve}`);
  const ids = userIds !== undefined ? userIds : (userId !== undefined ? [userId] : []);
  if (!Array.isArray(ids) || !ids.length || ids.some((u) => typeof u !== 'string' || !u)) {
    throw new Error('a certificate needs at least one user id, each a non-empty string');
  }
  if (typeof sign !== 'function') throw new TypeError('buildCertificate needs sign(digest), the device signer');
  const createdAt = toSeconds(created, 'created');

  /*
   * Expiry is OpenPGP's "seconds after the key's creation", whichever way it
   * was given. Zero would mean "never" to openpgp.js and gpg alike - a
   * caller asking for an expiry did not mean that, so it is refused.
   */
  let keyExpirationTime = null;
  if (expires !== undefined && expires !== null) {
    keyExpirationTime = expires instanceof Date ? toSeconds(expires, 'expires') - createdAt : expires;
    if (!Number.isInteger(keyExpirationTime) || keyExpirationTime <= 0 || keyExpirationTime > 0xffffffff) {
      throw new Error(`expires must fall after the key's creation (seconds after it, or a later Date), not ${expires}`);
    }
  }

  const primary = new openpgp.PublicKeyPacket();
  await primary.read(keyPacketBody(kinds.sign, signPublic, createdAt));
  const subkey = new openpgp.PublicSubkeyPacket();
  await subkey.read(keyPacketBody(kinds.ecdh, ecdhPublic, createdAt));
  const uids = ids.map((text) => {
    const uid = new openpgp.UserIDPacket();
    uid.read(utf8ToBytes(text));
    return uid;
  });

  /*
   * The certificate time is the key's time, not "now": lib-agent signs with
   * pubkey.created, and it keeps the whole certificate a function of
   * (device, user id, curve, time).
   *
   * EXCEPT 0, lib-agent's default, which becomes 1. GnuPG reads a
   * self-signature made at 0 as "no creation time": the user id then counts
   * as not self-signed when gpg matches a signature's Signer's User ID
   * against the key (gpg.conf's default-key "<user id>" puts one in every
   * signature), and gpg --verify says "Good signature ... [uncertain]" and
   * "WARNING: The key's User ID is not certified with a trusted signature!"
   * for the person's OWN ultimately trusted key ("issuer ... does not match
   * any User ID" under --debug trust). Measured on GnuPG 2.4.4: time 0 gives
   * [uncertain], time 1 gives [ultimate]. lib-agent's certificates, signed
   * at 0, have the same fault. Only the SIGNATURE moves: the key's creation
   * time - and so the fingerprint - stays lib-agent's.
   */
  const when = new Date(Math.max(createdAt, 1) * 1000);
  /*
   * nonDeterministicSignaturesViaNotation OFF: openpgp.js v6 salts every v4
   * signature with a random notation, against fault attacks on a SOFTWARE
   * EdDSA signer. The signer here is the device; the salt would only make
   * two inits of the same key differ byte for byte, for no protection.
   */
  const config = { ...openpgp.config, nonDeterministicSignaturesViaNotation: false };
  const expiry = keyExpirationTime === null ? {} : { keyExpirationTime, keyNeverExpires: false };

  const hooks = openpgp.setHardwareHooks({});
  const before = { ...hooks };
  const signQ = openpgpPoint(signPublic);
  openpgp.setHardwareHooks({
    /*
     * The hook fires for every openpgp.js signature in the process, so it
     * answers only for this key and is removed in `finally`. It is given the
     * digest openpgp.js computed; the device signs it; the result is checked
     * against the device's own public key before openpgp.js encodes it - a
     * signature that does not verify would make a certificate gpg rejects
     * on import with nothing saying why.
     */
    signer: async (algo, hashAlgo, hashed, publicKeyParams) => {
      if (algo !== kinds.sign.algo || !bytesEqual(publicKeyParams.Q, signQ)) return null;
      const sig = Uint8Array.from(await sign(Uint8Array.from(hashed)));
      if (!verifyDigest(kinds.sign.keyType, signPublic, hashed, sig)) {
        throw new Error('the OnlyKey\'s self-signature does not verify against its own public key');
      }
      return { r: sig.slice(0, 32), s: sig.slice(32, 64) };
    },
  });

  try {
    const list = new openpgp.PacketList();
    list.push(primary);
    for (let i = 0; i < uids.length; i++) {
      const cert = new openpgp.SignaturePacket();
      Object.assign(cert, {
        signatureType: openpgp.enums.signature.certPositive,
        publicKeyAlgorithm: kinds.sign.algo,
        hashAlgorithm: openpgp.enums.hash.sha256,
        keyFlags: [openpgp.enums.keyFlags.certifyKeys | openpgp.enums.keyFlags.signData],
        ...PRIMARY_PREFS,
        ...expiry,
        /*
         * Primary User ID only when there is a choice to make: openpgp.js's
         * generateKey marks the first of several, and a single-id
         * certificate stays lib-agent's bytes (it has no such subpacket).
         */
        ...(uids.length > 1 && i === 0 ? { isPrimaryUserID: true } : {}),
      });
      // Sequential, never Promise.all: each signature is a press on one device.
      await cert.sign(primary, { userID: uids[i], key: primary }, when, false, config);
      cert.unhashedSubpackets.push(CUSTOM_SUBPACKET);
      list.push(uids[i], cert);
    }

    const binding = new openpgp.SignaturePacket();
    Object.assign(binding, {
      signatureType: openpgp.enums.signature.subkeyBinding,
      publicKeyAlgorithm: kinds.sign.algo,
      hashAlgorithm: openpgp.enums.hash.sha256,
      keyFlags: [openpgp.enums.keyFlags.encryptCommunication | openpgp.enums.keyFlags.encryptStorage],
      ...expiry,
    });
    await binding.sign(primary, { key: primary, bind: subkey }, when, false, config);
    binding.unhashedSubpackets.push(CUSTOM_SUBPACKET);

    list.push(subkey, binding);
    const bytes = list.write();
    return {
      /*
       * WITH the CRC-24 line (emitChecksum): openpgp.js v6 leaves it out
       * by default, as RFC 9580 allows, but GnuPG 2.4.4 then reads the
       * -----END line as base64 ("invalid radix64 character 2D") and
       * rejects the key - measured. lib-agent writes the checksum too.
       */
      armored: openpgp.armor(openpgp.enums.armor.publicKey, bytes, undefined, undefined, undefined, true),
      bytes,
      fingerprint: primary.getFingerprint().toUpperCase(),
      subkeyFingerprint: subkey.getFingerprint().toUpperCase(),
      keygrips: { sign: keygrip(kinds.sign.grip, signPublic), ecdh: keygrip(kinds.ecdh.grip, ecdhPublic) },
    };
  } finally {
    openpgp.setHardwareHooks(before);
  }
}

/**
 * A DETACHED signature over `data` by a derived key, as `gpg -bsa` prints it -
 * what git stores in a signed commit (the agent service's gpg shim; onlykey-edge
 * mcp-service.md §4.2a: "the gpg shim signs itself, no Gpg4win; it holds only the
 * agent's key"). The same hook and the same checks as buildCertificate: the
 * digest openpgp.js computes goes to the device (`sign`), and the signature is
 * checked against the device's own key before it is encoded.
 *
 * @param {object} openpgp the fork (node-onlykey-lib/crypto/pgp)
 * @param {object} o
 * @param {Uint8Array} o.data what is signed (a commit object, as git hands it to gpg)
 * @param {Uint8Array} o.signPublic the derived signing key's public key
 * @param {string} o.curve 'ed25519' | 'p256' - the certificate's curve
 * @param {number} o.created the certificate's creation time (seconds) - it is in the fingerprint
 * @param {(digest: Uint8Array) => Promise<Uint8Array>} o.sign the device signer (64-byte r||s)
 * @param {Date} [o.when] the signature's time (default now)
 * @returns {Promise<{armored: string, fingerprint: string, created: number}>}
 */
async function signDetached(openpgp, { data, signPublic, curve, created, sign, when = new Date() }) {
  const kinds = CURVES[curve];
  if (!kinds) throw new Error(`no GPG key for curve ${curve}`);
  if (typeof sign !== 'function') throw new TypeError('signDetached needs sign(digest), the device signer');
  const primary = new openpgp.PublicKeyPacket();
  await primary.read(keyPacketBody(kinds.sign, signPublic, toSeconds(created, 'created')));
  const config = { ...openpgp.config, nonDeterministicSignaturesViaNotation: false };
  const hooks = openpgp.setHardwareHooks({});
  const before = { ...hooks };
  const signQ = openpgpPoint(signPublic);
  openpgp.setHardwareHooks({
    signer: async (algo, hashAlgo, hashed, publicKeyParams) => {
      if (algo !== kinds.sign.algo || !bytesEqual(publicKeyParams.Q, signQ)) return null;
      const sig = Uint8Array.from(await sign(Uint8Array.from(hashed)));
      if (!verifyDigest(kinds.sign.keyType, signPublic, hashed, sig)) {
        throw new Error("the OnlyKey's signature does not verify against its own public key");
      }
      return { r: sig.slice(0, 32), s: sig.slice(32, 64) };
    },
  });
  try {
    const literal = new openpgp.LiteralDataPacket();
    literal.setBytes(Uint8Array.from(data), 'binary');
    const packet = new openpgp.SignaturePacket();
    Object.assign(packet, {
      signatureType: openpgp.enums.signature.binary,
      publicKeyAlgorithm: kinds.sign.algo,
      hashAlgorithm: openpgp.enums.hash.sha256,
    });
    await packet.sign(primary, literal, when, true, config);
    const list = new openpgp.PacketList();
    list.push(packet);
    /* WITH the CRC-24 line, as for certificates: GnuPG 2.4.4 (git verify-commit) rejects armor without it */
    const armored = openpgp.armor(openpgp.enums.armor.signature, list.write(), undefined, undefined, undefined, true);
    return { armored, fingerprint: primary.getFingerprint().toUpperCase(), created: Math.floor(when.getTime() / 1000) };
  } finally {
    openpgp.setHardwareHooks(before);
  }
}

/**
 * A REVOCATION CERTIFICATE for a derived key (spec session, 2026-10-03:
 * `keychain cert --revoke`): a key revocation signature (0x20) over the primary
 * key, made by the device - a physical press, never a budget - and armored as a
 * public key block, as `gpg --gen-revoke` writes it. Importing it into a keyring
 * that holds the certificate marks the key revoked. The derived key can always
 * be re-derived, so a revocation can always be made later, too.
 *
 * @param {object} openpgp the fork
 * @param {{signPublic: Uint8Array, curve: string, created: number, sign: Function, reason?: number, text?: string, when?: Date}} o
 *   reason: RFC 4880 5.2.3.23 (0 no reason, 1 superseded, 2 compromised, 3 retired); default 0
 * @returns {Promise<{armored: string, fingerprint: string}>}
 */
async function buildRevocation(openpgp, { signPublic, curve, created, sign, reason = 0, text = '', when = new Date() }) {
  const kinds = CURVES[curve];
  if (!kinds) throw new Error(`no GPG key for curve ${curve}`);
  if (typeof sign !== 'function') throw new TypeError('buildRevocation needs sign(digest), the device signer');
  const primary = new openpgp.PublicKeyPacket();
  await primary.read(keyPacketBody(kinds.sign, signPublic, toSeconds(created, 'created')));
  const config = { ...openpgp.config, nonDeterministicSignaturesViaNotation: false };
  const hooks = openpgp.setHardwareHooks({});
  const before = { ...hooks };
  const signQ = openpgpPoint(signPublic);
  openpgp.setHardwareHooks({
    signer: async (algo, hashAlgo, hashed, publicKeyParams) => {
      if (algo !== kinds.sign.algo || !bytesEqual(publicKeyParams.Q, signQ)) return null;
      const sig = Uint8Array.from(await sign(Uint8Array.from(hashed)));
      if (!verifyDigest(kinds.sign.keyType, signPublic, hashed, sig)) {
        throw new Error("the OnlyKey's revocation signature does not verify against its own public key");
      }
      return { r: sig.slice(0, 32), s: sig.slice(32, 64) };
    },
  });
  try {
    const packet = new openpgp.SignaturePacket();
    Object.assign(packet, {
      signatureType: openpgp.enums.signature.keyRevocation,
      publicKeyAlgorithm: kinds.sign.algo,
      hashAlgorithm: openpgp.enums.hash.sha256,
      reasonForRevocationFlag: reason,
      reasonForRevocationString: text,
    });
    await packet.sign(primary, { key: primary }, when, false, config);
    const list = new openpgp.PacketList();
    list.push(packet);
    const armored = openpgp.armor(openpgp.enums.armor.publicKey, list.write(), undefined, undefined, undefined, true);
    return { armored, fingerprint: primary.getFingerprint().toUpperCase() };
  } finally {
    openpgp.setHardwareHooks(before);
  }
}

/*
 * An algorithm + OID pair back to the device key it came from - the inverse
 * of CURVES, for reading a certificate back. Anything else (an RSA key, a key
 * on another curve) is not a derived key: null.
 *
 * @returns {null | {curve: string, role: 'sign'|'ecdh', algo: number,
 *   oid: Uint8Array, keyType: number, grip: string}}
 */
function kindOf(algo, oidBytes) {
  for (const curve of Object.keys(CURVES)) {
    for (const role of ['sign', 'ecdh']) {
      const k = CURVES[curve][role];
      if (k.algo === algo && bytesEqual(k.oid, oidBytes)) return { curve, role, ...k };
    }
  }
  return null;
}

module.exports = {
  buildRevocation,
  ALGO,
  OID,
  CURVES,
  openpgpPoint,
  keyPacketBody,
  keygrip,
  verifyDigest,
  kindOf,
  buildCertificate,
  signDetached,
};
