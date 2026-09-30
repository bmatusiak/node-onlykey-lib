/*
 * cli/gpg-key.js - the OpenPGP key an OnlyKey-derived GPG identity is, and
 * the keygrips gpg knows its parts by.
 *
 * WHAT IT REPLACES. lib-agent's gpg/protocol.py + encode.py: `onlykey-gpg
 * init` asks the device for two public keys derived from "gpg://<user id>" -
 * a signing key and an ECDH key - and wraps them in an OpenPGP certificate
 * whose self-signatures the DEVICE makes. gpg imports that certificate and
 * from then on believes it has a key; the private halves never exist
 * anywhere but inside the OnlyKey, and cli/gpg-agent.js does their work.
 *
 * WHOSE ENCODING. The packets are the vendored openpgp fork's - the same
 * openpgp.js the web app and ok-rn use, so there is one OpenPGP encoder in
 * this library, not two. The fork's hardware hook (setHardwareHooks
 * `signer`) is what lets openpgp.js make a self-signature with a key it has
 * no private half for: it hashes and encodes, the hook gets the digest, the
 * device signs it.
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
 * already has. This file takes the time as given; the default is the
 * caller's.
 */
'use strict';

const crypto = require('crypto');

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const { ed25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

const ALGO = { ECDH: 18, ECDSA: 19, EDDSA_LEGACY: 22 };

/*
 * The curve OIDs, DER body without tag and length (RFC 6637 11; the Ed25519
 * and Curve25519 ones are GnuPG's, now RFC 9580 9.2's "legacy" entries) -
 * byte for byte lib-agent's protocol.SUPPORTED_CURVES.
 */
const OID = {
  ed25519: Buffer.from('2B06010401DA470F01', 'hex'),
  cv25519: Buffer.from('2B060104019755010501', 'hex'),
  p256: Buffer.from('2A8648CE3D030107', 'hex'),
};

/*
 * ECDH's KDF parameters (RFC 6637 9): length 3, reserved 1, then SHA-256 (8)
 * and AES-128 (7) - lib-agent's `\x03\x01\x08\x07`, and what gpg and
 * openpgp.js choose for these curves themselves. Part of the key packet, so
 * part of the fingerprint: they have to match lib-agent's for the same
 * fingerprint to come out.
 */
const KDF_SHA256_AES128 = Buffer.from('03010807', 'hex');

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

/*
 * The point as OpenPGP carries it: the 25519 curves in "native" form, 0x40
 * then the 32 bytes (RFC 9580 11.2.1's legacy prefix); P-256 uncompressed,
 * 0x04 || X || Y. The device returns the bare 32 or 64 bytes.
 */
function openpgpPoint(raw) {
  const r = Buffer.from(raw);
  if (r.length === 32) return Buffer.concat([Buffer.of(0x40), r]);
  if (r.length === 64) return Buffer.concat([Buffer.of(0x04), r]);
  throw new Error(`a device public key is 32 or 64 bytes, not ${r.length}`);
}

/** An OpenPGP MPI: the bit length, then the bytes without leading zeros (RFC 4880 3.2). */
function mpi(bytes) {
  let b = Buffer.from(bytes);
  let i = 0;
  while (i < b.length && b[i] === 0) i += 1;
  b = b.subarray(i);
  const bits = b.length ? (b.length - 1) * 8 + (32 - Math.clz32(b[0])) : 0;
  const head = Buffer.alloc(2);
  head.writeUInt16BE(bits);
  return Buffer.concat([head, b]);
}

/**
 * A v4 ECC public-key packet body (RFC 4880 5.5.2, RFC 6637 9) - the one
 * hand-encoded piece, see the top of the file.
 *
 * @param {{algo: number, oid: Buffer}} kind  CURVES[..].sign or .ecdh
 * @param {Uint8Array} raw  the device's public key, 32 or 64 bytes
 * @param {number} created  seconds since the epoch
 */
function keyPacketBody(kind, raw, created) {
  const head = Buffer.alloc(6);
  head[0] = 4;
  head.writeUInt32BE(created >>> 0, 1);
  head[5] = kind.algo;
  return Buffer.concat([
    head,
    Buffer.of(kind.oid.length), kind.oid,
    mpi(openpgpPoint(raw)),
    kind.algo === ALGO.ECDH ? KDF_SHA256_AES128 : Buffer.alloc(0),
  ]);
}

/* ------------------------------------------------------------ keygrips */

/*
 * THE KEYGRIP is how gpg names a key to its agent: SHA-1 over the key's
 * parameters as a libgcrypt S-expression, `(1:p32:...)(1:a..)...(1:q..)`
 * (libgcrypt's compute_keygrip). It is not the fingerprint - it does not
 * cover the creation time or the algorithm id, only the math - and gpg sends
 * it in HAVEKEY, SIGKEY and SETKEY, so the agent has to compute exactly what
 * gpg computes or it holds "no secret key" for its own key.
 *
 * The parameter values are lib-agent's (protocol.py keygrip_ed25519,
 * keygrip_curve25519, keygrip_nist256), which gpg has agreed with for years;
 * the test pins them against keygrips gpg itself printed (--with-keygrip).
 * `q` is the bare 32 bytes for the 25519 curves - libgcrypt strips the 0x40
 * before hashing - and 04||X||Y for P-256.
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
 */
function keygrip(grip, raw) {
  const params = GRIP_PARAMS[grip];
  if (!params) throw new Error(`no keygrip for curve ${grip}`);
  const q = grip === 'p256' ? openpgpPoint(raw) : Buffer.from(raw);
  const parts = [...Object.entries(params).map(([k, v]) => [k, Buffer.from(v, 'hex')]), ['q', q]];
  const h = crypto.createHash('sha1');
  for (const [name, value] of parts) {
    h.update(`(${name.length}:${name}${value.length}:`);
    h.update(value);
    h.update(')');
  }
  return h.digest('hex').toUpperCase();
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
const CUSTOM_SUBPACKET = { type: 26, critical: false, body: Buffer.from('ONLYKEY-GPG') };

/**
 * The public certificate: primary signing key, user id, the device's
 * positive certification (0x13), ECDH subkey, the device's subkey binding
 * (0x18) - lib-agent's create_primary + create_subkey, two device signatures
 * in all, in that order.
 *
 * @param {object} opts
 * @param {string} opts.userId
 * @param {'ed25519'|'nist256p1'} opts.curve
 * @param {number} opts.created  seconds since the epoch (key AND signature time)
 * @param {Uint8Array} opts.signPublic  the device's signing public key
 * @param {Uint8Array} opts.ecdhPublic  the device's ECDH public key
 * @param {(digest: Uint8Array, what: string) => Promise<Uint8Array>} opts.sign
 *   the device's 64-byte r||s over `digest` with the signing key
 * @returns {Promise<{armored: string, bytes: Uint8Array, fingerprint: string,
 *   subkeyFingerprint: string, keygrips: {sign: string, ecdh: string}}>}
 */
async function buildCertificate({ userId, curve, created, signPublic, ecdhPublic, sign }) {
  const kinds = CURVES[curve];
  if (!kinds) throw new Error(`no GPG key for curve ${curve}`);

  const primary = new openpgp.PublicKeyPacket();
  await primary.read(keyPacketBody(kinds.sign, signPublic, created));
  const subkey = new openpgp.PublicSubkeyPacket();
  await subkey.read(keyPacketBody(kinds.ecdh, ecdhPublic, created));
  const uid = new openpgp.UserIDPacket();
  uid.read(new TextEncoder().encode(userId));

  /*
   * The certificate time is the key's time, not "now": lib-agent signs with
   * pubkey.created, and a signature younger than the key it certifies is
   * the only thing that makes sense for a key backdated to the epoch.
   */
  const when = new Date(created * 1000);
  /*
   * nonDeterministicSignaturesViaNotation OFF: openpgp.js v6 salts every v4
   * signature with a random notation, against fault attacks on a SOFTWARE
   * EdDSA signer. The signer here is the device; the salt would only make
   * two inits of the same key differ byte for byte, for no protection.
   */
  const config = { ...openpgp.config, nonDeterministicSignaturesViaNotation: false };

  const hooks = openpgp.setHardwareHooks({});
  const before = { ...hooks };
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
      if (algo !== kinds.sign.algo || !Buffer.from(publicKeyParams.Q).equals(openpgpPoint(signPublic))) return null;
      const sig = Buffer.from(await sign(Uint8Array.from(hashed)));
      if (!verifyDigest(kinds.sign.keyType, signPublic, hashed, sig)) {
        throw new Error('the OnlyKey\'s self-signature does not verify against its own public key');
      }
      return { r: Uint8Array.from(sig.subarray(0, 32)), s: Uint8Array.from(sig.subarray(32, 64)) };
    },
  });

  try {
    const cert = new openpgp.SignaturePacket();
    Object.assign(cert, {
      signatureType: openpgp.enums.signature.certPositive,
      publicKeyAlgorithm: kinds.sign.algo,
      hashAlgorithm: openpgp.enums.hash.sha256,
      keyFlags: [openpgp.enums.keyFlags.certifyKeys | openpgp.enums.keyFlags.signData],
      ...PRIMARY_PREFS,
    });
    await cert.sign(primary, { userID: uid, key: primary }, when, false, config);
    cert.unhashedSubpackets.push(CUSTOM_SUBPACKET);

    const binding = new openpgp.SignaturePacket();
    Object.assign(binding, {
      signatureType: openpgp.enums.signature.subkeyBinding,
      publicKeyAlgorithm: kinds.sign.algo,
      hashAlgorithm: openpgp.enums.hash.sha256,
      keyFlags: [openpgp.enums.keyFlags.encryptCommunication | openpgp.enums.keyFlags.encryptStorage],
    });
    await binding.sign(primary, { key: primary, bind: subkey }, when, false, config);
    binding.unhashedSubpackets.push(CUSTOM_SUBPACKET);

    const list = new openpgp.PacketList();
    list.push(primary, uid, cert, subkey, binding);
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

/* ------------------------------------------------------------ reading them back */

/*
 * An algorithm + OID pair back to the device key it came from. Anything else
 * in the keyring (an RSA key, a key on another curve) is not a derived key
 * and is skipped.
 */
function kindOf(algo, oidBytes) {
  for (const curve of Object.keys(CURVES)) {
    for (const role of ['sign', 'ecdh']) {
      const k = CURVES[curve][role];
      if (k.algo === algo && k.oid.equals(oidBytes)) return { curve, role, ...k };
    }
  }
  return null;
}

/**
 * Every derived key in an armored (or binary) keyring export, as the agent
 * needs it: which device key it is, and its keygrip.
 *
 * WHICH USER ID. lib-agent's agent.py get_identity(): "We assume the first
 * user ID is used to generate Agent-based GPG keys." The derivation is keyed
 * by that string, so it is the one the device is asked about.
 *
 * @param {string|Uint8Array} data
 * @returns {Promise<Array<{userId: string, curve: string, role: 'sign'|'ecdh',
 *   keyType: number, raw: Buffer, keygrip: string, fingerprint: string, created: number}>>}
 */
async function readDerivedKeys(data) {
  const keys = typeof data === 'string'
    ? await openpgp.readKeys({ armoredKeys: data })
    : await openpgp.readKeys({ binaryKeys: Uint8Array.from(data) });
  const out = [];
  for (const key of keys) {
    const user = key.users.find((u) => u.userID);
    if (!user) continue;
    const userId = user.userID.userID;
    for (const packet of [key.keyPacket, ...key.subkeys.map((s) => s.keyPacket)]) {
      const { oid, Q } = packet.publicParams || {};
      if (!oid || !Q) continue;
      const kind = kindOf(packet.algorithm, Buffer.from(oid.write()).subarray(1));
      if (!kind) continue;
      const raw = Buffer.from(Q).subarray(1);
      out.push({
        userId,
        curve: kind.curve,
        role: kind.role,
        keyType: kind.keyType,
        raw,
        keygrip: keygrip(kind.grip, raw),
        fingerprint: packet.getFingerprint().toUpperCase(),
        created: Math.floor(packet.created.getTime() / 1000),
      });
    }
  }
  return out;
}

module.exports = {
  ALGO,
  OID,
  CURVES,
  openpgpPoint,
  keyPacketBody,
  keygrip,
  verifyDigest,
  buildCertificate,
  readDerivedKeys,
};
