/*
 * keys.js - loading private keys into slots.
 *
 * From OnlyKeyWizard.js:696-827 (initKeySelect) and OnlyKeyComm.js:1841-1921
 * (confirmRsaKeySelect). Between them these hold the densest crypto knowledge
 * in OnlyKey-App - curve OIDs, MPI offsets, the slot-typing convention - and
 * all of it sits inside DOM handlers.
 *
 * This module takes ALREADY-PARSED key objects, the way the original does. It
 * does not parse PGP or SSH itself: that needs kbpgp or openpgp, and putting
 * a 2 MB dependency underneath slot arithmetic would mean an app that only
 * writes a label still pays for it. The parsers live behind crypto/ subpaths.
 */
'use strict';

const { sha256 } = require('@noble/hashes/sha2.js');
const { fromLatin1 } = require('../bytes');

/**
 * The curve identifiers the device uses. Not OIDs - the device's own numbering.
 * 0 means "unrecognised", and reaches the device as an error rather than a key.
 */
const CURVE = { NONE: 0, ED25519: 1, NIST256P1: 2 };

/**
 * OIDs, as the byte arrays a PGP key carries them in.
 *
 * CURVE25519 is present and the original's branch for it is dead: it re-tests
 * the Ed25519 OID, byte for byte, so a cv25519 key never matches and falls
 * through to CURVE.NONE. The real value is here.
 */
const OID = {
  ED25519: [43, 6, 1, 4, 1, 218, 71, 15, 1],        // 1.3.6.1.4.1.11591.15.1
  NIST256P1: [42, 134, 72, 206, 61, 3, 1, 7],       // 1.2.840.10045.3.1.7
  CURVE25519: [43, 6, 1, 4, 1, 151, 85, 1, 5, 1],   // 1.3.6.1.4.1.3029.1.5.1
};

/**
 * Compare two OIDs.
 *
 * Element-wise and order-sensitive. The original is
 * `a.sort().join(',') === b.sort().join(',')`, which is wrong three ways: it
 * MUTATES both operands, it compares as a multiset so a permuted OID matches,
 * and Uint8Array.prototype.sort is numeric while Array.prototype.sort is
 * lexicographic - so if openpgp hands back a plain Array the two sort
 * differently and a correct OID fails to match.
 */
function oidEquals(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if ((a[i] & 0xff) !== (b[i] & 0xff)) return false;
  }
  return true;
}

/** Which curve a PGP OID names, or CURVE.NONE. */
function curveFromOid(oid) {
  if (oidEquals(oid, OID.ED25519)) return CURVE.ED25519;
  if (oidEquals(oid, OID.NIST256P1)) return CURVE.NIST256P1;
  if (oidEquals(oid, OID.CURVE25519)) return CURVE.ED25519;
  return CURVE.NONE;
}

/**
 * Type modifiers, OR'd into the type byte of OKSETPRIV.
 * From OnlyKeyComm.js:188-192.
 */
const MODIFIER = { BACKUP: 0x80, SIGNATURE: 0x40, DECRYPTION: 0x20 };

/** ECC private keys live in a separate slot namespace, 100 above RSA's. */
const ECC_SLOT_OFFSET = 100;

/** Where the auto convention puts each role. */
const ROLE_SLOT = { DECRYPTION: 1, SIGNATURE: 2 };

/**
 * Strip the DER sign-padding byte from an RSA prime.
 *
 * A DER INTEGER carries a leading zero when its high bit is set, which for an
 * RSA prime at any supported size it always is. The original slices
 * unconditionally, which happens to be right for those sizes and wrong in
 * general; conditional is the same result and survives a key that is not.
 */
function stripSignPad(bytes) {
  const b = Uint8Array.from(bytes);
  return b.length && b[0] === 0x00 ? b.subarray(1) : b;
}

/**
 * Extract key material from an sshpk-parsed key.
 *
 * WORKS, AND IS CURRENTLY UNREACHABLE FROM MOBILE. This reads an already-
 * parsed key, the same way fromPgpKey does, so nothing here depends on sshpk.
 * The gap is the PARSER: the desktop app deliberately loads sshpk through a
 * runtime `require` rather than bundling it (ok-app-rewrite
 * src/api/device/sshpkNode.ts:14) because it is a Node library, and it will
 * not run under Hermes as-is.
 *
 * So SSH import is deferred rather than half-ported. When a Hermes-safe parser
 * exists, this is the whole of what it has to feed - there is no second half
 * waiting to be written. PGP has one already (fromPgpKey), which is why that
 * path shipped first.
 *
 * @returns {{kind, curve, scalar}|{kind, p, q}}
 */
function fromSshpk(key) {
  if (key.type === 'ed25519') {
    return { kind: 'ecc', curve: CURVE.ED25519, scalar: Uint8Array.from(key.part.k.data) };
  }
  if (key.curve === 'nistp256') {
    return { kind: 'ecc', curve: CURVE.NIST256P1, scalar: Uint8Array.from(key.part.d.data) };
  }
  if (key.type === 'rsa') {
    return {
      kind: 'rsa',
      p: stripSignPad(key.part.p.data),
      q: stripSignPad(key.part.q.data),
    };
  }
  throw new Error(`unsupported SSH key type: ${key.type || key.curve}`);
}

/**
 * Extract key material from an openpgp-parsed key packet.
 *
 * The MPI offsets are asymmetric and that is not a mistake: an EdDSA primary
 * is [oid, Q, s] so the scalar is params[2], while an ECDH subkey is
 * [oid, Q, kdfParams, d] so it is params[3]. RSA secret params are
 * [n, e, d, p, q, u] for both, so p and q are always [3] and [4].
 *
 * @param {object} packet   primaryKey or subKeys[i].keyPacket
 * @param {boolean} isSubkey
 */
function fromPgpPacket(packet, isSubkey = false) {
  if (!packet) throw new Error('no key packet');

  /*
   * TWO PACKET SHAPES, because two generations of OpenPGP.js are in play.
   *
   * v4 - what the desktop app parses with - exposes a flat `params` array of
   * MPI objects, and which entry holds the secret scalar depends on whether
   * the packet is a subkey:
   *
   *     params[0].oid            the curve
   *     params[2].data           primary ECC scalar
   *     params[3].data           subkey ECC scalar
   *     params[3], params[4]     RSA p and q
   *
   * v5 and later - which the vendored PQC fork is - splits them into named
   * objects and drops the positional guessing entirely:
   *
   *     publicParams.oid         the curve
   *     privateParams.seed       Ed25519 (algorithm 22)
   *     privateParams.d          ECDH and NIST (algorithms 18, 19)
   *     privateParams.p / .q     RSA
   *
   * Both are read here rather than making callers normalise, because the
   * choice is not theirs: it is whichever OpenPGP.js the host app already
   * has, and a mobile app and a desktop app do not have the same one.
   */
  if (packet.privateParams || packet.publicParams) {
    return fromModernPacket(packet);
  }

  const params = packet.params || [];
  const oid = params[0] && params[0].oid;

  if (oid) {
    const curve = curveFromOid(oid);
    if (curve === CURVE.NONE) {
      throw new Error('unsupported ECC curve; expected Ed25519, NIST P-256 or Curve25519');
    }
    const scalarIndex = isSubkey ? 3 : 2;
    const scalar = params[scalarIndex] && params[scalarIndex].data;
    if (!scalar) {
      throw new Error(`ECC scalar missing at params[${scalarIndex}]`);
    }
    return { kind: 'ecc', curve, scalar: Uint8Array.from(scalar) };
  }

  if (params.length < 5) {
    throw new Error(`RSA key needs 6 secret params, got ${params.length}`);
  }
  return {
    kind: 'rsa',
    p: stripSignPad(params[3].data),
    q: stripSignPad(params[4].data),
  };
}

/** The v5+ shape: named params, no positional guessing. */
function fromModernPacket(packet) {
  const pub = packet.publicParams || {};
  const priv = packet.privateParams;

  /*
   * A locked key has no privateParams at all - the field is null until
   * decryptKey() has run. Saying so is the difference between "your
   * passphrase is wrong" and a TypeError three frames deeper.
   */
  if (!priv) {
    throw new Error(
      'this key is still encrypted; decrypt it with its passphrase first',
    );
  }

  if (pub.oid) {
    /* An OID object carries a length prefix in write(); .oid is the bare
     * bytes, which is the same thing the v4 shape exposes. */
    const bytes = pub.oid.oid || pub.oid;
    const curve = curveFromOid(bytes);
    if (curve === CURVE.NONE) {
      throw new Error('unsupported ECC curve; expected Ed25519, NIST P-256 or Curve25519');
    }
    const scalar = priv.seed || priv.d;
    if (!scalar) {
      throw new Error(
        `ECC secret missing; privateParams has [${Object.keys(priv).join(', ')}]`,
      );
    }
    return { kind: 'ecc', curve, scalar: Uint8Array.from(scalar) };
  }

  if (!priv.p || !priv.q) {
    throw new Error(
      `unsupported key: no curve and no RSA primes; privateParams has ` +
      `[${Object.keys(priv).join(', ')}]`,
    );
  }
  /*
   * Stripped the same way as v4. An RSA prime is generated with its top bit
   * set, so it never legitimately begins with a zero byte and this cannot
   * eat a real one - and if it somehow did, prepareKey() rejects a length
   * that is not an exact multiple of 64 rather than sending a short key.
   */
  return { kind: 'rsa', p: stripSignPad(priv.p), q: stripSignPad(priv.q) };
}

/**
 * Every usable key in a parsed PGP private key, primary first.
 *
 * The order is the contract: assignPgpSlots() reads index 0 as the primary,
 * index 1 as the decryption subkey and index 2 as the signing subkey. So a
 * subkey this cannot read is an ERROR rather than something to skip - dropping
 * it would silently shift every later key into the wrong role, and the result
 * is a device that signs with the decryption key.
 *
 * Takes the already-parsed key object rather than armored text, so this file
 * stays free of OpenPGP.js. The fork is 1.2 MB parsed and deliberately not
 * reachable from the package root; the caller that already has it passes what
 * it produced.
 */
function fromPgpKey(key) {
  if (!key || !key.keyPacket) {
    throw new Error('not a parsed PGP key: no keyPacket');
  }

  const packets = [
    { packet: key.keyPacket, label: 'primary key' },
    ...(key.subkeys || []).map((sub, i) => ({
      packet: sub.keyPacket, label: `subkey ${i + 1}`,
    })),
  ];

  return packets.map(({ packet, label }, index) => {
    try {
      return fromPgpPacket(packet, index > 0);
    } catch (err) {
      throw new Error(`${label}: ${err.message}`);
    }
  });
}
/**
 * Turn extracted material into what OKSETPRIV needs.
 *
 * @param {object} material  from fromSshpk or fromPgpPacket
 * @param {object} [opts] {slot, backup, signature, decryption, autoAssign}
 * @returns {{slot: number, type: number, key: Uint8Array}}
 */
function prepareKey(material, opts = {}) {
  const { backup = false, signature = false, decryption = false, autoAssign = false } = opts;
  let slot = opts.slot;

  let type;
  let key;

  if (material.kind === 'ecc') {
    if (material.curve === CURVE.NONE) {
      throw new Error('unsupported ECC key type');
    }
    if (material.scalar.length !== 32) {
      throw new Error(`ECC scalar must be 32 bytes, got ${material.scalar.length}`);
    }
    type = material.curve;
    key = material.scalar;
  } else {
    /*
     * 64 bytes of prime per 512 bits of modulus: 1024 -> 1, 4096 -> 4.
     *
     * The length must be an EXACT multiple, not merely divide to something in
     * range. The original uses parseInt(p.length / 64, 10), so a 100-byte
     * prime reads as type 1 and the device then waits for 128 bytes that never
     * arrive - a hang with no error at either end. Checked here.
     */
    const size = material.p.length / 64;
    if (!Number.isInteger(size) || size < 1 || size > 4) {
      throw new Error(
        `unsupported RSA size: p is ${material.p.length} bytes (expected 64, 128, 192 or 256)`,
      );
    }
    if (material.q.length !== material.p.length) {
      throw new Error(
        `RSA primes differ in length: p is ${material.p.length}, q is ${material.q.length}`,
      );
    }
    type = size;
    key = new Uint8Array(material.p.length + material.q.length);
    key.set(material.p, 0);
    key.set(material.q, material.p.length);
  }

  if (backup) type |= MODIFIER.BACKUP;
  if (signature) type |= MODIFIER.SIGNATURE;
  if (decryption) type |= MODIFIER.DECRYPTION;

  /*
   * The auto convention, from OnlyKeyComm.js:1885-1895.
   *
   * Slot 1 is decryption; slot 2 is signature AND clears any backup flag
   * first. The original's comment says why: "Only set backup flag on
   * decryption key." A signing key that kept it would be included in backups
   * it has no business being in.
   */
  if (autoAssign) {
    if (slot === ROLE_SLOT.DECRYPTION) {
      type |= MODIFIER.DECRYPTION;
    } else if (slot === ROLE_SLOT.SIGNATURE) {
      type &= ~MODIFIER.BACKUP;
      type |= MODIFIER.SIGNATURE;
    }
  }

  if (material.kind === 'ecc' && slot !== undefined && slot < ECC_SLOT_OFFSET) {
    slot += ECC_SLOT_OFFSET;
  }

  return { slot, type, key };
}

/**
 * Assign PGP subkeys to slots.
 *
 * The Keybase and Protonmail convention, from OnlyKeyWizard.js:781-811:
 * subkey 1 is the decryption key and goes to slot 1; the signing key is
 * subkey 2 when there is one, otherwise the primary, and goes to slot 2.
 *
 * A Protonmail X25519 key has exactly two entries - primary and one subkey -
 * so the same rule puts the primary on signature and the subkey on
 * decryption, which is what that layout means.
 *
 * @param {Array} candidates  index 0 the primary, then subkeys in order
 */
function assignPgpSlots(candidates) {
  if (!candidates.length) throw new Error('no keys to assign');

  const assignments = [];
  const signing = candidates.length > 2 ? candidates[2] : candidates[0];
  assignments.push({ role: 'signature', slot: ROLE_SLOT.SIGNATURE, key: signing });

  if (candidates.length > 1) {
    assignments.push({ role: 'decryption', slot: ROLE_SLOT.DECRYPTION, key: candidates[1] });
  }
  return assignments;
}

/* ------------------------------------------------------------- backup key */

/** The backup passphrase must be at least this long (OnlyKeyWizard.js:858). */
const BACKUP_PASSPHRASE_MIN = 25;

/**
 * Where a passphrase-derived backup key lives.
 * 161 = 0x80 backup | 0x20 decryption | 1, matching the original's comment.
 */
const BACKUP_SLOT = 131;
const BACKUP_TYPE = 161;

function validateBackupPassphrase(passphrase, confirm = null) {
  const problems = [];
  const text = String(passphrase || '');
  if (!text.length) problems.push('Passphrase is required.');
  else if (text.length < BACKUP_PASSPHRASE_MIN) {
    problems.push(`Passphrase must be at least ${BACKUP_PASSPHRASE_MIN} characters.`);
  }
  if (confirm !== null && text !== String(confirm)) {
    problems.push('Passphrases do not match.');
  }
  return problems;
}

/**
 * Derive the backup key from a passphrase.
 *
 * SHA-256 of the passphrase bytes, 32 bytes, one unchunked packet. latin1
 * rather than UTF-8, matching what the original's forge path produces for
 * bytes above 0x7f.
 */
function backupKeyFromPassphrase(passphrase) {
  const problems = validateBackupPassphrase(passphrase);
  if (problems.length) throw new Error(problems.join(' '));
  return { slot: BACKUP_SLOT, type: BACKUP_TYPE, key: sha256(fromLatin1(String(passphrase))) };
}

module.exports = {
  CURVE,
  OID,
  MODIFIER,
  ECC_SLOT_OFFSET,
  ROLE_SLOT,
  BACKUP_SLOT,
  BACKUP_TYPE,
  BACKUP_PASSPHRASE_MIN,
  oidEquals,
  curveFromOid,
  stripSignPad,
  fromSshpk,
  fromPgpPacket,
  fromPgpKey,
  prepareKey,
  assignPgpSlots,
  validateBackupPassphrase,
  backupKeyFromPassphrase,
};
