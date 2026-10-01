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

const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { fromLatin1, utf8ToBytes } = require('../bytes');

/**
 * The curve identifiers the device uses. Not OIDs - the device's own numbering.
 * 0 means "unrecognised", and reaches the device as an error rather than a key.
 *
 * SECP256K1 is 3, KEYTYPE_P256K1 (okcore.h:231 at release 3.1.0): the
 * firmware generates it (okcrypto.cpp:580-582), signs with it (:879), does
 * ECDH with it (:1130-1131) and derives its public key (:2368-2369). It was
 * missing here, so an imported secp256k1 key - SSH or OpenPGP - was refused
 * as an unknown curve although the device takes it. The desktop rewrite maps
 * both to 3 (ok-app-rewrite
 * keyMaterial.test.ts "maps secp256k1 SSH ECDSA to type 3, not NIST",
 * "maps OpenPGP secp256k1 to type 3").
 */
const CURVE = { NONE: 0, ED25519: 1, NIST256P1: 2, SECP256K1: 3 };

/**
 * Every key type OKSETPRIV accepts, from okcore.h:218-228.
 *
 * A SUPERSET of CURVE above, which only carries the three a PGP key can be.
 * These are what a caller writing a RAW key picks from, and there is no way to
 * derive them from the material: 32 bytes is an Ed25519 scalar, a Curve25519
 * scalar or a P-256 scalar, and the device is told which.
 *
 * NACL and ED25519 are both 1 in the firmware - not a mistake here, the same
 * define twice - so they are one entry.
 *
 * HMACSHA1 is 9, and its slots are the two in slots.HMAC_SLOTS. Writing one
 * clears that slot's button-press requirement without saying so; the device
 * plugin reports that, since the firmware will not.
 */
/**
 * THE TWO TABLES COLLIDE, AND THE COLLIDING VALUE IS 5.
 *
 * `KEY_TYPE` below is the byte a SLOT is written with, over the vendor
 * interface. `okconnect.KEYTYPE` is the byte a DERIVE request carries, over
 * CTAPHID. They are different protocols with independently grown numbering,
 * and they overlap:
 *
 *   keys.KEY_TYPE.MLKEM768      = 5     a slot holds an ML-KEM-768 key
 *   okconnect.KEYTYPE.XWING     = 5     derive an X-Wing key for a label
 *
 * Same number, different algorithm, different wire, and nothing in either
 * table stops a caller passing one where the other belongs. The failure is
 * silent in the worst way: the device does something, and what it does is
 * cryptographically unrelated to what was asked. Always name the table when
 * one of these travels through a variable called `type`.
 */
const KEY_TYPE = {
  ED25519: 1,
  P256R1: 2,
  P256K1: 3,
  CURVE25519: 4,
  MLKEM768: 5,
  XWING: 6,
  HMACSHA1: 9,
  ECDH_P256R: 102,
  ECDH_P256K: 103,
  ECDH_CURVE25519: 104,
};

/**
 * The types a person picks when writing a raw key, in the order a form shows
 * them, with the byte length each one wants.
 *
 * The lengths are checked rather than assumed: the device takes what it is
 * given, so a 31-byte scalar written as Ed25519 is accepted and then signs
 * nothing that verifies.
 */
const RAW_KEY_TYPES = [
  { name: 'Ed25519', type: KEY_TYPE.ED25519, bytes: 32 },
  { name: 'Curve25519', type: KEY_TYPE.CURVE25519, bytes: 32 },
  { name: 'NIST P-256', type: KEY_TYPE.P256R1, bytes: 32 },
  { name: 'secp256k1', type: KEY_TYPE.P256K1, bytes: 32 },
  /*
   * HMAC-SHA1 keys are 20 bytes, and only the two reserved slots take one.
   * `slots` names those; repeating the numbers here would be a second copy.
   */
  { name: 'HMAC-SHA1', type: KEY_TYPE.HMACSHA1, bytes: 20, hmacOnly: true },
];

/**
 * How many bytes of PUBLIC key a post-quantum slot answers with.
 *
 * okcore.h:233 and :240. X-Wing is the ML-KEM key with an X25519 key glued to
 * the end - `pk_M(1184) || pk_X(32)` - which is also why its ciphertext is 32
 * bytes longer than ML-KEM's.
 *
 * These matter to a READER, not to a writer: the reply is raw reports with no
 * length anywhere in them, so a caller that does not know how many bytes to
 * expect cannot tell a finished key from a truncated one.
 */
const PUBLIC_KEY_BYTES = {
  [KEY_TYPE.MLKEM768]: 1184,
  [KEY_TYPE.XWING]: 1216,
};

/**
 * Key types the DEVICE makes, rather than ones a host writes into a slot.
 *
 * Deliberately not part of RAW_KEY_TYPES, which is "the types a person picks
 * when writing a raw key". A post-quantum slot is written by asking the
 * device to generate into it; the private half is a 32-byte seed that never
 * leaves. Writing a host-chosen seed into one of these slots would probably
 * work - the ordinary write path does not special-case the type - but nothing
 * here has tested it, and offering it in the same list as Ed25519 would be
 * presenting an untested path as an equal option.
 *
 * NO RELEASED FIRMWARE HAS EITHER OF THESE. See version.js's `postQuantum`
 * capability, which was measured across every pinned release.
 */
const GENERATED_KEY_TYPES = [
  { name: 'ML-KEM-768', type: KEY_TYPE.MLKEM768, publicKeyBytes: PUBLIC_KEY_BYTES[KEY_TYPE.MLKEM768] },
  { name: 'X-Wing', type: KEY_TYPE.XWING, publicKeyBytes: PUBLIC_KEY_BYTES[KEY_TYPE.XWING] },
];

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
  /* RFC 4880bis / OpenPGP.js 'secp256k1'; 132 is the two base-128 bytes 0x81 0x04. */
  SECP256K1: [43, 129, 4, 0, 10],                   // 1.3.132.0.10
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
  if (oidEquals(oid, OID.SECP256K1)) return CURVE.SECP256K1;
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
 * An ECC private scalar as the 32 bytes OKSETPRIV takes.
 *
 * A 33-byte scalar whose first byte is zero is the same number with a sign
 * byte in front: an SSH mpint (and sshpk's `part.d.data`) adds one whenever
 * the top bit of the 32-byte value is set, which is half of all P-256 and
 * secp256k1 keys. Those were thrown here as "must be 32 bytes"; the byte is
 * dropped instead. Only that shape is: a 32-byte scalar that happens to start
 * with zero is kept as it is (it is a full-width value), and anything else of
 * the wrong length is still refused, because the device takes whatever it is
 * given and a short key signs nothing that verifies. Vectors: ok-app-rewrite
 * keyMaterial.test.ts eccScalar32.
 */
function eccScalar32(scalar) {
  const bytes = Uint8Array.from(scalar);
  if (bytes.length === 33 && bytes[0] === 0x00) return bytes.subarray(1);
  if (bytes.length !== 32) {
    throw new Error(`ECC scalar must be 32 bytes, got ${bytes.length}`);
  }
  return bytes;
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
  /*
   * sshpk has no secp256k1 of its own; a key that carries it arrives named
   * either way depending on who built the object, and the rewrite accepts
   * both (keyMaterial.test.ts "maps secp256k1 SSH ECDSA to type 3").
   */
  if (key.curve === 'secp256k1' || key.curve === 'k256') {
    return { kind: 'ecc', curve: CURVE.SECP256K1, scalar: Uint8Array.from(key.part.d.data) };
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
      throw new Error('unsupported ECC curve; expected Ed25519, NIST P-256, secp256k1 or Curve25519');
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
      throw new Error('unsupported ECC curve; expected Ed25519, NIST P-256, secp256k1 or Curve25519');
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
    type = material.curve;
    key = eccScalar32(material.scalar);
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
 * How a backup passphrase becomes bytes before it is hashed.
 *
 * ## Why there are two, and why UTF-8 is the default (owner, 2026-09-30)
 *
 * The device never sees the passphrase. It receives the 32-byte SHA-256 of
 * SOME byte string in slot 131 and is indifferent to how that string was
 * made - so the encoding is a contract between the program that set the key
 * and the program that restores, and the two have disagreed:
 *
 *   - the classic desktop App hashes Latin-1 (OpenPGP.js
 *     util.str_to_Uint8Array, which THROWS above U+00FF), and this library
 *     copied it up to 0.3.0;
 *   - python-onlykey (f4ecaf2+) and trustcrypto's rewrite hash UTF-8.
 *
 * The two only produce different bytes for characters U+0080..U+00FF: pure
 * ASCII is the same byte string either way, and Latin-1 cannot represent
 * anything above U+00FF at all. "pässword" is the whole problem in one word:
 * Latin-1 sha256 fe699eee..., UTF-8 sha256 3478267b...
 *
 * UTF-8 is what the rest of the ecosystem settled on and what every
 * character a person can type has, so it is what a NEW key is made from.
 * Latin-1 stays, named as legacy, because backups protected by the classic
 * App (and by this library up to 0.3.0) exist and must still restore - see
 * backupPassphraseCandidates() and device.restore({ passphrase }).
 */
const PASSPHRASE_ENCODING = Object.freeze({
  UTF8: 'utf-8',
  LATIN1_LEGACY: 'latin-1-legacy',
  /*
   * The ONE-OFF BUG, reproduced on purpose: this library up to 0.3.0 hashed
   * every UTF-16 code unit with its top byte dropped (bytes.fromLatin1,
   * charCodeAt & 0xff). For a passphrase within U+00FF that is exactly
   * Latin-1; above it, "€" (U+20AC) became 0xAC and an emoji became two
   * surrogate halves' low bytes. A backup made that way opens with these bytes
   * and nothing else. Never tried automatically (backupPassphraseCandidates
   * does not list it) and offered by no GUI: the CLI's --latin-passphrase is
   * the only door to it (owner's decision), because it is a special case for a
   * few people, not a choice anyone should be shown.
   */
  TRUNCATED_LEGACY: 'truncated-legacy',
});

/**
 * Does the passphrase hash differently in Latin-1 than in UTF-8?
 *
 * True only when every character fits in Latin-1 (<= U+00FF) AND at least one
 * is outside ASCII (>= U+0080). Otherwise there is no second key to try: ASCII
 * is identical, and a string with anything above U+00FF has no Latin-1 form
 * (the classic App threw on it, so no legacy backup can exist for it).
 */
function passphraseHasLegacyForm(passphrase) {
  const text = String(passphrase);
  let wide = false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code > 0xff) return false;
    if (code >= 0x80) wide = true;
  }
  return wide;
}

/**
 * The bytes a passphrase is hashed from.
 *
 * NEVER TRUNCATES. Up to 0.3.0 this was fromLatin1(), which keeps `& 0xff` of
 * each UTF-16 unit - so "pašsword" (š = U+0161) hashed as "paasword" and two
 * different passphrases produced the same backup key, silently. A Latin-1
 * form is now produced only for a string that HAS one, and anything else is
 * refused with a message rather than mangled.
 *
 * UTF-8 is written out by bytes.utf8ToBytes rather than TextEncoder: Hermes
 * has no TextEncoder, and src/ has to run there.
 *
 * @param {string} passphrase
 * @param {'utf-8'|'latin-1-legacy'|'truncated-legacy'} [encoding='utf-8']
 * @returns {Uint8Array}
 */
function passphraseBytes(passphrase, encoding = PASSPHRASE_ENCODING.UTF8) {
  const text = String(passphrase);
  if (encoding === PASSPHRASE_ENCODING.UTF8) return utf8ToBytes(text);
  if (encoding === PASSPHRASE_ENCODING.LATIN1_LEGACY) {
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) > 0xff) {
        throw new Error(
          `this passphrase has no Latin-1 form: "${text[i]}" (U+${text.charCodeAt(i)
            .toString(16).toUpperCase().padStart(4, '0')}) is above U+00FF. ` +
          'The classic App refused such passphrases, so no legacy backup was ' +
          'made from one; use the UTF-8 form.',
        );
      }
    }
    return fromLatin1(text);
  }
  /* 0.3.0's bytes exactly, truncation and all - see PASSPHRASE_ENCODING. */
  if (encoding === PASSPHRASE_ENCODING.TRUNCATED_LEGACY) return fromLatin1(text);
  throw new Error(
    `unknown passphrase encoding "${encoding}" - use "${PASSPHRASE_ENCODING.UTF8}", ` +
    `"${PASSPHRASE_ENCODING.LATIN1_LEGACY}" or "${PASSPHRASE_ENCODING.TRUNCATED_LEGACY}"`,
  );
}

/**
 * Derive the backup key from a passphrase.
 *
 * SHA-256 of the passphrase bytes, 32 bytes, one unchunked packet.
 *
 * CHANGED IN 0.4.0: the bytes are UTF-8 unless `encoding: 'latin-1-legacy'`
 * is asked for. Up to 0.3.0 they were Latin-1 (truncating above U+00FF). For
 * an ASCII passphrase the key is unchanged; for one with characters in
 * U+0080..U+00FF it is a different key - which is why restore() tries both.
 *
 * @param {string} passphrase
 * @param {{encoding?: 'utf-8'|'latin-1-legacy'|'truncated-legacy'}} [opts]
 * @returns {{slot: number, type: number, key: Uint8Array, encoding: string}}
 */
function backupKeyFromPassphrase(passphrase, { encoding = PASSPHRASE_ENCODING.UTF8 } = {}) {
  const problems = validateBackupPassphrase(passphrase);
  if (problems.length) throw new Error(problems.join(' '));
  return {
    slot: BACKUP_SLOT,
    type: BACKUP_TYPE,
    key: sha256(passphraseBytes(passphrase, encoding)),
    encoding,
  };
}

/**
 * Every backup key this passphrase could have been made into, newest first.
 *
 * One entry (UTF-8) for a passphrase whose two forms are the same bytes or
 * whose Latin-1 form does not exist; two (UTF-8, then Latin-1 legacy) only
 * when they differ. That is what keeps a pure-ASCII restore to one attempt.
 *
 * @param {string} passphrase
 * @returns {Array<{slot: number, type: number, key: Uint8Array, encoding: string}>}
 */
function backupPassphraseCandidates(passphrase) {
  const out = [backupKeyFromPassphrase(passphrase)];
  if (passphraseHasLegacyForm(passphrase)) {
    out.push(backupKeyFromPassphrase(passphrase, { encoding: PASSPHRASE_ENCODING.LATIN1_LEGACY }));
  }
  return out;
}

/**
 * The backup key taken from a PGP private key instead of a passphrase.
 *
 * The desktop's Setup Step 9. Same destination as the passphrase form - slot
 * 131 - and a different source: one of the key's own private scalars, chosen
 * by the person who owns it.
 *
 * ## The type byte is assembled, not a constant
 *
 * BACKUP_TYPE is 161, which is 0x80 backup | 0x20 decryption | 1 Ed25519. That
 * constant is right for a PASSPHRASE, whose sha256 is used as an Ed25519
 * scalar, and wrong for anything else - a NIST P-256 scalar written as type 161
 * is accepted by the device and then decrypts nothing. So the curve comes from
 * the key.
 *
 * `alsoSignature` adds 0x40, which is what the desktop's "set as signature key"
 * checkbox does. It is off by default: a backup key that also signs is a key
 * whose use in one role is visible in the other.
 *
 * @param {Uint8Array} scalar  the chosen private scalar
 * @param {object} opts
 * @param {number} opts.curve  CURVE.ED25519 or CURVE.NIST256P1
 * @param {boolean} [opts.alsoSignature=false]
 * @returns {{slot: number, type: number, key: Uint8Array}}
 */
function backupKeyFromPgp(scalar, { curve, alsoSignature = false } = {}) {
  if (!(scalar instanceof Uint8Array) || !scalar.length) {
    throw new Error('a backup key needs the private scalar as bytes');
  }
  /*
   * Refused rather than defaulted. CURVE.NONE is what curveFromOid returns for
   * a curve it does not know, and writing that as a type gives the device a
   * key it cannot use - discovered at restore time, which is the worst moment.
   */
  if (curve !== CURVE.ED25519 && curve !== CURVE.NIST256P1) {
    throw new Error(
      `a backup key must be Ed25519 or NIST P-256, got curve ${curve} - the ` +
      'device is told the type and cannot infer it from the bytes',
    );
  }

  let type = MODIFIER.BACKUP | MODIFIER.DECRYPTION | curve;
  if (alsoSignature) type |= MODIFIER.SIGNATURE;

  return { slot: BACKUP_SLOT, type, key: Uint8Array.from(scalar) };
}

module.exports = {
  KEY_TYPE,
  RAW_KEY_TYPES,
  PUBLIC_KEY_BYTES,
  GENERATED_KEY_TYPES,
  CURVE,
  OID,
  MODIFIER,
  ECC_SLOT_OFFSET,
  ROLE_SLOT,
  BACKUP_SLOT,
  BACKUP_TYPE,
  BACKUP_PASSPHRASE_MIN,
  PASSPHRASE_ENCODING,
  oidEquals,
  curveFromOid,
  stripSignPad,
  eccScalar32,
  fromSshpk,
  fromPgpPacket,
  fromPgpKey,
  prepareKey,
  assignPgpSlots,
  validateBackupPassphrase,
  passphraseHasLegacyForm,
  passphraseBytes,
  backupKeyFromPassphrase,
  backupPassphraseCandidates,
  backupKeyFromPgp,
};
