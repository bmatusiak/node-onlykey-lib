export namespace KEY_TYPE {
    let ED25519: number;
    let P256R1: number;
    let P256K1: number;
    let CURVE25519: number;
    let MLKEM768: number;
    let XWING: number;
    let HMACSHA1: number;
    let ECDH_P256R: number;
    let ECDH_P256K: number;
    let ECDH_CURVE25519: number;
}
/**
 * The types a person picks when writing a raw key, in the order a form shows
 * them, with the byte length each one wants.
 *
 * The lengths are checked rather than assumed: the device takes what it is
 * given, so a 31-byte scalar written as Ed25519 is accepted and then signs
 * nothing that verifies.
 */
export const RAW_KEY_TYPES: ({
    name: string;
    type: number;
    bytes: number;
    hmacOnly?: undefined;
} | {
    name: string;
    type: number;
    bytes: number;
    hmacOnly: boolean;
})[];
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
export const PUBLIC_KEY_BYTES: {
    [KEY_TYPE.MLKEM768]: number;
    [KEY_TYPE.XWING]: number;
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
export const GENERATED_KEY_TYPES: {
    name: string;
    type: number;
    publicKeyBytes: number;
}[];
export namespace CURVE {
    export let NONE: number;
    let ED25519_1: number;
    export { ED25519_1 as ED25519 };
    export let NIST256P1: number;
    export let SECP256K1: number;
}
export namespace OID {
    let ED25519_2: number[];
    export { ED25519_2 as ED25519 };
    let NIST256P1_1: number[];
    export { NIST256P1_1 as NIST256P1 };
    let CURVE25519_1: number[];
    export { CURVE25519_1 as CURVE25519 };
    let SECP256K1_1: number[];
    export { SECP256K1_1 as SECP256K1 };
}
export namespace MODIFIER {
    let BACKUP: number;
    let SIGNATURE: number;
    let DECRYPTION: number;
}
/** ECC private keys live in a separate slot namespace, 100 above RSA's. */
export const ECC_SLOT_OFFSET: 100;
export namespace ROLE_SLOT {
    let DECRYPTION_1: number;
    export { DECRYPTION_1 as DECRYPTION };
    let SIGNATURE_1: number;
    export { SIGNATURE_1 as SIGNATURE };
}
/**
 * Where a passphrase-derived backup key lives.
 * 161 = 0x80 backup | 0x20 decryption | 1, matching the original's comment.
 */
export const BACKUP_SLOT: 131;
export const BACKUP_TYPE: 161;
/** The backup passphrase must be at least this long (OnlyKeyWizard.js:858). */
export const BACKUP_PASSPHRASE_MIN: 25;
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
export const PASSPHRASE_ENCODING: Readonly<{
    UTF8: "utf-8";
    LATIN1_LEGACY: "latin-1-legacy";
    TRUNCATED_LEGACY: "truncated-legacy";
}>;
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
export function oidEquals(a: any, b: any): boolean;
/** Which curve a PGP OID names, or CURVE.NONE. */
export function curveFromOid(oid: any): number;
/**
 * Strip the DER sign-padding byte from an RSA prime.
 *
 * A DER INTEGER carries a leading zero when its high bit is set, which for an
 * RSA prime at any supported size it always is. The original slices
 * unconditionally, which happens to be right for those sizes and wrong in
 * general; conditional is the same result and survives a key that is not.
 */
export function stripSignPad(bytes: any): Uint8Array<ArrayBuffer>;
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
export function eccScalar32(scalar: any): Uint8Array<ArrayBuffer>;
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
export function fromSshpk(key: any): {
    kind: any;
    curve: any;
    scalar: any;
} | {
    kind: any;
    p: any;
    q: any;
};
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
export function fromPgpPacket(packet: object, isSubkey?: boolean): {
    kind: string;
    curve: number;
    scalar: Uint8Array<ArrayBuffer>;
    p?: undefined;
    q?: undefined;
} | {
    kind: string;
    p: Uint8Array<ArrayBuffer>;
    q: Uint8Array<ArrayBuffer>;
    curve?: undefined;
    scalar?: undefined;
};
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
export function fromPgpKey(key: any): ({
    kind: string;
    curve: number;
    scalar: Uint8Array<ArrayBuffer>;
    p?: undefined;
    q?: undefined;
} | {
    kind: string;
    p: Uint8Array<ArrayBuffer>;
    q: Uint8Array<ArrayBuffer>;
    curve?: undefined;
    scalar?: undefined;
})[];
/**
 * Turn extracted material into what OKSETPRIV needs.
 *
 * @param {object} material  from fromSshpk or fromPgpPacket
 * @param {object} [opts] {slot, backup, signature, decryption, autoAssign}
 * @returns {{slot: number, type: number, key: Uint8Array}}
 */
export function prepareKey(material: object, opts?: object): {
    slot: number;
    type: number;
    key: Uint8Array;
};
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
export function assignPgpSlots(candidates: any[]): {
    role: string;
    slot: number;
    key: any;
}[];
export function validateBackupPassphrase(passphrase: any, confirm?: null): string[];
/**
 * Does the passphrase hash differently in Latin-1 than in UTF-8?
 *
 * True only when every character fits in Latin-1 (<= U+00FF) AND at least one
 * is outside ASCII (>= U+0080). Otherwise there is no second key to try: ASCII
 * is identical, and a string with anything above U+00FF has no Latin-1 form
 * (the classic App threw on it, so no legacy backup can exist for it).
 */
export function passphraseHasLegacyForm(passphrase: any): boolean;
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
export function passphraseBytes(passphrase: string, encoding?: "utf-8" | "latin-1-legacy" | "truncated-legacy"): Uint8Array;
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
export function backupKeyFromPassphrase(passphrase: string, { encoding }?: {
    encoding?: "utf-8" | "latin-1-legacy" | "truncated-legacy";
}): {
    slot: number;
    type: number;
    key: Uint8Array;
    encoding: string;
};
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
export function backupPassphraseCandidates(passphrase: string): Array<{
    slot: number;
    type: number;
    key: Uint8Array;
    encoding: string;
}>;
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
export function backupKeyFromPgp(scalar: Uint8Array, { curve, alsoSignature }?: {
    curve: number;
    alsoSignature?: boolean | undefined;
}): {
    slot: number;
    type: number;
    key: Uint8Array;
};
