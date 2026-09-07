// JS port of python-onlykey's onlykey/age_plugin/derived_xwing.py - the
// browser-side twin of the derived (label-based) X-Wing split-custody math.
// Ported from onlykey-testing/lib/age_pqc.js (proven byte-for-byte against
// the Python reference there via test/fixtures/derived-xwing-vector.json
// and test/05-age-pqc-derived.test.js), with encodeIdentity/decodeIdentity
// replaced by the real bech32 scheme (see derived_xwing.py/bech32.py) - the
// old scheme here was stale/superseded and `age` rejects it outright.
//
// Wire contract this mirrors (see okcrypto.cpp's okcrypto_xwing_web_derive,
// RESERVED_KEY_WEB_DERIVATION + KEYTYPE_XWING dispatch):
//   DERIVE_PUBLIC_KEY -> [ pk_X(32) | mlkem_seed(32) ]
//   DERIVE_SHAREDSEC  -> [ ss_X(32) | mlkem_seed(32) ]
// The device never returns sk_X or the ML-KEM secret key - only a one-way
// SHA256(sk_X || tag)-derived seed the host expands locally.

const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { shake256, sha3_256 } = require('@noble/hashes/sha3.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { x25519 } = require('@noble/curves/ed25519.js');
const { utf8ToBytes, bytesToUtf8 } = require('../bytes');

const MLKEM_PK = 1184;
const MLKEM_CT = 1088;
const XWING_PK = 1216;
const XWING_CT = 1120;
const SEED = 32;

// draft-connolly-cfrg-xwing-kem-09 combiner label "\.//^\"
const XWING_LABEL = Uint8Array.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);

function concatBytes(...arrays) {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}

// 32-byte derivation tag for a derived-identity label - the value folded
// into the firmware's HKDF as additional_data. MUST match
// onlykey_hid.py's derived_label_tag() exactly: SHA256(utf8(label)).
function deriveLabelTag(label) {
    return sha256(utf8ToBytes(label));
}

// Expands the 32-byte device-derived seed (SHAKE256 -> 64-byte d||z) into an
// ML-KEM-768 keypair. Matches the firmware (xwing_shake256/keypair_derand)
// and python-onlykey's mlkem_keypair_from_seed() (kyber_py's
// _keygen_internal(d, z)) - @noble/post-quantum's ml_kem768.keygen(seed64)
// splits the same way internally (seed[:32]=d, seed[32:]=z; see
// createKyber() in @noble/post-quantum's ml-kem.ts).
function mlkemKeypairFromSeed(mlkemSeed) {
    if (mlkemSeed.length !== SEED) {
        throw new Error(`mlkem_seed must be ${SEED} bytes, got ${mlkemSeed.length}`);
    }
    const seed64 = shake256(mlkemSeed, { dkLen: 64 });
    return ml_kem768.keygen(seed64); // { publicKey, secretKey }
}

// Builds the 1216-byte X-Wing recipient public key (pk_M || pk_X).
function buildRecipient(pkX, mlkemSeed) {
    if (pkX.length !== 32) {
        throw new Error(`pk_X must be 32 bytes, got ${pkX.length}`);
    }
    const { publicKey: pkM } = mlkemKeypairFromSeed(mlkemSeed);
    return concatBytes(pkM, pkX);
}

// X-Wing Combiner (draft-connolly-cfrg-xwing-kem-09 Section 5.3):
// SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
function xwingCombiner(ssM, ssX, ctX, pkX) {
    return sha3_256(concatBytes(ssM, ssX, ctX, pkX, XWING_LABEL));
}

// Finishes X-Wing decapsulation given the device's ss_X and the seed.
// ssX: 32-byte X25519 shared secret from the device (sk_X stays there)
// ciphertext: 1120-byte X-Wing ct (ct_M || ct_X) from the age stanza
// pkX: recipient X25519 public key
// mlkemSeed: 32-byte ML-KEM seed from the device
// Returns the 32-byte X-Wing shared secret. ct_M never leaves the host.
function splitDecapsulate(ssX, ciphertext, pkX, mlkemSeed) {
    if (ssX.length !== 32) throw new Error('ss_X must be 32 bytes');
    if (ciphertext.length !== XWING_CT) {
        throw new Error(`X-Wing ct must be ${XWING_CT} bytes, got ${ciphertext.length}`);
    }
    const ctM = ciphertext.subarray(0, MLKEM_CT);
    const ctX = ciphertext.subarray(MLKEM_CT, XWING_CT);
    const { secretKey: skM } = mlkemKeypairFromSeed(mlkemSeed);
    const ssM = ml_kem768.decapsulate(ctM, skM);
    return xwingCombiner(ssM, ssX, ctX, pkX);
}

// Returns ct_X (the 32 bytes the device needs) from a stanza ciphertext.
function ctXOf(ciphertext) {
    return ciphertext.subarray(MLKEM_CT, XWING_CT);
}

// Standard X-Wing Encapsulation (host/sender side, for encrypt). Mirrors
// xwing.py's xwing_encaps_host() exactly. Note: x25519 here comes from the
// vendored @noble/curves (already an unavoidable transitive dependency of
// @noble/post-quantum - see vendor/@noble/VENDORED.md) rather than nacl.js,
// so this matches onlykey-testing/lib/age_pqc.js's already-proven-correct
// call sites exactly.
function xwingEncapsHost(pk) {
    if (pk.length !== XWING_PK) {
        throw new Error(`X-Wing pk must be ${XWING_PK} bytes, got ${pk.length}`);
    }
    const pkM = pk.subarray(0, MLKEM_PK);
    const pkX = pk.subarray(MLKEM_PK, XWING_PK);

    const ekX = x25519.utils.randomSecretKey();
    const ctX = x25519.getPublicKey(ekX);
    const ssX = x25519.getSharedSecret(ekX, pkX);

    const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(pkM);

    const ss = xwingCombiner(ssM, ssX, ctX, pkX);
    const ct = concatBytes(ctM, ctX);
    return { sharedSecret: ss, ciphertext: ct };
}

// ---- bech32 (real, BIP-173 checksum algorithm, no 90-char length cap) ----
// Ported directly from python-onlykey's bech32.py - a 1216-byte X-Wing
// recipient encodes to something far longer than the standard's 90-char
// cap, so that cap is deliberately not enforced here either, matching the
// Python side exactly.
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
    let chk = 1;
    for (const v of values) {
        const b = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) {
            if ((b >>> i) & 1) chk ^= BECH32_GEN[i];
        }
    }
    return chk >>> 0;
}

function bech32HrpExpand(hrp) {
    const out = [];
    for (const ch of hrp) out.push(ch.charCodeAt(0) >>> 5);
    out.push(0);
    for (const ch of hrp) out.push(ch.charCodeAt(0) & 31);
    return out;
}

function bech32CreateChecksum(hrp, data) {
    const values = bech32HrpExpand(hrp).concat(data);
    const polymod = bech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
    const out = [];
    for (let i = 0; i < 6; i++) out.push((polymod >>> (5 * (5 - i))) & 31);
    return out;
}

function bech32VerifyChecksum(hrp, data) {
    return bech32Polymod(bech32HrpExpand(hrp).concat(data)) === 1;
}

// General power-of-2 base conversion (8-bit bytes <-> 5-bit bech32 groups).
function convertBits(data, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << toBits) - 1;
    for (const value of data) {
        if (value < 0 || (value >> fromBits) !== 0) return null;
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push((acc >>> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
        return null;
    }
    return ret;
}

function bech32Encode(hrp, data) {
    const values = convertBits(Array.from(data), 8, 5, true);
    const checksum = bech32CreateChecksum(hrp, values);
    return hrp + '1' + values.concat(checksum).map((d) => BECH32_CHARSET[d]).join('');
}

// Returns { hrp, data: Uint8Array } or { hrp: null, data: null } if invalid.
function bech32Decode(bech) {
    for (const ch of bech) {
        const code = ch.charCodeAt(0);
        if (code < 33 || code > 126) return { hrp: null, data: null };
    }
    bech = bech.toLowerCase();
    const pos = bech.lastIndexOf('1');
    if (pos < 1 || pos + 7 > bech.length) return { hrp: null, data: null };
    const hrp = bech.slice(0, pos);
    const data = [];
    for (const ch of bech.slice(pos + 1)) {
        const idx = BECH32_CHARSET.indexOf(ch);
        if (idx === -1) return { hrp: null, data: null };
        data.push(idx);
    }
    if (!bech32VerifyChecksum(hrp, data)) return { hrp: null, data: null };
    const decoded = convertBits(data.slice(0, -6), 5, 8, false);
    if (decoded === null) return { hrp: null, data: null };
    return { hrp, data: Uint8Array.from(decoded) };
}

// ---- age1onlykey... recipient encoding (slot-based, ported for parity) ---
const RECIPIENT_HRP = 'age1onlykey';

function encodeRecipient(pubkey) {
    return bech32Encode(RECIPIENT_HRP, pubkey);
}

function decodeRecipient(recipient) {
    const { hrp, data } = bech32Decode(String(recipient).trim().toLowerCase());
    if (hrp !== RECIPIENT_HRP || data === null) {
        throw new Error(`not a valid ${RECIPIENT_HRP} recipient: ${recipient}`);
    }
    return data;
}

// ---- derived age identity encoding (label-based, no slot) ----------------
// Mirrors derived_xwing.py's encode_identity/decode_identity exactly: real
// bech32, HRP == the SAME "age-plugin-onlykey-" slot-identity HRP (age
// picks which plugin binary to exec from this literal prefix text - a
// distinct HRP breaks dispatch entirely), disambiguated from a slot
// identity by a 0xFF marker byte as the first payload byte.
const IDENTITY_HRP = 'age-plugin-onlykey-'; // MUST match cli.py's IDENTITY_HRP
const DERIVED_MARKER = 0xff;

function encodeIdentity(label) {
    if (typeof label !== 'string' || !label) {
        throw new Error('derived identity needs a non-empty label');
    }
    const payload = concatBytes(Uint8Array.of(DERIVED_MARKER), utf8ToBytes(label));
    return bech32Encode(IDENTITY_HRP, payload).toUpperCase();
}

function decodeIdentity(s) {
    const { hrp, data } = bech32Decode(String(s).trim().toLowerCase());
    if (hrp !== IDENTITY_HRP || !data || data.length < 1 || data[0] !== DERIVED_MARKER) {
        return null;
    }
    return { derived: true, label: bytesToUtf8(data.subarray(1)) };
}

module.exports = {
    mlkemKeypairFromSeed,
    buildRecipient,
    xwingCombiner,
    splitDecapsulate,
    ctXOf,
    xwingEncapsHost,
    deriveLabelTag,
    encodeRecipient,
    decodeRecipient,
    encodeIdentity,
    decodeIdentity,
    XWING_LABEL,
    MLKEM_PK,
    MLKEM_CT,
    XWING_PK,
    XWING_CT,
    SEED,
};
