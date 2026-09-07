// Composite PGP-PQC (ML-KEM-768 + ML-DSA-65 + X25519 + Ed25519) key
// generation and 160-byte blob packing - maintainer TC-11.
//
// Mirrors python-onlykey's onlykey/pqc.py (wire layout/constants) and
// python-onlykey/onlykey/openpgp_bridge/bridge.js's parseKey() (blob field
// order, byte-identical to okpqc.h's PQC_OFF_* layout). Key GENERATION here
// uses the vendored PQC-aware openpgp.js
// fork's own generateKey({type:'pqc'}) - it already produces the exact
// eccSecretKey/mldsaSeed/mlkemSeed fields bridge.js already knows how to
// extract, so there's no need to hand-roll composite key generation.
//
// Device transport (OKSIGN/OKDECRYPT chunked send/poll, hardware hooks
// registration) lives in onlykey-3rd-party.js alongside the other device-
// facing OnlyKey API methods - this file is intentionally device-free,
// same split as age_pqc.js (math here) vs onlykey-3rd-party.js
// (derive_xwing_recipient/derive_xwing_decap there).

// Blob layout, matching okpqc.h's PQC_OFF_* defines:
//   [0:32]   Ed25519 secret       (sign, ecc half)
//   [32:64]  ML-DSA-65 seed       (sign, pqc half)
//   [64:96]  X25519 secret        (decrypt, ecc half)
//   [96:160] ML-KEM-768 seed      (decrypt, pqc half)
const OFF_ED25519 = 0;
const OFF_MLDSA_SEED = 32;
const OFF_X25519 = 64;
const OFF_MLKEM_SEED = 96;
const BLOB_LEN = 160;

const ED25519_SK_LEN = 32;
const MLDSA_SEED_LEN = 32;
const X25519_SK_LEN = 32;
const MLKEM_SEED_LEN = 64;

// pqc.py's component selector (sign only; decrypt infers the half from
// input size instead - see okpqc_decrypt()).
const HALF_ECC = 0;
const HALF_PQC = 1;

// Wire sizes (okpqc.h) - what the device expects/returns per operation.
const MLKEM_CT_LEN = 1088;
const X25519_PT_LEN = 32;
const SS_LEN = 32;
const ED25519_SIG_LEN = 64;
const MLDSA_SIG_LEN = 3309;

// okcore.h's key_type byte for a loaded composite slot (RSA slots 1-4):
// KEYTYPE_PQC_PGP(7) | FEATURE_DECRYPT(0x20) | FEATURE_SIGN(0x40) = 0x67.
const PQC_KEY_TYPE_BYTE = 0x67;

function packBlob(ed25519Sk, mldsaSeed, x25519Sk, mlkemSeed) {
    const parts = [
        ['ed25519Sk', ed25519Sk, ED25519_SK_LEN],
        ['mldsaSeed', mldsaSeed, MLDSA_SEED_LEN],
        ['x25519Sk', x25519Sk, X25519_SK_LEN],
        ['mlkemSeed', mlkemSeed, MLKEM_SEED_LEN],
    ];
    for (const [name, val, len] of parts) {
        if (!val || val.length !== len) {
            throw new Error(name + ' must be ' + len + ' bytes, got ' + (val && val.length));
        }
    }
    const blob = new Uint8Array(BLOB_LEN);
    blob.set(ed25519Sk, OFF_ED25519);
    blob.set(mldsaSeed, OFF_MLDSA_SEED);
    blob.set(x25519Sk, OFF_X25519);
    blob.set(mlkemSeed, OFF_MLKEM_SEED);
    return blob;
}

function unpackBlob(blob) {
    if (!blob || blob.length !== BLOB_LEN) {
        throw new Error('blob must be ' + BLOB_LEN + ' bytes, got ' + (blob && blob.length));
    }
    return {
        ed25519Sk: blob.slice(OFF_ED25519, OFF_ED25519 + ED25519_SK_LEN),
        mldsaSeed: blob.slice(OFF_MLDSA_SEED, OFF_MLDSA_SEED + MLDSA_SEED_LEN),
        x25519Sk: blob.slice(OFF_X25519, OFF_X25519 + X25519_SK_LEN),
        mlkemSeed: blob.slice(OFF_MLKEM_SEED, OFF_MLKEM_SEED + MLKEM_SEED_LEN),
    };
}

// Generates a v6 composite PGP key (pqc_mldsa_ed25519 primary + subkey
// pqc_mlkem_x25519) via the vendored openpgp.js fork, extracts the four
// private seeds the exact way bridge.js's parseKey() already does, and
// packs them into the 160-byte blob okpqc.h expects. The caller is
// expected to load `blob` onto the device (via `onlykey-cli setpqc`, per
// TC-11 step 2 - not from the browser, see the plan's note on why) and
// then discard the local private material.
async function generateCompositeKey(openpgp, { userId } = {}) {
    // hooks.signer (unlike hooks.ecdh/hooks.mlkemDecaps) fires
    // UNCONDITIONALLY whenever registered - it is not gated on the target
    // key being hardware-backed (confirmed by direct read of openpgp.js's
    // sign$1: `if (hooks.signer) { ... }`, no isHardwareBacked check).
    // generateKey() below creates real self-signatures using the freshly
    // generated LOCAL private key material, so if a stale hooks.signer is
    // still registered from a previous decrypt/sign session, it would
    // hijack that signing and corrupt the new key's self-signature.
    // Clearing here makes generateCompositeKey() safe to call regardless
    // of what hook state the caller left behind.
    openpgp.clearHardwareHooks();
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'pqc',
        userIDs: userId ? [userId] : [],
        subkeys: [{}],
        format: 'object',
        config: { v6Keys: true },
    });

    const primaryParams = privateKey.keyPacket.privateParams;
    const subkeyParams = privateKey.subkeys[0].keyPacket.privateParams;

    const blob = packBlob(
        primaryParams.eccSecretKey,
        primaryParams.mldsaSeed,
        subkeyParams.eccSecretKey,
        subkeyParams.mlkemSeed
    );

    const armoredPublicKey = await publicKey.armor();
    return { armoredPublicKey, blob };
}

// Wires the vendored openpgp.js fork's hardware-backing hooks
// (hooks.ecdh / hooks.mlkemDecaps / hooks.signer - see
// vendor/openpgp/VENDORED.md) to the OnlyKey device's
// composite_decrypt()/composite_sign() (onlykey-3rd-party.js), so normal
// openpgp.decrypt()/sign()/verify() calls transparently route private-key
// operations through the device. `ok` is the object `app.onlykey3rd()`
// returns (same one age-derive.js's `ok.derive_xwing_recipient` etc. come
// from). `slot` is the RSA slot (1-4) the composite key was loaded into
// via `onlykey-cli setpqc` - TC-11 step 2, done via the CLI, not this app
// (OKSETPRIV isn't reachable over the browser's WebAuthn transport at
// all - confirmed by direct firmware read, see the plan's phase 2 note).
function registerCompositeHooks(openpgp, ok, slot) {
    openpgp.setHardwareHooks({
        // Classical (X25519) half of composite decryption.
        // `ephemeralPublicKey` is the sender's 32-byte ephemeral point -
        // okpqc_decrypt (firmware) infers the X25519 half purely from this
        // exact input size, same as composite_decrypt() does client-side.
        ecdh: async function(algo, ephemeralPublicKey) {
            return ok.composite_decrypt(slot, ephemeralPublicKey);
        },
        // Post-quantum (ML-KEM-768) half of composite decryption.
        // `mlkemCipherText` is 1088 bytes - okpqc_decrypt infers the
        // ML-KEM half from this exact size too. openpgp.js does the
        // composite key combine (SHA3-256, draft-ietf-openpgp-pqc-10
        // section 4.2.1) and the RFC 3394 AES key-unwrap itself once both
        // shares are available - no need to port onlykey_pqc.py's
        // composite_decrypt KDF math to JS at all.
        mlkemDecaps: async function(algo, mlkemCipherText) {
            return ok.composite_decrypt(slot, mlkemCipherText);
        },
        // Composite signing: openpgp.js calls this ONCE per signature with
        // algo=pqc_mldsa_ed25519 and expects BOTH halves back together as
        // { eccSignature, mldsaSignature } - confirmed by reading the
        // fork's own non-hook fallback path (sign$2/openpgp.js), which
        // returns this exact shape. `hashed` is passed to the device
        // UNCHANGED for both halves - the ML-DSA half's FIPS 204 "empty
        // context" framing ([0x00,0x00]||hashed, confirmed at
        // openpgp.js's sign$4) is added by okpqc.cpp/mldsa_native
        // firmware-side, not here (see okpqc.cpp's own comment on this -
        // this was the biggest hardware-verification risk flagged in the
        // plan, now resolved by direct code read on both sides, still
        // worth confirming empirically).
        //
        // The two halves are signed SEQUENTIALLY, not in parallel - the
        // device only handles one outstanding chunked-send/challenge-
        // confirm/poll sequence at a time (shared firmware state:
        // CRYPTO_AUTH, packet_buffer_details, large_resp_buffer), so
        // running both concurrently would corrupt one or both operations.
        // This means composite signing needs the challenge PIN confirmed
        // TWICE on-device (once per half) - a real device-side property,
        // not a bug in this wiring.
        signer: async function(algo, hashAlgo, hashed) {
            if (algo !== openpgp.enums.publicKey.pqc_mldsa_ed25519) return null;
            const eccSignature = await ok.composite_sign(slot, HALF_ECC, hashed);
            const mldsaSignature = await ok.composite_sign(slot, HALF_PQC, hashed);
            return { eccSignature, mldsaSignature };
        },
    });
}

module.exports = {
    BLOB_LEN,
    OFF_ED25519,
    OFF_MLDSA_SEED,
    OFF_X25519,
    OFF_MLKEM_SEED,
    ED25519_SK_LEN,
    MLDSA_SEED_LEN,
    X25519_SK_LEN,
    MLKEM_SEED_LEN,
    HALF_ECC,
    HALF_PQC,
    MLKEM_CT_LEN,
    X25519_PT_LEN,
    SS_LEN,
    ED25519_SIG_LEN,
    MLDSA_SIG_LEN,
    PQC_KEY_TYPE_BYTE,
    packBlob,
    unpackBlob,
    generateCompositeKey,
    registerCompositeHooks,
};
