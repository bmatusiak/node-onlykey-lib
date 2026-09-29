/*
 * classic_pgp.js - openpgp hardware hooks for a CLASSIC key held in OnlyKey
 * slots (RSA 1-4, ECC 101-116). The sibling of composite_pgp.js: the same
 * fork, the same setHardwareHooks(), for the keys the web app's encrypt and
 * decrypt pages use. `ok` is okcrypto - its sign()/decrypt() run over the
 * vendor interface or, in a browser, the WebAuthn tunnel.
 *
 *   classic.registerClassicHooks(openpgp, ok, { signSlot: 2, decryptSlot: 1 });
 *   const hwKey = openpgp.createHardwarePrivateKey(publicKey);
 *   await openpgp.decrypt({ message, decryptionKeys: hwKey });
 *
 * What the device does, read at release 3.1.0 (okcrypto.cpp), and so what each
 * hook sends:
 *   RSA sign    a BARE digest of 28/32/48/64 bytes (SHA-224/256/384/512 - no
 *               SHA-1); the device adds the DigestInfo and answers modulus-size
 *               bytes (:605, :634, :1330-1355).
 *   RSA decrypt the ciphertext at EXACTLY modulus size - so the PGP MPI, which
 *               drops leading zeros, is left-padded here (:661); the answer is
 *               the unpadded PKCS#1 plaintext, the session-key block openpgp
 *               expects, of a length only the device knows (:696, :1439).
 *   ECC sign    64 bytes, r||s; a 32- or 64-byte input is signed as given, any
 *               other length is SHA-256'd first (:840-848) - so a 48-byte
 *               SHA-384 digest would be signed as something else, and is
 *               refused here rather than producing a bad signature.
 *   X25519 ECDH the sender's point, the 32-byte shared secret back (:968-970).
 *
 * ONE SET OF HOOKS: setHardwareHooks replaces what was registered, so a page
 * registers either these or the composite ones for the key it is using.
 * A slot left out (no signSlot, no decryptSlot) makes that hook fall through
 * to software, which fails on a hardware placeholder - by design, loudly.
 */
'use strict';

const RSA_DIGESTS = new Map([[28, 'SHA-224'], [32, 'SHA-256'], [48, 'SHA-384'], [64, 'SHA-512']]);

/** An MPI (leading zeros dropped) back at a fixed width. */
function leftPad(bytes, width) {
  if (bytes.length > width) throw new Error(`the ciphertext is ${bytes.length} bytes, longer than the ${width}-byte modulus`);
  const out = new Uint8Array(width);
  out.set(bytes, width - bytes.length);
  return out;
}

function registerClassicHooks(openpgp, ok, { signSlot = null, decryptSlot = null, ...opts } = {}) {
  const P = openpgp.enums.publicKey;

  async function signEcc(hashed) {
    if (hashed.length !== 32 && hashed.length !== 64) {
      throw new Error(
        `the device signs a 32- or 64-byte digest as given and re-hashes anything else; `
        + `this signature's digest is ${hashed.length} bytes - use SHA-256 or SHA-512`,
      );
    }
    return ok.sign(signSlot, hashed, { ...opts, expectBytes: 64 });
  }

  openpgp.setHardwareHooks({
    signer: async function(algo, hashAlgo, hashed, publicKeyParams) {
      if (signSlot === null) return null;
      switch (algo) {
        case P.rsaEncryptSign:
        case P.rsaSign: {
          if (!RSA_DIGESTS.has(hashed.length)) {
            throw new Error(
              `the device signs SHA-224/256/384/512 digests with RSA; this one is ${hashed.length} bytes`,
            );
          }
          const s = await ok.sign(signSlot, hashed, { ...opts, expectBytes: publicKeyParams.n.length });
          return { s };
        }
        case P.ecdsa:
        case P.eddsaLegacy: {
          const sig = await signEcc(hashed);
          return { r: sig.subarray(0, 32), s: sig.subarray(32, 64) };
        }
        case P.ed25519:
          return { RS: await signEcc(hashed) };
        default:
          return null;
      }
    },

    decryptor: async function(keyAlgo, sessionKeyParams, publicKeyParams) {
      if (decryptSlot === null) return null;
      if (keyAlgo !== P.rsaEncryptSign && keyAlgo !== P.rsaEncrypt) return null;
      const c = leftPad(sessionKeyParams.c, publicKeyParams.n.length);
      /* No expectBytes: the plaintext's length is the device's to know. */
      return ok.decrypt(decryptSlot, c, opts);
    },

    ecdh: async function(algo, ephemeralPublicKey) {
      if (decryptSlot === null) return null;
      if (algo !== P.ecdh && algo !== P.x25519) return null;
      /*
       * X25519 only: a 0x40-prefixed native point (legacy cv25519) or 32 bare
       * bytes; the device drops a prefix itself. A NIST point (65 bytes, 04||X||Y)
       * comes back as the 64-byte shared POINT, and openpgp wants its X - not
       * wired or tested yet, so refused rather than guessed.
       */
      if (ephemeralPublicKey.length === 65) {
        throw new Error('ECDH with a P-256/secp256k1 PGP key on the device is not supported yet - X25519 (cv25519) is');
      }
      return ok.decrypt(decryptSlot, ephemeralPublicKey, { ...opts, expectBytes: 32 });
    },
  });
}

module.exports = { registerClassicHooks, leftPad, RSA_DIGESTS };
