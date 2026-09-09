/**
 * Enough of SubtleCrypto for OpenPGP.js to run where the platform has none.
 *
 * React Native gives you `crypto.getRandomValues` and no `crypto.subtle`.
 * OpenPGP.js v6 reads WebCrypto at MODULE SCOPE - a dozen sites do
 * `const webCrypto$N = util.getWebCrypto()` - and `getWebCrypto` THROWS when
 * `globalThis.crypto.subtle` is absent, so the fork's factory dies before it
 * exports anything. Metro then hands back `undefined` from `require()` without
 * rethrowing, which is why that looked for a long time like a bundling problem.
 * See ok-rn/FINDING-the-openpgp-fork-does-not-load-under-hermes.md.
 *
 * ## Why a shim rather than a polyfill package
 *
 * Every primitive openpgp asks for is already a dependency of this library -
 * @noble/curves, @noble/ciphers, @noble/hashes. `react-native-quick-crypto`
 * would also work and was rejected: it is a native module, it would have to be
 * built for iOS as well, and it would put the answer outside the shared
 * library, which is the opposite of what this project is for.
 *
 * ## It does not install itself
 *
 * This library is platform-free by design, and a host that HAS WebCrypto must
 * keep its own - Node's and a browser's are complete, constant-time where it
 * matters, and better tested than this will ever be. So the host calls
 * `install()` once at startup, and `install()` refuses to replace a real one
 * unless told to.
 *
 * ## RSA, and what its absence actually costs
 *
 * @noble has no RSA, so the RSA algorithms throw a NotSupportedError naming
 * themselves. This used to be justified as "code nobody runs", which is wrong:
 * RSA slots 1-4 exist, keys.js has a full RSA path, and the app imports RSA
 * keys.
 *
 * What the absence costs is narrower and worth knowing exactly, because it is
 * not obvious. openpgp's RSA sign and verify wrap their WebCrypto call in
 * try/catch and fall through to a BigInt implementation
 * (openpgp.js:6107-6118, 6134-6144), so the refusal here is CAUGHT and RSA
 * sign, verify, encrypt and decrypt all work - measured, in
 * test/webcrypto-rsa-fallback.test.js.
 *
 * Key GENERATION is the one exception. `generate$b` (openpgp.js:6204) takes the
 * WebCrypto branch with no try/catch, so the refusal escapes - even though a
 * complete Miller-Rabin fallback sits twenty lines below it, unreachable
 * because getWebCrypto() answers truthy.
 *
 * So: "no RSA here" means "no RSA key generation", and nothing else.
 *
 * ## Fidelity
 *
 * Checked against Node's own `crypto.subtle` rather than against this file's
 * intentions - see test/webcrypto.test.js. Where the two disagree, this one is
 * wrong. WebCrypto's error TYPES are part of its contract too: callers branch
 * on `NotSupportedError` and `OperationError`, and openpgp's fallbacks do.
 */
'use strict';

const { sha256, sha384, sha512, sha224 } = require('@noble/hashes/sha2.js');
const { sha1 } = require('@noble/hashes/legacy.js');
const { hmac } = require('@noble/hashes/hmac.js');
const { extract, expand } = require('@noble/hashes/hkdf.js');
const { cbc, ctr, gcm, aeskw } = require('@noble/ciphers/aes.js');
const { ed25519, x25519 } = require('@noble/curves/ed25519.js');
const { p256, p384, p521 } = require('@noble/curves/nist.js');

const { toBase64Url, fromBase64Url } = require('../bytes');

/* ------------------------------------------------------------------ errors */

/**
 * WebCrypto rejects with DOMException, and its `name` is load-bearing.
 *
 * openpgp branches on it, and so does anything else written against the real
 * API. A plain Error with the right message would still take the wrong branch.
 */
function cryptoError(name, message) {
  const DOMException = globalThis.DOMException;
  if (typeof DOMException === 'function') return new DOMException(message, name);
  const err = new Error(message);
  err.name = name;
  return err;
}

const notSupported = (what) => cryptoError('NotSupportedError', `${what} is not implemented by node-onlykey-lib's WebCrypto shim`);
const operationFailed = (what) => cryptoError('OperationError', what);

/* ------------------------------------------------------------------ shapes */

const HASHES = {
  'SHA-1': sha1,
  'SHA-224': sha224,
  'SHA-256': sha256,
  'SHA-384': sha384,
  'SHA-512': sha512,
};

const CURVES = {
  'P-256': { curve: p256, bytes: 32, hash: sha256, crv: 'P-256' },
  'P-384': { curve: p384, bytes: 48, hash: sha384, crv: 'P-384' },
  'P-521': { curve: p521, bytes: 66, hash: sha512, crv: 'P-521' },
};

/** An algorithm argument is either a string or an object with a `name`. */
function algName(algorithm) {
  return typeof algorithm === 'string' ? algorithm : String(algorithm && algorithm.name);
}

function hashName(algorithm) {
  const h = typeof algorithm === 'string' ? algorithm : algorithm && algorithm.hash;
  return typeof h === 'string' ? h : (h && h.name);
}

function hashFor(algorithm) {
  const name = hashName(algorithm);
  const fn = HASHES[name];
  if (!fn) throw notSupported(`hash ${name}`);
  return fn;
}

function bytes(data) {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  throw new TypeError('expected BufferSource');
}

/**
 * An ArrayBuffer holding exactly these bytes.
 *
 * NOT `u8.buffer`. A Uint8Array from subarray() SHARES its backing store, so
 * `.buffer` hands back the whole original - which silently returned a 33-byte
 * ECDH secret where 32 were wanted, and would have done the same anywhere else
 * a view was narrowed. Caught by comparing against Node's own WebCrypto; a
 * self-consistent test would have agreed with it.
 */
function bufferOf(u8) {
  return u8.slice().buffer;
}

/**
 * A key handle.
 *
 * The real API returns an opaque CryptoKey whose material a caller cannot
 * read; here the material is a property, because there is nowhere to hide it in
 * JavaScript and pretending otherwise would be a false claim. `extractable` is
 * still honoured, so a caller that relies on export failing gets that.
 */
function makeKey(type, algorithm, extractable, usages, material) {
  return { type, algorithm, extractable, usages: usages.slice(), _material: material };
}

function requireUsage(key, usage) {
  if (!key.usages.includes(usage)) {
    throw cryptoError('InvalidAccessError', `key does not allow ${usage}`);
  }
}

/* ------------------------------------------------------------------- subtle */

function createSubtle() {
  const subtle = {
    async digest(algorithm, data) {
      return bufferOf(hashFor(algorithm)(bytes(data)));
    },

    async importKey(format, keyData, algorithm, extractable, usages) {
      const name = algName(algorithm);

      if (format === 'raw') {
        const material = bytes(keyData);
        switch (name) {
          case 'AES-CBC': case 'AES-CTR': case 'AES-GCM': case 'AES-KW':
          case 'HMAC': case 'HKDF':
            return makeKey('secret', algorithm, extractable, usages, material);
          case 'ECDH': case 'ECDSA':
            // A raw EC key is always the PUBLIC point.
            return makeKey('public', algorithm, extractable, usages, material);
          case 'Ed25519': case 'X25519':
            return makeKey('public', algorithm, extractable, usages, material);
          default:
            throw notSupported(`importKey('raw', …, ${name})`);
        }
      }

      if (format === 'jwk') {
        const jwk = keyData;
        if (jwk.kty === 'oct') {
          return makeKey('secret', algorithm, extractable, usages, fromBase64Url(jwk.k));
        }
        if (jwk.kty === 'OKP') {
          const isPrivate = typeof jwk.d === 'string';
          return makeKey(
            isPrivate ? 'private' : 'public', algorithm, extractable, usages,
            fromBase64Url(isPrivate ? jwk.d : jwk.x),
          );
        }
        if (jwk.kty === 'EC') {
          const spec = CURVES[jwk.crv];
          if (!spec) throw notSupported(`curve ${jwk.crv}`);
          if (typeof jwk.d === 'string') {
            return makeKey('private', algorithm, extractable, usages, fromBase64Url(jwk.d));
          }
          const point = new Uint8Array(1 + spec.bytes * 2);
          point[0] = 0x04;
          point.set(fromBase64Url(jwk.x), 1);
          point.set(fromBase64Url(jwk.y), 1 + spec.bytes);
          return makeKey('public', algorithm, extractable, usages, point);
        }
        if (jwk.kty === 'RSA') throw notSupported('RSA');
        throw notSupported(`importKey('jwk', kty=${jwk.kty})`);
      }

      throw notSupported(`importKey format ${format}`);
    },

    async exportKey(format, key) {
      if (!key.extractable) {
        throw cryptoError('InvalidAccessError', 'key is not extractable');
      }
      const name = algName(key.algorithm);

      if (format === 'raw') {
        if (key.type === 'public' || key.type === 'secret') return bufferOf(bytes(key._material));
        throw cryptoError('InvalidAccessError', "raw export of a private key");
      }

      if (format !== 'jwk') throw notSupported(`exportKey format ${format}`);

      if (key.type === 'secret') {
        return { kty: 'oct', k: toBase64Url(key._material), ext: true };
      }

      if (name === 'Ed25519' || name === 'X25519') {
        const priv = key.type === 'private';
        const pub = priv
          ? (name === 'Ed25519'
            ? ed25519.getPublicKey(key._material)
            : x25519.getPublicKey(key._material))
          : key._material;
        const jwk = { kty: 'OKP', crv: name, x: toBase64Url(pub), ext: true };
        if (priv) jwk.d = toBase64Url(key._material);
        return jwk;
      }

      if (name === 'ECDH' || name === 'ECDSA') {
        const spec = CURVES[key.algorithm.namedCurve];
        if (!spec) throw notSupported(`curve ${key.algorithm && key.algorithm.namedCurve}`);
        const priv = key.type === 'private';
        const point = priv
          ? spec.curve.getPublicKey(key._material, false)
          : bytes(key._material);
        const jwk = {
          kty: 'EC', crv: spec.crv,
          x: toBase64Url(point.subarray(1, 1 + spec.bytes)),
          y: toBase64Url(point.subarray(1 + spec.bytes)),
          ext: true,
        };
        if (priv) jwk.d = toBase64Url(key._material);
        return jwk;
      }

      throw notSupported(`exportKey('jwk', ${name})`);
    },

    async generateKey(algorithm, extractable, usages) {
      const name = algName(algorithm);

      if (name === 'Ed25519' || name === 'X25519') {
        const secret = randomBytes(32);
        const pub = name === 'Ed25519'
          ? ed25519.getPublicKey(secret)
          : x25519.getPublicKey(secret);
        return {
          privateKey: makeKey('private', algorithm, extractable, usages, secret),
          publicKey: makeKey('public', algorithm, true, usages, pub),
        };
      }

      if (name === 'ECDH' || name === 'ECDSA') {
        const spec = CURVES[algorithm.namedCurve];
        if (!spec) throw notSupported(`curve ${algorithm.namedCurve}`);
        const secret = spec.curve.utils.randomSecretKey();
        return {
          privateKey: makeKey('private', algorithm, extractable, usages, secret),
          publicKey: makeKey('public', algorithm, true, usages, spec.curve.getPublicKey(secret, false)),
        };
      }

      if (name === 'AES-CBC' || name === 'AES-CTR' || name === 'AES-GCM' || name === 'AES-KW') {
        const length = (algorithm.length || 256) / 8;
        return makeKey('secret', algorithm, extractable, usages, randomBytes(length));
      }

      if (name.startsWith('RSA')) throw notSupported('RSA');
      throw notSupported(`generateKey(${name})`);
    },

    async encrypt(algorithm, key, data) {
      requireUsage(key, 'encrypt');
      return aesOperation(algorithm, key, bytes(data), true);
    },

    async decrypt(algorithm, key, data) {
      requireUsage(key, 'decrypt');
      return aesOperation(algorithm, key, bytes(data), false);
    },

    async sign(algorithm, key, data) {
      requireUsage(key, 'sign');
      const name = algName(algorithm);
      const message = bytes(data);

      if (name === 'HMAC') {
        return bufferOf(hmac(hashFor(key.algorithm), key._material, message));
      }
      if (name === 'Ed25519') {
        return bufferOf(ed25519.sign(message, key._material));
      }
      if (name === 'ECDSA') {
        const spec = CURVES[key.algorithm.namedCurve];
        if (!spec) throw notSupported(`curve ${key.algorithm.namedCurve}`);
        /*
         * WebCrypto's ECDSA signature is the raw r||s pair, NOT the DER
         * encoding @noble returns by default. Handing back DER produces a
         * signature that verifies nowhere.
         */
        const digest = hashFor(algorithm)(message);
        // Already the raw r||s pair at this @noble version, which is what
        // WebCrypto wants; the DER encoding would verify nowhere.
        return bufferOf(spec.curve.sign(digest, key._material, { prehash: false, format: 'compact' }));
      }
      if (name.startsWith('RSA')) throw notSupported('RSA');
      throw notSupported(`sign(${name})`);
    },

    async verify(algorithm, key, signature, data) {
      requireUsage(key, 'verify');
      const name = algName(algorithm);
      const sig = bytes(signature);
      const message = bytes(data);

      if (name === 'HMAC') {
        const mine = hmac(hashFor(key.algorithm), key._material, message);
        if (mine.length !== sig.length) return false;
        let diff = 0;
        for (let i = 0; i < mine.length; i++) diff |= mine[i] ^ sig[i];
        return diff === 0;
      }
      if (name === 'Ed25519') {
        try {
          return ed25519.verify(sig, message, key._material);
        } catch {
          return false;
        }
      }
      if (name === 'ECDSA') {
        const spec = CURVES[key.algorithm.namedCurve];
        if (!spec) throw notSupported(`curve ${key.algorithm.namedCurve}`);
        try {
          /*
           * lowS: false, and this is not a relaxation of anything.
           *
           * @noble rejects a high-S signature by default - a malleability
           * guard that matters for consensus systems. WebCrypto does NOT
           * normalise S, so about half of every real implementation's
           * signatures have S in the upper half and are perfectly valid.
           * Leaving the default on rejected 9 of 20 genuine signatures from
           * Node's own subtle, which is a test that passes half the time.
           */
          return spec.curve.verify(sig, hashFor(algorithm)(message), key._material, {
            prehash: false, format: 'compact', lowS: false,
          });
        } catch {
          return false;
        }
      }
      if (name.startsWith('RSA')) throw notSupported('RSA');
      throw notSupported(`verify(${name})`);
    },

    async deriveBits(algorithm, key, length) {
      const name = algName(algorithm);

      if (name === 'HKDF') {
        const hash = hashFor(algorithm);
        const salt = algorithm.salt ? bytes(algorithm.salt) : new Uint8Array(0);
        const info = algorithm.info ? bytes(algorithm.info) : new Uint8Array(0);
        const prk = extract(hash, key._material, salt);
        return bufferOf(expand(hash, prk, info, length / 8));
      }

      if (name === 'ECDH') {
        const peer = algorithm.public;
        const curveName = key.algorithm.namedCurve || algName(key.algorithm);

        if (curveName === 'X25519' || algName(key.algorithm) === 'X25519') {
          return bufferOf(x25519.getSharedSecret(key._material, peer._material));
        }
        const spec = CURVES[curveName];
        if (!spec) throw notSupported(`ECDH over ${curveName}`);
        /*
         * WebCrypto's ECDH yields the X COORDINATE only. @noble returns the
         * compressed point, whose first byte is a parity tag - passing that on
         * gives a secret one byte too long that agrees with nobody.
         */
        const shared = spec.curve.getSharedSecret(key._material, peer._material).subarray(1);
        const want = length === undefined ? shared.length : length / 8;
        if (want > shared.length) throw operationFailed('requested more bits than the curve yields');
        return bufferOf(shared.subarray(0, want));
      }

      throw notSupported(`deriveBits(${name})`);
    },

    async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
      if (algName(wrapAlgorithm) !== 'AES-KW') throw notSupported(`wrapKey with ${algName(wrapAlgorithm)}`);
      requireUsage(wrappingKey, 'wrapKey');
      const material = new Uint8Array(await subtle.exportKey(format, key));
      return bufferOf(aeskw(wrappingKey._material).encrypt(material));
    },

    async unwrapKey(format, wrapped, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usages) {
      if (algName(unwrapAlgorithm) !== 'AES-KW') throw notSupported(`unwrapKey with ${algName(unwrapAlgorithm)}`);
      requireUsage(unwrappingKey, 'unwrapKey');
      let material;
      try {
        material = aeskw(unwrappingKey._material).decrypt(bytes(wrapped));
      } catch (e) {
        // A failed unwrap is an OperationError, not whatever the cipher threw.
        throw operationFailed('key unwrap failed');
      }
      return subtle.importKey(format, material, unwrappedKeyAlgorithm, extractable, usages);
    },
  };

  /** AES, shared by encrypt and decrypt because the modes are symmetric here. */
  function aesOperation(algorithm, key, data, encrypting) {
    const name = algName(algorithm);
    const secret = bytes(key._material);

    if (name === 'AES-GCM') {
      const iv = bytes(algorithm.iv);
      const aad = algorithm.additionalData ? bytes(algorithm.additionalData) : undefined;
      const cipher = gcm(secret, iv, aad);
      try {
        return bufferOf(encrypting ? cipher.encrypt(data) : cipher.decrypt(data));
      } catch (e) {
        throw operationFailed('AES-GCM authentication failed');
      }
    }

    if (name === 'AES-CBC') {
      /*
       * WebCrypto's AES-CBC always applies PKCS#7 padding; @noble's does too by
       * default. openpgp leans on that - its CFB-over-CBC trick encrypts one
       * block and takes the ciphertext MINUS the final block, which is the pad
       * block. Turning padding off here would shift everything it reads.
       */
      const cipher = cbc(secret, bytes(algorithm.iv));
      return bufferOf(encrypting ? cipher.encrypt(data) : cipher.decrypt(data));
    }

    if (name === 'AES-CTR') {
      // The counter block is the whole IV; the `length` argument is the number
      // of counter bits, which @noble's ctr does not take.
      const cipher = ctr(secret, bytes(algorithm.counter));
      return bufferOf(encrypting ? cipher.encrypt(data) : cipher.decrypt(data));
    }

    if (name === 'AES-KW') throw notSupported('AES-KW through encrypt(); use wrapKey');
    throw notSupported(`${encrypting ? 'encrypt' : 'decrypt'}(${name})`);
  }

  return subtle;
}

/** Random bytes from whatever the platform did provide. */
function randomBytes(n) {
  const out = new Uint8Array(n);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  throw cryptoError(
    'NotSupportedError',
    'no crypto.getRandomValues - install react-native-get-random-values first',
  );
}

/**
 * Put the shim on `globalThis.crypto.subtle`, if there is nothing better there.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.force=false] replace a real SubtleCrypto. Almost
 *   always wrong: a platform's own implementation is more complete and better
 *   tested than this one. Provided for tests that want to exercise the shim
 *   where a real one exists.
 * @returns {{installed: boolean, reason: string}}
 */
function install({ force = false } = {}) {
  const g = globalThis;
  if (!g.crypto) {
    // Not writable on every runtime, so this can legitimately fail.
    try {
      Object.defineProperty(g, 'crypto', { value: {}, configurable: true, writable: true });
    } catch {
      return { installed: false, reason: 'globalThis.crypto is absent and cannot be created' };
    }
  }
  if (g.crypto.subtle && !force) {
    return { installed: false, reason: 'the platform already has crypto.subtle' };
  }
  try {
    Object.defineProperty(g.crypto, 'subtle', {
      value: createSubtle(), configurable: true, writable: true,
    });
  } catch {
    return { installed: false, reason: 'crypto.subtle is not writable on this runtime' };
  }
  return { installed: true, reason: force ? 'replaced the platform implementation' : 'the platform had none' };
}

module.exports = { createSubtle, install, HASHES, CURVES };
