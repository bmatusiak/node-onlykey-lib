/*
 * The vault's key schedule and its session cache.
 *
 * Ported from onlykey.github.io/src/plugins/vault/vault.js - OKCrypto
 * (lines 20-58) and OKSessionCache (lines 159-257). Storage is NOT here: the
 * web app keeps ciphertext in IndexedDB and a phone has no such thing, so what
 * to persist and where is the host's business. What is here is the part that
 * has to be identical everywhere, because a vault entry written by the web app
 * has to open on the phone and the other way round.
 *
 * THE SHARED SECRET COMES FROM THE DEVICE, and getting it is not this file's
 * job either. It is an ECDH derive over the CTAP tunnel - derive_public_key
 * then derive_shared_secret, both with a key action in the opt bytes of a
 * keyhandle (onlykey-3rd-party.js:277-320) - and it requires a touch. This
 * file takes the 32 bytes that come back.
 *
 * ONE PROPERTY DOES NOT SURVIVE THE PORT, and it is worth stating plainly
 * rather than discovering. The web app derives a NON-EXTRACTABLE CryptoKey:
 * the AES key exists inside the browser's crypto implementation and JavaScript
 * can never read it back. There is no such thing in a pure-JS implementation,
 * and Hermes has no WebCrypto to borrow it from. Here the key is a Uint8Array
 * that any code in the process can read. The cache zeroes it on eviction,
 * which limits how long it is around but does not change what it is.
 */
'use strict';

const { hkdf } = require('@noble/hashes/hkdf.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { gcm } = require('@noble/ciphers/aes.js');
const { utf8ToBytes, bytesToUtf8, toBase64, fromBase64 } = require('../bytes');

/**
 * The HKDF info string, byte for byte from the web app.
 *
 * It is domain separation, so it is not a label anyone may tidy: change it and
 * every vault entry ever written becomes unreadable, with no error beyond a
 * failed tag check.
 */
const HKDF_INFO = utf8ToBytes('onlyagent-vault-v1');

/**
 * A 32-byte ZERO salt, which is what the web app passes.
 *
 * Not an oversight to fix. HKDF with an empty or zero salt is well defined and
 * the input keying material here is already a high-entropy ECDH secret, so the
 * salt is doing nothing either way - but it is part of the derivation, and
 * substituting a random salt would produce different keys for the same secret
 * and silently orphan every stored credential.
 */
const HKDF_SALT = new Uint8Array(32);

/** AES-GCM nonce length, in bytes. */
const NONCE_BYTES = 12;

/** AES-GCM tag length, in bytes. */
const TAG_BYTES = 16;

/**
 * The device's ECDH secret to a 256-bit AES key.
 *
 * @param {Uint8Array} sharedSecret  from derive_shared_secret
 * @returns {Uint8Array} 32 bytes
 */
function deriveVaultKey(sharedSecret) {
  const ikm = Uint8Array.from(sharedSecret);
  if (!ikm.length) throw new Error('the shared secret is empty');
  return hkdf(sha256, ikm, HKDF_SALT, HKDF_INFO, 32);
}

/**
 * Encrypt one credential.
 *
 * The blob is `nonce || ciphertext || tag`, base64, exactly as the web app
 * writes it - a fresh 12-byte nonce prepended to what AES-GCM produced.
 *
 * @param {Uint8Array} key        from deriveVaultKey
 * @param {string} plaintext
 * @param {function} randomBytes  (n) => Uint8Array
 */
function seal(key, plaintext, randomBytes) {
  if (typeof randomBytes !== 'function') {
    /*
     * Injected, not reached for. Node has crypto and Hermes has nothing until
     * a polyfill is installed, so a library that reaches for a global fails at
     * the point of use on the platform that lacks it. Asking makes the
     * requirement visible at composition time.
     */
    throw new TypeError('seal needs randomBytes (from the host plugin)');
  }
  const nonce = Uint8Array.from(randomBytes(NONCE_BYTES));
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`the nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`);
  }

  const ct = gcm(Uint8Array.from(key), nonce).encrypt(utf8ToBytes(String(plaintext)));
  const out = new Uint8Array(NONCE_BYTES + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_BYTES);
  return toBase64(out);
}

/**
 * Decrypt one credential.
 *
 * A tag failure throws, and that is the only signal there is: AES-GCM does not
 * distinguish "wrong key" from "tampered blob", and neither should this.
 */
function open(key, blob) {
  const raw = fromBase64(String(blob));
  /*
   * 12 nonce + 16 tag is the shortest possible blob, for an empty plaintext.
   * The web app checks for 28 and so does this - a shorter input would
   * otherwise reach the cipher as a nonce and a truncated tag.
   */
  if (raw.length < NONCE_BYTES + TAG_BYTES) {
    throw new Error(`blob too short: ${raw.length} bytes, minimum ${NONCE_BYTES + TAG_BYTES}`);
  }
  const nonce = raw.subarray(0, NONCE_BYTES);
  const body = raw.subarray(NONCE_BYTES);
  const pt = gcm(Uint8Array.from(key), nonce).decrypt(body);
  /*
   * bytesToUtf8, not TextDecoder. HERMES HAS NEITHER TextDecoder NOR
   * TextEncoder, and this is a library whose whole reason for existing is that
   * one implementation serves the desktop app, the web app and the phone. A
   * global that exists in Node and not on the target cannot be caught by any
   * amount of unit testing here - it throws at the point of use, on the one
   * platform the tests do not run on.
   */
  return bytesToUtf8(pt);
}

/* ------------------------------------------------------------ the cache */

const DEFAULT_POLICY = 'session:30m';

/**
 * How long a derived key may be kept, from a policy string.
 *
 * The vocabulary is the web app's:
 *
 *   'always'       never cache - touch the device every single time
 *   'startup'      keep until the process ends
 *   'session:30m'  keep for 30 minutes
 *   'session:2h'   keep for 2 hours
 *
 * Anything unrecognised means 'always', which is the fail-closed direction: a
 * typo in a policy costs an extra touch rather than caching a key forever.
 *
 * SLIDING IS DECIDED BY LENGTH, not stated. A window of an hour or less slides
 * - each use restarts it - and anything longer is absolute. That is the web
 * app's rule (`sliding: ttlMs <= 3600000`) and it is preserved rather than
 * tidied, because the two disagree about when a key expires and a user who set
 * 2h on one client should not get a different answer on another.
 */
function parsePolicy(policy) {
  if (!policy || policy === 'always') return { ttlMs: 0, sliding: false, noCache: true };
  if (policy === 'startup') return { ttlMs: 0, sliding: false, noCache: false };

  const match = /^session:(\d+)(m|h)$/.exec(policy);
  if (!match) return { ttlMs: 0, sliding: false, noCache: true };

  const value = parseInt(match[1], 10);
  const ttlMs = match[2] === 'h' ? value * 3600000 : value * 60000;
  return { ttlMs, sliding: ttlMs <= 3600000, noCache: false };
}

/**
 * A TTL cache of derived keys, one per service.
 *
 * `now` is injectable so the expiry rules can be tested without waiting for
 * them, and there is no timer in here at all. The web app runs a reaper every
 * 30 seconds; a library that installed its own interval would keep a host
 * process alive and would have to be torn down. `reap()` is exposed instead
 * and the host decides whether to call it on a schedule, on resume, or never -
 * `get()` already refuses an expired entry, so a reaper only controls how long
 * dead key material sits in memory.
 */
function createSessionCache({ now = Date.now, defaultPolicy = DEFAULT_POLICY } = {}) {
  const entries = new Map();
  const policies = new Map();

  /** Overwrite key material rather than dropping the reference to it. */
  function wipe(entry) {
    if (entry && entry.key) entry.key.fill(0);
  }

  function expired(entry, at) {
    if (entry.ttlMs <= 0) return false;
    const since = entry.sliding ? entry.lastUsedAt : entry.createdAt;
    return at - since > entry.ttlMs;
  }

  return {
    getPolicy(serviceId) {
      return policies.get(serviceId) || defaultPolicy;
    },

    setPolicy(serviceId, policy) {
      policies.set(serviceId, policy);
      /*
       * Tightening a policy takes effect NOW. Switching a service to 'always'
       * while its key is still cached would otherwise leave the key usable for
       * the rest of its old TTL, which is the opposite of what was asked for.
       */
      if (parsePolicy(policy).noCache) this.evict(serviceId);
    },

    get(serviceId) {
      const entry = entries.get(serviceId);
      if (!entry) return null;

      const at = now();
      if (expired(entry, at)) {
        wipe(entry);
        entries.delete(serviceId);
        return null;
      }
      entry.lastUsedAt = at;
      return entry.key;
    },

    put(serviceId, key) {
      const policy = this.getPolicy(serviceId);
      const parsed = parsePolicy(policy);
      if (parsed.noCache) return false;

      const at = now();
      /* Replacing an entry must not leave the old key material behind. */
      wipe(entries.get(serviceId));
      entries.set(serviceId, {
        key: Uint8Array.from(key),
        createdAt: at,
        lastUsedAt: at,
        policy,
        ttlMs: parsed.ttlMs,
        sliding: parsed.sliding,
      });
      return true;
    },

    evict(serviceId) {
      wipe(entries.get(serviceId));
      return entries.delete(serviceId);
    },

    clear() {
      for (const entry of entries.values()) wipe(entry);
      entries.clear();
    },

    /** Drop everything expired. Returns the service ids that went. */
    reap() {
      const at = now();
      const gone = [];
      for (const [serviceId, entry] of entries) {
        if (expired(entry, at)) gone.push(serviceId);
      }
      for (const serviceId of gone) this.evict(serviceId);
      return gone;
    },

    /** What is cached and for how much longer, for a sessions panel. */
    status() {
      const at = now();
      return [...entries].map(([serviceId, entry]) => {
        const since = entry.sliding ? entry.lastUsedAt : entry.createdAt;
        const remainingMs = entry.ttlMs > 0
          ? Math.max(0, entry.ttlMs - (at - since))
          : Infinity;
        return {
          serviceId,
          policy: entry.policy,
          sliding: entry.sliding,
          remainingMs,
          remaining: remainingMs === Infinity
            ? 'until close'
            : `${Math.ceil(remainingMs / 60000)}m`,
        };
      });
    },

    get size() { return entries.size; },
  };
}

module.exports = {
  HKDF_INFO,
  HKDF_SALT,
  NONCE_BYTES,
  TAG_BYTES,
  DEFAULT_POLICY,
  deriveVaultKey,
  seal,
  open,
  parsePolicy,
  createSessionCache,
};
