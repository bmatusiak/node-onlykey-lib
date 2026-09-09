/*
 * The vault key schedule and session cache.
 *
 * The port's whole job is to be IDENTICAL to the web app's, because a
 * credential written in a browser has to open on a phone. The web app uses
 * WebCrypto; this uses @noble, because Hermes has no WebCrypto. So the first
 * test here derives the same key both ways and compares - Node happens to have
 * both implementations available, which is a chance to check the claim rather
 * than assert it.
 *
 * Everything else is about the cache, where the rules are subtle enough to get
 * wrong quietly: a policy that slides only below a threshold, an eviction that
 * has to happen when a policy TIGHTENS, and key material that has to be
 * overwritten rather than merely dropped.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { webcrypto } = require('node:crypto');

const vault = require('../src/crypto/vault');
const { fromBase64, utf8ToBytes } = require('../src/bytes');

const fixedRandom = fill => n => new Uint8Array(n).fill(fill);

/* ------------------------------------------------------- the key schedule */

test('the derived key matches what WebCrypto derives', async () => {
  /*
   * The one assertion that makes the port safe to ship. The web app does:
   *
   *   deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
   *               info: 'onlyagent-vault-v1' }, ikm, { name: 'AES-GCM', length: 256 })
   *
   * If @noble's HKDF disagreed by so much as the salt handling, every vault
   * entry written by one client would fail to open on the other - and the only
   * symptom would be a failed tag check, which is indistinguishable from a
   * wrong password.
   */
  const secret = new Uint8Array(32).map((_, i) => (i * 13 + 7) & 0xff);

  const ikm = await webcrypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const reference = new Uint8Array(await webcrypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: utf8ToBytes('onlyagent-vault-v1'),
    },
    ikm,
    256,
  ));

  const ours = vault.deriveVaultKey(secret);
  assert.equal(ours.length, 32);
  assert.deepEqual(Array.from(ours), Array.from(reference));
});

test('the info string and salt are the ones every stored entry depends on', () => {
  /*
   * Pinned as values, not as behaviour. These are domain separation: changing
   * either one silently orphans every credential ever written, with no error
   * beyond a tag failure at the point someone needs their password.
   */
  assert.equal(new TextDecoder().decode(vault.HKDF_INFO), 'onlyagent-vault-v1');
  assert.equal(vault.HKDF_SALT.length, 32);
  assert.ok(vault.HKDF_SALT.every(b => b === 0), 'the salt is 32 zero bytes');
});

test('a blob decrypts with WebCrypto, which is what the web app will use', async () => {
  /*
   * The other direction of the same compatibility claim: not just the key, but
   * the container. nonce || ciphertext || tag, base64.
   */
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(3));
  const blob = vault.seal(key, 'correct horse', fixedRandom(0x42));

  const raw = fromBase64(blob);
  const aes = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const pt = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) }, aes, raw.subarray(12),
  );

  assert.equal(new TextDecoder().decode(pt), 'correct horse');
});

test('a round trip survives unicode and empty strings', () => {
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(1));
  for (const text of ['', 'a', 'pässwörd ✓', 'x'.repeat(4096)]) {
    const blob = vault.seal(key, text, fixedRandom(0x11));
    assert.equal(vault.open(key, blob), text, `round trip failed for ${text.length} chars`);
  }
});

test('the wrong key and a tampered blob fail the same way', () => {
  /*
   * AES-GCM cannot tell them apart and neither should this. A decoder that
   * reported "wrong key" for one and "corrupt" for the other would be claiming
   * to know something it does not.
   */
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(1));
  const other = vault.deriveVaultKey(new Uint8Array(32).fill(2));
  const blob = vault.seal(key, 'secret', fixedRandom(5));

  assert.throws(() => vault.open(other, blob));

  const raw = fromBase64(blob);
  raw[raw.length - 1] ^= 0xff;
  const tampered = Buffer.from(raw).toString('base64');
  assert.throws(() => vault.open(key, tampered));
});

test('a blob too short to hold a nonce and a tag is refused', () => {
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(1));
  assert.throws(() => vault.open(key, Buffer.alloc(27).toString('base64')), /too short/);
});

test('a fresh nonce is used every time', () => {
  /*
   * Not a style point. AES-GCM with a repeated nonce under the same key leaks
   * the XOR of the plaintexts and destroys the authentication guarantee, so a
   * seal that reused one would be worse than no encryption at all.
   */
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(1));
  let n = 0;
  const counting = size => new Uint8Array(size).fill(n++);

  const a = fromBase64(vault.seal(key, 'same', counting));
  const b = fromBase64(vault.seal(key, 'same', counting));
  assert.notDeepEqual(
    Array.from(a.subarray(0, 12)), Array.from(b.subarray(0, 12)),
    'the same nonce was used twice',
  );
});

test('seal refuses to invent randomness', () => {
  const key = vault.deriveVaultKey(new Uint8Array(32).fill(1));
  assert.throws(() => vault.seal(key, 'x'), /needs randomBytes/);
});

/* -------------------------------------------------------------- policies */

test('the policy vocabulary is the web app\'s, including its fail-closed default', () => {
  assert.deepEqual(vault.parsePolicy('always'), { ttlMs: 0, sliding: false, noCache: true });
  assert.deepEqual(vault.parsePolicy('startup'), { ttlMs: 0, sliding: false, noCache: false });
  assert.deepEqual(vault.parsePolicy('session:30m'), { ttlMs: 1800000, sliding: true, noCache: false });
  assert.deepEqual(vault.parsePolicy('session:2h'), { ttlMs: 7200000, sliding: false, noCache: false });

  /* A typo must cost a touch, never a cached key. */
  for (const bad of ['session:30', 'session:x m', '30m', '', null, 'forever']) {
    assert.equal(vault.parsePolicy(bad).noCache, true, `${JSON.stringify(bad)} was cached`);
  }
});

test('sliding is decided by length, which is where the two policies differ', () => {
  /*
   * <= 1h slides, > 1h is absolute. It reads like an arbitrary threshold and it
   * is - but it is the web app's, and a client that renewed a 2h window on use
   * would keep a key alive indefinitely while another client expired it.
   */
  assert.equal(vault.parsePolicy('session:60m').sliding, true);
  assert.equal(vault.parsePolicy('session:1h').sliding, true);
  assert.equal(vault.parsePolicy('session:61m').sliding, false);
  assert.equal(vault.parsePolicy('session:2h').sliding, false);
});

/* ----------------------------------------------------------- the cache */

function clockedCache(opts = {}) {
  let t = 1000;
  const cache = vault.createSessionCache({ now: () => t, ...opts });
  return { cache, advance: ms => { t += ms; }, at: () => t };
}

test('a cached key comes back until its window closes', () => {
  const { cache, advance } = clockedCache();
  const key = new Uint8Array(32).fill(9);

  cache.setPolicy('github', 'session:30m');
  assert.equal(cache.put('github', key), true);
  assert.ok(cache.get('github'), 'the key was not cached');

  advance(29 * 60000);
  assert.ok(cache.get('github'), 'expired early');

  /* Sliding: the get above restarted the window. */
  advance(29 * 60000);
  assert.ok(cache.get('github'), 'a sliding window did not slide');

  advance(31 * 60000);
  assert.equal(cache.get('github'), null, 'the window never closed');
});

test('an absolute window does not slide, however often it is used', () => {
  const { cache, advance } = clockedCache();
  cache.setPolicy('bank', 'session:2h');
  cache.put('bank', new Uint8Array(32).fill(1));

  for (let i = 0; i < 5; i++) {
    advance(20 * 60000);
    assert.ok(cache.get('bank'), `gone after ${(i + 1) * 20} minutes`);
  }
  advance(30 * 60000);          /* 2h10m total */
  assert.equal(cache.get('bank'), null, 'an absolute window slid');
});

test('policy "always" means the key is never cached at all', () => {
  const { cache } = clockedCache();
  cache.setPolicy('root', 'always');
  assert.equal(cache.put('root', new Uint8Array(32).fill(1)), false);
  assert.equal(cache.get('root'), null);
  assert.equal(cache.size, 0);
});

test('tightening a policy evicts immediately', () => {
  /*
   * The failure this prevents: switching a service to "always" while its key is
   * cached, and having it stay usable for the rest of the old window. The user
   * asked for a touch every time and would not get one.
   */
  const { cache } = clockedCache();
  cache.setPolicy('mail', 'session:30m');
  cache.put('mail', new Uint8Array(32).fill(1));
  assert.ok(cache.get('mail'));

  cache.setPolicy('mail', 'always');
  assert.equal(cache.get('mail'), null, 'the old key outlived the policy change');
});

test('"startup" keeps a key with no expiry', () => {
  const { cache, advance } = clockedCache();
  cache.setPolicy('ssh', 'startup');
  cache.put('ssh', new Uint8Array(32).fill(4));

  advance(30 * 24 * 3600000);
  assert.ok(cache.get('ssh'), 'a startup policy expired');
  assert.equal(cache.status()[0].remaining, 'until close');
});

test('evicted key material is overwritten, not just dropped', () => {
  /*
   * The port loses WebCrypto's non-extractable CryptoKey - here the key is a
   * Uint8Array any code in the process can read - so how long it stays readable
   * is the only control left. Zeroing on eviction is that control, and it only
   * works if the SAME buffer is zeroed.
   */
  const { cache } = clockedCache();
  cache.setPolicy('x', 'session:30m');
  cache.put('x', new Uint8Array(32).fill(0xab));

  const held = cache.get('x');
  assert.ok(held.some(b => b !== 0), 'the cache handed back a zeroed key');

  cache.evict('x');
  assert.ok(held.every(b => b === 0), 'the key material was left in memory');
});

test('a replaced entry does not leave the old key behind', () => {
  const { cache } = clockedCache();
  cache.setPolicy('x', 'session:30m');
  cache.put('x', new Uint8Array(32).fill(1));
  const first = cache.get('x');

  cache.put('x', new Uint8Array(32).fill(2));
  assert.ok(first.every(b => b === 0), 'the replaced key was left in memory');
  assert.ok(cache.get('x').every(b => b === 2));
});

test('clear wipes everything it was holding', () => {
  const { cache } = clockedCache();
  cache.setPolicy('a', 'startup');
  cache.setPolicy('b', 'startup');
  cache.put('a', new Uint8Array(32).fill(1));
  cache.put('b', new Uint8Array(32).fill(2));

  const held = [cache.get('a'), cache.get('b')];
  cache.clear();

  assert.equal(cache.size, 0);
  assert.ok(held.every(k => k.every(b => b === 0)), 'clear left key material behind');
});

test('reap drops what is expired and says what went', () => {
  /*
   * There is deliberately no timer in the library - one would keep a host
   * process alive and need tearing down. get() already refuses an expired
   * entry, so reaping only controls how long dead key material sits in memory,
   * and when that happens is the host's call.
   */
  const { cache, advance } = clockedCache();
  cache.setPolicy('short', 'session:5m');
  cache.setPolicy('long', 'session:2h');
  cache.put('short', new Uint8Array(32).fill(1));
  cache.put('long', new Uint8Array(32).fill(2));

  advance(10 * 60000);
  assert.deepEqual(cache.reap(), ['short']);
  assert.equal(cache.size, 1);
  assert.deepEqual(cache.reap(), [], 'reaping twice dropped something extra');
});

test('status reports what a sessions panel needs to draw', () => {
  const { cache, advance } = clockedCache();
  cache.setPolicy('github', 'session:30m');
  cache.put('github', new Uint8Array(32).fill(1));

  advance(10 * 60000);
  const [row] = cache.status();
  assert.equal(row.serviceId, 'github');
  assert.equal(row.policy, 'session:30m');
  assert.equal(row.sliding, true);
  assert.equal(row.remaining, '20m');
});

test('the default policy applies to a service nobody configured', () => {
  const { cache } = clockedCache();
  assert.equal(cache.getPolicy('unknown'), vault.DEFAULT_POLICY);
  assert.equal(cache.put('unknown', new Uint8Array(32).fill(1)), true);
  assert.ok(cache.get('unknown'), 'the default policy did not cache');
});

test('a sealed blob opens where there is no TextDecoder', () => {
  /*
   * HERMES HAS NO TextDecoder, and open() used one. Every test here passed,
   * because they run in Node - the failure appeared only on the phone, as
   * `ReferenceError: Property 'TextDecoder' doesn't exist` thrown from inside
   * a decrypt, which the caller above it reported as a wrong key.
   *
   * Deleting the global is the closest Node can get to the target platform,
   * and it is enough: it is exactly the condition that was untested.
   */
  const saved = globalThis.TextDecoder;
  const savedEnc = globalThis.TextEncoder;
  // eslint-disable-next-line no-undef
  delete globalThis.TextDecoder;
  // eslint-disable-next-line no-undef
  delete globalThis.TextEncoder;
  try {
    const key = vault.deriveVaultKey(new Uint8Array(32).fill(9));
    const blob = vault.seal(key, 'hunter2', (n) => new Uint8Array(n).fill(4));
    assert.equal(vault.open(key, blob), 'hunter2');
  } finally {
    globalThis.TextDecoder = saved;
    globalThis.TextEncoder = savedEnc;
  }
});
