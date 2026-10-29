/*
 * identity - WHO THIS KEY IS, read once, held in memory, and PROVEN.
 *
 * (Brad, 2026-10-28: "the identity service hold the user that is loaded in the app"; "the identity check basically
 * uses the identity plugin, the plugin then contains the stuff to get and hold the identity"; "imagine redesign the
 * app in the future for something else, other than edge or password manager, the identity is a feature"; "verify
 * they are the key ... this is universal, not directly to the webapp, so anything that uses the identity plugin needs
 * to verify the key is true, this includes the CLI".)
 *
 * WHY IT IS ONE PLUGIN. A host's features each asked the key the same questions - the bucket identity, Edge's device
 * and public keys, the key's site - every time one of them started: on a key over the WebAuthn tunnel each is a
 * browser ceremony (and on a key without emulator patch 0016 a 5.5 s wait before it), and the web app's login read
 * the same public key twice (box timeline, 2026-10-28). Read here once, they are held for every feature; a feature
 * that needs a secret (the bucket key, a sign) still asks the key, every time - nothing secret is ever held.
 *
 * WHY "PROVEN". A public key read from a device proves nothing about the device: anything can answer with someone's
 * public key. The key is the identity's key only when it does what only the identity's private key can:
 *   verify()          the key signs a fresh random challenge with the identity's private key (agent ED25519, the
 *                     bucket identity's own label) and the signature is checked against the identity public key;
 *   proveByBucket()   the bucket key the key derived is the one the identity certified - its certificate signs that
 *                     bucket public key under the identity public key, and only the key derives the matching secret.
 *                     A login that opens its bucket is proven with no second press.
 * requireVerified() refuses until one of them has passed. Every host composes the same plugin - the web app, the
 * desktop, the phone, the CLI - so the rule is the same everywhere.
 *
 * WHAT OTHER FEATURES ADD. A service with identityPart() (Edge: its device id and public keys) is asked once at
 * load and its part kept under its service name - identity does not know the features, they offer themselves.
 *
 * WHEN IT IS FORGOTTEN. The host says so - forget() - when the key locks, is unplugged or another key is picked; the
 * next load() reads the key again. load({force: true}) reads again on purpose (This Key's "read the key again").
 *
 *   identity.load(opts?)        -> held             (one read for every caller at once; held after)
 *   identity.current()          -> held | null      (no request)
 *   identity.verify(opts?)      -> held             (a press or the code, as the key's derive setting asks)
 *   identity.proveByBucket({bucketPublicKey, certificate, derivedPublicKey}) -> held
 *   identity.requireVerified()  -> held, or throws
 *   identity.forget(why?)
 *   identity.on('change', fn)   (held | null)
 * held: {id, publicKey, site, capabilities: string[], parts: {<service>: part}, verified: null | {how: 'signature' | 'bucket', at}, at}
 */
'use strict';

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bucketIdentity = require('../../bucket/src/bucket-identity');

const PROOF_DOMAIN = 'OKIDENTITY-PROOF-v1';
const utf8 = (s) => new TextEncoder().encode(s);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function setup(imports, register) {
  const { app, host, okcrypto } = imports;
  const events = new app.EventEmitter();
  let held = null;
  let loading = null;
  let generation = 0;

  const changed = () => { try { events.emit('change', held); } catch { /* a listener's error is not identity's */ } };

  async function read(opts) {
    const gen = generation;
    /*
     * FIRST, WHAT THE KEY CAN DO (ctap_bridge's capabilities): a key with emulator patch 0016 says "wipes-delivered"
     * and okcrypto drops its 5.5 s wait before every request from here on - so every read after this one is quick.
     * A key that cannot answer: none, the waits stay.
     */
    const capabilities = typeof okcrypto.keyCapabilities === 'function'
      ? await okcrypto.keyCapabilities(opts).catch(() => [])
      : [];
    const { publicKey, id } = await bucketIdentity.readIdentity(okcrypto, opts);
    /* the key's site (ctap_bridge's): where its bucket sync lives; a key without the plugin has none */
    const site = await okcrypto.keySite(opts).then((s) => (s && s.on ? s.site : null), () => null);
    const parts = {};
    const services = (app && app.services) || {};
    for (const name of Object.keys(services)) {
      const svc = services[name];
      if (!svc || svc === identity || typeof svc.identityPart !== 'function') continue;
      try {
        parts[name] = await svc.identityPart(opts);
      } catch (e) {
        parts[name] = { error: String((e && e.message) || e) };
      }
    }
    /* forgotten while it read (the key locked, another was picked): this read is not that key's */
    if (gen !== generation) throw new Error('identity: the key changed while it was read');
    held = { id, publicKey, site, capabilities, parts, verified: null, at: Date.now() };
    changed();
    return held;
  }

  const identity = {
    async load({ force = false, ...opts } = {}) {
      if (held && !force) return held;
      /* every caller that asks while it reads gets the same read: one request each, not one per caller */
      if (!loading) loading = read(opts).finally(() => { loading = null; });
      return loading;
    },

    current() {
      return held;
    },

    async verify(opts = {}) {
      const h = held || await identity.load(opts);
      if (typeof host?.randomBytes !== 'function') throw new Error('identity: verify needs randomBytes from the host plugin');
      const challenge = sha256(concat(utf8(PROOF_DOMAIN), Uint8Array.from(host.randomBytes(32))));
      const signature = await okcrypto.agent.sign(sha256(utf8(bucketIdentity.IDENTITY_LABEL)), challenge, { ...opts, version: 1, keyType: 1 });
      let ok = false;
      try { ok = ed25519.verify(Uint8Array.from(signature).slice(0, 64), challenge, h.publicKey); } catch { ok = false; }
      if (!ok) throw Object.assign(new Error('identity: this key did not prove it holds the identity - its signature over a fresh challenge does not verify'), { code: 'IDENTITY_NOT_PROVEN' });
      return identity.proven('signature', h);
    },

    proveByBucket({ bucketPublicKey, certificate, derivedPublicKey }) {
      const h = held;
      if (!h) throw new Error('identity: nothing loaded to prove');
      const certified = bucketIdentity.verifyCertificate({ identityPublicKey: h.publicKey, bucketPublicKey, certificate });
      if (!certified || !same(Uint8Array.from(derivedPublicKey), Uint8Array.from(bucketPublicKey))) {
        throw Object.assign(new Error("identity: this key's bucket key is not the one the identity certified"), { code: 'IDENTITY_NOT_PROVEN' });
      }
      return identity.proven('bucket', h);
    },

    /* internal: mark the held identity proven (a check above has passed for exactly this one) */
    proven(how, h) {
      if (h !== held) throw new Error('identity: the key changed while it was proven');
      held = { ...held, verified: { how, at: Date.now() } };
      changed();
      return held;
    },

    requireVerified() {
      if (!held) throw Object.assign(new Error('identity: no key identity is loaded'), { code: 'IDENTITY_NOT_LOADED' });
      if (!held.verified) throw Object.assign(new Error('identity: this key has not proven its identity yet'), { code: 'IDENTITY_NOT_PROVEN' });
      return held;
    },

    forget() {
      generation += 1;
      /* another key may answer next: what this one could do is not known of that one */
      if (typeof okcrypto.forgetKeyCapabilities === 'function') okcrypto.forgetKeyCapabilities();
      if (held === null) return;
      held = null;
      changed();
    },

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },
  };

  register(null, { identity });
}

setup.consumes = ['app', 'host', 'okcrypto'];
setup.provides = ['identity'];

module.exports = setup;
