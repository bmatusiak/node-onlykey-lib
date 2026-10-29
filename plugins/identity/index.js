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
 *   proveByBucket()   the bucket this device sealed for the identity opens with the secret the key derives for it -
 *                     only the key that sealed it derives that secret. A login that opens its bucket is proven with
 *                     no second press; a device with no bucket yet proves the key with verify() before sealing one.
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
 *   identity.proveByBucket({sealed, key}) -> {held, bucket}
 *   identity.requireVerified()  -> held, or throws
 *   identity.forget(why?)
 *   identity.on('change', fn)   (held | null)
 * held: {id, publicKey, site, parts: {<service>: part}, verified: null | {how: 'signature' | 'bucket', at}, at}
 */
'use strict';

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bucketIdentity = require('../../bucket/src/bucket-identity');
const bucket = require('../../bucket/src/bucket.js');

const PROOF_DOMAIN = 'OKIDENTITY-PROOF-v1';
const utf8 = (s) => new TextEncoder().encode(s);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

function setup(imports, register) {
  const { app, host, okcrypto } = imports;
  const events = new app.EventEmitter();
  let held = null;
  let loading = null;
  let generation = 0;

  const changed = () => { try { events.emit('change', held); } catch { /* a listener's error is not identity's */ } };

  /*
   * the key's site (ctap_bridge's): where its bucket sync lives; a key without the plugin has none (null). A read that
   * FAILED is not "none": it stays undefined (not read), so the next load asks again - key 3 in Chrome, 2026-10-29: one
   * failed read over WebAuthn was kept as "your key names no server" for the whole session, and Read again kept it.
   */
  const readSite = (opts) => okcrypto.keySite(opts).then((s) => (s && s.on ? s.site : null), () => undefined);

  async function read(opts, withSite) {
    const gen = generation;
    const { publicKey, id } = await bucketIdentity.readIdentity(okcrypto, opts);
    /* not asked unless wanted (the CLI's commands: one key request fewer - Brad, 2026-10-29: "don't hammer the key") */
    const site = withSite ? await readSite(opts) : undefined;
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
    held = { id, publicKey, site, parts, verified: null, at: Date.now() };
    changed();
    return held;
  }

  const identity = {
    /*
     * site: false - the identity alone (held.site stays undefined: not read); a later load that wants the site reads just
     * that, once, and adds it to what is held.
     */
    async load({ force = false, site = true, ...opts } = {}) {
      /* the site asked at most once a load: a read that just asked it (and failed) is not asked again until the next */
      let asked = false;
      if (!held || force) {
        /* every caller that asks while it reads gets the same read: one request each, not one per caller */
        if (!loading) { loading = read(opts, site).finally(() => { loading = null; }); asked = site; }
        await loading;
      }
      if (site && !asked && held && held.site === undefined) {
        const gen = generation;
        const s = await readSite(opts);
        if (gen === generation && held && held.site === undefined) { held = { ...held, site: s }; changed(); }
      }
      return held;
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

    /*
     * THE BUCKET THIS DEVICE KEPT FOR THE IDENTITY OPENS (Brad, 2026-10-28: "bucket will use the identity, so the key
     * feature is identity, and verify they are the key"): `sealed` is the bucket file this device sealed earlier for
     * the held identity, `key` the secret the key derived just now for it. Only the key that sealed it derives that
     * secret, so it opening - with the owner inside the seal this identity (or the Edge identity this same key reports,
     * a bucket kept under it before) - proves the key. A device with no sealed bucket yet has nothing to open: it
     * proves the key with verify() before it seals one, or a device repeating someone's public key would plant a
     * bucket under that identity. -> {held, bucket}: the bucket opened once, for the caller.
     */
    proveByBucket({ sealed, key }) {
      const h = held;
      if (!h) throw new Error('identity: nothing loaded to prove');
      let opened;
      try {
        opened = bucket.open(sealed, { key });
      } catch (e) {
        throw Object.assign(new Error(`identity: this key did not open the bucket kept for this identity (${(e && e.code) || (e && e.message)})`), { code: 'IDENTITY_NOT_PROVEN', cause: e });
      }
      const edge = h.parts && h.parts.edge && h.parts.edge.identityId;
      const owner = opened.bucket.owner;
      if (!opened.sealed || !(owner === h.id || (edge && owner === edge))) {
        throw Object.assign(new Error("identity: the bucket that opened is not this identity's"), { code: 'IDENTITY_NOT_PROVEN' });
      }
      return { held: identity.proven('bucket', h), bucket: opened.bucket };
    },

    /*
     * THE LOGIN PLAN (PROPOSAL-login-plan.md; Brad, 2026-10-29: "a 'login plan' that runs a 'login budget' - 1 press =
     * logs into our app"; "keep it in the identity plugin"). fn is the login itself, run as it always is - the bucket
     * opened, the identity proven, this device's bucket key made and certified. Around it ONE Edge budget, approved with
     * one press, pays every request fn makes that the plan names: each derive by its label (`derives`, derive_secret's
     * touchless derive on slot 128) and the identity's own signatures (`signs`, slot 201, the identity label). Each paid
     * request is announced first (TX start for exactly its bytes) and receipted after (okcrypto's use hook), so it is a
     * link on the key's chain - every login is in its history ("i know all the logins that happened"). The budget's reason
     * names the login (the app, the device, the site); whatever it did not spend is ended with fn.
     *
     * THE HEAD IT OPENS ON: the key's current one (HEAD, no press). The copy behind it is checked right after, from the
     * checkpoint the press returns (`budget.checkpoint`, both halves) back to the one the bucket kept - so nothing before
     * the login is read from the key (Brad: "anything before a checkpoint can be verified without the key"). The login
     * budget pays only the login's own requests, which is why it may open before that check; any other budget checks first.
     *
     * No Edge here, or a key whose firmware has no login budget (it refuses a derive scope): fn alone, with its codes as
     * today. -> {result, budget: {grantId, seq, checkpoint} | null, paid: n}
     */
    /*
     * THE APP FILES IT AS ITS OWN BUDGET (Brad, 2026-10-29: "after login, it gets added into the budget history"): an Edge
     * copy checks every budget's grant against its opening words, and every use's receipt against its message, so the
     * host is handed both - onOpened(budget, {reason, scopes, lifetime}) once the press opened it, before fn runs, and
     * onUse({seq, message}) after each paid request's receipt (seq: the use's link). A host that files neither still logs
     * in; its copy then cannot check the login's links.
     */
    async login(fn, { reason = 'log in', derives = [], signs = 0, onPress, ttlMinutes = 2, onOpened, onUse } = {}) {
      const edge = app.services && app.services.edge;
      if (!edge || typeof edge.grant !== 'function' || typeof okcrypto.setUseHook !== 'function' || (!derives.length && !signs)) {
        return { result: await fn(), budget: null, paid: 0 };
      }
      /* the Edge ops, as edge/src/codes.js fixes them (core never requires edge/: Edge is the plugin's, found through app.services) */
      const OP = { SIGN: 1, DERIVE: 17 };
      const { MSG } = require('../../src/protocol/msg');
      const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
      const signLabel = sha256(utf8(bucketIdentity.IDENTITY_LABEL));
      const scopes = [...new Set(derives)].slice(0, signs ? 3 : 4).map((d) => ({ op: OP.DERIVE, slot: 128, cap: 1, derive: d }));
      if (signs) scopes.push({ op: OP.SIGN, slot: 201, cap: signs, label: signLabel });
      /* what the budget may still pay: each derive once by its label hash, the identity's signatures up to `signs` */
      const left = new Map(scopes.filter((s) => s.op === OP.DERIVE).map((s) => [hex(sha256(utf8(s.derive))), 1]));
      let signsLeft = signs;
      const h = await edge.head();
      let budget;
      try {
        budget = await edge.grant({ scopes, reasonHash: sha256(utf8(reason)), verifiedHead: h.head, ttlMinutes, onPress });
      } catch (e) {
        /* a firmware without the login budget refuses a derive scope: the login as it always was */
        if (e && (e.status === 'scope-not-allowed' || (e.name === 'EdgeError' && e.code === 0x03))) return { result: await fn(), budget: null, paid: 0 };
        throw e;
      }
      /* the scopes as a host keeps them (JSON): a label as its hex, which grants.scopeLabel reads back as the same bytes */
      if (onOpened) await onOpened(budget, { reason, scopes: scopes.map((s) => (s.label ? { ...s, label: hex(s.label) } : s)), lifetime: ttlMinutes });
      let paid = 0;
      const was = okcrypto.setUseHook((msg, slot, payload) => {
        const derive = msg === 0xfc && slot === 128 && payload.length === 33 && payload[0] === 1 && left.get(hex(payload.subarray(1))) > 0;
        const sign = msg === MSG.OKSIGN && slot === 201 && signsLeft > 0 && payload.length > 32 && hex(payload.subarray(payload.length - 32)) === hex(signLabel);
        if (!derive && !sign) return null;
        let at = null;
        return {
          async before() {
            const now = await edge.head();
            await edge.txStart(now.head, sha256(payload));
            at = now.seq === null ? 0 : now.seq + 1;
          },
          async after() {
            if (derive) left.set(hex(payload.subarray(1)), 0); else signsLeft -= 1;
            paid += 1;
            const message = `${reason}: ${derive ? 'derive' : 'sign'} ${paid}`;
            await edge.receipt(at, 0, sha256(utf8(message)));
            if (onUse) await onUse({ seq: at, message });
          },
        };
      });
      try {
        return { result: await fn(), budget, paid };
      } finally {
        okcrypto.setUseHook(was);
        /* the uses the login did not need end with it: a login budget never outlives its login */
        if (left.size + signs > paid) await edge.revoke(budget.grantId).catch(() => undefined);
      }
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
