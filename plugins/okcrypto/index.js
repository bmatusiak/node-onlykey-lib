/*
 * okcrypto - age, post-quantum, and composite PGP.
 *
 * The second plugin plugins/session authorises
 * (`setup.allowed = [['device'], ['okcrypto']]`). It is the seam between the
 * device-free crypto in src/crypto/ and a device that holds the private keys.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *
 * The pure crypto is here: age file encryption, X-Wing, the composite blob
 * format, and the hardware-hook wiring that lets ordinary openpgp calls route
 * private-key operations to the device.
 *
 * The DEVICE-SIDE DERIVE operations are not, and that is a boundary rather
 * than an omission. `derive_xwing_recipient` and `derive_xwing_decap` reach the
 * firmware by sending OKCONNECT with a key action in opt1, a key type in opt2
 * and an encrypt-response flag in opt3 - and those three bytes are read by
 * `bridge_to_onlykey()` in libraries/fido2/ok_extension.cpp, which is the CTAP
 * path. okcore.cpp's vendor dispatch has an OKCONNECT case too, and it does
 * not look at them: over the vendor interface a keyhandle's opt bytes have
 * nowhere to go, because that frame is [header|msg|slot|field].
 *
 * So those two operations need a CTAPHID transport on IFACE.FIDO, which no
 * transport implements yet. IFACE.FIDO is already reachable - okemu_hid_deliver
 * accepts it, and src/protocol/ctap.js has the framing - so this is work, not
 * a wall, and it belongs with the FIDO/BLE track rather than being guessed at
 * here.
 *
 * OKSIGN and OKDECRYPT, by contrast, ARE in okcore.cpp's vendor dispatch, and
 * they now run over the same transport as everything else. Both hazards this
 * comment used to warn about were checked against the firmware rather than
 * inferred, and both were real:
 *
 *   Framing. process_packets() reads buffer[4] as the command, buffer[5] as
 *   the SLOT, buffer[6] as 0xFF-or-length and buffer[7..] as data
 *   (okcore.cpp:7472-7519). src/device/chunker.js's hex framing has no slot
 *   byte - it was built for OKRESTORE and OKFWUPDATE, which have none - so
 *   reusing it would have put the length where the slot is read and started
 *   the data one byte early. chunker.sendSlotStream() is the right frame.
 *
 *   The response. It is PUSHED, unsolicited, as one 64-byte vendor report:
 *   send_transport_response(sig, 64, true, true) (okcrypto.cpp:728-736).
 *   There is no OKGETRESPONSE on this path. And the encrypt flag is a lie
 *   here - send_transport_response ignores both of its trailing arguments
 *   unless outputmode is WEBAUTHN (okcore.cpp:2840-2846), so over the vendor
 *   interface the signature comes back in PLAINTEXT. Sealing it under the
 *   transit key, which the argument list plainly suggests, would have
 *   decrypted noise.
 *
 * What this does NOT hide is that both operations need a human. The firmware
 * raises a three-button challenge before it will sign or decrypt, so these
 * take a `confirm` callback and hand it the digits - the same split as
 * device.captureBackup(), and for the same reason: pressing a button is
 * platform-specific and the library has no business knowing how.
 */
'use strict';

const age = require('../../src/crypto/age_file');
const pqc = require('../../src/crypto/age_pqc');
const composite = require('../../src/crypto/composite_pgp');
const vault = require('../../src/crypto/vault');
const okconnect = require('../../src/crypto/okconnect');
const tunnelling = require('../../src/protocol/tunnel');
const { CtapHid } = require('../../src/protocol/ctaphid');
const chunker = require('../../src/device/chunker');
const okmsg = require('../../src/protocol/okmsg');
const { challengeDigits } = require('../../src/protocol/challenge');
const { MSG } = require('../../src/protocol/msg');
const { IFACE } = require('../../src/transport/contract');

function setup(imports, register) {
  const { app, transport, host } = imports;

  /*
   * Randomness comes from the host plugin, not from a global. Node has crypto
   * and Hermes has nothing until a polyfill is installed, so reaching for one
   * fails at the point of use on the platform that lacks it.
   */
  const randomBytes = host && host.randomBytes;
  const EventEmitter = app.EventEmitter;

  const events = new EventEmitter();

  /*
   * `transport` and `session` are declared in setup.consumes and deliberately
   * not destructured yet.
   *
   * They are not decoration. The device operations described above need both -
   * the transport to reach the device and the session to seal each chunk under
   * the transit key - and dropping them from consumes now would make the
   * `['okcrypto']` group in plugins/session's setup.allowed vacuous, which is
   * the one declaration saying this plugin is entitled to the session key at
   * all. Removing and restoring that entitlement later is a worse change than
   * leaving it stated.
   */

  /**
   * A slot-addressed crypto operation, end to end.
   *
   * The listener goes on BEFORE the first chunk. The device answers as soon
   * as the last challenge button lands, and on a fast host that can be before
   * a listener attached afterwards would exist - the same reason
   * transport.request() subscribes first.
   */
  async function deviceOperation(msg, slot, data, opts = {}) {
    const {
      confirm = null,
      duo = false,
      timeoutMs = 30000,
      onProgress = null,
    } = opts;

    const payload = Uint8Array.from(data);
    if (!payload.length) throw new Error('nothing to sign or decrypt');

    const digits = challengeDigits(payload, { duo });

    /*
     * Whether the device has already answered.
     *
     * It may answer after ONE press rather than three. done_process_packets()
     * only computes Challenge_button1/2/3 when the slot's challenge-mode
     * preference is 0 (okcore.cpp:7571-7587); when it is 1 the payload handler
     * accepts ANY single press (OnlyKey.ino:821) and the digits are never
     * computed at all. Measured on device: "Challenge3 entered2" for a press
     * of button 2 against digits of 1-6-6.
     *
     * A caller that presses all three regardless leaves two stray presses
     * behind, and on an unlocked device a stray press runs gen_press() and
     * types a slot at the keyboard. So confirm() is handed a way to stop.
     */
    let answered = false;
    let off = null;
    const answer = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (off) off();
        reject(new Error(
          `no response within ${timeoutMs}ms; the challenge was ` +
          `${digits.join('-')} - were those buttons pressed?`,
        ));
      }, timeoutMs);

      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;

        /*
         * The state broadcast arrives about once a second and is not an
         * answer to anything. Ignoring it by shape rather than by timing is
         * what stops a signature request from resolving with "UNLOCKED".
         */
        const state = okmsg.parseState(event.data);
        if (state.state === 'unlocked' || state.state === 'locked'
            || state.state === 'uninitialized') return;

        clearTimeout(timer);
        answered = true;
        if (off) off();

        /*
         * An error is TEXT and a signature is 64 random-looking bytes, so the
         * two are told apart by the firmware's own wording rather than by
         * length. "Error incorrect challenge was entered" is the one a caller
         * will actually hit, and it deserves to arrive as that sentence
         * rather than as 64 bytes of something.
         */
        if (state.state === 'error') {
          reject(new Error(state.raw));
          return;
        }
        resolve(Uint8Array.from(event.data));
      });
    });

    await chunker.sendSlotStream({
      msg,
      slot,
      data: payload,
      send: (frame) => transport.write(IFACE.VENDOR, frame),
      onProgress,
    });
    events.emit('challenge', { slot, digits });

    try {
      if (confirm) await confirm({ digits, slot, isAnswered: () => answered });
      return await answer;
    } catch (err) {
      if (off) off();
      throw err;
    }
  }

  /**
   * Derived vault keys, kept under the web app's own TTL policies.
   *
   * One per plugin instance, so it dies with the session rather than with a
   * screen. The eviction is real - createSessionCache overwrites the key
   * bytes rather than dropping the reference, because a Uint8Array that is
   * merely unreachable is still in memory until something reuses the page.
   *
   * NOT SWEPT ON A TIMER. Expiry is checked on read, which is enough for
   * correctness; a timer here would keep the process awake to wipe something
   * nobody is asking for. A host that wants eager wiping calls reap().
   */
  const vaultKeys = vault.createSessionCache({});
  /**
   * The CTAPHID channel, allocated once and kept.
   *
   * CTAPHID is channel-oriented: INIT trades the broadcast channel for a
   * private CID, and every later frame carries it. A CtapHid that has not
   * been init()ed refuses with "no CTAPHID channel", so this cannot be built
   * per call and used immediately - and building one per call would also
   * allocate a new channel each time, which the firmware has a finite table
   * of.
   *
   * Lazily, because most sessions never derive anything, and the INIT costs
   * a round trip to a device that may be locked.
   */
  let tunnelReady = null;

  function openTunnel() {
    if (tunnelReady) return tunnelReady;
    tunnelReady = (async () => {
      const ctap = new CtapHid(transport);
      await ctap.init();
      return tunnelling.createTunnel(ctap, { randomBytes });
    })().catch((error) => {
      /* Not cached, so the next call tries again rather than replaying it. */
      tunnelReady = null;
      throw error;
    });
    return tunnelReady;
  }
  /**
   * One OKCONNECT derive, end to end.
   *
   * The three opt bytes are the whole point of using the tunnel: a key
   * action, a key type and an encrypt-response flag, read by
   * bridge_to_onlykey() in ok_extension.cpp. Over the vendor interface they
   * have nowhere to sit - that frame is [header|msg|slot|field] - which is
   * why OKCONNECT over vendor HID only sets the clock
   * (FINDING-okconnect-is-two-protocols.md).
   *
   * A FRESH TRANSIT KEYPAIR PER CALL. It is ephemeral by construction in the
   * reference too; reusing one would make every response decryptable with a
   * single stolen secret, and the IV is a fixed twelve zero bytes, so a
   * reused key would also reuse the keystream.
   */
  async function derive({
    action,
    keytype = okconnect.KEYTYPE.P256R1,
    label = null,
    publicKey = null,
    timeoutMs = 60000,
    onKeepAlive = null,
  }) {
    if (typeof randomBytes !== 'function') {
      throw new Error('okcrypto needs randomBytes from the host plugin to derive');
    }

    const app = okconnect.newTransitKeypair();
    const data = okconnect.buildMessage({
      transitPublicKey: app.publicKey,
      label,
      publicKey,
    });

    const bound = await openTunnel();

    /*
     * enc_resp is always 1. ok_extension.cpp forces any truthy opt3 to
     * "encrypt everything except the transit public key", so 1 and 2 are the
     * same mode - and an unencrypted response is a derived secret in the
     * clear on the wire.
     */
    const answer = await bound.send(
      { cmd: okconnect.OKCONNECT, opt1: action, opt2: keytype, opt3: 1, data },
      { timeoutMs, onKeepAlive },
    );

    if (!answer || !answer.data || !answer.data.length) {
      throw new Error(
        'the device answered the derive with no data'
        + (answer && answer.status ? ` (status ${answer.status})` : ''),
      );
    }

    const opened = okconnect.openResponse(answer.data, app.secretKey);

    /*
     * The transit secret is wiped rather than left for the GC. It decrypts
     * this response and nothing else, and it is the only thing between the
     * captured ciphertext and the derived key.
     */
    app.secretKey.fill(0);

    /*
     * The two actions return DIFFERENT SHAPES, and reading one as the other
     * yields a plausible-looking value rather than an error: a shared-secret
     * payload ends with the public key AND THEN the 32-byte secret, so taking
     * "the last public-key-width bytes" returns part of the public key with
     * the secret glued on.
     */
    const isShared = action === okconnect.KEYACTION.DERIVE_SHARED_SECRET
      || action === okconnect.KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS;

    if (isShared) {
      const { secret, publicKey: pub } = okconnect.sharedSecretFrom(opened.payload, keytype);
      return { status: opened.status, payload: opened.payload, secret, publicKey: pub };
    }

    return {
      status: opened.status,
      payload: opened.payload,
      publicKey: okconnect.publicKeyFrom(opened.payload, keytype),
    };
  }
  const okcrypto = {
    /* ---- the device-free crypto, re-exported ---------------------------- */

    age,
    pqc,
    composite,
    vault,

    /**
     * Route openpgp's private-key operations to the device.
     *
     * composite_pgp takes the openpgp instance as an argument rather than
     * importing one, which is what keeps the 1.2 MB fork off this plugin's
     * dependency graph - a caller doing age or X-Wing never loads it. Pass it
     * in from `node-onlykey-lib/crypto/pgp`.
     */
    registerPgpHooks(openpgp, slot) {
      return composite.registerCompositeHooks(openpgp, okcrypto, slot);
    },

    /* ---- device operations --------------------------------------------- */

    /**
     * Sign with a key the device holds. OKSIGN.
     *
     * Three phases, and the middle one is a person:
     *
     *   1. the payload goes out in 57-byte chunks addressed to a slot;
     *   2. the device raises a three-button challenge derived from those
     *      exact bytes and waits;
     *   3. the signature comes back as one unsolicited 64-byte report.
     *
     * `confirm({ digits, isAnswered })` is how phase 2 happens. The digits are
     * computed
     * here from the same sha256 the firmware uses, so the caller knows which
     * buttons without having to ask the device - which it could not do
     * anyway, since telling the host the challenge would defeat it.
     *
     * HOW MANY presses are needed is a device preference, not a constant, and
     * the host cannot read it: with the slot's challenge mode set to 1 any
     * ONE press confirms and the digits are never computed. Press one at a
     * time and stop when isAnswered() goes true - the extra presses are not
     * harmless, they type slots.
     */
    async composite_sign(slot, data, opts = {}) {
      return deviceOperation(MSG.OKSIGN, slot, data, opts);
    },

    /** Decrypt with a key the device holds. OKDECRYPT, same three phases. */
    async composite_decrypt(slot, data, opts = {}) {
      return deviceOperation(MSG.OKDECRYPT, slot, data, opts);
    },

    /**
     * Report what this build can actually do on a device.
     *
     * Stated rather than discovered by calling something and getting undefined:
     * composite_pgp's hooks are registered against whatever object is passed to
     * registerPgpHooks, and an object silently missing composite_decrypt fails
     * inside openpgp with a message about the PGP message rather than about
     * the device.
     */
    /**
     * The 32-byte shared secret for a label - the two-step the web app does.
     *
     * derive_public_key then derive_shared_secret AGAINST THAT KEY. The
     * device is both parties, which looks odd until you see that the point is
     * not agreement with anyone - it is a value only this key can recompute.
     */
    async deriveSharedSecretFor(label, opts = {}) {
      const pub = await okcrypto.derivePublicKey(label, opts);
      const shared = await okcrypto.deriveSharedSecret(label, pub.publicKey, opts);
      return shared.secret;
    },
    /** The constants a caller needs to ask for a derivation. */
    KEYTYPE: okconnect.KEYTYPE,
    KEYACTION: okconnect.KEYACTION,

    /**
     * The device's derived PUBLIC key for a label.
     *
     * Deterministic: the same label on the same device always derives the
     * same key, which is what makes per-site secrets work without storing
     * anything. An ABSENT label is not an empty one - see derivationHash.
     */
    derivePublicKey(label, { keytype, requirePress = false, ...opts } = {}) {
      return derive({
        action: requirePress
          ? okconnect.KEYACTION.DERIVE_PUBLIC_KEY_REQ_PRESS
          : okconnect.KEYACTION.DERIVE_PUBLIC_KEY,
        keytype,
        label,
        ...opts,
      });
    },

    /**
     * The shared secret between a label's derived key and `publicKey`.
     *
     * This is the value the web app calls a "generated password" and the
     * value the vault derives its AES key from - the same call, read two
     * ways.
     *
     * Resolves with `secret` (32 bytes - THE value) alongside `publicKey`.
     * The response carries both, and which one a caller wants is not
     * guessable from the payload.
     */
    deriveSharedSecret(label, publicKey, { keytype, requirePress = false, ...opts } = {}) {
      if (!publicKey) throw new Error('deriveSharedSecret needs a public key');
      return derive({
        action: requirePress
          ? okconnect.KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS
          : okconnect.KEYACTION.DERIVE_SHARED_SECRET,
        keytype,
        label,
        publicKey,
        ...opts,
      });
    },
    /**
     * Credentials sealed under a key only the device can derive.
     *
     * The key is HKDF over the device's shared secret for a label, so it is
     * reproducible on any host holding the same key and stored on none of
     * them. Losing the phone loses the sealed blobs; losing the KEY loses the
     * ability to open them anywhere, which is the point.
     */
    vault: {
      /** Policy vocabulary: always | startup | session:30m | session:2h. */
      getPolicy: (label) => vaultKeys.getPolicy(label),
      setPolicy: (label, policy) => vaultKeys.setPolicy(label, policy),

      /** Drop a cached key now, wiping its bytes. */
      lock: (label) => vaultKeys.evict(label),
      reap: () => vaultKeys.reap(),

      /** Whether a key is cached, WITHOUT deriving one to find out. */
      isUnlocked: (label) => vaultKeys.get(label) !== null,

      /**
       * The vault key for a label, from the cache or from the device.
       *
       * Touching the device is the expensive part - it needs a button - so a
       * cached key is used when the policy allows one. A policy of 'always'
       * caches nothing and touches every time, which is what it is for.
       */
      async key(label, opts = {}) {
        const cached = vaultKeys.get(label);
        if (cached) return cached;

        const derived = await okcrypto.deriveSharedSecretFor(label, opts);
        const key = vault.deriveVaultKey(derived);
        vaultKeys.put(label, key);
        return key;
      },

      async seal(label, plaintext, opts = {}) {
        if (typeof randomBytes !== 'function') {
          throw new Error('okcrypto needs randomBytes from the host plugin to seal');
        }
        const key = await okcrypto.vault.key(label, opts);
        return vault.seal(key, plaintext, randomBytes);
      },

      /**
       * A tag failure is the ONLY signal, and it does not distinguish a wrong
       * key from a tampered blob. Neither does this - saying which would tell
       * an attacker holding the blob whether a guessed key was close.
       */
      async open(label, blob, opts = {}) {
        const key = await okcrypto.vault.key(label, opts);
        return vault.open(key, blob);
      },
    },
    get deviceOperations() {
      return {
        compositeSign: true,
        compositeDecrypt: true,
        /*
         * The OKCONNECT key exchange these ride on IS written now, and proven
         * against the firmware (ok-rn __e2e_tests__/10-derive): a label derives
         * the same P-256 key twice and two labels of equal length derive
         * different ones, with the device's own status string coming back
         * readable through the transit cipher.
         *
         * X-Wing specifically is still unverified. Wire keytype 5 becomes
         * opt2 == KEYTYPE_XWING inside the firmware (it does opt2++) and
         * returns 64 bytes rather than a 65-byte EC point, so the shape is
         * different from everything tested - and claiming it works on the
         * strength of the P-256 path having worked is exactly the kind of
         * inference this field exists to avoid.
         */
        derivePublicKey: true,
        deriveSharedSecret: true,
        deriveXwing: false,
        reason: 'derive_public_key and derive_shared_secret are implemented and '
          + 'proven for P-256; the X-Wing key type returns a different shape and '
          + 'has not been run against the device yet',
      };
    },

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },
  };

  register(null, {
    okcrypto,
    onDestroy: () => events.removeAllListeners(),
  });
}

setup.consumes = ['app', 'transport', 'session', 'host'];
setup.provides = ['okcrypto'];

module.exports = setup;
