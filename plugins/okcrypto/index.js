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
 * The DEVICE-SIDE DERIVE operations are here too, and this comment used to say
 * the opposite. It described them as a deliberate boundary needing "a CTAPHID
 * transport on IFACE.FIDO, which no transport implements yet" - and by the time
 * anyone read that, `derivePublicKey`, `deriveSharedSecret`,
 * `deriveSharedSecretFor`, `derivePassword` and the whole `deviceAge` X-Wing
 * pair were implemented below, over a tunnel that does exactly what the comment
 * said was missing.
 *
 * Left as a warning rather than quietly deleted: a header describing an
 * architecture the file has outgrown is worse than no header, because it is
 * read BEFORE the code and believed instead of it.
 *
 * How they reach the firmware, which is still worth knowing: OKCONNECT carries
 * a key action in opt1, a key type in opt2 and an encrypt-response flag in
 * opt3, and those three bytes are read by `bridge_to_onlykey()` in
 * libraries/fido2/ok_extension.cpp - the CTAP path. okcore.cpp's vendor
 * dispatch has an OKCONNECT case too and does NOT look at them, because over
 * the vendor interface a keyhandle's opt bytes have nowhere to go: that frame
 * is [header|msg|slot|field]. So these ride the CTAPHID tunnel
 * (src/protocol/tunnel.js) on IFACE.FIDO, not the vendor path.
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
const vaultStore = require('../../src/crypto/vault_store');
const okconnect = require('../../src/crypto/okconnect');
const keys = require('../../src/device/keys');
const tunnelling = require('../../src/protocol/tunnel');
const { CtapHid } = require('../../src/protocol/ctaphid');
const chunker = require('../../src/device/chunker');
const okmsg = require('../../src/protocol/okmsg');
const { challengeDigits } = require('../../src/protocol/challenge');
const { toBase64Url, utf8ToBytes } = require('../../src/bytes');
const { MSG } = require('../../src/protocol/msg');
const { IFACE } = require('../../src/transport/contract');

function setup(imports, register) {
  const { app, transport, host, session, device } = imports;

  /*
   * The device's own account of what it is, for the one decision that cannot be
   * made from the wire alone: whether a touch-free derive is possible at all.
   *
   * Read at the point of use rather than captured here - `session.capabilities`
   * is null until connect() has run, and this plugin is set up first.
   */
  const deviceCan = (name) => {
    const caps = session && session.capabilities;
    return caps ? caps[name] : null;
  };

  /*
   * Randomness comes from the host plugin, not from a global. Node has crypto
   * and Hermes has nothing until a polyfill is installed, so reaching for one
   * fails at the point of use on the platform that lacks it.
   */
  const randomBytes = host && host.randomBytes;

  /*
   * Persistent storage, if the host supplied any.
   *
   * Built once, lazily, and null when there is nowhere to persist - a host
   * without storage still does everything except remember. The methods that
   * need it say which one is missing rather than failing at a write.
   */
  let storeApi = null;
  function persistence() {
    if (storeApi) return storeApi;
    if (!host || !host.store) {
      throw new Error(
        'the vault has nowhere to persist: the host supplied no store. Pass one ' +
        'as plugins.config = { host: { store } } - three methods, getItem, ' +
        'setItem and removeItem.',
      );
    }
    storeApi = vaultStore.createVaultStore({
      store: host.store,
      now: () => (host.now ? host.now() : Date.now()),
    });
    return storeApi;
  }
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
      /*
       * How many bytes the answer is, when it is more than one report. The
       * device sends a large response as consecutive 64-byte reports in one
       * tight loop (send_transport_response, okcore.cpp) and nothing
       * interleaves with them, so a 3309-byte ML-DSA signature is 52 reports
       * to collect. Zero means "the first report is the answer", which is
       * what every operation here was before composite signing arrived.
       */
      expectBytes = 0,
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
    /*
     * Leading status broadcasts and error sentences are recognised only
     * BEFORE the first data byte, exactly as python-onlykey's read_exact
     * does. Once the answer has started, a report may legitimately be all
     * zeros or read as text, and dropping one would corrupt the result
     * silently.
     */
    let started = false;
    const collected = [];
    let got = 0;
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
        if (!started) {
          const state = okmsg.parseState(event.data);
          if (state.state === 'unlocked' || state.state === 'locked'
              || state.state === 'uninitialized') return;
          if (state.state === 'error') {
            clearTimeout(timer);
            answered = true;
            if (off) off();
            reject(okmsg.deviceError(state.raw));
            return;
          }
          started = true;
        }
        answered = true;
        const chunk = Uint8Array.from(event.data);
        if (!expectBytes) {
          clearTimeout(timer);
          if (off) off();
          resolve(chunk);
          return;
        }
        collected.push(chunk);
        got += chunk.length;
        if (got < expectBytes) return;
        clearTimeout(timer);
        if (off) off();
        const out = new Uint8Array(got);
        let at = 0;
        for (const c of collected) { out.set(c, at); at += c.length; }
        resolve(out.slice(0, expectBytes));
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
  /**
   * What a device status line looks like, and nothing else does.
   *
   * The four states the firmware reports, anchored at the start because that
   * is where the status sits.
   */
  const DEVICE_STATUS = /^(UNINITIALIZED|INITIALIZED|UNLOCKED|LOCKED)/i;

  /**
   * How many times a derive is re-sent when the reply carries no device status.
   *
   * A reply with no status is not an answer to this request - see the guard in
   * deriveOnce. That happens for two reasons and they need the same handling:
   * the device REFUSED the request (and this poll landed on the previous
   * response before it was wiped), or the request itself was lost.
   *
   * The second is real and measured. On v2.1.0 a request issued immediately
   * after another one is dropped: the shared-secret derives failed every time
   * while the public-key derives before them passed, and the plugin's own
   * sendField has retried since it was written for exactly this reason.
   *
   * Bounded, because a refusal will not start answering however many times it
   * is asked - retrying only means the honest error takes longer to arrive.
   */
  const DERIVE_ATTEMPTS = 3;

  /*
   * A derive is IDEMPOTENT, which is what makes retrying it safe: the same
   * label and the same press flag derive the same key, and the device holds no
   * state between attempts.
   *
   * A REQ_PRESS variant is the exception, and it is the reason every attempt
   * is ANNOUNCED. The comment here used to claim that `onKeepAlive` was handed
   * a fresh chance to press on each attempt; it was not - the same closure was
   * passed straight through, so a host whose press budget is one per call had
   * already spent it by attempt two.
   *
   * That matters most on firmware that BLOCKS for a touch instead of asking
   * for one (capabilities().presenceTest === 'blocking', the 2.1 line). There
   * is no keepalive to answer there, so a host presses on a timer, and a
   * retry it is never told about goes out with no press behind it - which
   * makes the retry useless on exactly the firmware that needs it.
   *
   * The event carries the attempt number rather than the library guessing
   * what the host should do about it. See
   * ok-rn/FINDING-blocking-presence-fails-a-second-shared-secret.md, which
   * this was added to settle.
   */
  async function derive(opts) {
    let last = null;
    for (let attempt = 1; attempt <= DERIVE_ATTEMPTS; attempt++) {
      events.emit('progress', {
        step: 'derive',
        action: opts && opts.action,
        label: opts && opts.label,
        attempt,
        attempts: DERIVE_ATTEMPTS,
      });
      try {
        return await deriveOnce(opts);
      } catch (err) {
        last = err;
        if (!/did not answer this derive/.test(String(err && err.message))) throw err;

        /*
         * TELL THE HOST A RETRY IS COMING, so a press-required derive can be
         * pressed again.
         *
         * MEASURED, on v2.1.1: attempts 2 and 3 went out with no press behind
         * them at all, because the host had armed one press for the ceremony
         * and the library asked again without saying so.
         *
         *     derive attempt 1/3 for "vault.example"
         *     pressed button 1 for the derive (timer)
         *     derive attempt 2/3 for "vault.example"      <- no press
         *     derive attempt 3/3 for "vault.example"      <- no press
         *
         * On keepalive firmware this is harmless - the device asks again on
         * its own and the host is already answering. On BLOCKING firmware it
         * is the only signal there is, because nothing else ever calls this
         * hook there, and without it the retry could not succeed however many
         * times it ran.
         *
         * The library does not press. It says a fresh touch is wanted and
         * leaves the deciding to whoever owns the buttons.
         */
        if (attempt < DERIVE_ATTEMPTS && typeof opts.onKeepAlive === 'function') {
          try {
            await opts.onKeepAlive({ retry: true, attempt: attempt + 1 });
          } catch (_) {
            /* A host that cannot press is not a reason to skip the retry. */
          }
        }
      }
    }
    throw last;
  }

  async function deriveOnce({
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

    /*
     * CONFIG MODE KILLS CTAPHID, so say so instead of timing out.
     *
     * Entering config mode locks the device and it stays there until restart -
     * there is no message to leave. While in it the vendor interface still
     * answers and CTAPHID goes silent, so a derive waits out its timeout
     * against a device that is working exactly as designed.
     *
     * That is this project's most expensive failure shape: six tests failing in
     * a row with "no CTAPHID reply", none of them naming a cause, all of them
     * downstream of one gesture forty seconds earlier
     * (FINDING-enabling-touch-free-derive-mid-run-kills-ctaphid.md).
     *
     * Checked before the request rather than after the silence, because the
     * silence carries no information at all.
     */
    if (session && session.configMode) {
      throw new Error(
        'this device is in CONFIG MODE, where it answers the vendor interface '
        + 'and goes silent on CTAPHID - so this derive would time out rather '
        + 'than fail. Config mode ends only at a restart; restart the firmware '
        + 'and try again.',
      );
    }

    /*
     * DO NOT ASK A FIRMWARE FOR A KEY TYPE IT DOES NOT HAVE.
     *
     * X-Wing arrived after v3.0.2; `KEYTYPE_XWING` appears nowhere in
     * libraries@5d7ce7a. An older device does not refuse the request - it has
     * no branch for the type, so `pubsize` is never set and it answers with a
     * perfectly well-formed status line and whatever happens to be in the key
     * area. Measured on a v3.0.2 soft key: the derive returned successfully
     * and the caller got 64 bytes that are not a key.
     *
     * The status guard below cannot catch that, because the status is real.
     * Only knowing what the firmware has can, so this asks before it sends.
     */
    if (keytype === okconnect.KEYTYPE.XWING && deviceCan('xwingDerive') === false) {
      throw new Error(
        'this firmware has no X-Wing key type, so it cannot derive one. It '
        + 'answers the request with a valid status and no key rather than '
        + 'refusing, which is why this is checked here instead of being left '
        + 'to the device. X-Wing arrived after v3.0.2.',
      );
    }

    const app = okconnect.newTransitKeypair();
    const data = okconnect.buildMessage({
      transitPublicKey: app.publicKey,
      label,
      publicKey,
      keytype,
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
     * THE STATUS IS THE PROOF THAT THIS IS AN ANSWER.
     *
     * Every device response begins with a status line - UNLOCKED, LOCKED,
     * INITIALIZED, UNINITIALIZED, optionally with a version and a model letter.
     * If the decrypted bytes do not start with one, they are not a response to
     * this request.
     *
     * That happens for real, and it is the most expensive failure mode in this
     * file's history. When the firmware REFUSES a derive - a key type it does
     * not have, a preference bit it reads as clear - it returns an error code
     * and calls wipedata(), which is a TIMER rather than an immediate clear. A
     * poll landing in that window gets whatever is left of the previous
     * response: a plausible number of bytes, stable per label, and completely
     * wrong.
     *
     * Measured on a v3.0.2 soft key, five attempts at a derive the firmware
     * was refusing outright: payloads of 76, 84 and 86 bytes, each with a
     * different 65-byte "public key" and a status that was empty or a few
     * bytes of binary noise. Every one was returned to the caller as a derived
     * public key. The vault then sealed blobs under it, and the only symptom
     * anywhere was a confusing complaint about key framing several layers up.
     *
     * The LENGTH is not a guard: 76 and 86 both look reasonable, and the value
     * is stable per label because the stale buffer is. Only the status can tell
     * an answer from a leftover.
     */
    if (!DEVICE_STATUS.test(String(opened.status || ''))) {
      throw new Error(
        'the device did not answer this derive - the reply carries no device '
        + 'status, so it is not a response to this request. The usual cause is '
        + 'the firmware REFUSING the request (a key type it does not have, or '
        + 'a preference it reads as clear) and this poll landing on the '
        + 'previous response before it was wiped.',
      );
    }

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

    /**
     * Encrypt, decrypt, sign and verify messages and files.
     *
     * The four pages the desktop app links out to. Re-exported rather than
     * wrapped: every one of these takes the openpgp instance as its first
     * argument, so wrapping them here would mean either importing the 1.2 MB
     * fork into this plugin - which the whole shape of this file avoids - or
     * inventing a second way to pass it.
     *
     * A caller that wants DEVICE-BACKED decryption calls registerPgpHooks
     * first; from then on `messages.decryptMessage` routes the private-key
     * half to the key without knowing it has.
     */
    messages: require('../../src/crypto/pgp_messages'),

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
    /**
     * Sign with an ORDINARY key the device holds - an Ed25519 or ECDSA slot
     * (101-132) or an RSA slot: OKSIGN, the bytes as given, the first report
     * back. The three phases described above.
     *
     * Split from composite_sign, which used to be this: the composite hooks
     * call that with a half selector, and this suite of ordinary signing
     * (9-cryptoSign) called the same function with a raw payload. One name
     * cannot mean both, and the full run said so the moment the composite
     * shape was fixed.
     */
    async sign(slot, data, opts = {}) {
      return deviceOperation(MSG.OKSIGN, slot, data, opts);
    },
    /** Decrypt with an ordinary key the device holds. OKDECRYPT, same three phases. */
    async decrypt(slot, data, opts = {}) {
      return deviceOperation(MSG.OKDECRYPT, slot, data, opts);
    },
    /**
     * Sign one HALF of a composite key: `(slot, half, digest)`.
     *
     * The shape composite_pgp's hooks call - `ok.composite_sign(slot,
     * HALF_ECC, hashed)` - and the reference's (python-onlykey pqc.py):
     * the payload is the selector byte and then the digest, OKSIGN to the
     * RSA slot the key was loaded into, and the answer is 64 bytes (Ed25519)
     * or 3309 (ML-DSA-65) collected across reports. This took `(slot, data)`
     * before, so the hooks handed it the selector AS the data and the
     * firmware was asked to sign nothing - measured on the bench key from
     * the hardKeyConfig suite: "nothing to sign or decrypt".
     */
    async composite_sign(slot, half, digest, opts = {}) {
      if (half !== composite.HALF_ECC && half !== composite.HALF_PQC) {
        throw new Error(`composite_sign: half must be HALF_ECC (0) or HALF_PQC (1), got ${half}`);
      }
      const bytes = Uint8Array.from(digest);
      const payload = new Uint8Array(1 + bytes.length);
      payload[0] = half;
      payload.set(bytes, 1);
      const expectBytes = half === composite.HALF_ECC
        ? composite.ED25519_SIG_LEN : composite.MLDSA_SIG_LEN;
      return deviceOperation(MSG.OKSIGN, slot, payload, { expectBytes, ...opts });
    },
    /**
     * Decrypt one half of a composite exchange: no selector - the firmware
     * infers X25519 from a 32-byte point and ML-KEM from a 1088-byte
     * ciphertext - and a 32-byte shared secret back either way.
     */
    async composite_decrypt(slot, data, opts = {}) {
      return deviceOperation(MSG.OKDECRYPT, slot, data, { expectBytes: composite.SS_LEN, ...opts });
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
     *
     * ## The two steps do not want the same press
     *
     * The reference asks for the public key WITHOUT a touch and the shared
     * secret WITH one (vault.js:342-344, and its comment says why): fetching a
     * public key is not sensitive, computing the ECDH is. Passing one
     * `requirePress` to both got the UX wrong in both directions - a touch
     * demanded to fetch a public key, or no touch on the step that actually
     * derives the secret.
     *
     * They also map to different things ON THE DEVICE. The touch-free variants
     * are gated on an EEPROM bit (derived_key_challenge_mode bit 3), so on a
     * key without "derived keys per site without touch" enabled they are
     * REFUSED - as CTAP2_ERR_EXTENSION_NOT_SUPPORTED, which reads like the
     * firmware has no such feature. The REQ_PRESS variants skip that check and
     * ask for a finger instead.
     *
     * @param {object} [opts]
     * @param {boolean} [opts.requirePress] both steps, when a caller means both
     * @param {boolean} [opts.pressForPublicKey] just the public-key step
     * @param {boolean} [opts.pressForSecret] just the shared-secret step
     */
    async deriveSharedSecretFor(label, opts = {}) {
      const { requirePress, pressForPublicKey, pressForSecret, ...rest } = opts;
      const pub = await okcrypto.derivePublicKey(label, {
        ...rest,
        requirePress: pressForPublicKey ?? requirePress ?? false,
      });
      const shared = await okcrypto.deriveSharedSecret(label, pub.publicKey, {
        ...rest,
        requirePress: pressForSecret ?? requirePress ?? false,
      });
      return shared.secret;
    },

    /**
     * The derived secret as the PASSWORD STRING the other clients show.
     *
     * base64url of the 32 bytes, which is what a JWK `k` member is and
     * therefore what build_AESGCM returns (onlykey-3rd-party.js:95). We
     * rendered it as hex, so this app showed a different password for the same
     * site than the web app and the desktop app do - a silent incompatibility,
     * since both strings look like a perfectly good password.
     */
    async derivePassword(label, opts = {}) {
      const secret = await okcrypto.deriveSharedSecretFor(label, opts);
      return toBase64Url(secret);
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
     * age files encrypted to an identity the DEVICE holds half of.
     *
     * NOT `age`. That name is the pure module, re-exported above, and taking
     * it for this would silently replace a published API with one that has
     * different functions of the same shape. `vault` learned that the hard
     * way: seal(key, plaintext, randomBytes) and seal(label, plaintext, opts)
     * are indistinguishable at the call site and mean different things.
     *
     * X-Wing is split custody by design: the device keeps sk_X and never
     * emits it, while the ML-KEM half travels as a 32-byte SEED that the host
     * expands itself. So encryption needs no device at all - a recipient is
     * public - and decryption needs exactly one round trip, for the X25519
     * half that the device will not give up.
     */
    deviceAge: {
      /**
       * The device's X-Wing identity for a label.
       *
       * Deterministic, like every other derivation here, so an identity does
       * not need storing - only its label does.
       */
      async identity(label, opts = {}) {
        const derived = await okcrypto.derivePublicKey(label, {
          ...opts,
          keytype: okconnect.KEYTYPE.XWING,
        });
        const pkX = derived.publicKey.subarray(0, 32);
        const mlkemSeed = derived.publicKey.subarray(32);
        const recipient = pqc.buildRecipient(pkX, mlkemSeed);
        return {
          label,
          pkX,
          mlkemSeed,
          recipient,
          recipientString: pqc.encodeRecipient(recipient),
        };
      },

      /**
       * Encrypt to a recipient. NO DEVICE IS INVOLVED.
       *
       * Worth stating because it is the useful half: anyone can encrypt to
       * this identity with only the recipient string, and the key is needed
       * solely to read the result.
       */
      encrypt(plaintext, recipient) {
        const pk = typeof recipient === 'string'
          ? pqc.decodeRecipient(recipient)
          : recipient;
        const { ciphertext, sharedSecret } = pqc.xwingEncapsHost(pk);
        return age.encryptAgeFile(plaintext, { ciphertext, sharedSecret });
      },

      /**
       * Decrypt with the device.
       *
       * The stanza carries the whole 1120-byte X-Wing ciphertext, but only
       * ct_X - its last 32 bytes - goes to the device. ct_M never leaves the
       * host: the ML-KEM half is decapsulated here from the seed, which is
       * what makes this one round trip rather than a 1120-byte upload.
       */
      async decrypt(fileBytes, label, opts = {}) {
        const id = await okcrypto.deviceAge.identity(label, opts);
        return age.decryptAgeFile(fileBytes, async (ciphertext) => {
          const ctX = pqc.ctXOf(ciphertext);
          const answer = await okcrypto.deriveSharedSecret(label, ctX, {
            ...opts,
            keytype: okconnect.KEYTYPE.XWING,
          });
          return pqc.splitDecapsulate(answer.secret, ciphertext, id.pkX, id.mlkemSeed);
        });
      },

      /**
       * The identity of a key the device GENERATED and keeps in a slot.
       *
       * The other kind entirely. `identity()` above derives a key from a
       * label on demand and it exists nowhere; this one reads the public half
       * of a key whose private half is a seed sitting in flash.
       *
       * Nothing is derived, so nothing here needs a button.
       */
      async slotIdentity(slot, opts = {}) {
        const publicKey = await device.getPublicKey(slot, {
          ...opts,
          bytes: keys.PUBLIC_KEY_BYTES[keys.KEY_TYPE.XWING],
          keyType: keys.KEY_TYPE.XWING,
        });
        return {
          slot,
          publicKey,
          recipientString: pqc.encodeRecipient(publicKey),
          identityString: pqc.encodeSlotIdentity(slot, publicKey),
        };
      },

      /**
       * Decrypt with a key held in a SLOT.
       *
       * ## This is NOT the label path with a number instead of a string
       *
       * The two send different things and get different things back, and
       * confusing them produces a shared secret that is wrong in a way
       * nothing reports:
       *
       *   label   ct_X only, 32 bytes  ->  64 bytes back, and the HOST does
       *           the ML-KEM half from the seed (splitDecapsulate)
       *   slot    the WHOLE ciphertext, 1120 bytes  ->  32 bytes back, which
       *           ARE the shared secret - the DEVICE ran the combiner
       *
       * So there is no splitDecapsulate here and there must not be. The
       * firmware checks the length (`large_buffer_offset == XWING_CT_SIZE`,
       * okcrypto.cpp:2069) and refuses 32 bytes where it wants 1120, which is
       * the merciful case; running the ML-KEM half twice would not be
       * refused by anything.
       *
       * A three-button challenge is raised over the ciphertext, the same as
       * signing. It does NOT need config mode, and cannot have it: config
       * mode answers eleven message types and silently drops the rest, and
       * OKDECRYPT is not among them (okcore.cpp:347).
       */
      async decryptWithSlot(fileBytes, slot, opts = {}) {
        return age.decryptAgeFile(fileBytes, async (ciphertext) => {
          /*
           * 32, written out rather than reached for: age_pqc exports
           * XWING_CT and XWING_PK but no shared-secret constant, and
           * `pqc.XWING_SS || 32` reads as if one might exist. The number is
           * XWING_SS_SIZE at okcore.h:242 and it is the SHA3-256 combiner's
           * output width, so it is not going to move without the algorithm
           * moving with it.
           */
          const secret = await okcrypto.decrypt(slot, ciphertext, {
            ...opts,
            expectBytes: 32,
          });
          if (secret.length !== 32) {
            throw new Error(
              `slot ${slot} returned ${secret.length} bytes for an X-Wing `
              + 'decapsulation; the shared secret is 32',
            );
          }
          return secret;
        });
      },

      /**
       * Decrypt with whichever kind of identity the string names.
       *
       * The reason the two identity forms share an HRP is that age picks a
       * plugin binary from that prefix - but the happy consequence is this:
       * a caller holds an identity string and does not have to know which
       * kind it is.
       */
      async decryptWithIdentity(fileBytes, identityString, opts = {}) {
        const id = pqc.decodeIdentity(identityString);
        if (!id) throw new Error('not an OnlyKey age identity');

        if (id.derived) return okcrypto.deviceAge.decrypt(fileBytes, id.label, opts);

        /*
         * CHECK THE FINGERPRINT FIRST, when there is one.
         *
         * An identity names a slot and a slot can be generated again. Without
         * this the attempt fails as an age "no identity matched", which is
         * true and useless - it points at the file rather than at the key. A
         * versioned identity carries SHA-256(pubkey)[0..8] precisely so the
         * client can say what actually happened.
         *
         * It costs one public-key read, no button and no attempt counter.
         */
        if (id.fingerprint) {
          const { publicKey } = await okcrypto.deviceAge.slotIdentity(id.slot, opts);
          if (!pqc.identityMatchesKey(id, publicKey)) {
            throw new Error(
              `slot ${id.slot} holds a different key from the one this identity `
              + 'was made for - it has been generated again since',
            );
          }
        }
        return okcrypto.deviceAge.decryptWithSlot(fileBytes, id.slot, opts);
      },
    },
    /**
     * Credentials sealed under a key only the device can derive.
     *
     * Named deviceVault rather than vault for the reason above: the pure module
     * is re-exported as `vault` and has a seal() of its own.
     *
     * The key is HKDF over the device's shared secret for a label, so it is
     * reproducible on any host holding the same key and stored on none of
     * them. Losing the phone loses the sealed blobs; losing the KEY loses the
     * ability to open them anywhere, which is the point.
     */
    deviceVault: {
      /**
       * Policy vocabulary: always | startup | session:30m | session:2h.
       *
       * TWO COPIES, AND THE STORED ONE IS THE AUTHORITY.
       *
       * `vaultKeys` holds the policy that governs caching RIGHT NOW, in a Map
       * built when this plugin was constructed. The stored record's `policy`
       * field is the only copy that survives the process.
       *
       * setPolicy used to write the live one and stop, so the two drifted the
       * moment anybody changed a policy: a screen redrawing from list() read
       * the stale record and the control snapped back, and a restart brought
       * back an empty live map that cached a key for a service stored under
       * `always`. See ok-rn/FINDING-a-vault-policy-change-was-never-stored.md.
       */
      getPolicy: (label) => vaultKeys.getPolicy(label),

      async setPolicy(label, policy) {
        /*
         * Live first. Tightening to a no-cache policy EVICTS, and that has to
         * happen even if the write below fails - a key left cached under a
         * policy that forbids caching is the failure that matters.
         */
        vaultKeys.setPolicy(label, policy);
        if (!okcrypto.deviceVault.canPersist) return policy;

        /*
         * Read-modify-write: put() demands the sealed blob, and a policy
         * change must not be able to lose it. No record yet is not an error -
         * save() records getPolicy() at seal time, so a policy chosen before
         * the credential exists is written the moment it does.
         */
        const record = await persistence().get(label);
        if (record) await persistence().put({ ...record, policy });
        return policy;
      },

      /** Drop a cached key now, wiping its bytes. */
      lock: (label) => vaultKeys.evict(label),

      /**
       * Forget every cached key at once, zeroing the bytes.
       *
       * What a host calls when the DEVICE LOCKS. A cached vault key outliving
       * the lock is the whole of the protection gone: the key was derived with
       * a touch, and after a lock there is nobody to have touched anything.
       * `clear()` overwrites each key rather than dropping the reference,
       * because an unreachable Uint8Array is still in memory until something
       * reuses the page.
       *
       * Separate from `reap()`, which only drops what has EXPIRED. Expiry is
       * about a policy running out; this is about the premise of every policy
       * being gone at once.
       */
      lockAll: () => vaultKeys.clear(),

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

        /*
         * THREE details here decide whether a blob sealed by this app can be
         * opened by the web app, and every one of them fails silently if it is
         * wrong - the key is the right length, stable per label, and simply not
         * the same key. None of them is a preference.
         *
         *   1. The phrase is "vault:" + serviceId, not the bare serviceId
         *      (vault.js:327). Deriving from the bare label produces a valid
         *      key for a label the other clients never derive.
         *
         *   2. The public-key step takes no touch and the secret step does
         *      (vault.js:342-344) - handled by deriveSharedSecretFor.
         *
         *   3. The HKDF input is the UTF-8 of the base64url TEXT, not the raw
         *      32 bytes. The reference calls derive_shared_secret, which
         *      returns build_AESGCM's JWK `k` - a 43-character string - and
         *      hands it to toBytes(), whose hex branch cannot match a 43-char
         *      base64url string, so it falls through to TextEncoder().encode().
         *      43 bytes of ASCII go into HKDF, not 32 bytes of secret.
         *
         * The third is the one that looks like a bug in the reference and is
         * not ours to correct: the blobs already exist.
         */
        let secret;
        try {
          secret = await okcrypto.deriveSharedSecretFor(`vault:${label}`, {
            ...opts,
            pressForPublicKey: false,
            pressForSecret: opts.requirePress ?? true,
          });
        } catch (err) {
          /*
           * NO FALLBACK TO THE PRESS VARIANT, however tempting.
           *
           * The press flag is an INPUT to the derivation, not a permission
           * check in front of it - ok_extension.cpp:245 sets
           * additional_data[0] = 1 for the REQ_PRESS variants, and
           * additional_data is what the key is derived from. Retrying the
           * public-key step with a press would derive a different key, so the
           * vault would appear to work while sealing blobs that no other
           * client can open and that this app could not open either once the
           * preference was turned on.
           *
           * The status is misleading on its own, so it is translated. It says
           * the extension is unsupported; what is actually true is that an
           * EEPROM bit is clear.
           */
          if (/EXTENSION_NOT_SUPPORTED/.test(String(err && err.message))) {
            /*
             * The status names the wrong cause, and WHICH right cause depends
             * on the firmware. Three releases behave three ways here
             * (src/device/version.js, touchFreeDerive):
             *
             *   'always'      v3.0.1 and earlier - no preference exists, so a
             *                 refusal here means something else entirely and
             *                 the raw status is the most honest thing to show.
             *   'preference'  after v3.0.2 - an EEPROM bit is clear, and
             *                 turning it on fixes this.
             *   'broken'      v3.0.2 exactly - the check reads a RAM cache the
             *                 raw-HID pipeline zeroes, so the device refuses a
             *                 preference it is already holding. Telling
             *                 somebody to enable a setting that cannot take
             *                 effect is worse than telling them nothing.
             *
             * There is no fallback to the press variant in any of them: the
             * press flag is an INPUT to the derivation, so retrying with a
             * touch derives a different key.
             */
            const can = deviceCan('touchFreeDerive');
            if (can === 'broken') {
              throw new Error(
                'this firmware cannot do a touch-free derive at all, so the '
                + 'vault cannot be opened on it. v3.0.2 checks a cached copy '
                + 'of the preference that its own raw-HID path clears, so it '
                + 'refuses the derive whatever the setting says. Later '
                + 'firmware reads the setting properly.',
              );
            }
            if (can === 'always') {
              throw new Error(
                'the device refused a touch-free derive, and this firmware has '
                + 'no preference gating one - so the cause is not a setting. '
                + `The device said: ${String(err && err.message)}`,
              );
            }
            throw new Error(
              'the vault needs the device preference "derived keys per site ' +
              'without touch" enabled (derived_key_challenge_mode bit 3). The ' +
              'firmware refuses the touch-free derive without it, and reports ' +
              'that as CTAP2_ERR_EXTENSION_NOT_SUPPORTED. Retrying with a touch ' +
              'is not a workaround: it derives a DIFFERENT key, so the blobs ' +
              'would not interoperate. Set field 21 to 8 in config mode. See ' +
              'ok-rn/FINDING-the-press-flag-changes-the-derived-key.md',
              { cause: err },
            );
          }
          throw err;
        }
        const key = vault.deriveVaultKey(utf8ToBytes(toBase64Url(secret)));
        vaultKeys.put(label, key);
        return key;
      },

      async seal(label, plaintext, opts = {}) {
        if (typeof randomBytes !== 'function') {
          throw new Error('okcrypto needs randomBytes from the host plugin to seal');
        }
        const key = await okcrypto.deviceVault.key(label, opts);
        return vault.seal(key, plaintext, randomBytes);
      },

      /**
       * A tag failure is the ONLY signal, and it does not distinguish a wrong
       * key from a tampered blob. Neither does this - saying which would tell
       * an attacker holding the blob whether a guessed key was close.
       */
      async open(label, blob, opts = {}) {
        const key = await okcrypto.deviceVault.key(label, opts);
        return vault.open(key, blob);
      },

      /* ---- persistence ------------------------------------------------- */

      /**
       * Whether anything can be remembered at all.
       *
       * Asked rather than discovered by a failed save, so a screen can hide a
       * button instead of offering one that throws.
       */
      get canPersist() {
        return Boolean(host && host.store);
      },

      /**
       * Seal a credential and store it under its service id.
       *
       * The blob is what is stored; the KEY is derived from the device and
       * kept nowhere. So this is safe to back up and impossible to read
       * without the key that made it.
       */
      async save(serviceId, plaintext, opts = {}) {
        const encrypted = await okcrypto.deviceVault.seal(serviceId, plaintext, opts);
        return persistence().put({
          serviceId,
          encrypted,
          policy: vaultKeys.getPolicy(serviceId),
        });
      },

      /** Read one back, decrypting it. Null when there is no such record. */
      async load(serviceId, opts = {}) {
        const record = await persistence().get(serviceId);
        if (!record) return null;
        return okcrypto.deviceVault.open(serviceId, record.encrypted, opts);
      },

      /**
       * What is stored, WITHOUT opening any of it.
       *
       * Listing must not touch the device: a screen showing twelve saved
       * credentials would otherwise ask for twelve button presses to draw
       * itself.
       */
      /**
       * What is stored, and the moment a stored policy comes back into force.
       *
       * A fresh process starts with an empty policy map, so getPolicy would
       * answer with the DEFAULT for a service stored under `always` - and
       * vaultKeys.put would cache its key, having been told nothing to the
       * contrary. Every host has to list the vault before it can use anything
       * from it, which makes this the one place the restored policy is
       * guaranteed to be applied before a key is derived.
       *
       * Unconditional rather than only-if-unset: setPolicy writes through, so
       * the record is never the stale copy, and re-applying it costs an evict
       * for exactly the services that must not be cached anyway.
       */
      async list() {
        const records = await persistence().list();
        for (const record of records) {
          if (record.policy) vaultKeys.setPolicy(record.serviceId, record.policy);
        }
        return records;
      },
      serviceIds: () => persistence().serviceIds(),
      forget: (serviceId) => persistence().remove(serviceId),

      /**
       * Every sealed blob, in the web app's export envelope.
       *
       * Still sealed, so this is safe to copy about in the sense that
       * matters. It is not private, though: the service ids are in the clear,
       * so an export says which sites someone has accounts on.
       */
      exportJSON: () => persistence().exportJSON(),
      importJSON: (json, opts) => persistence().importJSON(json, opts),

      /** Forget every stored credential. The keys were never stored. */
      forgetAll: () => persistence().clear(),
    },
    get deviceOperations() {
      return {
        compositeSign: true,
        compositeDecrypt: true,
        /*
         * All of these are measured against the firmware, not inferred.
         *
         * The P-256 pair: a label derives the same key twice, two labels derive
         * different ones, and the shared secret matches an ECDH computed
         * host-side from a scalar the test holds (ok-rn __e2e_tests__/10-derive
         * and 13-deriveParity). That last one is what caught a peer key framed
         * with its 0x04 at the wrong end - determinism alone had passed it.
         *
         * X-Wing was listed here as "still unverified" long after it stopped
         * being so, on the reasoning that its shape differs from everything
         * tested: wire keytype 5 becomes opt2 == KEYTYPE_XWING in the firmware
         * (it does opt2++) and 64 bytes come back rather than a 65-byte EC
         * point. That caution was right at the time and is now answered
         * directly - 10-derive derives the split-custody pair on device, checks
         * the two halves differ and are stable, and round-trips a whole age
         * file through it.
         */
        derivePublicKey: true,
        deriveSharedSecret: true,
        deriveXwing: true,
        reason: '',
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

/*
 * `device` joined this list for the SLOT age identities.
 *
 * Decrypting a file addressed to a slot has to read that slot's public key -
 * to build the recipient, and to check the fingerprint an identity carries
 * before spending a button press on a key that has since been generated
 * again. That read is device.getPublicKey, and duplicating its collector here
 * would be a second copy of the one piece of code that has already produced
 * two findings.
 *
 * No cycle: plugins/device consumes app, transport and session, and knows
 * nothing about okcrypto.
 */
setup.consumes = ['app', 'transport', 'session', 'host', 'device'];
setup.provides = ['okcrypto'];

module.exports = setup;
