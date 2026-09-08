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
 * OKSIGN and OKDECRYPT, by contrast, ARE in okcore.cpp's vendor dispatch, so
 * the composite halves can run over the same transport as everything else -
 * but not yet, and not by reusing what is here. Two things are missing and
 * both need checking against the device rather than inferring:
 *
 *   Framing. bridge_to_onlykey() lays a composite chunk out as
 *   [header|cmd|slot|0xFF-or-len|57 bytes]. src/device/chunker.js writes
 *   [header|msg|0xFF-or-len|57 bytes] - no slot byte - because it was built
 *   for OKRESTORE and OKFWUPDATE, which do not have one. Close enough to look
 *   reusable and wrong by one byte, which would put the chunk header where the
 *   firmware reads the slot.
 *
 *   The response. The web client polls for it through the CTAP tunnel's
 *   own mechanism. Whether the vendor path pushes the answer unsolicited or
 *   expects an OKGETRESPONSE is not something to guess at inside a signing
 *   routine.
 *
 * So this plugin currently provides the crypto and the openpgp wiring, and the
 * device operations land with the FIDO work. registerPgpHooks() below is
 * deliberately left able to accept a device object that supplies them, so
 * nothing here changes when they arrive.
 */
'use strict';

const age = require('../../src/crypto/age_file');
const pqc = require('../../src/crypto/age_pqc');
const composite = require('../../src/crypto/composite_pgp');

function setup(imports, register) {
  const { app } = imports;
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

  const okcrypto = {
    /* ---- the device-free crypto, re-exported ---------------------------- */

    age,
    pqc,
    composite,

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
     * Report what this build can actually do on a device.
     *
     * Stated rather than discovered by calling something and getting undefined:
     * composite_pgp's hooks are registered against whatever object is passed to
     * registerPgpHooks, and an object silently missing composite_decrypt fails
     * inside openpgp with a message about the PGP message rather than about
     * the device.
     */
    get deviceOperations() {
      return {
        compositeSign: false,
        compositeDecrypt: false,
        deriveXwing: false,
        reason: 'device operations need the CTAPHID transport on IFACE.FIDO',
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

setup.consumes = ['app', 'transport', 'session'];
setup.provides = ['okcrypto'];

module.exports = setup;
