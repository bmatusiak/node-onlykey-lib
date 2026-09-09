/*
 * The button challenge - user presence on an OnlyKey.
 *
 * Every operation that touches a private key blocks until three buttons have
 * been pressed, and the device NEVER SAYS WHICH THREE. It cannot: the vendor
 * interface is busy holding the request open, and the real device shows them on
 * its own display. A host works them out from the same data the device hashed.
 *
 *     done_process_packets(), okcore.cpp:7574-7586
 *
 *       SHA256_CTX msg_hash;
 *       sha256_init(&msg_hash);
 *       sha256_update(&msg_hash, packet_buffer, packet_buffer_offset);
 *       sha256_final(&msg_hash, temp);
 *       Challenge_button1 = (temp[0]  % 6) + '0' + 1;
 *       Challenge_button2 = (temp[15] % 6) + '0' + 1;
 *       Challenge_button3 = (temp[31] % 6) + '0' + 1;
 *
 * So the digits are a function of the REQUEST, and a different request has
 * different ones. That is the point - it binds the press to what is being
 * approved rather than to the mere fact that someone touched the device.
 *
 * Matches onlykey-testing/lib/pqc.js:59-71, which is the implementation proven
 * against a physical key.
 *
 * WHAT IS HASHED IS packet_buffer, NOT THE FRAME. process_packets() strips the
 * header and accumulates only the payload, across as many 64-byte reports as it
 * takes, and done_process_packets() runs on the last one. Hashing a single
 * report, or a frame with its header still attached, produces three plausible
 * digits that are simply wrong - and a wrong press is indistinguishable from no
 * press until the 20-second window closes with "Error incorrect challenge was
 * entered".
 */
'use strict';

const { sha256 } = require('@noble/hashes/sha2.js');

/** The buttons a standard OnlyKey has. A DUO has three - see below. */
const BUTTONS = 6;
const DUO_BUTTONS = 3;

/**
 * The three buttons the device is about to ask for.
 *
 * @param {Uint8Array} packet the accumulated payload, exactly as the firmware
 *   assembled it in `packet_buffer`
 * @param {object} [opts]
 * @param {boolean} [opts.duo=false] the hardware is an OnlyKey DUO, which takes
 *   mod 3 rather than mod 6 because it has half the buttons. Getting this wrong
 *   yields digits in 1..6 for a device that can only produce 1..3, so two
 *   thirds of them are unpressable.
 * @param {string} [opts.formula] 'modern', 'duo' or 'legacy', as
 *   device/version.js `capabilities().challengeFormula` returns it. Prefer this
 *   over `duo`, which cannot express the legacy case; `duo: true` is the same
 *   as `formula: 'duo'`.
 * @returns {number[]} three button numbers, each 1..6 (or 1..3 on a DUO)
 */
function challengeDigits(packet, opts = {}) {
  if (!(packet instanceof Uint8Array)) {
    throw new TypeError('challengeDigits needs the packet as a Uint8Array');
  }
  const formula = opts.formula || (opts.duo ? 'duo' : 'modern');
  const hash = sha256(packet);

  /*
   * The pre-v0.2-beta.9 formula, from onlykey-pgp.js:441-449:
   *
   *   if (byte < 6) return 1; else return (byte % 5) + 1;
   *
   * Not mod 6. It is a different distribution, not an off-by-one - a byte under
   * 6 always gives button 1, so button 1 comes up about a third of the time and
   * button 6 never comes up at all.
   *
   * TRANSCRIBED from the reference client and UNVERIFIED against hardware by
   * this project. See device/version.js.
   */
  if (formula === 'legacy') {
    const legacy = (byte) => (byte < 6 ? 1 : (byte % 5) + 1);
    return [legacy(hash[0]), legacy(hash[15]), legacy(hash[31])];
  }

  const modulus = formula === 'duo' ? DUO_BUTTONS : BUTTONS;
  /*
   * The firmware adds '0' + 1 because it compares against button_selected,
   * which is an ASCII digit. These are numbers - the thing a caller presses -
   * so only the +1 survives.
   */
  return [hash[0] % modulus + 1, hash[15] % modulus + 1, hash[31] % modulus + 1];
}

module.exports = { challengeDigits, BUTTONS, DUO_BUTTONS };
