'use strict';
/**
 * WHAT A PRESS IS FOR, as the firmware states it (Brad, 2026-10-10: "the firmware needs to
 * PRESENT this info because the firmware is the thing that is signing"; "the confirm sheet should
 * only get the data from firmware").
 *
 * The key_chain firmware plugin writes a press record the moment a sign or decrypt starts waiting
 * for its press: the transport, the opcode, the slot, the SHA-256 of the exact bytes, and on a
 * derived code the 32-byte label that picks the key. Here, for ANY app that shows the press - the
 * phone (ok-rn's press sheet) or, for a hard key plugged into a computer, the CLI ("hardkey may
 * not use ok-rn ... cli becomes the app") - the record is read, and the label named from that
 * app's own Key Chain list: the app's names, the firmware's facts.
 *
 * Record layout (okplugin_key_chain.cpp okplugin_key_chain_primed), 69 bytes:
 *   [0] 1 version . [1] transport (0 vendor, 1 WebAuthn) . [2] opcode . [3] slot .
 *   [4] has_label . [5..36] subject = SHA-256 of the bytes to sign . [37..68] label or zeros
 *
 * A DERIVE'S PRESS (okplugin_key_chain_derive_wait): the same layout, opcode 0xE4 (OKCONNECT),
 * slot 128, the label set, and a 70th byte - the confirmation the derive gate asks (field 30):
 * 1 a button press, 0 the 3-digit code. The code is not in the record: it is computed from the
 * subject exactly as the gate computes it (codeOf). Its end, event "press_end": [0] 1, [1] the
 * test's result as a signed byte (1 entered, 0 timed out, -2 wrong button, -1 cancelled).
 */
const { toHex } = require('../../src/bytes');
const { labelHashOf, identityName } = require('./derive');

const PRESS_BYTES = 69;
/** the press record of a slot-128 derive: OKCONNECT */
const DERIVE_OPCODE = 0xe4;
const DERIVE_SLOT = 128;

/** bytes (Uint8Array) or hex -> {transport, opcode, slot, subject, label} or null (not a v1 record) */
function decodePress(rec) {
  const b = typeof rec === 'string' ? Uint8Array.from((rec.match(/../g) || []).map((x) => parseInt(x, 16))) : rec;
  if (!b || b.length < PRESS_BYTES || b[0] !== 1) return null;
  return {
    transport: b[1] === 1 ? 'webauthn' : 'vendor',
    opcode: b[2],
    slot: b[3],
    subject: toHex(b.subarray(5, 37)),
    label: b[4] === 1 ? toHex(b.subarray(37, 69)) : null,
    /* a derive's record says which confirmation it waits for (none: a 'silent' record - answered unasked); others do not */
    mode: b.length > PRESS_BYTES ? (b[PRESS_BYTES] === 1 ? 'press' : b[PRESS_BYTES] === 2 ? 'none' : 'code') : null,
  };
}

/**
 * The Key Chain entries whose label is this one -> {listed, name}. listed: some entry has it; name:
 * the first that has a name (gpg://…, ssh://…). An entry the firmware recorded on its own holds
 * only the hash - listed, unnamed - until a computer's list with the text is merged in.
 */
function nameOfLabel(list, label) {
  const want = String(label || '').toLowerCase();
  const hits = (Array.isArray(list) ? list : []).filter((e) => labelHashOf(e) === want);
  return { listed: hits.length > 0, name: hits.map(identityName).find(Boolean) || null };
}

/**
 * The 3-digit code a derive's gate waits for, from its record's subject (hex): bytes 0, 15 and
 * 31 of the hash, mod 6, plus one (a soft key is not a DUO, whose buttons are 3).
 */
function codeOf(subject, buttons = 6) {
  const h = Uint8Array.from((String(subject).match(/../g) || []).map((x) => parseInt(x, 16)));
  if (h.length !== 32) throw new TypeError('keychain: the subject is a 32-byte hash');
  return [h[0] % buttons + 1, h[15] % buttons + 1, h[31] % buttons + 1];
}

/** "press_end": bytes or hex -> {result} (1 entered, 0 timed out, -2 wrong button, -1 cancelled) */
function decodePressEnd(rec) {
  const b = typeof rec === 'string' ? Uint8Array.from((rec.match(/../g) || []).map((x) => parseInt(x, 16))) : rec;
  if (!b || b.length < 2 || b[0] !== 1) return null;
  return { result: b[1] > 127 ? b[1] - 256 : b[1] };
}

module.exports = { PRESS_BYTES, DERIVE_OPCODE, DERIVE_SLOT, decodePress, decodePressEnd, codeOf, nameOfLabel };
