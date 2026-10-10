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
 */
const { toHex } = require('../../src/bytes');
const { labelHashOf, identityName } = require('./derive');

const PRESS_BYTES = 69;

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

module.exports = { PRESS_BYTES, decodePress, nameOfLabel };
