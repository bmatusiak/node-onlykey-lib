'use strict';

/**
 * A COMPUTER'S PRESS, APPROVED IN THE APP FIRST (Brad, 2026-11-03: "edge gives a prompt sheet, i press approve, and then
 * the key press - so i press approve on the app, and then on the key, like edge"; "i dont know what i was approving").
 *
 * Before a request that waits for a press leaves the computer (okcrypto beforePress, set by the CLI's desktop link -
 * cli/desktop.js), the computer asks the app that holds the key, on the same wire as EDGE_REQUEST / EDGE_IDENTITY_SET:
 *
 *   {type: 'EDGE_PRESS_ASK', v: 1, nonce, what, subject?, code?}
 *        -> {ok: true} once the person approved it on the app's sheet - then the request goes to the key and its press
 *           is asked; or {ok: false, refusal: 'declined'|'timeout'|'busy'|'invalid', detail} - the key is never asked
 *
 *   what     the computer's own words for the press - "sign the agent's PGP certificate for gpg://…" - plain text, at
 *            most 280 bytes, shown quoted (a claim, as a budget's reason is)
 *   subject  SHA-256 (hex) of exactly the bytes the key will sign - the "message" the CLI prints and a soft key's
 *            press sheet shows, so the two can be compared
 *   code     the 3-button code the key will ask for ("2 4 2"), when it asks one
 *
 * Pure: no I/O here.
 */
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');

const TYPE = 'EDGE_PRESS_ASK';
const MAX_WHAT = 280;

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);

/** The computer: "may I ask the key for this press?" */
function build({ what, subject, code, nonce = randomBytes(16) }) {
  const w = String(what || '').trim();
  if (!w) throw new TypeError('edge press ask: say what the press is for');
  const m = { type: TYPE, v: 1, nonce: toHex(nonce), what: utf8ToBytes(w).length > MAX_WHAT ? `${w.slice(0, MAX_WHAT - 1)}…` : w };
  if (subject) m.subject = String(subject).toLowerCase();
  if (code) m.code = String(code);
  const ok = verify(m);
  if (!ok.ok) throw new RangeError(`edge press ask: ${ok.reason}`);
  return m;
}

/**
 * The app: a message well formed and new. seen: nonces already taken.
 * @returns {{ok: boolean, reason?: string}}
 */
function verify(msg, { seen } = {}) {
  if (!msg || msg.type !== TYPE || msg.v !== 1 || !isHex(msg.nonce, 16)) return { ok: false, reason: 'malformed' };
  if (typeof msg.what !== 'string' || !msg.what.trim() || utf8ToBytes(msg.what).length > MAX_WHAT) return { ok: false, reason: 'malformed what' };
  if (msg.subject !== undefined && !isHex(msg.subject, 32)) return { ok: false, reason: 'malformed subject' };
  if (msg.code !== undefined && !/^[1-6]( [1-6]){2}$/.test(msg.code)) return { ok: false, reason: 'malformed code' };
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/** "fdcb 11e0 5954 9b90" - the message's first 8 bytes, the way the CLI prints it */
const shortSubject = (hex) => String(hex || '').slice(0, 16).replace(/(.{4})/g, '$1 ').trim();

module.exports = { TYPE, MAX_WHAT, build, verify, shortSubject };
