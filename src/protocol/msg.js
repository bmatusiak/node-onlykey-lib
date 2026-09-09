/*
 * msg.js - the OnlyKey message and field tables.
 *
 * These exist in four places today and no two agree on all of it:
 *
 *   OnlyKey-App/app/scripts/onlyKey/OnlyKeyComm.js   14 messages + 28 fields
 *   OnlyKey-App/app/app.js                           a second, inline copy
 *   onlykey.github.io/.../hid-cli/index.js           the command table
 *   onlykey-testing/lib/device/okmsg.js              18 messages, no fields
 *
 * The message BYTES agree everywhere - that was checked pairwise, not assumed.
 * Four names differ: the app calls 0xE1-0xE4 OKSETPIN / OKSETSDPIN / OKSETPIN2
 * / OKSETTIME where the firmware header calls them OKPIN / OKPINSD / OKPINSEC /
 * OKCONNECT. Both spellings are exported, because both appear in code that
 * will read this, and an alias costs nothing next to a subtle mismatch.
 *
 * The field table exists only in OnlyKey-App, and its casing is inconsistent -
 * three entries are camelCase where the rest are upper. That is load-bearing:
 * the app's lookup is a plain property access, so `DERIVEDCHALLENGEMODE` finds
 * nothing. Preserved exactly, with upper-case aliases added.
 */
'use strict';

/**
 * okcore.h: `#define OKxxx (TYPE_INIT | 0xNN)`, TYPE_INIT = 0x80 (okcore.h:132).
 * Names follow the firmware header; the app's spellings are aliased below.
 *
 * Values verified against libraries/onlykey/okcore.h:133-155, not copied from
 * a client. Clients agree with it, which was checked pairwise rather than
 * assumed - but the header is the source of truth.
 */
const MSG = {
  OKPIN: 0xe1,          // set/advance the primary PIN state machine
  OKPINSD: 0xe2,        // ... self-destruct PIN
  OKPINSEC: 0xe3,       // ... second (plausible deniability) profile PIN
  OKCONNECT: 0xe4,      // also the set-time message; see setTimePayload()
  OKGETLABELS: 0xe5,
  OKSETSLOT: 0xe6,
  OKWIPESLOT: 0xe7,
  /*
   * 0xE8-0xEB are FREE, not missing. okcore.h:140-144 has them commented out:
   * "Removed custom U2F cert feature, msg types available for future new
   * features" - OKSETU2FPRIV, OKWIPEU2FPRIV, OKSETU2FCERT, OKWIPEU2FCERT.
   * Recorded so nobody re-derives them from the gap and assumes they work.
   */
  OKGETPUBKEY: 0xec,
  OKSIGN: 0xed,
  OKWIPEPRIV: 0xee,
  OKSETPRIV: 0xef,
  OKDECRYPT: 0xf0,
  OKRESTORE: 0xf1,
  OKGETRESPONSE: 0xf2,
  OKPING: 0xf3,
  OKFWUPDATE: 0xf4,
  OKHMAC: 0xf5,
  OKWEBAUTHN: 0xf6,
};

/** OnlyKey-App's names for the same bytes. */
const MSG_ALIASES = {
  OKSETPIN: MSG.OKPIN,
  OKSETSDPIN: MSG.OKPINSD,
  OKSETPIN2: MSG.OKPINSEC,
  OKSETTIME: MSG.OKCONNECT,
};

/** Reverse lookup, for turning a captured byte back into something readable. */
const MSG_NAMES = {};
for (const [name, value] of Object.entries(MSG)) MSG_NAMES[value] = name;

/** The three PIN state machines, by the name a caller would use. */
const PIN_KIND = {
  primary: MSG.OKPIN,
  secondary: MSG.OKPINSEC,
  selfDestruct: MSG.OKPINSD,
};

/**
 * Slot field ids, from OnlyKeyComm.js. 28 is unassigned - not an omission.
 *
 * Casing is verbatim: `derivedchallengeMode`, `storedchallengeMode` and
 * `hmacchallengeMode` really are mixed-case in the firmware's client, and
 * lookups are exact-match.
 */
const FIELD = {
  LABEL: 1,
  USERNAME: 2,
  NEXTKEY2: 3,
  DELAY2: 4,
  PASSWORD: 5,
  NEXTKEY3: 6,
  DELAY3: 7,
  TFATYPE: 8,
  TFAUSERNAME: 9,
  YUBIAUTH: 10,
  LOCKOUT: 11,
  WIPEMODE: 12,
  TYPESPEED: 13,
  KBDLAYOUT: 14,
  URL: 15,
  NEXTKEY1: 16,
  DELAY1: 17,
  NEXTKEY4: 18,
  NEXTKEY5: 19,
  BACKUPKEYMODE: 20,
  derivedchallengeMode: 21,
  storedchallengeMode: 22,
  SECPROFILEMODE: 23,
  LEDBRIGHTNESS: 24,
  LOCKBUTTON: 25,
  hmacchallengeMode: 26,
  modkeyMode: 27,
  YUBIANDHMAC: 29,
};

/* Upper-case aliases so callers need not know which three are odd. */
const FIELD_ALIASES = {
  DERIVEDCHALLENGEMODE: FIELD.derivedchallengeMode,
  STOREDCHALLENGEMODE: FIELD.storedchallengeMode,
  HMACCHALLENGEMODE: FIELD.hmacchallengeMode,
  MODKEYMODE: FIELD.modkeyMode,
};

/**
 * Key-type modifiers, OR'd into the type byte of OKSETPRIV.
 * From OnlyKeyComm.js `keyTypeModifiers`.
 */
const KEY_TYPE_MODIFIER = {
  Backup: 0x80,
  Signature: 0x40,
  Decryption: 0x20,
};

/** onlykey-3rd-party.js: the curve a derived key uses. */
const KEYTYPE = {
  NACL: 0,
  P256R1: 1,
  P256K1: 2,
  CURVE25519: 3,
};

/** onlykey-3rd-party.js: what to do with the derived key. */
const KEYACTION = {
  DERIVE_PUBLIC_KEY: 1,
  DERIVE_SHARED_SECRET: 2,
  DERIVE_PUBLIC_KEY_REQ_PRESS: 3,
  DERIVE_SHARED_SECRET_REQ_PRESS: 4,
};

/**
 * usb_desc.h interface numbers. The firmware routes replies by these, so they
 * are protocol rather than an implementation detail.
 *
 * SEREMU exists only in DEBUG firmware builds - a production device enumerates
 * three interfaces, not four.
 */
/**
 * usb_desc.h interface numbers. The firmware routes replies by these, so they
 * are protocol, not an implementation detail.
 *
 * SEREMU is the debug console and exists only on a DEBUG build - such a device
 * enumerates four interfaces, a production one three. That is what makes the
 * build detectable rather than merely assumed.
 *
 * The per-value casts are so the generated .d.ts says `KEYBOARD: 0` rather than
 * `KEYBOARD: number`. Without them every consumer's interface argument widens to
 * `number` and passing 7 typechecks.
 *
 * @typedef {0|1|2|3} Iface
 */
const IFACE = {
  KEYBOARD: /** @type {0} */ (0),
  FIDO: /** @type {1} */ (1),
  VENDOR: /** @type {2} */ (2),
  SEREMU: /** @type {3} */ (3),
};

/** Resolve a message by name (either spelling) or by number. */
function messageId(msg) {
  if (typeof msg === 'number') return msg & 0xff;
  const key = String(msg).toUpperCase();
  if (key in MSG) return MSG[key];
  if (key in MSG_ALIASES) return MSG_ALIASES[key];
  throw new Error(`unknown message: ${msg}`);
}

/** Resolve a field by name (exact, then upper-case alias) or by number. */
function fieldId(field) {
  if (typeof field === 'number') return field & 0xff;
  if (field in FIELD) return FIELD[field];
  const key = String(field).toUpperCase();
  if (key in FIELD) return FIELD[key];
  if (key in FIELD_ALIASES) return FIELD_ALIASES[key];
  throw new Error(`unknown field: ${field}`);
}

module.exports = {
  MSG,
  MSG_ALIASES,
  MSG_NAMES,
  PIN_KIND,
  FIELD,
  FIELD_ALIASES,
  KEY_TYPE_MODIFIER,
  KEYTYPE,
  KEYACTION,
  IFACE,
  messageId,
  fieldId,
};
