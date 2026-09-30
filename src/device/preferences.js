/**
 * The Preferences and Advanced surface, as data - and the per-firmware SHAPE
 * of each row, as a pure function of capabilities.
 *
 * ## Why this lives here and not in the device plugin
 *
 * It did live there, inside setup(), reachable only as device.preferences()
 * on a composed stack. So a GUI that wanted to draw the settings screen before
 * connecting, or a test that wanted the rows for a given firmware, had to
 * compose a whole plugin stack to read a table - and setPreference validated
 * against the STATIC row while preferences() handed out the version-shaped
 * one: on 3.0.5+ `derivedChallengeMode` was drawn as 0/1 and still accepted
 * 2..255 (bitmask 8 included), which the enum firmware refuses (G-4 of the G1
 * audit). One function now answers "what is this row on this firmware" for
 * both the screen and the write.
 *
 * Pure data and one require, so it stays browser/Hermes-clean like the rest
 * of src/.
 */
'use strict';

const { FIELD } = require('../protocol/msg');

/*
 * The whole Preferences and Advanced surface, as data.
 *
 * Every one of these is the SAME operation: OKSETSLOT on the global slot
 * ('XX', slot 0) carrying one field id and one byte. The desktop app spells
 * that out as twelve near-identical methods (OnlyKeyDevice.ts:1089-1160); as a
 * table it is one method, and a settings screen can render itself from it
 * rather than hard-coding the same list a third time.
 *
 * `requires` IS NOT DECORATION. set_slot gates these differently field by
 * field, and the difference is invisible until a write is silently refused:
 *
 *   always     accepted whenever the device is unlocked and initialized
 *   configMode needs config mode, else "Error not in config mode"
 *              (okcore.cpp cases 21, 22, 26, 27)
 *   firstUse   only on a device that has not completed setup - !initcheck -
 *              and refused for ever after (case 23)
 *
 * Two are worse than either: WIPEMODE and BACKUPKEYMODE take their DANGEROUS
 * value in config mode and their safe value only on first use, so which rule
 * applies depends on what you are setting. `requires` names the stricter of
 * the two and `note` says so.
 *
 * ## `oneWay` - this write CANNOT BE TAKEN BACK
 *
 * A property of the FIRMWARE, so it belongs here rather than in whichever GUI
 * happens to notice. ok-rn held the list privately for a while; the nw desktop
 * app and the CLI can write all three fields and would each have had to
 * rediscover the hazard, and the next irreversible field would have been added
 * to the table and adopted silently by every screen that renders from it.
 *
 *   webcryptPolicy  the FIRST write ends the legacy field-21 inheritance
 *                   permanently, in either direction, including a write of 0
 *   backupKeyMode   locking it (1) cannot be undone
 *   wipeMode        on a provisioned key only the destructive value is settable
 *                   at all - the gentler ones need first use - so it is one-way
 *                   in practice
 *
 * WHICH settings are irreversible is protocol. WHERE a GUI puts them and how
 * hard it makes them to trigger is that GUI's business: ok-rn moves them to a
 * separate screen behind a typed word, a CLI might simply require a flag.
 */
/*
 * NAMED FOR WHAT THEY GOVERN, not for the mechanism.
 *
 * These labels are what a GUI shows, so they are the user's vocabulary rather
 * than the firmware's. "Derived key challenge" describes the byte; "SSH/GPG
 * derived keys" describes the thing the person is deciding about, and the
 * choice of challenge-or-press is the row's VALUE, not its name.
 *
 * Fields 21, 22 and 30 all answer "how do you approve this". Field 31 answers
 * "is this allowed at all", which is why it reads as a permission and not as a
 * confirmation - and why its own screen, not this table, is where it is set.
 *
 * THE WORDS ARE THE DESKTOP APP'S (OnlyKey-App app/app.html), on purpose. A
 * person who has used the desktop App should meet the same row names and the
 * same choice sentences on every GUI - "follow the user feel of the original
 * apps" - and a GUI that renders this table inherits them without having to
 * copy them. Where the desktop and the firmware disagree the FIRMWARE decides
 * the value and the desktop only supplies the sentence (field 26 below).
 *
 * ## `section` - rows the desktop App shows as ONE panel
 *
 * Fields 21, 22 and 30 sit together under "User Input Modes" there, saved by
 * one button, because they are one decision made three times: how each kind
 * of key is approved. That grouping is the user's model, so it is data here
 * and not a list each GUI keeps privately - the same argument as `oneWay`. A
 * row without `section` is ungrouped; a GUI files it by its own rules.
 */
/*
 * The desktop App's three choice sentences (app.html:767-846), named once so
 * that the rows below cannot drift apart from each other - they already did
 * once, when the same wrong note about "No confirmation" was written twice.
 */
const INPUT_CHOICE = {
  challenge: 'Challenge Code (enter 3 digits)',
  press: 'Button Press (tap any button)',
  none: 'None (no confirmation) - for unattended agents',
};
const USER_INPUT_MODES = 'User Input Modes';
const PREFERENCES = {
  lockout:              { field: FIELD.LOCKOUT, max: 255, unit: 'minutes', label: 'Idle lockout', requires: 'always' },
  typeSpeed:            { field: FIELD.TYPESPEED, max: 10, label: 'Typing speed', requires: 'always' },
  keyboardLayout:       { field: FIELD.KBDLAYOUT, max: 255, label: 'Keyboard layout', requires: 'always' },
  ledBrightness:        { field: FIELD.LEDBRIGHTNESS, max: 255, label: 'LED brightness', requires: 'always' },
  lockButton:           { field: FIELD.LOCKBUTTON, max: 6, label: 'Lock button', requires: 'always' },

  /*
   * A BITMASK, not a flag. It was capped at 1 here, which made the one value
   * that matters unreachable: the firmware tests BIT 3 of this byte
   * (ok_extension.cpp:262, `is_bit_set(mode, 3)` = value 8) before it will
   * derive a per-site key without a touch, and setPreference refuses
   * anything above `max`. Its own setter takes the raw byte with no range
   * check at all (okcore.cpp:2021).
   *
   * The two bits mean different things on different paths, which is why this
   * cannot be presented as one on/off:
   *
   *   bit 0 (1)  SSH/GPG derived keys (slots above 200) ask for a BUTTON
   *              PRESS instead of the three-digit challenge code. Set, the
   *              firmware takes CRYPTO_AUTH = 3, the press path; clear, it
   *              hashes the request into a challenge code to type
   *              (libraries 20e1623 okcore.cpp:7128). This was labelled the
   *              other way round - "three-button challenge" - which offered
   *              a user the opposite of what the bit does. Same sense as the
   *              3.0.5 enum's 1 = press, so the meaning did not flip there;
   *              only the width did.
   *   bit 3 (8)  FIDO2 derives are allowed WITHOUT a touch; clear, they are
   *              refused as CTAP2_ERR_EXTENSION_NOT_SUPPORTED, which names
   *              the wrong cause entirely
   *              (FINDING-a-preference-bit-masquerades-as-an-unsupported-feature.md)
   */
  derivedChallengeMode: {
    field: FIELD.derivedchallengeMode,
    max: 255,
    label: 'SSH/GPG derived keys',
    requires: 'configMode',
    section: USER_INPUT_MODES,
    bits: {
      0: 'Button Press (tap any button) instead of the Challenge Code',
      3: 'Allow per-site derived keys without a touch',
    },
    note: 'A bitmask. Bit 3 (value 8) is what lets a derived key be produced without pressing a button; without it the device answers "extension not supported", which is not what it means.',
  },

  /*
   * Here, between 21 and 30, because that is the desktop App's order inside
   * "User Input Modes" and a GUI draws a section in table order.
   */
  storedChallengeMode:  { field: FIELD.storedchallengeMode, max: 1, label: 'Stored keys (PGP, SSH, RSA and ECC slots)', requires: 'configMode', section: USER_INPUT_MODES },

  /*
   * FIRMWARE 3.0.5 REINTERPRETS FIELD 21 ABOVE, and this field replaces it for
   * the derive path.
   *
   * From 3.0.5 fields 21, 22 and 30 are a 0/1/2 ENUM, not bitmasks, and
   * set_slot() refuses anything above 2 with "Error invalid user input mode" -
   * so the value 8 documented above stops working entirely. It is left as it is
   * because every pinned release before 3.0.5 still wants it.
   *
   * And 21 is the wrong byte for the web-and-agent derive in any case:
   * okcore_user_input_mode_for_slot() routes slot 128 straight to field 30, and
   * web_agent_derive_gate() reads okcore_web_agent_derive_mode() directly.
   *
   * THIS SETTING GOVERNS THE BROWSER. A web app reaches only the FIDO
   * interface, so it can neither read nor write this - the GUI that sets it is
   * one with VENDOR (desktop, react-native, CLI), on the browser's behalf.
   *
   * "NONE" IS ACCEPTED ON EVERY BUILD. set_slot case 30 checks only that the
   * value is 0-2 (libraries 213e670 okcore.cpp:1834-1850); there is no
   * OK_ALLOW_NO_PRESS test on this field, unlike 21 and 22. This note used to
   * say production firmware refuses it - that was 21 and 22's rule copied onto
   * the one field it does not apply to, and it would have hidden from a user a
   * choice the desktop App offers and the key takes.
   *
   * THE ROW EXISTS ONLY ON THE ENUM LINE (ENUM_ONLY_PREFERENCES), so this IS
   * its 3.0.5 shape and it has no entry in USER_INPUT_ENUM_ROWS below: an
   * overlay repeating it is how the wrong note came to be written twice.
   */
  webAgentDeriveMode: {
    field: FIELD.webAgentDeriveMode,
    max: 2,
    label: 'Web and agent derived keys',
    requires: 'configMode',
    section: USER_INPUT_MODES,
    choices: {
      0: INPUT_CHOICE.challenge,
      1: INPUT_CHOICE.press,
      2: INPUT_CHOICE.none,
    },
    note: 'How you approve a key derived on demand from a label, shared by the OnlyKey web app and by local agents over USB (onlykey-agent, python-onlykey, age): a shared-secret derive or a derived decapsulation. A public-key derive is never gated. It never changes WHICH key is derived, only how you authorise it, so anything already encrypted to a label still decrypts. "None" applies over USB AND to the web app: either can then derive and decrypt silently whenever the key is unlocked. A new key starts on Button Press.',
  },
  /*
   * FIELD 31 - what the browser may DO, as against field 30's how it is
   * confirmed. Two bytes on purpose; see FIELD.webcryptPolicy.
   *
   * IT IS A ONE-WAY LATCH, and that makes it unlike every other row here.
   * While unwritten the disable bit is inherited from legacy field 21 bit 1,
   * and the FIRST write of this byte ends that inheritance - it also becomes
   * the marker deciding whether a 2 in field 21 means the enum's "no press" or
   * the legacy bitfield's "disable extension". So writing it AT ALL, even to
   * 0, changes how field 21 is read afterwards, and only wiping the device
   * puts it back. "Unwritten" is blank EEPROM - 0xFF new, 0x00 after a wipe:
   * the firmware stores every write as value | OKWC_WRITTEN (0x80), so a
   * written 0 is 0x80 on flash and still means "derived keys only"
   * (libraries 6546199; okcore.h OKWC_IS_WRITTEN, release 3.1.0).
   *
   * Consequences a GUI must respect: never write this as part of a "restore
   * defaults" or a save-everything, and never write it to prove a form
   * round-trips. Only when the user asked for this specific change.
   *
   * ABSENT FROM THE BACKUP BLOB entirely, so a restore silently drops the
   * policy back to OKWC_UNSET and re-enables the legacy inheritance - unlike
   * field 30, which does appear there when non-zero.
   *
   * Undefined bits are REJECTED, not masked ("Error invalid webcrypt policy",
   * okcore.cpp:2117), so max is the valid mask rather than 255.
   */
  webcryptPolicy: {
    field: FIELD.webcryptPolicy,
    max: 3,
    /*
     * The desktop App's panel title and checkbox sentences (app.html:849-877).
     * "Webcrypt" is the OnlyKey web app's own name, so it names the thing the
     * user knows rather than the transport ("browser", "FIDO2") it rides on.
     * No `section`: the desktop gives it its own panel and its own Save, and
     * being oneWay it lives apart on every GUI anyway.
     */
    label: 'Webcrypt Access',
    requires: 'configMode',
    oneWay: true,
    bits: {
      0: 'Allow Webcrypt to use my stored keys (PGP)',
      1: 'Turn off Webcrypt entirely',
    },
    /*
     * WHAT THE KEY DOES BEFORE THIS IS EVER WRITTEN - which is every key
     * upgraded from v3.0.4, and every new one. okcore_webcrypt_policy()
     * (libraries b412e78, okcore.cpp:6187) answers an unwritten byte as v3.0.4
     * behaved: stored keys ALLOWED (bit 0), and the extension-off bit
     * inherited from legacy field 21 bit 1.
     *
     * A GUI must start its form HERE, not at 0. Starting at 0 means saving an
     * untouched form writes 0 - "derived keys only" - which turns web PGP OFF
     * on a key that had it on, and this field is one-way. 0c-coder's
     * OnlyKey-App fixed exactly that in 146e585 ("stored-key box starts
     * ticked"). Bit 1 cannot be known: field 21 is write-only from here, so
     * it starts off, and a key that had the extension turned off the old way
     * would have it turned back on by a save - the note says so.
     *
     * An earlier version of the note below said "stored keys no". That was
     * wrong for 3.0.5 and is what this corrects.
     */
    unwritten: 1,
    note: 'Governs the BROWSER, which cannot set it itself - a web app reaches only the FIDO interface. Until it is first written the key behaves as v3.0.4 did: derived keys yes, stored keys (PGP) YES, and the extension off only if the old SSH/GPG setting turned it off. Writing it once permanently ends that inheritance - leaving bit 0 off turns web PGP off - so set it only when you mean to.',
  },
  /* Before field 26, as the desktop App lists them (app.html:649-691). */
  modKeyMode:           { field: FIELD.modkeyMode, max: 1, label: 'Sysadmin mode', requires: 'configMode' },

  /*
   * FIELD 26 RUNS THE OTHER WAY ROUND from 21, 22 and 30: 0 is the SAFE value.
   * 0 = a button press is required, 1 = no press (okcore.cpp:7270-7300 at
   * 3.1.0, "0 = Default physical presence required, 1 = No physical presence
   * required for HMAC"; python-onlykey's README says the same). A GUI that
   * assumes "1 = press" like its neighbours turns the press OFF.
   *
   * The desktop App asks it as a question - "Require a button press for HMAC
   * challenge-response operations?" Yes/No - and wires those two buttons
   * INVERTED (Yes writes 1). That is a held finding against the desktop, not
   * a rule: the firmware decides the value, so here press-required is 0. The
   * choices are the desktop's own "Button Press (tap any button)" sentence and
   * its negation, because a bare Yes/No needs the question beside it to mean
   * anything and a GUI rendering a list of choices will not carry it; the
   * question is kept in the note.
   *
   * 129 and 130 are also accepted - no press for ONE of the two legacy slots
   * (the Authlite setup path writes them, okcore.cpp:7133-7155) - and left out:
   * they are a per-slot exception that slot setup writes, not a preference a
   * person picks, and offering them would ask the user to know slot numbers.
   * `max` stays 1 for that reason; a key found at 129/130 is not readable
   * from here anyway.
   *
   * ONLY the legacy HMAC slots (0x30/0x38, the two challenge-response slots)
   * read this. Per-slot HMAC on slots 1-24 carries its own setting and
   * ignores it, which is why the note says so.
   *
   * NO `section`, and not "User Input Modes": the desktop App gives it a
   * panel of its own ("HMAC User Input Mode", app.html:672-691), in a
   * different place in the list, with its own button. Grouping it with
   * 21/22/30 would tell the user it is the same kind of decision; it is a
   * different device interface (the YubiKey-style challenge-response) with the
   * opposite sense. And a one-row panel IS a row: its title is this label, so
   * a `section` of the same name would only draw that heading twice. `section`
   * is for rows the desktop gathers under one heading, which this is not.
   */
  hmacChallengeMode: {
    field: FIELD.hmacchallengeMode,
    max: 1,
    label: 'HMAC User Input Mode',
    requires: 'configMode',
    choices: {
      0: INPUT_CHOICE.press,
      1: 'No button press',
    },
    note: 'Require a button press for HMAC challenge-response operations? Applies to the two legacy HMAC challenge-response slots only; an HMAC key stored in slots 1-24 has its own setting. A new key requires the press.',
  },

  /*
   * How hard a finger has to press, and the ONE preference with a floor.
   *
   * okcore.cpp:2106-2119 accepts `buffer[7] > 1 && buffer[7] <= 100` and
   * answers "Error touchsense value out of range" otherwise - so 0 and 1
   * are refused, which every other preference here would have accepted.
   * That is why `min` exists at all; the alternative was letting a caller
   * send a byte the firmware throws away and calling it a success.
   *
   * Lower is MORE sensitive (it is an offset from the measured baseline);
   * the firmware's own default lives in EEPROM and is not readable, so
   * this sets without being able to show what it is now - the same
   * limitation every preference here has.
   */
  touchSense: {
    field: FIELD.TOUCHSENSE, min: 2, max: 100, label: 'Touch sensitivity',
    requires: 'configMode',
    note: 'Lower is more sensitive. The firmware refuses anything outside 2-100.',
  },

  wipeMode: {
    field: FIELD.WIPEMODE, max: 2, label: 'Wipe mode', requires: 'configMode',
    oneWay: true,
    note: 'Full wipe (2) needs config mode; the other values can only be set '
      + 'before setup is finished.',
  },
  backupKeyMode: {
    field: FIELD.BACKUPKEYMODE, max: 1, label: 'Backup key mode', requires: 'configMode',
    oneWay: true,
    note: 'Locking it (1) needs config mode, and cannot be undone afterwards.',
  },

  /*
   * SILENT: the one preference the firmware never acknowledges. set_slot case
   * 23 stores it on first use with its hidprint COMMENTED OUT (okcore.cpp:1910
   * at release 3.1.0), refuses it afterwards with a sentence that has no
   * "Error" in front (:1912), and on a non-STD build or an unencrypted profile
   * does nothing at all (:1905, :1907). Waiting for "Success|Error" therefore
   * cost three 10 s timeouts on exactly the path it is used on - the wizard,
   * mid PIN bracket (OnlyKey-App LIB-PORT.md gap 2). setPreference sends it
   * through sendUnanswered instead: silence is taken as done, a refusal
   * (including :1912, which okmsg.errorKind reads as 'refused') throws.
   *
   * Its window is only reached after the primary PIN is set: before that the
   * dispatcher answers "Error OnlyKey must be initialized first"
   * (okcore.cpp:384), and okcore_flashset_noncehash, which the primary PIN's
   * commit calls, is what sets `initialized` (:2977) while `initcheck` stays
   * false until restart - the `!initcheck` branch at :387.
   */
  secProfileMode: {
    field: FIELD.SECPROFILEMODE, max: 2, label: 'Second profile mode', requires: 'firstUse',
    silent: true,
    note: 'Only settable before setup is finished. A provisioned key refuses it.',
  },
};

/**
 * What fields 21, 22 and 30 become at firmware 3.0.5 - applied over the rows
 * above by preferences(), never instead of them.
 *
 * An OVERLAY rather than a second table, because only the SHAPE changes:
 * the field number, the gate and the label are the same settings either way,
 * and duplicating them is how two descriptions of one byte drift apart.
 *
 * `max` drops from 255 to the largest value the firmware will take, and the
 * bitmask is replaced outright - `bits: undefined` rather than omitted,
 * because a spread leaves an untouched key in place and a stale `bits` would
 * have the screen draw toggles beside the choices.
 *
 * "NONE" IS ON FIELD 30 ONLY. Production firmware refuses 2 on 21 and 22
 * ("Error unsupported user input mode" unless built with OK_ALLOW_NO_PRESS,
 * okcore.cpp:1789-1833 at 3.1.0) and fails a stale one closed to the
 * challenge code, so offering it there could only produce an error the user
 * cannot act on - the notes say why it is missing rather than leaving it
 * silently absent. Field 30 takes 2 on every build (see its row), and its row
 * is already this shape, so it has no entry here.
 *
 * WHAT A NEW KEY STARTS ON is in each note because the key cannot report any
 * of these back: a GUI has nothing to show as "current", and the first-use
 * default (OnlyKey.ino:425-437 at 3.1.0: 21, 22 and 30 all Button Press - "no
 * challenge code required for OnlyKey Agent") is the one thing a user can be
 * told for certain. v3.0.4 does the same for 21 and 22 (OnlyKey.ino:430-433
 * at v3.0.4-prod writes 1 - bit 0, the press), so a GUI's section heading may
 * say it for every line.
 */
/**
 * Fields that DO NOT EXIST before 3.0.5, as against 21 and 22, which exist
 * everywhere and only change shape.
 *
 * v3.0.4's set_slot() has no `case 30` or `case 31` (libraries@c8804e3); both
 * fall to `default: return;` (okcore.cpp:2125) and the key sends NOTHING - no
 * error, no success. sendField() then retries into silence and the caller
 * ends with "unknown", on a write that was never going to land. Offering the
 * row at all is the bug: a v3.0.4 user saw "Browser permissions" (now
 * "Webcrypt Access") and a derive
 * mode, set them, and nothing happened.
 *
 * Gated on userInputModeEnum because that capability IS the 3.0.5 line - both
 * fields arrived with the enum (97c8353, 720abfe) - and a second capability
 * with the same bound would be two names for one fact. An unknown version
 * (locked) hides them, the same safe direction as the reshaping: a row that
 * reappears on unlock costs nothing, a write into silence costs a confused
 * user.
 */
const ENUM_ONLY_PREFERENCES = new Set(['webAgentDeriveMode', 'webcryptPolicy']);

const USER_INPUT_ENUM_ROWS = {
  derivedChallengeMode: {
    max: 1,
    bits: undefined,
    choices: { 0: INPUT_CHOICE.challenge, 1: INPUT_CHOICE.press },
    note: 'How you approve a key derived for SSH or GPG (onlykey-agent). "None" is not offered: production firmware refuses it for these keys. From firmware 3.1.0 this is one of these values, not a bitmask - the old "bit 3 for no touch" is gone, and writing 8 is refused. A new key starts on Button Press.',
  },
  storedChallengeMode: {
    max: 1,
    choices: { 0: INPUT_CHOICE.challenge, 1: INPUT_CHOICE.press },
    note: 'How you approve a key the device already holds - PGP, SSH, and the RSA and ECC slots. "None" is not offered: production firmware refuses it for these keys. A new key starts on Button Press.',
  },
};

/**
 * One row, in the shape THIS firmware reads it.
 *
 * The static row with the 3.0.5 enum overlay applied when the capabilities say
 * the fields are enums (see USER_INPUT_ENUM_ROWS for why an overlay). Unknown
 * capabilities - null, or a locked device's `version: null` - give the legacy
 * shape, the same safe direction preferences() has always taken.
 *
 * Returned for an ENUM-ONLY row on any firmware: whether to OFFER it is
 * preferenceRows()'s decision, and whether to REFUSE a write to it is
 * setPreference's; this only says what it looks like.
 *
 * @param {string} name
 * @param {object|null} [capabilities]  version.capabilities(...) or session.capabilities
 * @returns {object|null} `{ name, field, max, ... }`, or null for an unknown name
 */
function preferenceRow(name, capabilities = null) {
  if (!Object.prototype.hasOwnProperty.call(PREFERENCES, name)) return null;
  const enumModes = Boolean(capabilities && capabilities.userInputModeEnum);
  const shape = enumModes ? USER_INPUT_ENUM_ROWS[name] : null;
  return shape ? { name, ...PREFERENCES[name], ...shape } : { name, ...PREFERENCES[name] };
}

/**
 * Every row this firmware has, each in its shape - what a settings screen
 * draws. The rows that do not exist before 3.0.5 are left out unless the
 * capabilities say the enum line (ENUM_ONLY_PREFERENCES says why).
 *
 * @param {object|null} [capabilities]
 * @returns {object[]}
 */
function preferenceRows(capabilities = null) {
  const enumModes = Boolean(capabilities && capabilities.userInputModeEnum);
  return Object.keys(PREFERENCES)
    .filter((name) => enumModes || !ENUM_ONLY_PREFERENCES.has(name))
    .map((name) => preferenceRow(name, capabilities));
}

module.exports = {
  PREFERENCES,
  USER_INPUT_ENUM_ROWS,
  ENUM_ONLY_PREFERENCES,
  INPUT_CHOICE,
  USER_INPUT_MODES,
  preferenceRow,
  preferenceRows,
};
