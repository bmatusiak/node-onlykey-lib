/*
 * slotConfig - the field table and its encodings.
 *
 * The encodings here are not a design; they are what the firmware already
 * parses, arrived at by whatever each value happened to be in a DOM node.
 * Changing one is a silent protocol change, so each is pinned - and two of
 * them are pinned against OnlyKey-App's OWN end-to-end fixture
 * (test/configure-slot-test.js:85-103), which asserts the exact bytes a real
 * device was sent.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const slotConfig = require('../src/device/slotConfig');
const { FIELD, MSG } = require('../src/protocol/msg');
const { toHex, toLatin1, fromLatin1 } = require('../src/bytes');

/** The meaningful prefix of a frame, before the zero padding. */
function head(frame, len) {
  return toHex(frame.subarray(0, len));
}

/* ---------------------------------------------------- the app's own fixture */

test('a password write matches OnlyKey-App’s end-to-end fixture', () => {
  /*
   * configure-slot-test.js:85-95 expects exactly:
   *   [255,255,255,255, SETSLOT=230, slot=1, field=5 (PASSWORD), "FooPassword"]
   * That fixture ran against a real device, so it is the strongest evidence
   * available for the frame layout.
   */
  const [write] = slotConfig.planSlotWrites({ password: 'FooPassword' }, 1);

  assert.equal(write.field, FIELD.PASSWORD);
  assert.equal(
    head(write.frame, 7 + 'FooPassword'.length),
    toHex(fromLatin1('\xff\xff\xff\xff\xe6\x01\x05FooPassword')),
  );
});

test('a NEXTKEY write sends the ASCII DIGIT, matching the same fixture', () => {
  /*
   * configure-slot-test.js:103 expects '\xff\xff\xff\xff\xe6\x01\x062' - the
   * trailing byte is 0x32, the character '2', not the number 2.
   *
   * This is the single easiest thing to "clean up" in this module and the
   * consequence is invisible: the firmware would read 0x02 as a keypress that
   * was never configured, and the slot would type the wrong thing forever.
   */
  const [write] = slotConfig.planSlotWrites({ nextKey3: '2' }, 1);

  assert.equal(write.field, FIELD.NEXTKEY3);
  assert.equal(head(write.frame, 8), toHex(fromLatin1('\xff\xff\xff\xff\xe6\x01\x062')));
  assert.equal(write.data[0], 0x32, 'the character, not the value');
  assert.notEqual(write.data[0], 2);
});

/* ------------------------------------------------------------------ ordering */

test('fields are written in the order the device expects', () => {
  // The order is data, not decoration - see the dependency asserted below.
  const names = slotConfig.SLOT_FIELDS.map((f) => f.name);
  assert.deepEqual(names.slice(0, 6), [
    'label', 'url', 'nextKey4', 'nextKey1', 'delay1', 'username',
  ]);
  assert.equal(names.length, 16);
});

test('the TFA type is written BEFORE the seed it describes', () => {
  /*
   * The device has to know which kind of second factor it is being given
   * before it is given one. The original arranges this with a flag set on a
   * previous scan; here the order does it, which is one fewer thing to keep in
   * step.
   */
  const writes = slotConfig.planSlotWrites(
    slotConfig.totpFields('JBSWY3DPEHPK3PXP'),
    3,
  );
  assert.deepEqual(writes.map((w) => w.name), ['tfaType', 'totpKey']);
  assert.equal(toLatin1(writes[0].data), 'googleAuthOtp');
});

test('a plan contains only the fields that were supplied', () => {
  const writes = slotConfig.planSlotWrites({ label: 'GitHub', password: 'hunter2' }, 2);
  assert.deepEqual(writes.map((w) => w.name), ['label', 'password']);
});

test('an empty string is written; an absent key is left alone', () => {
  // Blanking a field and not touching it are different operations, and the
  // difference is how a field is cleared without wiping the whole slot.
  assert.equal(slotConfig.planSlotWrites({ label: '' }, 1).length, 1);
  assert.equal(slotConfig.planSlotWrites({ label: undefined }, 1).length, 0);
  assert.equal(slotConfig.planSlotWrites({}, 1).length, 0);
});

/* ----------------------------------------------------------------- encodings */

test('whitespace is kept on credentials and trimmed elsewhere', () => {
  /*
   * Asymmetric on purpose (OnlyKeyWizard.js:991-997). A leading or trailing
   * space can be significant in a password or a username; trimming one changes
   * a stored credential and the user cannot see why login fails.
   */
  const [password] = slotConfig.planSlotWrites({ password: ' spaced ' }, 1);
  assert.equal(toLatin1(password.data), ' spaced ', 'password keeps its spaces');

  const [label] = slotConfig.planSlotWrites({ label: '  GitHub  ' }, 1);
  assert.equal(toLatin1(label.data), 'GitHub', 'label is trimmed');
});

test('type speed is a RAW byte, unlike every other numeric field', () => {
  // The only field the original runs through parseInt, so the only one that
  // reached the device as a number.
  const [write] = slotConfig.planSlotWrites({ typeSpeed: 4 }, 1);
  assert.equal(write.data[0], 4, 'the value, not the character');
  assert.notEqual(write.data[0], 0x34);
});

test('an empty type speed is refused rather than silently writing 0', () => {
  /*
   * The original does `parseInt('')` -> NaN, and its guard is
   * `contents < 0 || contents > 255`, which is FALSE for NaN on both sides. So
   * `bytes[cursor++] = NaN` coerced to 0 and the slot was set to the slowest
   * possible typing speed by ticking a box and leaving the field blank.
   */
  assert.throws(() => slotConfig.planSlotWrites({ typeSpeed: '' }, 1), /must be a byte 0-255/);
  assert.throws(() => slotConfig.planSlotWrites({ typeSpeed: 'fast' }, 1), /must be a byte 0-255/);
  assert.throws(() => slotConfig.planSlotWrites({ typeSpeed: 300 }, 1), /must be a byte 0-255/);
});

test('a delay must be a single digit', () => {
  assert.equal(slotConfig.planSlotWrites({ delay1: '5' }, 1)[0].data[0], 0x35);
  assert.throws(() => slotConfig.planSlotWrites({ delay1: '12' }, 1), /single digit/);
});

test('an over-long text field is refused with both lengths', () => {
  /*
   * The original has no length check at all - sendMessage stops at the end of
   * the buffer - so a 60-character password was stored truncated and the user
   * was shown success. The HTML maxlength never ran: the submit button is
   * type="button" with an onclick, so constraint validation never fires.
   */
  assert.throws(
    () => slotConfig.planSlotWrites({ label: 'x'.repeat(20) }, 1),
    /label is 20 characters, the device stores 16/,
  );
  assert.throws(
    () => slotConfig.planSlotWrites({ password: 'x'.repeat(60) }, 1),
    /the device stores 56/,
  );
});

test('nothing may exceed what one report can carry', () => {
  // Header, message id, slot and field take 7 of the 64 bytes.
  assert.equal(slotConfig.MAX_CONTENT, 57);
  assert.throws(
    () => slotConfig.planSlotWrites({ yubikey: new Uint8Array(58) }, 1),
    /one report holds 57/,
  );
});

/* ------------------------------------------------------------------- wiping */

test('wiping the whole slot omits the field byte entirely', () => {
  /*
   * That omission IS the difference between "wipe this field" and "wipe this
   * slot" - there is no separate message id.
   */
  const all = slotConfig.wipeMessage(3);
  assert.equal(head(all, 6), toHex(Uint8Array.of(0xff, 0xff, 0xff, 0xff, MSG.OKWIPESLOT, 3)));
  assert.equal(all[6], 0, 'no field byte, just padding');

  const one = slotConfig.wipeMessage(3, 'password');
  assert.equal(one[6], FIELD.PASSWORD);
});

test('wiping an unknown field is refused, not sent as undefined', () => {
  assert.throws(() => slotConfig.wipeMessage(1, 'nope'), /unknown slot field/);
});

/* ------------------------------------------------------------ second factors */

test('a TOTP seed is decoded from base32 and padding does not corrupt it', () => {
  /*
   * The original's base32tohex does indexOf on '=' , gets -1, and splices
   * "-1" into the bit string. A padded secret produced a silently wrong seed
   * and every generated code was rejected.
   */
  const unpadded = slotConfig.planSlotWrites(slotConfig.totpFields('JBSWY3DP'), 1);
  const padded = slotConfig.planSlotWrites(slotConfig.totpFields('JBSWY3DP===='), 1);
  assert.equal(toHex(padded[1].data), toHex(unpadded[1].data));
  assert.equal(toHex(unpadded[1].data), '48656c6c6f');  // "Hello"
});

test('a Yubikey credential rides the YUBIAUTH field with its type', () => {
  const writes = slotConfig.planSlotWrites(
    slotConfig.yubikeyFields({
      publicId: 'cccccccccccb',
      privateId: '010203040506',
      secretKey: '00'.repeat(16),
    }),
    5,
  );
  assert.deepEqual(writes.map((w) => w.name), ['tfaType', 'yubikey']);
  assert.equal(toLatin1(writes[0].data), 'YubikeyOtp');
  assert.equal(writes[1].field, FIELD.YUBIAUTH);
  assert.equal(writes[1].data.length, 6 + 6 + 16);
});
