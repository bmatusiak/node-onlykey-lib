'use strict';

const test = require('node:test');
const assert = require('node:assert');

const pin = require('../src/device/pin');
const parsers = require('../src/device/parsers');
const { MSG } = require('../src/protocol/msg');
const { toHex } = require('../src/bytes');

/* --------------------------------------------------------------- classic PIN */

test('a classic PIN is 7-10 button numbers', () => {
  // Verified empirically: 1234561 provisions a soft key and survives a restart.
  assert.deepEqual(pin.validatePin('1234561'), []);
  assert.match(pin.validatePin('123456')[0], /7-10 digits/);
  assert.match(pin.validatePin('12345612345')[0], /7-10 digits/);
});

test('a PIN digit outside the button range is refused', () => {
  // There are six buttons, so 7, 8, 9 and 0 cannot be entered at all.
  assert.match(pin.validatePin('1234567').join(' '), /button numbers/);
  assert.match(pin.validatePin('1234560').join(' '), /button numbers/);
});

test('a confirmation mismatch is reported', () => {
  assert.deepEqual(pin.validatePin('1234561', { confirm: '1234561' }), []);
  assert.match(pin.validatePin('1234561', { confirm: '1234562' }).join(' '), /do not match/);
});

test('the PIN sequence is six transitions, four of them sends', () => {
  // The same message id drives every one; meaning depends on position, which
  // is why each step waits for its prompt rather than assuming it.
  assert.equal(pin.PIN_SEQUENCE.length, 6);
  assert.equal(pin.PIN_SEQUENCE.filter((s) => s.send).length, 4);
  assert.equal(pin.PIN_SEQUENCE.filter((s) => s.digits).length, 2);
  assert.deepEqual(
    pin.PIN_SEQUENCE.filter((s) => s.expect).map((s) => s.expect),
    ['enter', 'storing', 'confirm', 'matched'],
  );
});

test('each PIN kind maps to its own message', () => {
  assert.equal(pin.pinMessage('primary')[4], MSG.OKPIN);
  assert.equal(pin.pinMessage('secondary')[4], MSG.OKPINSEC);
  assert.equal(pin.pinMessage('selfDestruct')[4], MSG.OKPINSD);
  assert.throws(() => pin.pinMessage('nope'), /unknown PIN kind/);
});

test('recovery returns to the ENTER step, never the confirm step', () => {
  // Re-confirming a PIN the device already rejected cannot succeed.
  assert.equal(pin.RECOVERY_STEP[MSG.OKPIN], 'enterPrimary');
  assert.equal(pin.RECOVERY_STEP[MSG.OKPINSEC], 'enterSecondary');
  assert.equal(pin.RECOVERY_STEP[MSG.OKPINSD], 'enterSelfDestruct');
});

test('the digit acknowledgement is counted, not matched once', () => {
  // The firmware prints one per digit, so a first-match wait returns after
  // digit one and the rest of the burst is still in flight.
  const output = 'password appended with 1\npassword appended with 2\n';
  assert.equal(output.match(pin.DIGIT_ACK).length, 2);
});

/* ------------------------------------------------------------------ DUO PIN */

test('DUO digits are ASCII, 48 + the digit', () => {
  const bytes = pin.encodeDuoPins(['1234567']);
  assert.deepEqual(Array.from(bytes), [49, 50, 51, 52, 53, 54, 55]);
});

test('a single DUO PIN is unpadded - that is the unlock path', () => {
  // The length asymmetry is what distinguishes unlocking from provisioning at
  // the buffer level.
  assert.equal(pin.encodeDuoPins(['1234567']).length, 7);
});

test('multiple DUO PINs each take a fixed 16-byte slot', () => {
  const bytes = pin.encodeDuoPins(['1234567', '', '7654321']);
  assert.equal(bytes.length, 48);
  assert.equal(bytes[0], 49, 'first PIN at 0');
  assert.equal(bytes[16], 0, 'the absent middle PIN is zeroed');
  assert.equal(bytes[32], 55, 'third PIN at 32');
});

test('the set sentinel is a leading FF that shifts every slot', () => {
  // Same message id for set and verify; this byte is the only difference.
  const verify = pin.encodeDuoPins(['1234567', '', '7654321']);
  const set = pin.encodeDuoPins(['1234567', '', '7654321'], { set: true });
  assert.equal(set.length, verify.length + 1);
  assert.equal(set[0], 0xff);
  assert.equal(set[1], 49, 'the first PIN now starts at offset 1');
  assert.equal(set[33], 55, 'and the third at 33');
});

test('a non-numeral DUO PIN is refused rather than encoded as NaN', () => {
  assert.throws(() => pin.encodeDuoPins(['12a4567']), /numerals/);
});

test('DUO validation enforces a maximum the original only had in HTML', () => {
  // Each PIN has a 16-byte slot, so a 17th character overflows into the next.
  const long = '1'.repeat(17);
  const out = pin.validateDuoPins({ pin: long, pinConfirm: long });
  assert.match(out.primary.join(' '), /at most 16/);
});

test('the self-destruct PIN is optional but must differ when given', () => {
  const none = pin.validateDuoPins({ pin: '1234567', pinConfirm: '1234567' });
  assert.equal(none.ok, true);

  const same = pin.validateDuoPins({
    pin: '1234567', pinConfirm: '1234567',
    selfDestruct: '1234567', selfDestructConfirm: '1234567',
  });
  assert.match(same.selfDestruct.join(' '), /cannot match the primary/);
});

test('the DUO PIN message is OKPIN in both directions', () => {
  const frame = pin.duoPinMessage(['1234567'], { set: true });
  assert.equal(frame[4], MSG.OKPIN);
  assert.equal(frame[5], 0xff, 'the set sentinel');
});

/* ----------------------------------------------------------------- parsers */

const BACKUP = [
  '-----BEGIN ONLYKEY BACKUP-----',
  'AAEC',        // 00 01 02
  'AwQF',        // 03 04 05
  '-----END ONLYKEY BACKUP-----',
].join('\n');

test('a backup becomes ONE continuous hex stream', () => {
  assert.equal(parsers.parseBackup(BACKUP), '000102030405');
});

test('markers and the digest line are excluded from the data', () => {
  // The test is a '--' prefix, not an exact match, so the trailing digest line
  // is skipped too.
  assert.equal(parsers.isMarker('--abc123'), true);
  assert.equal(parsers.isMarker('-----BEGIN ONLYKEY BACKUP-----'), true);
  assert.equal(parsers.isMarker('AAEC'), false);
});

test('the backup digest is a rolling chain, so reordering is caught', () => {
  const { sha256 } = require('@noble/hashes/sha2.js');
  const { concat } = require('../src/bytes');

  const l1 = Uint8Array.from([0, 1, 2]);
  const l2 = Uint8Array.from([3, 4, 5]);
  const chain = sha256(concat([sha256(concat([new Uint8Array(32), l1])), l2]));

  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const file = [
    '-----BEGIN ONLYKEY BACKUP-----',
    'AAEC', 'AwQF',
    '-----END ONLYKEY BACKUP-----',
    `--${b64(chain)}`,
  ].join('\n');

  const out = parsers.verifyBackup(file);
  assert.equal(out.ok, true, 'the chain matched');
  assert.equal(out.digest, toHex(chain));

  // Swapping two lines keeps every byte and still fails - which a hash over
  // the concatenation would not.
  const swapped = file.replace('AAEC\nAwQF', 'AwQF\nAAEC');
  assert.equal(parsers.verifyBackup(swapped).ok, false);
});

test('a backup with no digest line reports that rather than passing', () => {
  const out = parsers.verifyBackup(BACKUP);
  assert.equal(out.ok, false);
  assert.match(out.reason, /no digest/);
});

test('firmware blocks stay SEPARATE, unlike a backup', () => {
  // Concatenating them would destroy the block structure the loader needs.
  const fw = [
    '-----BEGIN SIGNED FIRMWARE-----',
    'aabbcc', 'ddeeff',
    '-----END SIGNED FIRMWARE-----',
  ].join('\n');
  assert.deepEqual(parsers.parseFirmware(fw), ['aabbcc', 'ddeeff']);
});

test('a backup fed to the firmware parser is caught, not mangled', () => {
  // Base64 is not hex, and the two file formats look alike enough to confuse.
  assert.throws(() => parsers.parseFirmware(BACKUP), /may be a backup/);
});

test('an odd-length firmware block is refused', () => {
  const fw = '-----BEGIN SIGNED FIRMWARE-----\nabc\n-----END-----';
  assert.throws(() => parsers.parseFirmware(fw), /odd length/);
});

test('a firmware block exposes its signature layout', () => {
  const block = 'a'.repeat(64) + '1' + 'b'.repeat(64);
  const out = parsers.describeFirmwareBlock(block);
  assert.equal(out.signature.length, 64);
  assert.equal(out.info, '1');
  assert.equal(out.nextSignature.length, 64);
});

test('the bootloader kick is the literal 1234', () => {
  assert.equal(parsers.BOOTLOADER_KICK, '1234');
});

/* ------------------------------------------------------- the rollover */

test('padding to the rollover, because the buffer cannot be cleared', () => {
  // pass_keypress starts at 1 and the tenth press resets it. Six digits in
  // means four more to go.
  assert.deepEqual(pin.rolloverPresses(6), [6, 6, 6, 6]);
  assert.deepEqual(pin.rolloverPresses(1), [6, 6, 6, 6, 6, 6, 6, 6, 6]);
  assert.deepEqual(pin.rolloverPresses(9), [6]);
});

test('nothing to do for an empty buffer or one already at the rollover', () => {
  // Padding an empty buffer would ADD nine digits and cost a session attempt
  // for no reason, which is worse than doing nothing.
  assert.deepEqual(pin.rolloverPresses(0), []);
  assert.deepEqual(pin.rolloverPresses(10), []);
  assert.deepEqual(pin.rolloverPresses(11), []);
});

test('padding with button 3 is refused, because 3 is the lock gesture', () => {
  // A press is a press. Padding with 3 would lock the key and restart it - the
  // opposite of clearing a buffer, and irreversible in the sense that the
  // session is gone.
  assert.throws(() => pin.rolloverPresses(6, {button: 3}), /lock gesture/);
});

test('a different pad button is allowed, for a device with fewer buttons', () => {
  assert.deepEqual(pin.rolloverPresses(8, {button: 1}), [1, 1]);
});
