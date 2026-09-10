/**
 * Version and capability detection, driven entirely by canned status lines.
 *
 * There is no device in this file on purpose. The emulator is built from
 * current firmware, so a test that needs a device can only ever prove the
 * current generation; every older branch has to be reachable from a fixture, or
 * it is in the wrong layer and will never be tested at all.
 *
 * The fixtures are real shapes, not invented ones:
 *
 *   UNLOCKEDv3.0.4-testc   what the emulator answers today
 *   UNLOCKEDv0.2-beta.8c   the exact string onlykey-api.js:167 switches on
 *   UNLOCKEDv0.2-beta.3    onlykey-testing feeds the desktop app this one
 *   UNINITIALIZED          firmware older than the version being in the string
 *
 * What these tests CANNOT do is confirm that an old device actually behaves the
 * way the branch says. That comes from OnlyKey-App and onlykey.github.io, which
 * are proven against those devices; this project has not run one. Tests that
 * pin transcribed old-firmware behaviour say so in their names.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  parseStatus, capabilities, parseRelease, stripModelSuffix, supportsFwUpdate,
  MODEL, BUILD, BREAKING_BETA_8C, PRE_VERSION_FIRMWARE,
} = require('../src/device/version');

/* -------------------------------------------------------------- the state */

test('the four state words are told apart', () => {
  assert.equal(parseStatus('UNLOCKEDv3.0.4-testc').state, 'unlocked');
  assert.equal(parseStatus('UNINITIALIZEDv3.0.4-testc').state, 'uninitialized');
  assert.equal(parseStatus('INITIALIZED').state, 'locked');
  assert.equal(parseStatus('BOOTLOADERv1').state, 'bootloader');
});

test('UNINITIALIZED is not read as INITIALIZED', () => {
  /*
   * "UNINITIALIZED" contains "INITIALIZED". A blank key read as a locked one
   * sends the user to a PIN prompt for a PIN that does not exist yet.
   */
  assert.equal(parseStatus('UNINITIALIZEDv3.0.4-testc').state, 'uninitialized');
  assert.equal(parseStatus('UNINITIALIZED').state, 'uninitialized');
});

test('the version is split off the state word, not sliced at an offset', () => {
  /*
   * python-onlykey reads okversion[19]. These two version strings are 12 and 11
   * characters, so a fixed index lands in a different place in each.
   */
  assert.equal(parseStatus('UNLOCKEDv3.0.4-testc').version, 'v3.0.4-testc');
  assert.equal(parseStatus('UNLOCKEDv0.2-beta.3').version, 'v0.2-beta.3');
  assert.equal(parseStatus('UNINITIALIZEDv3.0.4-testc').version, 'v3.0.4-testc');
});

test('trailing NULs and whitespace from a padded report are dropped', () => {
  const padded = 'UNLOCKEDv3.0.4-testc' + '\0'.repeat(44);
  assert.equal(parseStatus(padded).version, 'v3.0.4-testc');
});

test('a status arriving as report bytes parses the same as text', () => {
  const line = 'UNLOCKEDv3.0.4-testc';
  const bytes = new Uint8Array(64);
  for (let i = 0; i < line.length; i++) bytes[i] = line.charCodeAt(i);
  assert.deepEqual(parseStatus(bytes), parseStatus(line));
});

/* -------------------------------------------------------------- the model */

test('the model comes from the letter HW_MODEL appends', () => {
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodc').model, MODEL.CLASSIC);
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodp').model, MODEL.DUO);
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodn').model, MODEL.DUO);
  assert.equal(parseStatus('UNLOCKEDv2.1.0-prodo').model, MODEL.ORIGINAL);
});

test('an Original is classified, not looped on', () => {
  /*
   * The desktop app's switch has cases for n, p and c and none for o, so an
   * Original falls to a default that calls window.location.reload() - the app
   * restarts, reads the same string, and reloads again.
   */
  const info = parseStatus('UNLOCKEDv2.1.0-prodo');
  assert.equal(info.model, MODEL.ORIGINAL);
  assert.equal(capabilities(info).pollDelayMultiplier, 4);
});

test('p and n differ only in whether a PIN is set', () => {
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodp').pinSet, true);
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodn').pinSet, false);
});

test('only a DUO reports a PIN state, so everything else says null', () => {
  // false would read as "no PIN is set", which is a different claim.
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodc').pinSet, null);
  assert.equal(parseStatus('UNLOCKEDv2.1.0-prodo').pinSet, null);
});

test('firmware too old to append a letter reports an unknown model', () => {
  const info = parseStatus('UNLOCKEDv0.2-beta.3');
  assert.equal(info.model, MODEL.UNKNOWN);
  assert.equal(info.version, 'v0.2-beta.3', 'and keeps the 3 it ends with');
});

test('INITIALIZED-D is a locked DUO, INITIALIZED a locked Classic', () => {
  assert.equal(parseStatus('INITIALIZED-D').model, MODEL.DUO);
  assert.equal(parseStatus('INITIALIZED').model, MODEL.CLASSIC);
});

test('the DUO slot and profile counts follow the model', () => {
  /*
   * The library's device plugin defaulted to CLASSIC and was never told
   * otherwise, so against a DUO enumeration stopped at 12 of 24 in silence.
   */
  const duo = capabilities('UNLOCKEDv3.0.4-prodp');
  assert.equal(duo.slots, 24);
  assert.equal(duo.profiles, 4);
  assert.equal(duo.buttons, 3);

  const classic = capabilities('UNLOCKEDv3.0.4-prodc');
  assert.equal(classic.slots, 12);
  assert.equal(classic.profiles, 2);
  assert.equal(classic.buttons, 6);
});

/* -------------------------------------------------------------- the build */

test('the version keyword says which build is running', () => {
  // onlykey.h: -test when DEBUG is defined, -prod when it is not.
  assert.equal(parseStatus('UNLOCKEDv3.0.4-testc').build, BUILD.DEBUG);
  assert.equal(parseStatus('UNLOCKEDv3.0.4-prodc').build, BUILD.PRODUCTION);
});

test('a production build is known to have no serial console', () => {
  assert.equal(capabilities('UNLOCKEDv3.0.4-prodc').debugConsole, false);
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').debugConsole, true);
});

test('firmware older than the keyword reports an UNKNOWN console, not none', () => {
  /*
   * This is the distinction the whole three-valued answer exists for. Treating
   * unknown as absent would switch off console-driven PIN provisioning for
   * every old device - the exact population this work is meant to support.
   */
  assert.equal(parseStatus('UNLOCKEDv0.2-beta.8c').build, BUILD.UNKNOWN);
  assert.equal(capabilities('UNLOCKEDv0.2-beta.8c').debugConsole, null);
  assert.notEqual(capabilities('UNLOCKEDv0.2-beta.8c').debugConsole, false);
});

/* ------------------------------------------------------------ the release */

test('both shipped version shapes parse', () => {
  assert.deepEqual(parseRelease('v3.0.4-test'),
    { major: 3, minor: 0, patch: 4, prerelease: 'test' });
  assert.deepEqual(parseRelease('v0.2-beta.8'),
    { major: 0, minor: 2, patch: null, prerelease: 'beta.8' });
  assert.deepEqual(parseRelease('v1.0.0'),
    { major: 1, minor: 0, patch: 0, prerelease: null });
});

test('something that is not a version returns null rather than zeroes', () => {
  // Zeroes would compare as "very old" and silently take every legacy branch.
  assert.equal(parseRelease('BOOTLOADER'), null);
  assert.equal(parseRelease(''), null);
});

test('only a meaningful trailing letter is stripped', () => {
  assert.equal(stripModelSuffix('v3.0.4-testc'), 'v3.0.4-test');
  assert.equal(stripModelSuffix('v0.2-beta.8c'), 'v0.2-beta.8');
  assert.equal(stripModelSuffix('v0.2-beta.3'), 'v0.2-beta.3');
});

/* ------------------------------------------------------- the reply layout */

test('only v0.2-beta.8c takes the legacy OKCONNECT layout', () => {
  /*
   * Transcribed from onlykey-api.js:167, which compares the version field to
   * this exact string. The condition is "is 8c", not "older than 8c", and a
   * range comparison here would change behaviour on every older version.
   *
   * UNVERIFIED against hardware by this project.
   */
  assert.equal(capabilities('UNLOCKED' + BREAKING_BETA_8C).okconnectLayout, 'legacy');
  assert.equal(capabilities('UNLOCKEDv0.2-beta.3').okconnectLayout, 'modern');
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').okconnectLayout, 'modern');
});

/* ---------------------------------------------------- the challenge digits */

test('the challenge formula follows the model, then the version', () => {
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').challengeFormula, 'modern');
  assert.equal(capabilities('UNLOCKEDv3.0.4-prodp').challengeFormula, 'duo');
  assert.equal(capabilities('UNLOCKED' + BREAKING_BETA_8C).challengeFormula, 'legacy');
});

test('a locked DUO already picks the three-button formula', () => {
  /*
   * INITIALIZED-D carries no version, so the model is the only signal - and it
   * is enough. Showing 4, 5 or 6 to someone holding a three-button device asks
   * for a press they cannot make.
   */
  assert.equal(capabilities('INITIALIZED-D').challengeFormula, 'duo');
  assert.equal(capabilities('INITIALIZED-D').buttons, 3);
});

/* ------------------------------------------------------ the firmware updater */

test('the firmware-update test is the character test the desktop app ships', () => {
  /*
   * `version[9] != "." || version[10] > 6`. Transcribed rather than rewritten
   * as a version comparison: the character test is what has been proven
   * against the old devices.
   */
  assert.equal(supportsFwUpdate('v3.0.4-testc'), true, "index 9 is 's', not a dot");
  assert.equal(supportsFwUpdate('v0.2-beta.8c'), true, 'beta.8 is newer than beta.6');
  assert.equal(supportsFwUpdate('v0.2-beta.6'), false, 'the boundary itself is excluded');
  assert.equal(supportsFwUpdate('v0.2-beta.3'), false);
  assert.equal(supportsFwUpdate(''), false);
});

test('UNINITIALIZED with no version disables the updater and assumes a version', () => {
  /*
   * OnlyKeyComm.js:1343-1356. The version is the reference client's ASSUMPTION
   * about firmware that cannot say - carried as one, not measured.
   */
  const info = parseStatus('UNINITIALIZED');
  assert.equal(info.version, PRE_VERSION_FIRMWARE);
  assert.equal(info.fwUpdateOverUsb, false);
  assert.equal(capabilities(info).firmwareUpdateOverUsb, false);
});

test('UNINITIALIZED with a version enables it', () => {
  assert.equal(parseStatus('UNINITIALIZEDv3.0.4-testc').fwUpdateOverUsb, true);
});

/* ------------------------------------------------------------------ shape */

test('capabilities takes a raw line as readily as a parsed one', () => {
  const line = 'UNLOCKEDv3.0.4-testc';
  assert.deepEqual(capabilities(line), capabilities(parseStatus(line)));
});

test('a status nobody recognises degrades instead of throwing', () => {
  const info = parseStatus('WAT');
  assert.equal(info.state, 'unknown');
  assert.equal(info.model, MODEL.UNKNOWN);
  assert.equal(info.version, null);
  // And the capabilities are the safe modern defaults rather than an exception.
  assert.equal(capabilities(info).challengeFormula, 'modern');
  assert.equal(capabilities(info).debugConsole, null);
});

/* ------------------------------------------------- the touch-free derive */

/*
 * MEASURED against staged firmware, not transcribed. The split is one release
 * wide, and getting it wrong in either direction is expensive: too permissive
 * and the vault seals blobs on a device that cannot open them, too strict and
 * a working v2.1 key is refused a feature it has always had.
 */
test('v3.0.1 and earlier need no preference at all', () => {
  // ok_extension.cpp at a27ffa6 sets additional_data[0] for the REQ_PRESS
  // variants and carries straight on - there is no preference check anywhere.
  assert.equal(capabilities('UNLOCKEDv2.1.0-testc').touchFreeDerive, 'always');
  assert.equal(capabilities('UNLOCKEDv2.1.2-prodc').touchFreeDerive, 'always');
  assert.equal(capabilities('UNLOCKEDv3.0.0-prodc').touchFreeDerive, 'always');
  assert.equal(capabilities('UNLOCKEDv3.0.1-prodc').touchFreeDerive, 'always');
});

test('v3.0.2 added the check and reads a cache that is always stale', () => {
  // derived_key_challenge_mode is a RAM cache the raw-HID pipeline zeroes on
  // every done_process_packets(), so the FIDO2 path reads zero whatever is
  // persisted - the device refuses a preference it is holding. Measured: a
  // v3.0.2 soft key answers CTAP2_ERR_EXTENSION_NOT_SUPPORTED after being told
  // "Successfully set derived key challenge mode".
  assert.equal(capabilities('UNLOCKEDv3.0.2-testc').touchFreeDerive, 'broken');
});

test('after v3.0.2 the preference works, so it is required', () => {
  assert.equal(capabilities('UNLOCKEDv3.0.3-prodc').touchFreeDerive, 'preference');
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').touchFreeDerive, 'preference');
  assert.equal(capabilities('UNLOCKEDv3.1.0-prodc').touchFreeDerive, 'preference');
  assert.equal(capabilities('UNLOCKEDv4.0.0-prodc').touchFreeDerive, 'preference');
});

test('an unreadable version does not disable a working device', () => {
  // Old firmware and unparseable shapes both land here. Every pre-v3.0.2
  // release we have measured allows the touch-free derive, so refusing on
  // "unknown" would disable exactly the population this work exists to serve.
  assert.equal(capabilities('WAT').touchFreeDerive, 'always');
  assert.equal(capabilities('UNINITIALIZED').touchFreeDerive, 'always');
});

test('X-Wing arrived after v3.0.2, and absence is the default', () => {
  // KEYTYPE_XWING does not appear anywhere in libraries@5d7ce7a. The age file
  // format is built on it, so neither works on an older key.
  assert.equal(capabilities('UNLOCKEDv3.0.2-testc').xwingDerive, false);
  assert.equal(capabilities('UNLOCKEDv2.1.0-prodc').xwingDerive, false);
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').xwingDerive, true);
  assert.equal(capabilities('UNLOCKEDv3.1.0-prodc').xwingDerive, true);
  // Unknown defaults to absent - the opposite of touchFreeDerive, because this
  // is a feature old firmware does NOT have rather than one it does.
  assert.equal(capabilities('WAT').xwingDerive, false);
});

test('the 2.1 line blocks for a touch; the 3.0 line keeps the host informed', () => {
  // ok_extension.cpp mentions CTAP2_ERR_PROCESSING through the 3.0 line and
  // never in the 2.1 line. On the older firmware ctap_user_presence_test(5000)
  // blocks and then denies, so a host that presses only when asked never
  // presses at all.
  assert.equal(capabilities('UNLOCKEDv2.1.0-testc').presenceTest, 'blocking');
  assert.equal(capabilities('UNLOCKEDv2.1.1-prodc').presenceTest, 'blocking');
  assert.equal(capabilities('UNLOCKEDv3.0.0-prodc').presenceTest, 'keepalive');
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').presenceTest, 'keepalive');
  // Unknown is 'blocking' because pressing on a timer works on both, and
  // waiting to be asked works on only one.
  assert.equal(capabilities('WAT').presenceTest, 'blocking');
});

test('the config-mode gesture is a different button on a DUO', () => {
  // OnlyKey.ino:914 - a DUO wants button 1 held 180 main-loop iterations, a
  // classic button 6 held 72. Using the classic gesture on a DUO holds a button
  // that does something else and then waits for a lock that never comes.
  assert.deepStrictEqual(
    capabilities('UNLOCKEDv3.0.4-testp').configModeGesture, {button: 1, ticks: 180});
  assert.deepStrictEqual(
    capabilities('UNLOCKEDv3.0.4-testn').configModeGesture, {button: 1, ticks: 180});
  assert.deepStrictEqual(
    capabilities('UNLOCKEDv3.0.4-testc').configModeGesture, {button: 6, ticks: 72});
  // Unknown is a classic, which is what every release ships as.
  assert.deepStrictEqual(
    capabilities('WAT').configModeGesture, {button: 6, ticks: 72});
});

test('the backup gesture gained an upper bound in the 3.0 line', () => {
  // v2.1.x bounds it for OK_GO ONLY, so on classic hardware
  // `(duration < 126 || HW_ID!=OK_GO)` is always true and the band is open:
  //
  //     duration >= 72 && (duration < 126 || HW_ID!=OK_GO) && button == '1'
  //
  // v3.0.x bounds it on every model, because 180 became the DUO's config-mode
  // gesture on the same button:
  //
  //     duration < 180 && duration >= 72 && button == '1'
  //
  // So a hold of 200 takes a backup on a 2.1 key and TYPES A SLOT on a 3.0 one.
  assert.equal(capabilities('UNLOCKEDv2.1.1-prodc').gestures.backup.hi, null);
  assert.equal(capabilities('UNLOCKEDv2.1.0-prodc').gestures.backup.hi, null);
  assert.equal(capabilities('UNLOCKEDv3.0.2-prodc').gestures.backup.hi, 180);
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').gestures.backup.hi, 180);

  // Unknown reads as the open band, which is the safe direction: the
  // recommended hold is a backup on both lines, and inventing an upper bound
  // would only refuse a hold the device would have taken.
  assert.equal(capabilities('WAT').gestures.backup.hi, null);
});

test('the recommended hold is inside the band on BOTH lines', () => {
  // The whole reason `ticks` is published rather than left to a caller: the
  // number has to satisfy two different firmwares at once.
  for (const status of ['UNLOCKEDv2.1.1-prodc', 'UNLOCKEDv3.0.4-testc']) {
    const { backup } = capabilities(status).gestures;
    assert.ok(backup.ticks >= backup.lo, `${status}: below the floor`);
    assert.ok(backup.hi === null || backup.ticks < backup.hi, `${status}: past the ceiling`);
  }
});

test('a DUO stacks three gestures on two buttons, separated by duration', () => {
  // Button 3 at 100 cycles the profile and at 200 locks; button 1 at 100 takes
  // a backup and at 200 enters config mode, which ends only at restart. Every
  // one of those is a hold a classic reads as something else.
  const duo = capabilities('UNLOCKEDv3.0.4-testp').gestures;

  assert.deepStrictEqual(duo.cycleProfile, { button: 3, lo: 72, hi: 180, ticks: 100 });
  assert.deepStrictEqual(duo.lock, { button: 3, lo: 180, hi: null, ticks: 200 });
  assert.deepStrictEqual(duo.configMode, { button: 1, lo: 180, hi: null, ticks: 200 });
  assert.deepStrictEqual(duo.factoryDefault, { button: 2, lo: 360, hi: null, ticks: 380 });

  // The bands on button 3 abut rather than overlap - there is no hold that is
  // both, and no gap between them where nothing happens.
  assert.equal(duo.cycleProfile.hi, duo.lock.lo);

  // A classic has neither of the DUO-only ones, and locks from 72.
  const classic = capabilities('UNLOCKEDv3.0.4-testc').gestures;
  assert.equal('cycleProfile' in classic, false);
  assert.equal('factoryDefault' in classic, false);
  assert.deepStrictEqual(classic.lock, { button: 3, lo: 72, hi: null, ticks: 100 });
});

test('configModeGesture is READ OFF the band table, not restated beside it', () => {
  // Two copies of the same number is how the DUO's different gesture went
  // unnoticed in the first place.
  for (const status of ['UNLOCKEDv3.0.4-testp', 'UNLOCKEDv3.0.4-testc', 'WAT']) {
    const caps = capabilities(status);
    assert.equal(caps.configModeGesture.button, caps.gestures.configMode.button, status);
    assert.equal(caps.configModeGesture.ticks, caps.gestures.configMode.lo, status);
  }
});

test('duoSupported splits exactly where OK_GO became OK_HW_DUO', () => {
  // Measured from the pinned sources: the two constants never coexist. The 3.0
  // line replaced OK_GO outright rather than adding beside it, and the
  // firmware's own `//#define DEFINED_HWID OK_HW_DUO` override appears on the
  // same three releases and no earlier one.
  assert.equal(capabilities('UNLOCKEDv2.1.0-prodc').duoSupported, false);
  assert.equal(capabilities('UNLOCKEDv2.1.1-prodc').duoSupported, false);
  assert.equal(capabilities('UNLOCKEDv3.0.0-prodc').duoSupported, true);
  assert.equal(capabilities('UNLOCKEDv3.0.2-prodc').duoSupported, true);
  assert.equal(capabilities('UNLOCKEDv3.0.4-testc').duoSupported, true);

  // Unknown is FALSE, the opposite of touchFreeDerive's default: this is a
  // feature old firmware does not have, so guessing "present" would offer 24
  // slots on a key that has 12.
  assert.equal(capabilities('WAT').duoSupported, false);
});

test('duoSupported is about the FIRMWARE, model is about the device', () => {
  // A 3.0 build on classic hardware knows what a DUO is and is not one. Reading
  // duoSupported as "this is a DUO" would draw three buttons on a six-button key.
  const classic = capabilities('UNLOCKEDv3.0.4-testc');
  assert.equal(classic.duoSupported, true);
  assert.equal(classic.buttons, 6);
  assert.equal(classic.slots, 12);

  const duo = capabilities('UNLOCKEDv3.0.4-testp');
  assert.equal(duo.duoSupported, true);
  assert.equal(duo.buttons, 3);
  assert.equal(duo.slots, 24);
});
