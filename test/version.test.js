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
