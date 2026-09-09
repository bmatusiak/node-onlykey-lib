/*
 * The keystroke decoder, tested by round trip against the firmware's own
 * forward path.
 *
 * The decoder's whole claim is "this inverts what the firmware types", so the
 * test types things the way the firmware does and checks they come back. The
 * encoder below is not a convenience - it is a deliberate second
 * implementation of okemu_usb.cpp's translation, written from that file rather
 * than from keystrokes.js, so an error shared between the two would have to be
 * made twice in different words.
 *
 * That matters more here than in most modules. A decoder that is subtly wrong
 * does not throw; it hands back a password with one character changed, which
 * looks exactly like an answer.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const keystrokes = require('../src/device/keystrokes');
const { LAYOUTS } = require('../src/device/keylayouts.data');

const { MOD } = keystrokes;

/* ------------------------------------------------------------ the firmware */

/**
 * One character as the firmware puts it on the wire.
 *
 * Mirrors okemu_usb.cpp: usb_keyboard_write_unicode() looks the code point up
 * in keycodes_ascii[], splits the result into a usage and a modifier byte, and
 * usb_keyboard_press() sends the key report followed by an all-zero release.
 *
 *     key      = keycode & 0x3F   (and KEY_NON_US_100 -> 100)
 *     modifier = SHIFT/ALTGR/RCTRL bits of the keycode, mapped to HID bits
 */
function typeChar(ch, layoutName) {
  const spec = LAYOUTS[layoutName];
  const code = ch.charCodeAt(0);
  if (code < 0x20 || code > 0x7f) throw new Error(`not ASCII: ${JSON.stringify(ch)}`);

  const keycode = spec.ascii[code - 0x20];
  if (!keycode) return null;    /* this layout cannot type it */

  const reports = [];

  /*
   * The dead key first, where the character needs one.
   *
   * keylayouts.c puts the accent in bits ABOVE the six that reach the wire -
   * Canadian French has ASCII_5E = CIRCUMFLEX_BITS + KEY_SPACE - so an accented
   * character is two keystrokes and not one. Omitting this is what the
   * emulator itself used to do, and it turned every accented character into
   * its bare base key with no error anywhere
   * (ok-rn/FINDING-deadkeys-were-dropped-from-the-keyboard-override.md).
   */
  const bits = spec.deadkeysMask ? keycode & spec.deadkeysMask : 0;
  if (bits) {
    const dead = Object.values(spec.deadkeys || {}).find(d => d.bits === bits);
    if (dead) reports.push(...pressRelease(spec, dead.key));
  }

  reports.push(...pressRelease(spec, keycode));
  return reports;
}

/** One keycode as the press report and the all-zero release that follows. */
function pressRelease(spec, keycode) {
  let usage = keycode & 0x3f;
  if (spec.nonUs100 && usage === spec.nonUs100) usage = 100;

  let modifiers = 0;
  if (spec.shiftMask && (keycode & spec.shiftMask)) modifiers |= MOD.LSHIFT;
  if (spec.altgrMask && (keycode & spec.altgrMask)) modifiers |= MOD.RALT;
  if (spec.rctrlMask && (keycode & spec.rctrlMask)) modifiers |= MOD.RCTRL;

  return [
    [modifiers, 0, usage, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0],
  ];
}

/** A whole string, plus the reports for any character the layout lacks. */
function typeString(text, layoutName) {
  const reports = [];
  const missing = [];
  for (const ch of text) {
    const rs = typeChar(ch, layoutName);
    if (!rs) { missing.push(ch); continue; }
    reports.push(...rs);
  }
  return { reports, missing };
}

/* Keyboard.press(KEY_TAB) / KEY_RETURN reach the wire as plain usages. */
const tabReports = () => [[0, 0, 0x2b, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];
const returnReports = () => [[0, 0, 0x28, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];

/* ------------------------------------------------------------------ tests */

test('every printable ASCII character survives a US round trip', () => {
  let text = '';
  for (let c = 0x20; c <= 0x7e; c++) text += String.fromCharCode(c);

  const { reports, missing } = typeString(text, 'USA_ENGLISH');
  assert.deepEqual(missing, [], 'US English should be able to type all of ASCII');

  const { text: back, unmapped } = keystrokes.decode(reports);
  assert.deepEqual(unmapped, [], 'a usage the firmware sent could not be decoded');
  assert.equal(back, text);
});

test('the case of a letter is carried by the modifier byte, not the usage', () => {
  /*
   * The single most likely way to get this wrong is to read report[2] and look
   * it up: 'a' and 'A' are both usage 4. A decoder that ignored modifiers
   * would pass a lowercase-only test and lose every capital in a password.
   */
  const lower = typeChar('a', 'USA_ENGLISH');
  const upper = typeChar('A', 'USA_ENGLISH');

  assert.equal(lower[0][2], upper[0][2], 'expected the same usage for a and A');
  assert.notEqual(lower[0][0], upper[0][0], 'expected different modifiers');

  assert.equal(keystrokes.decode(lower).text, 'a');
  assert.equal(keystrokes.decode(upper).text, 'A');
});

test('a repeated character needs the release between the two presses', () => {
  /*
   * Reports are absolute state. "aa" is press, release, press - and a decoder
   * that treated each report as an event would either emit one 'a' (seeing the
   * same state twice) or three (counting the release). Both are silent.
   */
  const down = [0, 0, 0x04, 0, 0, 0, 0, 0];
  const up = [0, 0, 0, 0, 0, 0, 0, 0];

  assert.equal(keystrokes.decode([down, up, down, up]).text, 'aa');
  assert.equal(keystrokes.decode([down, down, up]).text, 'a',
    'a repeated report is the same key still held, not a second press');
});

test('the field separators come through as tab and newline', () => {
  const reports = [
    ...typeString('user', 'USA_ENGLISH').reports,
    ...tabReports(),
    ...typeString('pw', 'USA_ENGLISH').reports,
    ...returnReports(),
  ];

  const { text, events } = keystrokes.decode(reports);
  assert.equal(text, 'user\tpw\n');

  const names = events.filter(e => e.name).map(e => e.name);
  assert.deepEqual(names, ['TAB', 'RETURN']);
});

test('splitFields cuts on the separators and drops the trailing empty', () => {
  const { segments, separators } = keystrokes.splitFields('https://x\tbob\thunter2\n');
  assert.deepEqual(segments, ['https://x', 'bob', 'hunter2']);
  assert.deepEqual(separators, ['TAB', 'TAB', 'RETURN']);

  /* A field that is configured but empty is a real segment, not an artefact. */
  assert.deepEqual(keystrokes.splitFields('a\t\tb').segments, ['a', '', 'b']);
});

test('rollover error codes are not characters', () => {
  /*
   * 1..3 are what a real keyboard sends when more keys are down than it can
   * report. The firmware never sends them, but decoding usage 1 as a character
   * would corrupt a password rather than shortening it.
   */
  const { text, events } = keystrokes.decode([
    [0, 0, 1, 1, 1, 1, 1, 1],
    [0, 0, 0, 0, 0, 0, 0, 0],
  ]);
  assert.equal(text, '');
  assert.equal(events.length, 0);
});

test('a usage this layout has no character for is reported, not dropped', () => {
  /* 0x3a is F1 - no layout maps it to text. */
  const { text, unmapped } = keystrokes.decode([
    [0, 0, 0x3a, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0],
  ]);
  assert.equal(text, '');
  assert.equal(unmapped.length, 1, 'silence here looks identical to a broken table');
  assert.equal(unmapped[0].usage, 0x3a);
});

test('several usages appearing in one report decode in a stable order', () => {
  /*
   * The six-key array is filled by first free slot, so after a release its
   * order is no longer the order things were typed. Sorting makes the result
   * deterministic rather than dependent on that.
   */
  const both = [[0, 0, 0x05, 0x04, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];
  assert.equal(keystrokes.decode(both).text, 'ab');
});

test('a non-US layout decodes with its own table', () => {
  /*
   * German swaps y and z and puts @ on AltGr+Q. Decoding German reports with
   * the US table gives plausible-looking wrong text, which is exactly the
   * failure this guards.
   */
  const text = 'zy@';
  const { reports, missing } = typeString(text, 'GERMAN');
  assert.deepEqual(missing, []);

  assert.equal(keystrokes.decode(reports, { layout: 'GERMAN' }).text, text);
  assert.notEqual(
    keystrokes.decode(reports).text, text,
    'the US table decoded German correctly, so this test proves nothing',
  );
});

test('every layout with a table round-trips the characters it claims', () => {
  /*
   * The broad sweep. Each layout types whatever it says it can, and it must
   * come back - if any layout's inversion is wrong, this is where it shows,
   * rather than in a bug report from someone whose password came back mangled.
   */
  const checked = [];
  for (const { name, supported, ambiguous } of keystrokes.layouts()) {
    if (!supported) continue;

    /*
     * Characters the layout cannot distinguish are excluded, because no
     * decoder could get them right. Canadian French assigns KEY_TILDE +
     * SHIFT_MASK to both # and | (keylayouts.c:1385,1440), so the two are one
     * keystroke - see ok-rn/FINDING-layout-tables-map-two-characters-to-one-keystroke.md. That is a
     * property of the firmware table, not of this code.
     */
    const indistinct = new Set(ambiguous.join('').split(''));

    let typeable = '';
    for (let c = 0x20; c <= 0x7e; c++) {
      const ch = String.fromCharCode(c);
      if (indistinct.has(ch)) continue;
      if (typeChar(ch, name)) typeable += ch;
    }

    const { reports } = typeString(typeable, name);
    const { text, unmapped } = keystrokes.decode(reports, { layout: name });

    assert.deepEqual(unmapped, [], `${name}: undecodable usage`);
    assert.equal(text, typeable, `${name}: round trip changed the text`);
    checked.push(`${name}:${typeable.length}`);
  }

  assert.ok(checked.length >= 20, `only ${checked.length} layouts had tables`);
});

test('a layout that cannot distinguish two characters says so', () => {
  /*
   * The counterpart to the exclusion above. If `ambiguous` were quietly empty,
   * the sweep would still pass - it would just be testing less than it claims.
   */
  const caFr = keystrokes.layouts().find(l => l.name === 'CANADIAN_FRENCH');
  assert.ok(caFr.ambiguous.length > 0, 'the pipe/hash clash was not reported');
  assert.ok(
    caFr.ambiguous.some(pair => pair.includes('|') && pair.includes('#')),
    `expected # and | to clash, got ${JSON.stringify(caFr.ambiguous)}`,
  );

  const us = keystrokes.layouts().find(l => l.name === 'USA_ENGLISH');
  assert.deepEqual(us.ambiguous, [], 'US English should have no clashes');
});

test('an accented character is composed from its dead key and its base key', () => {
  /*
   * Canadian French types ^ as CIRCUMFLEX then space - two keystrokes, four
   * reports. A decoder that read them independently would return a space, and
   * a password containing ^ would come back one character short and wrong.
   */
  const reports = typeChar('^', 'CANADIAN_FRENCH');
  assert.equal(reports.length, 4, 'expected two press/release pairs');

  const { text, events } = keystrokes.decode(reports, { layout: 'CANADIAN_FRENCH' });
  assert.equal(text, '^');

  const dead = events.find(e => e.dead);
  assert.ok(dead, 'the dead key was not recognised as one');
  assert.equal(dead.text, '', 'a dead key must not produce text of its own');
  /*
   * `accented`, not the accent's NAME. Which accent it was is not on the wire:
   * Portuguese gives DEADKEY_CIRCUMFLEX and DEADKEY_TILDE the same keycode, so
   * "circumflex" is not something a report can express. What the decoder can
   * say is that this character was composed rather than typed directly.
   */
  assert.equal(events.find(e => e.accented)?.accented, true);
});

test('the streaming decoder gives the same answer as the one-shot', () => {
  /* A slot is typed over a second or two; a caller should not have to buffer. */
  const { reports } = typeString('Str3am!ng', 'USA_ENGLISH');

  const seen = [];
  const d = keystrokes.createDecoder({ onEvent: e => seen.push(e.text) });
  for (const r of reports) d.push(r);

  assert.equal(d.text, 'Str3am!ng');
  assert.equal(seen.join(''), 'Str3am!ng');
  assert.equal(d.text, keystrokes.decode(reports).text);

  d.reset();
  assert.equal(d.text, '');
});

test('an unknown layout name fails loudly', () => {
  assert.throws(
    () => keystrokes.decode([], { layout: 'KLINGON' }),
    /unknown keyboard layout/,
  );
});
