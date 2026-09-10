/*
 * The press bands.
 *
 * These numbers decide whether a button types a password or takes a backup, and
 * they were transcribed into ten files before they lived here. The tests are
 * about the BOUNDARIES, because that is where a transcription goes wrong: one
 * off at 71/72 is the difference between reading a slot and entering config
 * mode, which ends only at restart.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  PRESS_TICKS,
  RELEASE_ROUNDS,
  GESTURES,
  bandFor,
  isGesture,
  gestureRefusal,
} = require('../src/device/press');

test('the defaults sit inside their bands, not at the edges', () => {
  // The cost of being wrong downward is a press that reads as nothing; upward
  // it is irreversible. So both defaults have room beneath the next boundary.
  assert.equal(bandFor(PRESS_TICKS.TAP), 'tap');
  assert.equal(bandFor(PRESS_TICKS.HOLD), 'hold');
  assert.ok(PRESS_TICKS.HOLD < PRESS_TICKS.GESTURE - 20,
    'HOLD is close enough to the gesture floor to be worth re-checking');
});

test('the boundary between a b-profile read and a gesture', () => {
  assert.equal(bandFor(71), 'hold');
  assert.equal(bandFor(72), 'gesture');
  assert.equal(isGesture(71), false);
  assert.equal(isGesture(72), true);
});

test('the boundary between a tap and a hold', () => {
  assert.equal(bandFor(20), 'tap');
  assert.equal(bandFor(21), 'hold');
});

test('past 90 the firmware rejects rather than bands', () => {
  assert.equal(bandFor(89), 'gesture');
  assert.equal(bandFor(90), 'rejected');
});

test('a gesture is refused by name, and the message says what it would do', () => {
  const refusal = gestureRefusal(1, 80);
  assert.ok(refusal, 'a gesture-length hold must be refused by default');
  assert.match(refusal, /takes a backup/);
  assert.match(refusal, /allowGesture/);

  assert.match(gestureRefusal(3, 80), /locks the key and restarts it/);
  assert.match(gestureRefusal(6, 80), /enters config mode/);
});

test('a button with no gesture still refuses, without inventing a consequence', () => {
  // Buttons 4 and 5 have no gesture branch. The hold is still refused - it is
  // past the band where a slot read means anything - but the message must not
  // claim it does something it does not.
  const refusal = gestureRefusal(4, 80);
  assert.ok(refusal);
  assert.ok(!/button 4 /.test(refusal), refusal);
});

test('asking for it by name is allowed, and a short hold is never refused', () => {
  assert.equal(gestureRefusal(6, 80, {allowGesture: true}), null);
  assert.equal(gestureRefusal(6, 40), null);
});

test('RELEASE_ROUNDS is why two taps with no gap become one hold', () => {
  // key_off > 2 plus the round the hold retired in. Named here because the
  // consequence - merged presses summing past 72 - is a gesture nobody asked
  // for. See FINDING-counted-presses-merge-without-an-idle-gap.md.
  assert.equal(RELEASE_ROUNDS, 4);
  assert.equal(bandFor(PRESS_TICKS.TAP * 2), 'tap', 'two taps merged are still a tap');
  assert.equal(bandFor(PRESS_TICKS.HOLD * 2), 'gesture', 'two holds merged are a GESTURE');
});

test('every gesture in the table names a real consequence', () => {
  for (const [button, does] of Object.entries(GESTURES)) {
    assert.ok(does.length > 0, `button ${button} has an empty description`);
    assert.ok(!/^button/i.test(does), 'the description is a verb phrase, not a repeat of the button');
  }
});
