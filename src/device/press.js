/*
 * press.js - how long to hold a button, and what happens if you hold it longer.
 *
 * The firmware bands a press by MAIN-LOOP ITERATIONS, not by milliseconds. That
 * is the only unit it measures, and every number here is in it. At roughly 36ms
 * an iteration the bands are about 0.7s and 1.5s, but the firmware never sees a
 * clock and neither should a caller.
 *
 * WHY THIS IS IN THE LIBRARY. The numbers lived in ok-rn's transport and were
 * restated in ten more files across its screens, hooks and suites. A press band
 * is protocol - the same firmware runs on a physical key over USB - so a second
 * host would have transcribed them again, and a transcription that drifts by
 * one band is the difference between typing a password and taking a backup.
 *
 * WHAT IS NOT HERE. The act of pressing. A host presses buttons through
 * whatever it has - a JNI call to the soft key, a control transfer to a USB
 * key - and the library has no business knowing which. This is the arithmetic
 * and the refusal; `captureBackup` already draws the same line about its own
 * trigger.
 */
'use strict';

/**
 * The bands, from OnlyKey.ino:873-942.
 *
 *     <= 20      types the slot
 *     21 .. 71   types the slot's b profile
 *     >= 72      STOPS BEING A SLOT READ - see GESTURES below
 *     >= 90      rejected outright
 *
 * The gesture branches return before the band dispatch, so 21..71 is the whole
 * safe window for a b-profile read even though the b-profile band is written as
 * 21..89 in the source.
 *
 * TAP and HOLD sit in the middle of their bands rather than at an edge. The
 * cost of being wrong downward is a press that reads as nothing; the cost of
 * being wrong upward is irreversible.
 */
const PRESS_TICKS = {
  /** Types slot N. */
  TAP: 10,
  /** Types slot N+6, the b profile. Comfortably short of a gesture. */
  HOLD: 40,
  /** The first tick at which a press stops being a slot read. */
  GESTURE: 72,
  /** Past this the firmware rejects the press rather than banding it. */
  REJECTED: 90,
};

/**
 * Idle sense rounds before the firmware calls a press finished.
 *
 * `key_off > 2` (okcore.cpp:2723) - three rounds with no pad held - plus one
 * for the round the hold retired in, which still read as held.
 *
 * This is why counted presses with no idle gap between them MERGE: the firmware
 * never saw the release, so the two durations sum, and two taps of 10 become
 * one hold of 20. Past 72 that is a gesture.
 * See FINDING-counted-presses-merge-without-an-idle-gap.md.
 */
const RELEASE_ROUNDS = 4;

/**
 * What a hold past the gesture floor actually does, by button.
 *
 * Written out because "it is in the gesture band" is not a useful thing to tell
 * somebody: the consequences are different per button and three of them are
 * irreversible or disruptive.
 *
 * These are the CLASSIC assignments. A DUO takes config mode on button 1 held
 * past 180 instead - see capabilities().configModeGesture, which is the source
 * a caller should use rather than this table.
 */
const GESTURES = {
  1: 'takes a backup',
  2: 'dumps the slot labels',
  3: 'locks the key and restarts it',
  6: 'enters config mode',
};

/** Which band a count falls in: 'tap', 'hold', 'gesture' or 'rejected'. */
function bandFor(ticks) {
  if (ticks >= PRESS_TICKS.REJECTED) return 'rejected';
  if (ticks >= PRESS_TICKS.GESTURE) return 'gesture';
  if (ticks > 20) return 'hold';
  return 'tap';
}

/** True when a hold this long stops being a slot read. */
function isGesture(ticks) {
  return ticks >= PRESS_TICKS.GESTURE;
}

/**
 * Refuse a gesture-length hold unless it was asked for by name.
 *
 * There is no such thing as accidentally wanting one: at 72 iterations button 1
 * takes a backup, button 3 locks the key and restarts it, and button 6 enters
 * config mode - which ends only at restart. A slot read never needs to go past
 * 71, so the default makes that range unreachable rather than merely unlikely.
 *
 * Returns the message rather than throwing, so a caller can reject, throw or
 * render it. Null means the hold is fine.
 */
function gestureRefusal(button, ticks, { allowGesture = false } = {}) {
  if (allowGesture || !isGesture(ticks)) return null;
  const does = GESTURES[button];
  return (
    `${ticks} ticks is in the gesture band (>= ${PRESS_TICKS.GESTURE})`
    + (does ? `, where button ${button} ${does}` : '')
    + '. Pass allowGesture to mean it.'
  );
}

module.exports = {
  PRESS_TICKS,
  RELEASE_ROUNDS,
  GESTURES,
  bandFor,
  isGesture,
  gestureRefusal,
};
