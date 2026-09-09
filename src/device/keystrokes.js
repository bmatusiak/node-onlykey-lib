/*
 * HID keyboard reports back into text.
 *
 * WHY THIS EXISTS AT ALL
 *
 * On hardware a slot's contents are write-only. The key types them as USB
 * keystrokes into whatever window has focus, and the desktop app is explicit
 * that labels are the only slot data it can ever read back - there is no
 * command that asks the key what a slot holds, because there deliberately
 * isn't one.
 *
 * On a phone running the firmware in-process, the app is both the key and the
 * host. The keystrokes do not go to someone else's window; they arrive on
 * IFACE.KEYBOARD as reports the app can see. Decoding them is what turns a
 * device that types passwords into one that can also SHOW you a password - and
 * it is the only way to capture a backup, which the firmware likewise types
 * rather than sending as a reply.
 *
 * WHAT COMES OFF THE WIRE
 *
 * Standard 8-byte boot-protocol reports, which are ABSOLUTE STATE and not
 * events:
 *
 *     [ modifiers, 0, usage0, usage1, usage2, usage3, usage4, usage5 ]
 *
 * A key is pressed when its usage appears in the array and released when it
 * disappears, so the decoder diffs consecutive reports rather than reading each
 * one on its own. Typing "aa" is three reports - a, nothing, a - and reading
 * them independently gives "aa" only by accident; reading a chord like shift+a
 * independently gives nothing at all.
 *
 * The usages are real HID usage codes, not characters: 'a' and 'A' are both
 * usage 4 and differ only in the modifier byte. Which character a usage means
 * depends on the layout the firmware was compiled with, so the tables come from
 * the firmware itself (keylayouts.data.js, generated - see
 * ok-rn/tools/gen-keylayouts.js) rather than from an assumption that everyone
 * is on US English.
 */
'use strict';

const { LAYOUTS } = require('./keylayouts.data');

/** Report byte 0. Only the three that select a character are interesting. */
const MOD = {
  LCTRL: 0x01, LSHIFT: 0x02, LALT: 0x04, LGUI: 0x08,
  RCTRL: 0x10, RSHIFT: 0x20, RALT: 0x40, RGUI: 0x80,
};

const SHIFT_BITS = MOD.LSHIFT | MOD.RSHIFT;

/**
 * Usages that are structure rather than text.
 *
 * TAB and RETURN are the firmware's field separators: process_slot() writes
 * them into the keybuffer as the sentinels 1 and 2 (OnlyKey.ino:1108,1139,1169)
 * and sendKey() types them as KEY_TAB / KEY_RETURN, so they arrive here as
 * ordinary usages and are the only marks separating url from username from
 * password. They are kept in the text as \t and \n precisely so a caller can
 * split on them.
 */
const USAGE = {
  ENTER: 0x28,
  ESCAPE: 0x29,
  BACKSPACE: 0x2a,
  TAB: 0x2b,
  SPACE: 0x2c,
};

const NAMED = new Map([
  [USAGE.ENTER, { text: '\n', name: 'RETURN' }],
  [USAGE.TAB, { text: '\t', name: 'TAB' }],
  [USAGE.ESCAPE, { text: '', name: 'ESCAPE' }],
  [USAGE.BACKSPACE, { text: '', name: 'BACKSPACE' }],
]);

/** The default, and the only layout an OK_EMULATOR debug build can type. */
const DEFAULT_LAYOUT = 'USA_ENGLISH';

/**
 * usage + modifier state -> character, for one layout.
 *
 * Built by inverting the firmware's own forward table with exactly the
 * truncation the firmware applies. okemu_usb.cpp does:
 *
 *     key = keycode & 0x3F;  if (KEY_NON_US_100 && key == KEY_NON_US_100) key = 100;
 *
 * so the six low bits are what actually reach the wire, and a decoder that
 * used the full masked keycode would be inverting a value that was never sent.
 */
function buildTable(layout) {
  const spec = LAYOUTS[layout];
  if (!spec) {
    throw new Error(
      `unknown keyboard layout ${layout}; known: ${Object.keys(LAYOUTS).join(', ')}`,
    );
  }

  /*
   * Where each accent lives on the wire.
   *
   * Built first, because a character that needs an accent is identified by
   * the KEYSTROKE that produces it and not by the accent's name. Portuguese
   * gives circumflex and tilde the same keycode, so "the accent on 0xF031" is
   * a thing the wire can express and "circumflex" is not.
   */
  const deadWireFor = new Map();      /* accent bits -> wire slot */
  const deadWires = new Set();        /* every wire slot that is an accent */
  for (const { bits, key } of Object.values(spec.deadkeys || {})) {
    const wire = wireFor(spec, key);
    if (wire === null) continue;
    deadWireFor.set(bits, wire);
    deadWires.add(wire);
  }

  const map = new Map();
  const collisions = new Map();

  for (let i = 0; i < spec.ascii.length; i++) {
    const keycode = spec.ascii[i];
    if (!keycode) continue;   /* this layout does not have this character */

    const wire = wireFor(spec, keycode);
    if (wire === null) continue;

    const bits = spec.deadkeysMask ? keycode & spec.deadkeysMask : 0;
    const lead = bits ? deadWireFor.get(bits) : undefined;
    /*
     * A character asking for an accent nothing can type is not typeable, and
     * claiming it would put a wrong character in the table.
     */
    if (bits && lead === undefined) continue;

    const k = sequence(lead, wire);
    const ch = String.fromCharCode(0x20 + i);

    /*
     * First writer wins, and a clash is RECORDED rather than resolved.
     *
     * Two characters can be the same keystrokes for two different reasons,
     * and both are in the shipped tables:
     *
     *   Canadian French  ASCII_23 = ASCII_7C = KEY_TILDE + SHIFT_MASK
     *                    so # and | are one key.
     *   Portuguese       DEADKEY_CIRCUMFLEX == DEADKEY_TILDE
     *                    so ^ and ~ are the same accent key then the same
     *                    base key.
     *
     * Neither is something a decoder can fix - the information is not on the
     * wire. Pretending otherwise means guessing, and a guess here is a
     * password with a wrong character that looks exactly like a right one.
     * What it can do is know, and say so.
     */
    if (map.has(k)) {
      const first = map.get(k);
      if (!collisions.has(k)) collisions.set(k, [first]);
      collisions.get(k).push(ch);
      continue;
    }
    map.set(k, ch);
  }

  /*
   * An accent key that is also a plain character loses its accent role.
   *
   * Swallowing a character someone typed is worse than failing to compose an
   * accent. In practice they do not collide - a layout puts its dead keys
   * where it has no plain character - but the rule has to be stated, because
   * the failure it prevents is silent.
   */
  for (const wire of [...deadWires]) {
    if (map.has(sequence(undefined, wire))) deadWires.delete(wire);
  }

  return { spec, map, deadWires, collisions };
}

/** The HID usage a keycode reaches the wire as. Mirrors okemu_keycode_to_key. */
function usageOf(spec, keycode) {
  let usage = keycode & 0x3f;
  if (spec.nonUs100 && usage === spec.nonUs100) usage = 100;
  return usage;
}

/** What a keycode looks like on the wire: usage plus the modifiers it needs. */
function wireFor(spec, keycode) {
  const usage = usageOf(spec, keycode);
  if (!usage) return null;
  return wireSlot(
    usage,
    Boolean(spec.shiftMask && (keycode & spec.shiftMask)),
    Boolean(spec.altgrMask && (keycode & spec.altgrMask)),
    Boolean(spec.rctrlMask && (keycode & spec.rctrlMask)),
  );
}

/** What a press looks like on the wire, independent of any pending accent. */
const wireSlot = (usage, shift, altgr, rctrl) =>
  usage | (shift ? 0x100 : 0) | (altgr ? 0x200 : 0) | (rctrl ? 0x400 : 0);

/** The full keystroke sequence for one character: optional accent, then key. */
const sequence = (lead, wire) => `${lead === undefined ? '' : lead}:${wire}`;
const tableCache = new Map();
function tableFor(layout) {
  let t = tableCache.get(layout);
  if (!t) { t = buildTable(layout); tableCache.set(layout, t); }
  return t;
}

/** The layouts this build of the firmware has tables for. */
function layouts() {
  return Object.entries(LAYOUTS).map(([name, spec]) => ({
    name,
    id: spec.id,
    /*
     * An all-zero table is not a parse failure, it is the firmware saying that
     * this layout types nothing: keylayouts.c guards every layout but US
     * English behind #if defined(SUPPORT_LAYOUT_x). Reporting it is the point -
     * a device set to an unsupported layout types NOTHING, and silence is
     * indistinguishable from a decoder that is broken.
     */
    /* This layout has a table to invert. Says nothing about the device. */
    supported: spec.ascii.some(v => v !== 0),

    /*
     * Whether THIS BUILD OF THE FIRMWARE can type it.
     *
     * A different question from `supported`, and the one a settings screen
     * needs. keylayouts.c guards every layout but US English behind
     * #if defined(SUPPORT_LAYOUT_x), and a debug build - which this app must
     * be, because provisioning is #ifdef DEBUG - enables none of them. A key
     * set to a layout that is not compiled in types NOTHING AT ALL, with no
     * error anywhere (FINDING-only-us-english-types-on-a-debug-build.md).
     *
     * Two come back true here. Dvorak is the second, and not because its own
     * block survives: the unguarded base block covers USA_ENGLISH, DVORAK and
     * an unset layout, so a key set to Dvorak types US ENGLISH rather than
     * nothing. Usable, and not what was asked for.
     */
    compiledIn: Boolean(spec.compiledIn),
    /*
     * Characters this layout types identically to another one, so a decoder
     * cannot recover which was meant. Reported rather than hidden - a caller
     * showing a password can say the word is ambiguous instead of showing a
     * confident wrong answer.
     */
    ambiguous: spec.ascii.some(v => v !== 0)
      ? [...tableFor(name).collisions.values()].map(chars => chars.join(''))
      : [],
  }));
}

/* ------------------------------------------------------------------ decode */

/**
 * A stateful decoder, because reports arrive one at a time.
 *
 * Held separately from the text so a caller can decode a stream as it lands
 * (a slot being typed out over a second or two) rather than having to buffer
 * every report first and decode at the end.
 */
function createDecoder({ layout = DEFAULT_LAYOUT, onEvent = null } = {}) {
  const { map, deadWires } = tableFor(layout);
  let held = new Set();
  let text = '';
  /* The dead key awaiting its base key, as its wire slot. */
  let pending = null;
  const events = [];

  function push(report) {
    if (!report || report.length < 3) return [];

    const modifiers = report[0];
    const now = new Set();
    for (let i = 2; i < report.length && i < 8; i++) {
      const usage = report[i];
      /*
       * 1..3 are the rollover/error codes a real keyboard sends when more keys
       * are down than it can report. The firmware never sends them, but a
       * decoder that turned them into characters would corrupt a password
       * rather than dropping one, so they are excluded explicitly.
       */
      if (usage > 3) now.add(usage);
    }

    const fresh = [];
    for (const usage of now) {
      if (!held.has(usage)) fresh.push(usage);
    }
    held = now;

    /*
     * Sorted, so a report that introduces two usages at once decodes in a
     * stable order. Set iteration follows insertion order, which is the order
     * of the six-key array - and that array is filled by first free slot, so
     * after a release it is no longer the order things were typed.
     */
    fresh.sort((a, b) => a - b);

    const out = [];
    for (const usage of fresh) {
      const wire = wireSlot(
        usage,
        Boolean(modifiers & SHIFT_BITS),
        Boolean(modifiers & MOD.RALT),
        Boolean(modifiers & MOD.RCTRL),
      );

      /*
       * A dead key produces no text of its own; it selects which character
       * the NEXT press means. Only when nothing is already pending, so an
       * accent followed by itself does not vanish into a second wait.
       */
      if (pending === null && deadWires.has(wire) && !NAMED.has(usage)) {
        pending = wire;
        const event = { usage, modifiers, text: '', name: 'DEADKEY', dead: true };
        out.push(event);
        events.push(event);
        if (onEvent) onEvent(event);
        continue;
      }

      const event = decodeUsage(usage, modifiers, wire, map, pending);
      pending = null;
      out.push(event);
      events.push(event);
      text += event.text;
      if (onEvent) onEvent(event);
    }
    return out;
  }

  return {
    push,
    /** Every report at once, for a capture that is already complete. */
    pushAll(reports) { for (const r of reports) push(r); return this; },
    get text() { return text; },
    get events() { return events.slice(); },
    get layout() { return layout; },
    reset() { held = new Set(); text = ''; pending = null; events.length = 0; },
  };
}

function decodeUsage(usage, modifiers, wire, map, pending) {
  const named = NAMED.get(usage);
  if (named) {
    return { usage, modifiers, text: named.text, name: named.name };
  }

  const hit = map.get(sequence(pending === null ? undefined : pending, wire));
  if (hit !== undefined) {
    return {
      usage, modifiers, text: hit, name: null,
      ...(pending === null ? null : { accented: true }),
    };
  }

  /*
   * Unmapped, and reported rather than dropped.
   *
   * A key this layout has no character for is either a control key the caller
   * may care about (a function key, an arrow) or a sign that the device is on
   * a different layout than the decoder was told. Both are worth surfacing:
   * silently producing a shorter password is the failure mode that looks like
   * success.
   */
  return {
    usage, modifiers, text: '', name: null, unmapped: true,
    ...(pending === null ? null : { accented: true }),
  };
}
/** One-shot: a complete capture in, text and events out. */
function decode(reports, opts = {}) {
  const d = createDecoder(opts);
  d.pushAll(reports);
  return { text: d.text, events: d.events, unmapped: d.events.filter(e => e.unmapped) };
}

/* ------------------------------------------------------------------ fields */

/**
 * Split decoded text on the separators the firmware puts between fields.
 *
 * process_slot() emits TAB or RETURN after each field it types, chosen per slot
 * by the `addchar` byte, and types nothing at all for a field that is not
 * configured. So the separators say where the boundaries are but NOT which
 * field is which - a slot with only a password produces one segment, and so
 * does a slot with only a username.
 *
 * Mapping segments onto url / username / password / OTP therefore needs the
 * slot's own configuration, which the caller has and this does not. Guessing it
 * here would put a username in a password box some of the time, which is the
 * kind of wrong that is discovered late.
 */
function splitFields(text) {
  const segments = [];
  const separators = [];
  let current = '';

  for (const ch of text) {
    if (ch === '\t' || ch === '\n') {
      segments.push(current);
      separators.push(ch === '\t' ? 'TAB' : 'RETURN');
      current = '';
      continue;
    }
    current += ch;
  }
  segments.push(current);

  /*
   * A trailing separator - which is normal, since the last field usually ends
   * with RETURN to submit the form - leaves an empty final segment that is an
   * artefact of the separator rather than a field.
   */
  if (segments.length > 1 && segments[segments.length - 1] === '') segments.pop();

  return { segments, separators };
}

module.exports = {
  MOD,
  USAGE,
  DEFAULT_LAYOUT,
  layouts,
  createDecoder,
  decode,
  splitFields,
};
