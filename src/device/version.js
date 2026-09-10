/**
 * What the device is, and therefore what it can be asked to do.
 *
 * Every OnlyKey announces itself in one string - the reply to set_time, and the
 * once-a-second broadcast after that:
 *
 *   UNLOCKEDv3.0.4-testc
 *   ^^^^^^^^             state
 *           ^^^^^^^^^^^  version, exactly as the firmware composed it
 *                      ^ hardware model, appended by HW_MODEL()
 *
 * Before this file the project parsed that string in exactly one place - a
 * React hook, with a regex, for display - so the library could not branch on a
 * firmware version even in principle. Old-firmware support is entirely a
 * branching problem, which made that the thing to fix first.
 *
 * ## Ask for a capability, not a version number
 *
 * Nothing outside this file should compare version numbers. A caller asks
 * `capabilities(status).challengeFormula` and gets an answer; the mapping from
 * version to answer lives in ONE table, so adding a firmware generation is one
 * entry rather than a hunt for comparisons. Every entry cites the source it was
 * transcribed from, and an entry with no citation should not be added.
 *
 * ## The build is in the string
 *
 * onlykey.h composes the version like this:
 *
 *   #ifdef DEBUG
 *   #define OKversionkeyword "-test"
 *   #else
 *   #define OKversionkeyword "-prod"
 *   #endif
 *   #define OKversion "v" maj "." min "." pat OKversionkeyword
 *
 * So a device SAYS which build it is running. `-test` is a DEBUG build with the
 * serial console; `-prod` is a production build without one. This matters
 * because the library's PIN provisioning waits on console prompts that a
 * production build never prints, and until now nothing could tell the two
 * apart. The keyword is recent, so older firmware answers 'unknown' rather than
 * a guess - see `build` below, and `debugConsole` in the capabilities.
 *
 * ## Every branch here is reachable from a fixture
 *
 * The emulator is built from current firmware, so CI can only ever exercise the
 * current generation. Everything in this file therefore takes a STRING and
 * returns a decision, with no device involved, and test/version.test.js drives
 * every branch from canned status lines. A version branch that can only be
 * exercised by old hardware is in the wrong layer.
 *
 * Old-firmware behaviour here is TRANSCRIBED from OnlyKey-App and
 * onlykey.github.io, which are proven against those devices. It has not been
 * run against one by this project. Where that matters it is said again at the
 * entry.
 */
'use strict';

/**
 * Hardware, as HW_MODEL() spells it (okcore.cpp:7978-8005).
 *
 * The two reference clients disagree about the names and neither covers the
 * whole set: the desktop app maps n/p to DUO and c to Classic and has NO CASE
 * for o, so an Original falls through to a branch that calls
 * window.location.reload() and loops; the web app only asks whether the byte is
 * 'c' and calls everything else 'Go' or 'Original' depending on which reply
 * layout it parsed. These are the firmware's own four.
 */
const MODEL = {
  CLASSIC: 'classic',       // 'c' - LQFP or BGA with dual LEDs
  DUO: 'duo',               // 'p' with a PIN set, 'n' without
  ORIGINAL: 'original',     // 'o' - discontinued
  UNKNOWN: 'unknown',
};

/** Which firmware build, from the version keyword. */
const BUILD = {
  DEBUG: 'debug',           // '-test': the serial console exists
  PRODUCTION: 'production', // '-prod': it does not
  UNKNOWN: 'unknown',       // older than the keyword; do not guess
};

/** The model letter HW_MODEL appends, and what it means. */
const MODEL_SUFFIX = {
  c: MODEL.CLASSIC,
  p: MODEL.DUO,
  n: MODEL.DUO,
  o: MODEL.ORIGINAL,
};

/**
 * The version the desktop app assumes when a device says UNINITIALIZED with no
 * version after it (OnlyKeyComm.js:1343-1348). Such firmware predates the
 * version being in the string at all. The app also disables its in-app firmware
 * update on this path and tells the user to upgrade.
 */
const PRE_VERSION_FIRMWARE = 'v0.2-beta.6';

/**
 * The one version whose OKCONNECT reply is laid out differently.
 *
 * onlykey-api.js:167 compares the 12-byte version field against this EXACT
 * string, model letter included, and switches the whole reply layout on it. It
 * is a string comparison in the reference and it stays one here: the condition
 * is not "older than 8c", it is "is 8c".
 */
const BREAKING_BETA_8C = 'v0.2-beta.8c';

/**
 * Split a status line into what it actually tells you.
 *
 * The version is taken by SPLITTING on the state word, not by slicing at a
 * fixed index - `msg.split("UNLOCKED").pop()` (OnlyKeyComm.js:1335).
 * python-onlykey reads `okversion[19]`, a fixed offset that breaks the moment a
 * version string is a different length, and version strings have already been
 * three different lengths.
 *
 * @param {string|Uint8Array} status the device's reply, as text or as bytes
 */
function parseStatus(status) {
  const raw = typeof status === 'string' ? status : textOf(status);
  const trimmed = raw.replace(/\0+$/, '').trim();

  const out = {
    raw: trimmed,
    state: 'unknown',
    /** Everything after the state word, model letter included - what the desktop displays. */
    version: null,
    /** The same string, named for the 12-byte field the OKCONNECT reply carries it in. */
    versionField: null,
    release: null,
    model: MODEL.UNKNOWN,
    /** A DUO reports whether a PIN is set. Nothing else does, hence null. */
    pinSet: null,
    build: BUILD.UNKNOWN,
    /** Whether firmware can be updated from a host over USB. */
    fwUpdateOverUsb: false,
  };

  /*
   * Longest state word first. "UNINITIALIZED" contains "INITIALIZED", so a
   * shorter pattern tested earlier would claim it.
   */
  if (/^UNINITIALIZEDv/.test(trimmed)) {
    out.state = 'uninitialized';
    out.version = trimmed.slice('UNINITIALIZED'.length);
    out.fwUpdateOverUsb = true; // OnlyKeyComm.js:1334
  } else if (/^UNINITIALIZED/.test(trimmed)) {
    /*
     * No version after the word: firmware older than the version being there.
     * Assumed, not measured - it is the reference client's guess and we carry
     * it as one, which is why the constant is named for what it means.
     */
    out.state = 'uninitialized';
    out.version = PRE_VERSION_FIRMWARE;
    out.fwUpdateOverUsb = false; // OnlyKeyComm.js:1349
  } else if (/^UNLOCKED/.test(trimmed)) {
    out.state = 'unlocked';
    out.version = trimmed.slice('UNLOCKED'.length);
  } else if (/^INITIALIZED-D/.test(trimmed)) {
    // Provisioned, locked, and a DUO. The trailing -D is the only model signal.
    out.state = 'locked';
    out.model = MODEL.DUO;
  } else if (/^INITIALIZED/.test(trimmed)) {
    out.state = 'locked';
    out.model = MODEL.CLASSIC;
  } else if (/BOOTLOADER/.test(trimmed)) {
    // The desktop app treats bootloader as uninitialized (OnlyKeyComm.js:1020).
    out.state = 'bootloader';
  } else if (/^Error/i.test(trimmed)) {
    out.state = 'error';
  }

  if (out.version) {
    out.versionField = out.version;

    const letter = out.version.slice(-1).toLowerCase();
    const model = MODEL_SUFFIX[letter];
    if (model) {
      out.model = model;
      // 'n' is a DUO with no PIN set, 'p' one with. Only a DUO reports this.
      if (model === MODEL.DUO) out.pinSet = letter === 'p';
    }

    out.release = parseRelease(stripModelSuffix(out.version));
    if (out.release) {
      if (out.release.prerelease === 'test') out.build = BUILD.DEBUG;
      else if (out.release.prerelease === 'prod') out.build = BUILD.PRODUCTION;
    }

    if (out.state === 'unlocked') {
      out.fwUpdateOverUsb = supportsFwUpdate(out.version);
    }
  }

  return out;
}

/**
 * Drop the model letter HW_MODEL appended, if one is there.
 *
 * Only a letter that MEANS something is dropped, so `v0.2-beta.3` keeps its 3
 * and reports an unknown model - which is right, since firmware that old
 * appended nothing.
 *
 * A version whose own last character happened to be n, p, c or o would lose it.
 * That is not a flaw here: the firmware appends unconditionally, so such a
 * version is genuinely ambiguous on the wire, and both reference clients read
 * the last character exactly this way.
 */
function stripModelSuffix(version) {
  return MODEL_SUFFIX[version.slice(-1).toLowerCase()] ? version.slice(0, -1) : version;
}

/**
 * Numbers out of a version string, for ordering.
 *
 * Two shapes have shipped and both have to parse:
 *
 *   v3.0.4-test   major.minor.patch with a build keyword
 *   v0.2-beta.8   major.minor with a prerelease that has its own number
 */
function parseRelease(version) {
  const m = /^v(\d+)\.(\d+)(?:\.(\d+))?(?:-(.+))?$/.exec(version);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] === undefined ? null : Number(m[3]),
    prerelease: m[4] === undefined ? null : m[4],
  };
}

/**
 * Whether firmware can be updated over USB. Transcribed from
 * OnlyKeyComm.js:1360:
 *
 *   if (version && (version[9] != "." || version[10] > 6))
 *
 * Kept as the same character test rather than rewritten as a version
 * comparison, because the character test is what has been proven against the
 * old devices. What it reaches for is "newer than v0.2-beta.6": in that string
 * index 9 is the dot of `beta.6` and index 10 is that 6, so a string without a
 * dot there is a different shape and therefore newer.
 *
 * It compares a CHARACTER against a number, so `version[10] > 6` is '7' > 6,
 * which JavaScript coerces and which happens to work - and which would stop
 * working at a two-digit number. Transcribed, not corrected: correcting it
 * would be improving a protocol we have no way to test against.
 */
function supportsFwUpdate(version) {
  return Boolean(version) && (version[9] !== '.' || version[10] > 6);
}

/**
 * What this device can be asked to do.
 *
 * Every entry cites where it came from, and entries whose old-firmware branch
 * has never been run against old hardware say so.
 *
 * @param {object|string} status a parseStatus result, or a raw status line
 */
function capabilities(status) {
  const info = typeof status === 'string' ? parseStatus(status) : status;

  return {
    /**
     * The OKCONNECT reply layout.
     *
     * 'legacy': public key at [21..53], version at [8..20], body NOT encrypted.
     * 'modern': public key at [0..32], body AES-GCM under the transit key.
     *
     * onlykey-api.js:167-197. The reference switches on an exact string match
     * against the version field, so this does too.
     *
     * The legacy branch is UNVERIFIED against hardware by this project.
     */
    okconnectLayout: info.versionField === BREAKING_BETA_8C ? 'legacy' : 'modern',

    /**
     * Which formula turns the payload hash into three button numbers.
     *
     *   'modern'  byte % 6 + 1                firmware okcore.cpp:7583-7585
     *   'duo'     byte % 3 + 1                firmware okcore.cpp:7578-7581
     *   'legacy'  byte < 6 ? 1 : byte % 5 + 1 onlykey-pgp.js:441-449
     *
     * The DUO branch exists in the firmware and in NO host client. We show
     * challenge digits on screen, so getting it wrong puts 4, 5 and 6 in front
     * of someone holding a device with three buttons.
     *
     * The legacy branch is UNVERIFIED against hardware by this project.
     */
    challengeFormula:
      info.versionField === BREAKING_BETA_8C
        ? 'legacy'
        : info.model === MODEL.DUO
          ? 'duo'
          : 'modern',

    /**
     * Multiplier on poll and inter-chunk delays.
     *
     * The Original hardware is slower and the web app waits four times as long
     * for it - onlykey-pgp.js:133-135 and 236-239, both keyed on
     * `OKversion == 'Original'`.
     *
     * UNVERIFIED against hardware by this project.
     */
    pollDelayMultiplier: info.model === MODEL.ORIGINAL ? 4 : 1,

    /** Firmware update from a host over USB - see supportsFwUpdate(). */
    firmwareUpdateOverUsb: info.fwUpdateOverUsb,

    /**
     * Whether a serial console is there to talk to.
     *
     *   true   a DEBUG build ('-test'), so SEREMU exists and prints prompts
     *   false  a production build ('-prod'), so it does not
     *   null   firmware older than the keyword
     *
     * null is UNKNOWN, not false. The console may well be there, and treating
     * unknown as absent would disable PIN provisioning on every old device -
     * exactly the population this work exists to support.
     *
     * onlykey.h:96-100. This decides whether the library may wait on console
     * prompts or must drive provisioning over the vendor interface instead.
     */
    debugConsole:
      info.build === BUILD.DEBUG ? true : info.build === BUILD.PRODUCTION ? false : null,

    /**
     * How many slots and profiles the device has.
     *
     * A DUO is 24 slots across 4 profiles, a Classic 12 across 2. Using the
     * Classic count against a DUO stops enumeration at 12 of 24 with no error,
     * which is the shape of failure this whole file exists to remove.
     */
    slots: info.model === MODEL.DUO ? 24 : 12,
    profiles: info.model === MODEL.DUO ? 4 : 2,

    /**
     * What the touch-free derive needs from this firmware.
     *
     *   'always'      it just works. No preference, nothing to turn on.
     *   'preference'  needs derived_key_challenge_mode bit 3 set.
     *   'broken'      the check exists and reads a stale cache, so the device
     *                 refuses it whatever the preference says.
     *
     * MEASURED, and the split is exactly one release wide:
     *
     *   v2.1.0 - v3.0.1   NO GATE AT ALL. ok_extension.cpp sets
     *                     additional_data[0] for the REQ_PRESS variants and
     *                     carries straight on; there is no preference check
     *                     anywhere (`git show a27ffa6:fido2/ok_extension.cpp`).
     *   v3.0.2            the check was ADDED, against `derived_key_challenge_mode`
     *                     - a RAM cache of an EEPROM byte that the raw-HID
     *                     pipeline zeroes on every done_process_packets(). By
     *                     the time the FIDO2 path reads it, it is always zero.
     *                     So the device answers CTAP2_ERR_EXTENSION_NOT_SUPPORTED
     *                     to a preference it is holding.
     *   after v3.0.2      the same check, reloading the byte from EEPROM first,
     *                     so the preference works as intended.
     *
     * Why a host needs to know: the press flag is an INPUT to the derivation,
     * not a permission check in front of it, so retrying with a touch derives a
     * DIFFERENT key (FINDING-the-press-flag-changes-the-derived-key.md). There
     * is no fallback. A caller that cannot do a touch-free derive cannot open
     * the vault at all, and the honest thing is to say why rather than to offer
     * a button that seals blobs nothing else can read.
     *
     * 'broken' is what the vault should refuse on, naming the firmware rather
     * than the preference - telling someone to enable a setting that cannot
     * take effect is worse than telling them nothing.
     */
    touchFreeDerive: (() => {
      const rel = parseRelease(stripModelSuffix(info.versionField || ''));
      /*
       * Unknown means don't guess. A version we cannot parse is old firmware
       * or a shape we have not seen, and the pre-v3.0.2 releases we HAVE
       * measured all allow it - so 'always' is both the honest reading of the
       * evidence and the one that does not disable a working device.
       */
      if (!rel) return 'always';
      if (rel.major < 3) return 'always';
      if (rel.major > 3 || rel.minor > 0) return 'preference';
      /* 3.0.x */
      if (rel.patch === null || rel.patch < 2) return 'always';
      if (rel.patch === 2) return 'broken';
      return 'preference';
    })(),

    /**
     * Whether the X-Wing hybrid key type exists at all.
     *
     * MEASURED: `KEYTYPE_XWING` does not appear anywhere in libraries@5d7ce7a
     * (v3.0.2) and does in the working tree, so it arrived after v3.0.2. The
     * age file format built on it therefore cannot work on an older key either.
     *
     * Defaults to FALSE for a version we cannot read, which is the opposite of
     * touchFreeDerive's default and deliberately so: that one is a feature old
     * firmware HAS, and this is one it does not. Guessing "present" would offer
     * a screen that produces an identity the device cannot use.
     */
    xwingDerive: (() => {
      const rel = parseRelease(stripModelSuffix(info.versionField || ''));
      if (!rel) return false;
      if (rel.major > 3) return true;
      if (rel.major < 3) return false;
      if (rel.minor > 0) return true;
      return rel.patch !== null && rel.patch > 2;
    })(),

    /**
     * How the device asks for a touch, and therefore how a host must press.
     *
     *   'keepalive'  the request returns CTAP2_ERR_PROCESSING while it waits,
     *                the host keeps polling, and a press answered from inside
     *                the keepalive completes it. No time limit worth naming.
     *   'blocking'   ctap_user_presence_test(5000) BLOCKS for five seconds and
     *                then denies. There is no keepalive to answer, so a host
     *                that only presses when asked never presses at all.
     *
     * MEASURED at each pin by whether ok_extension.cpp mentions
     * CTAP2_ERR_PROCESSING: present through the whole 3.0 line, absent in the
     * 2.1 line. The split is the generation boundary.
     *
     * Why a host cannot ignore this: on 'blocking' firmware the press has to be
     * sent on a TIMER shortly after the request, not in response to anything.
     * Waiting to be asked produces CTAP2_ERR_OPERATION_DENIED five seconds
     * later, which reads as a refusal rather than as nobody having touched it.
     * Measured on a v2.1.0 soft key: every press-required shared-secret derive
     * failed this way while the touch-free derives beside them passed.
     */
    presenceTest: (() => {
      const rel = parseRelease(stripModelSuffix(info.versionField || ''));
      /*
       * Unknown is treated as 'blocking', which is the SAFE direction: a host
       * that presses on a timer still completes a ceremony on keepalive
       * firmware, whereas one that waits to be asked cannot complete anything
       * on blocking firmware.
       */
      if (!rel) return 'blocking';
      return rel.major >= 3 ? 'keepalive' : 'blocking';
    })(),

    /**
     * The gesture that reaches config mode: which button, and for how long.
     *
     * OnlyKey.ino:914, verbatim:
     *
     *     (onlykeyhw==OK_HW_DUO && duration >= 180 && button_selected=='1')
     *     || (onlykeyhw!=OK_HW_DUO && duration >= 72 && button_selected=='6')
     *
     * `duration` is MAIN-LOOP ITERATIONS, not milliseconds - roughly 36ms each,
     * so the DUO's 180 is about six and a half seconds and the classic's 72 is
     * under three. The desktop app tells a DUO owner to hold for "10+ seconds"
     * and a classic owner for "5+", which are safe overshoots of these rather
     * than the numbers themselves.
     *
     * A host that uses the classic gesture on a DUO holds a button that does
     * something else entirely and then waits for a lock that never comes -
     * measured, as "the device never locked after three attempts".
     *
     * `ticks` is the FLOOR. Going further is not safer: past the same band a
     * hold stops being config mode and becomes another gesture, which is why
     * callers ask for this rather than picking a number that felt generous.
     */
    configModeGesture: info.model === MODEL.DUO
      ? { button: 1, ticks: 180 }
      : { button: 6, ticks: 72 },

    /** Three buttons on a DUO, six otherwise - see protocol/challenge.js. */
    buttons: info.model === MODEL.DUO ? 3 : 6,
  };
}

/** Latin-1 text out of report bytes, stopping at the first NUL. */
function textOf(bytes) {
  let out = '';
  for (const b of bytes) {
    if (b === 0) break;
    out += String.fromCharCode(b);
  }
  return out;
}

module.exports = {
  parseStatus,
  capabilities,
  parseRelease,
  stripModelSuffix,
  supportsFwUpdate,
  MODEL,
  BUILD,
  MODEL_SUFFIX,
  BREAKING_BETA_8C,
  PRE_VERSION_FIRMWARE,
};
