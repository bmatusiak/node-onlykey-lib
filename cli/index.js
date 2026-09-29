#!/usr/bin/env node
/*
 * onlykey-js - the OnlyKey command line, built on this library.
 *
 * WHAT IT IS FOR. python-onlykey's `onlykey-cli` is a second implementation
 * of the OnlyKey protocol, and every disagreement between it, the desktop app,
 * the web app and ok-rn has had to be found by hand. This CLI has no protocol
 * code of its own: each command is a few lines over the device plugin, over
 * the same session and transport the GUIs run (cli/desktop.js composes them).
 * A command that works here therefore works in every GUI on this library, and
 * a bug fixed in the library is fixed here too. Over time it takes over
 * onlykey-cli's commands one by one; cli/README.md keeps the table.
 *
 * WHY THE NAME. `onlykey-js`, not `onlykey-cli`: both can be installed on one
 * machine while the port is incomplete, and a bin that shadowed python's would
 * make "which one ran?" a question in every bug report.
 *
 * READS, THEN WRITES. Step 1 was read-only. Step 2 adds python's writes -
 * setslot, wipeslot, the device settings, settime, genkey, setkey, loadkey,
 * wipekey - each over the device plugin's own operation. What the key SAYS
 * is printed on stdout, success or refusal, as python prints it; a refusal
 * also exits 1, where python exits 0 and a script cannot tell. Secrets are
 * prompted for (cli/prompt.js) rather than taken from the command line; the
 * one exception is setkey's hex, which python's form puts there and which
 * is prompted for when left off.
 *
 * WHAT IT DOES NOT DO. There is no firmware update path - that is
 * deliberately not something this program can do - and no backup or
 * restore, which need their own safety design before they get a command.
 *
 * TESTABILITY. `main(argv, io)` is the whole program. `io` supplies output and
 * `start`, the function that composes the stack; the bin passes stdout and
 * startDesktop, a test passes arrays and a stack over the fake firmware. No
 * subprocess and no device is needed to test a command.
 */
'use strict';

const { parseArgs } = require('node:util');
const PKG = require('../package.json');

const NAME = 'onlykey-js';

/** A failure that is the user's to fix: printed as one sentence, not a stack. */
class CliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.exitCode = exitCode;
  }
}

/**
 * The key answered, and the answer was no.
 *
 * `said` is the device's own sentence and goes to STDOUT, where python prints
 * it: a script comparing the two CLIs sees the same line. `hint`, when there
 * is one, is ours and goes to stderr - what to do about it.
 */
class DeviceRefusal extends CliError {
  constructor(said, hint = null) {
    super(said, 1);
    this.said = said;
    this.hint = hint;
  }
}

/** A mistake in the command line itself: exit 2, the usage line on stderr. */
const usage = (message) => new CliError(message, 2);

/* ------------------------------------------------------------ formatting */

/*
 * python-onlykey's displaycapabilities() prints `print('%-14s' % name, value)`:
 * a name left-justified in 14 columns, a space, the value. Kept, so output a
 * script already parses keeps parsing.
 */
const row = (name, value) => `${String(name).padEnd(14)} ${value}`;

/*
 * python's Slot.to_str(): "Slot <name>: <label>", with <empty> for no label.
 * A slot that never answered is not "empty" - it is unknown, and saying empty
 * would be a claim about the key's contents.
 */
const slotLine = (name, label) =>
  `Slot ${name}: ${label === null || label === undefined ? '<not reported>' : label || '<empty>'}`;

/** python's SLOTS_NAME_DUO: DUO slot number (1..24) -> the name it prints. */
const DUO_COLOURS = ['Green', 'Blue', 'Yellow', 'Purple'];
function duoSlotName(n) {
  const within = (n - 1) % 6;            // 0..5 inside one colour's run of six
  const button = (within % 3) + 1;       // 1a 2a 3a 1b 2b 3b
  return `${DUO_COLOURS[Math.floor((n - 1) / 6)]} ${button}${within < 3 ? 'a' : 'b'}`;
}

/** python's SLOTS_NAME for a classic: 1..6 are 1a..6a, 7..12 are 1b..6b. */
const classicSlotName = (n) => (n <= 6 ? `${n}a` : `${n - 6}b`);

/* ------------------------------------------------------------ the device */

/**
 * Compose, open, connect, run `fn`, and always release the key.
 *
 * Every device command goes through here so none can forget the destroy: a
 * held hidapi handle keeps the process alive and the interface busy for the
 * next program that wants it.
 */
async function withDevice(io, opts, fn) {
  const app = await io.start({ path: opts.path });
  try {
    const { device } = app.services;
    const connected = await device.connect();
    return await fn({ device, connected, identity: connected.identity });
  } finally {
    await app.destroy();
  }
}

/**
 * Refuse, with the reason, anything that needs an unlocked key.
 *
 * A LOCKED key does not refuse a label read: it says nothing at all, and only
 * its once-a-second status broadcast keeps arriving (measured; see
 * src/device/slots.js). Without this check the command would wait out a
 * fifteen-second timeout to report what the connect reply already said.
 */
function requireUnlocked(identity, what, { firstUse = false } = {}) {
  if (identity.state === 'unlocked') return;
  /*
   * Some settings can be written ONLY before setup is finished (wipe mode's
   * safe values, the second-profile mode - see `requires: 'firstUse'` in the
   * device plugin's PREFERENCES), so a settings write lets an uninitialized
   * key through and lets the key decide.
   */
  if (firstUse && identity.state === 'uninitialized') return;
  if (identity.state === 'locked') {
    throw new CliError(`The OnlyKey is locked. Enter your PIN on the key, then run "${what}" again.`);
  }
  if (identity.state === 'uninitialized') {
    throw new CliError('This OnlyKey has not been set up yet (it has no PIN). Set it up first.');
  }
  throw new CliError(`The OnlyKey answered "${identity.raw}", which is not an unlocked key.`);
}

/**
 * The capability flags, split into what the key has and what it does not.
 *
 * Only the booleans: they are the yes/no questions a person asks ("does this
 * key do agent v2?"). The structured entries (gesture bands and the like) are
 * for code and would be noise here.
 */
function capabilityFlags(caps) {
  const yes = [];
  const no = [];
  for (const [name, value] of Object.entries(caps || {})) {
    if (value === true) yes.push(name);
    else if (value === false) no.push(name);
  }
  return { yes: yes.sort(), no: no.sort() };
}

/* ------------------------------------------------------------ commands */

const COMMANDS = {};

COMMANDS.help = {
  mirrors: 'help, -h, --help',
  summary: 'this list',
  async run(io) {
    io.out(`${NAME} v${PKG.version} - the OnlyKey command line, on node-onlykey-lib`);
    io.out('');
    io.out(`Usage: ${NAME} <command> [arguments] [--path <hid path>] [--yes]`);
    io.out('');
    io.out('Commands:');
    for (const [name, cmd] of Object.entries(COMMANDS)) {
      io.out(`  ${name.padEnd(14)} ${cmd.summary}${cmd.writes ? '  [writes]' : ''}`);
      if (cmd.usage) io.out(`  ${''.padEnd(14)}   ${name} ${cmd.usage}`);
    }
    io.out('');
    io.out('Options:');
    io.out(`  ${'--path <path>'.padEnd(14)} which OnlyKey, when more than one is plugged in`);
    io.out(`  ${'--yes'.padEnd(14)} confirm a setting that cannot be undone (wipemode, backupkeymode, webcryptpolicy)`);
    io.out(`  ${'-h, --help'.padEnd(14)} this list`);
    io.out('');
    io.out('[writes] commands change what is on the key; most need it in config mode.');
    io.out('Secrets (password, gkey, totpkey, a PGP passphrase) are prompted for, or read as one');
    io.out('line from stdin when stdin is not a terminal - never taken as arguments. setkey also');
    io.out('takes its hex as an argument, as python\'s does, and prompts for it when left off.');
    io.out('There is no firmware update, backup or restore command.');
    return 0;
  },
};

COMMANDS.version = {
  mirrors: 'version',
  summary: 'this program\'s version (does not touch the key)',
  /*
   * NO DEVICE, as in python-onlykey, which moved to a lazy connection for
   * exactly this: `version` must work with no key plugged in, and must not put
   * traffic on a key that did not ask for it. The firmware's version is
   * `fwversion`.
   */
  async run(io) {
    io.out(`${NAME} v${PKG.version} (node-onlykey-lib)`);
    return 0;
  },
};

COMMANDS.fwversion = {
  mirrors: 'fwversion',
  summary: 'the key\'s firmware version',
  device: true,
  async run(io, opts) {
    return withDevice(io, opts, ({ identity }) => {
      /*
       * python prints okversion[8:] - the status string after "UNLOCKED". On a
       * locked key that string is "INITIALIZED" and python prints "ZED". A
       * locked key does not report its version, so say that instead.
       */
      if (!identity.version) {
        if (identity.state === 'locked') {
          throw new CliError('The OnlyKey is locked, and a locked key does not report its firmware version. '
            + 'Enter your PIN on the key, then run "fwversion" again.');
        }
        throw new CliError(`The OnlyKey did not report a firmware version (it answered "${identity.raw}").`);
      }
      io.out(identity.version);
      return 0;
    });
  },
};

COMMANDS.status = {
  mirrors: '(new)',
  summary: 'status line, firmware version, model and capability summary',
  device: true,
  async run(io, opts) {
    return withDevice(io, opts, ({ connected, identity }) => {
      io.out(row('status', connected.status || '(none)'));
      io.out(row('state', identity.state));
      io.out(row('firmware', identity.version || 'not reported while locked'));
      io.out(row('model', identity.model));
      if (identity.version) io.out(row('build', identity.build));
      if (identity.pinSet !== null) io.out(row('pin set', identity.pinSet ? 'yes' : 'no'));
      /*
       * Capabilities are derived from the version, so a locked key - which
       * reports none - would show the OLDEST firmware's, as if it were that
       * firmware. Better nothing than a confident wrong answer.
       */
      if (identity.version) {
        const { yes } = capabilityFlags(connected.capabilities);
        io.out(row('capabilities', yes.join(' ') || '-'));
      } else {
        io.out(row('capabilities', 'unknown until unlocked'));
      }
      return 0;
    });
  },
};

COMMANDS.capabilities = {
  mirrors: 'capabilities',
  summary: 'what this key\'s firmware can do, flag by flag',
  device: true,
  async run(io, opts) {
    return withDevice(io, opts, ({ connected, identity }) => {
      /*
       * NOT the same source as python's. python-onlykey asks the firmware for
       * a capabilities report (OKGETLABELS 'c'), which no signed release sends
       * - release 3.1.0 included - so on every key in the field it prints
       * "Firmware does not report capabilities". This library derives them
       * from the version the key does report (src/device/version.js), which is
       * what the GUIs decide with. The `source` line says so.
       */
      if (!identity.version) {
        throw new CliError('Capabilities are read from the firmware version, which a locked key does not report. '
          + 'Enter your PIN on the key, then run "capabilities" again.');
      }
      const caps = connected.capabilities || {};
      const { yes, no } = capabilityFlags(caps);
      io.out(row('firmware', identity.version));
      io.out(row('source', 'firmware version (node-onlykey-lib\'s table)'));
      io.out(row('flags', yes.join(' ') || '-'));
      io.out(row('not supported', no.join(' ') || '-'));
      for (const [name, value] of Object.entries(caps)) {
        if (typeof value === 'number' || typeof value === 'string') io.out(row(name, value));
      }
      return 0;
    });
  },
};

COMMANDS.getlabels = {
  mirrors: 'getlabels',
  summary: 'the label of every slot',
  device: true,
  async run(io, opts) {
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'getlabels');
      /*
       * connect() has just told the device plugin the model, and readLabels
       * reads 12 or 24 by it - python has to ask separately (is_duo()).
       */
      const { labels } = await device.readLabels();
      const duo = labels.length === 24;
      /*
       * python's layout: a classic in pairs (1a, 1b), a DUO in runs of six per
       * colour, a blank line after each group.
       */
      if (duo) {
        for (let n = 1; n <= 24; n++) {
          io.out(slotLine(duoSlotName(n), labels[n - 1]));
          if (n % 6 === 0) io.out('');
        }
      } else {
        for (let pair = 1; pair <= 6; pair++) {
          io.out(slotLine(classicSlotName(pair), labels[pair - 1]));
          io.out(slotLine(classicSlotName(pair + 6), labels[pair + 5]));
          io.out('');
        }
      }
      return 0;
    });
  },
};

COMMANDS.getkeylabels = {
  mirrors: 'getkeylabels',
  summary: 'the label of every RSA and ECC key slot',
  device: true,
  async run(io, opts) {
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'getkeylabels');
      const { keys } = await device.readKeyLabels();
      for (const { slot, kind, label } of keys) {
        io.out(slotLine(kind === 'rsa' ? `RSA Key ${slot}` : `ECC Key ${slot - 100}`, label));
      }
      return 0;
    });
  },
};

/* ------------------------------------------------------------ writing: shared */

/*
 * The library's PURE helpers, used to check a command line completely before
 * the key is opened: a label one character too long, a TOTP seed with a typo,
 * a key of the wrong length are all refused here with nothing sent. The
 * device plugin runs the same checks again when it writes - these are the
 * same functions, not a copy of their rules.
 */
const slotConfig = require('../src/device/slotConfig');
const encoders = require('../src/device/encoders');
const deviceKeys = require('../src/device/keys');
const slotsLib = require('../src/device/slots');
const okmsg = require('../src/protocol/okmsg');
const { fromLatin1, fromHex } = require('../src/bytes');

const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/**
 * The device's own sentence inside a library error, if it carries one.
 *
 * setSlot, setPreference and wipeKey attach it as `deviceText`. loadKey and
 * wipeSlot do not (a library gap: they throw a plain Error whose message
 * ends in the sentence), so it is read off the end of the message for those.
 */
function deviceSentence(err) {
  if (!err) return null;
  if (err.deviceText) return err.deviceText;
  const m = /(?:^|: )((?:Error|No PIN set|Timeout occured)\b.*)$/.exec(String(err.message || ''));
  return m ? m[1].trim() : null;
}

/** What to do about a refusal, when there is something to do. */
function hintFor(said) {
  switch (okmsg.errorKind(said)) {
    case 'configMode':
      return 'this write needs config mode. Put the OnlyKey in config mode, then run the command again.';
    case 'locked':
      return 'enter your PIN on the key, then run the command again.';
    default:
      return null;
  }
}

/*
 * SILENCE IS NOT A REFUSAL. Outside config mode the firmware drops OKSETPRIV
 * without a word (the fake firmware's `setPrivSilent` models it), so a key
 * write that is never acknowledged is, nearly always, a key that is not in
 * config mode. python prints the empty read and exits 0; say what it means.
 */
const SILENT_WRITE_HINT = 'Outside config mode the OnlyKey drops a key write without answering, '
  + 'so put it in config mode and run the command again.';

/**
 * Run one library write, turning its failures into what the person needs:
 * the key's own "no" (stdout, like python), a bad value (a usage error), or
 * silence (with the config-mode explanation).
 */
async function deviceWrite(fn) {
  try {
    return await fn();
  } catch (err) {
    const said = deviceSentence(err);
    if (said) throw new DeviceRefusal(said, hintFor(said));
    if (err instanceof RangeError) throw usage(err.message);
    if (/never acknowledged|no acknowledgement|produced no key/.test(String(err && err.message))) {
      throw new CliError(`${err.message}. ${SILENT_WRITE_HINT}`);
    }
    throw err;
  }
}

/*
 * python's slot names. `setslot 1b ...` is slot 7 and `setslot green1b ...`
 * is slot 4 whatever the model - python maps the NAME, not the device - so
 * this does too; a number is taken as it is.
 */
const SLOT_BY_NAME = (() => {
  const map = new Map();
  for (let n = 1; n <= 12; n++) map.set(classicSlotName(n), n);
  for (let n = 1; n <= 24; n++) map.set(duoSlotName(n).replace(' ', '').toLowerCase(), n);
  return map;
})();

/** A credential slot, 1..24, from python's name or a number. */
function parseSlot(arg) {
  const text = String(arg).toLowerCase();
  const n = SLOT_BY_NAME.has(text) ? SLOT_BY_NAME.get(text) : (/^\d+$/.test(text) ? Number(text) : NaN);
  if (!(n >= 1 && n <= 24)) {
    throw usage(`"${arg}" is not a slot: use 1a-6b, green1a-purple3b, or a number 1-24`);
  }
  return n;
}

const KEY_SLOT_KINDS = { rsa: 'RSA1-RSA4', ecc: 'ECC1-ECC16', hmac: 'HMAC1-HMAC2' };

/**
 * A key slot by python's name: RSA1-4 (slots 1-4), ECC1-16 (101-116),
 * HMAC1 (130) and HMAC2 (129) - python's numbering, HMAC1 the higher.
 */
function parseKeySlot(arg, kinds, command) {
  const text = String(arg);
  let m;
  let key = null;
  if ((m = /^rsa([1-4])$/i.exec(text))) {
    key = { kind: 'rsa', slot: Number(m[1]), name: `RSA${m[1]}` };
  } else if ((m = /^ecc(\d{1,2})$/i.exec(text)) && Number(m[1]) >= 1 && Number(m[1]) <= 16) {
    key = { kind: 'ecc', slot: 100 + Number(m[1]), name: `ECC${Number(m[1])}` };
  } else if ((m = /^hmac([12])$/i.exec(text))) {
    key = { kind: 'hmac', slot: m[1] === '1' ? 130 : 129, name: `HMAC${m[1]}` };
  }
  if (!key || !kinds.includes(key.kind)) {
    throw usage(`"${arg}" is not a key slot ${command} takes: ${kinds.map((k) => KEY_SLOT_KINDS[k]).join(', ')}`);
  }
  return key;
}

/*
 * python's letters (protocol.py CLI_KEY_LETTERS / CLI_KEY_FEATURES), onto the
 * library's key types and role bits. `b` is backup AND decryption, as there:
 * a backup key is a decryption key.
 */
const { KEY_TYPE, MODIFIER } = deviceKeys;
const KEY_LETTERS = {
  x: KEY_TYPE.ED25519,
  n: KEY_TYPE.P256R1,
  s: KEY_TYPE.P256K1,
  c: KEY_TYPE.CURVE25519,
  m: KEY_TYPE.MLKEM768,
  w: KEY_TYPE.XWING,
  h: KEY_TYPE.HMACSHA1,
};
const KEY_LETTER_NAMES = {
  x: 'Ed25519', n: 'NIST P-256', s: 'secp256k1', c: 'Curve25519',
  m: 'ML-KEM-768', w: 'X-Wing', h: 'HMAC-SHA1',
};
const KEY_FEATURES = {
  d: { bits: MODIFIER.DECRYPTION, roles: { decryption: true } },
  s: { bits: MODIFIER.SIGNATURE, roles: { signature: true } },
  b: { bits: MODIFIER.BACKUP | MODIFIER.DECRYPTION, roles: { backup: true, decryption: true } },
};

function parseFeatures(arg) {
  if (!own(KEY_FEATURES, arg)) {
    throw usage(`features must be d (decryption), s (signing) or b (backup, which is also decryption); got "${arg}"`);
  }
  return KEY_FEATURES[arg];
}

/**
 * loadKey, with the key's acknowledgement.
 *
 * loadKey RETURNS what it wrote but not what the key said ("Successfully set
 * ECC Key") - that goes out only as a `keyAck` progress event (a library
 * gap). It is the line python prints, so it is collected here.
 */
async function loadKeyAck(device, slot, spec, opts = {}) {
  let response = null;
  const off = device.on('progress', (p) => {
    if (p && p.step === 'keyAck' && p.slot === slot) response = p.response;
  });
  try {
    const result = await device.loadKey(slot, spec, opts);
    return { ...result, response };
  } finally {
    off();
  }
}

/**
 * Writing an HMAC key removes that slot's button press, and the device does
 * not say so; the library returns it (clearedPressRequirement), so say it.
 */
function warnPressFree(io, result) {
  if (result && result.clearedPressRequirement) {
    io.err(`${NAME}: note: writing an HMAC key clears the button-press requirement on that slot `
      + '(the key does not report this).');
  }
}

/** Prompt for a secret, refusing an empty answer rather than writing nothing. */
async function promptSecret(io, question, what) {
  const value = await io.prompt(question);
  if (!value) throw usage(`no ${what} was entered; nothing was written`);
  return value;
}

/* ------------------------------------------------------------ writing: slots */

/*
 * setslot's field names, python's, onto the library's slot fields. The
 * addchar numbering is python's too, and it is NOT the wire numbering:
 * addchar1 is NEXTKEY4 (typed before the username), addchar2 NEXTKEY1, and so
 * on - it follows the order the key types them in (url, addchar1, addchar2,
 * delay1, username, addchar3, delay2, password, addchar4, addchar5, delay3).
 */
const SLOT_TYPES = {
  label: { field: 'label' },
  ecckeylabel: { field: 'label', keyLabel: 'ecc' },
  rsakeylabel: { field: 'label', keyLabel: 'rsa' },
  url: { field: 'url' },
  addchar1: { field: 'nextKey4' },
  delay1: { field: 'delay1' },
  username: { field: 'username' },
  addchar2: { field: 'nextKey1' },
  delay2: { field: 'delay2' },
  password: { field: 'password', secret: 'Password: ' },
  addchar3: { field: 'nextKey2' },
  delay3: { field: 'delay3' },
  '2fa': { field: 'tfaType' },
  /*
   * gkey: a Google Authenticator seed, in base32, sent as bytes. python
   * decodes with b32decode, which REQUIRES '=' padding, so an unpadded seed
   * whose length is not a multiple of eight - most of them - fails there.
   * The library's decoder takes it with or without.
   */
  gkey: { field: 'totpKey', secret: 'Key: ', encode: (v) => encoders.base32ToBytes(v) },
  /* totpkey: the key as typed, sent as its characters (python's from_ascii). */
  totpkey: { field: 'totpKey', secret: 'Key: ', encode: (v) => fromLatin1(v) },
  addchar4: { field: 'nextKey5' },
  addchar5: { field: 'nextKey3' },
  typespeed: { field: 'typeSpeed' },
};

/**
 * The label index of a KEY slot, from python's forms: rsakeylabel takes the
 * key number 1-4 (label index 25-28), ecckeylabel 1-16 (29-44). A key name -
 * RSA2, ECC7 - is accepted as well.
 */
function keyLabelIndex(arg, kind) {
  const named = /^(rsa|ecc)\d+$/i.test(String(arg));
  const n = named
    ? parseKeySlot(arg, [kind], `${kind}keylabel`).slot % 100
    : Number(/^\d+$/.test(String(arg)) ? arg : NaN);
  const max = kind === 'rsa' ? 4 : 16;
  if (!(n >= 1 && n <= max)) throw usage(`${kind}keylabel takes a key number 1-${max}, got "${arg}"`);
  return slotsLib.labelIndexForKeySlot(kind === 'rsa' ? n : 100 + n);
}

COMMANDS.setslot = {
  mirrors: 'setslot',
  usage: '<id> <field> [value]',
  writes: true,
  summary: 'set one field of a slot (label, url, username, password, 2fa, gkey, ...)',
  async run(io, opts, args) {
    const [id, type, ...values] = args;
    if (!id || !type) throw usage('setslot needs a slot and a field');
    if (!own(SLOT_TYPES, type)) {
      throw usage(`"${type}" is not a slot field; one of: ${Object.keys(SLOT_TYPES).join(', ')}`);
    }
    const spec = SLOT_TYPES[type];
    const slot = spec.keyLabel ? keyLabelIndex(id, spec.keyLabel) : parseSlot(id);

    let value;
    if (spec.secret) {
      /* See cli/prompt.js: a secret on the command line is in the shell history. */
      if (values.length) {
        throw usage(`setslot ${type} does not take the value as an argument - it would be left in your `
          + 'shell history. Leave it off and enter it at the prompt, or pipe it on stdin.');
      }
      value = await promptSecret(io, spec.secret, type);
      if (spec.encode) {
        try {
          value = spec.encode(value);
        } catch (err) {
          throw usage(err.message);
        }
      }
      if (spec.encode && !value.length) throw usage(`the ${type} is empty; nothing was written`);
    } else {
      /*
       * Exactly one. python reads argv[4] and ignores the rest, so an
       * unquoted `label My Bank` stores "My" and says it succeeded.
       */
      if (values.length !== 1) {
        throw usage(values.length
          ? `setslot ${type} takes one value, got ${values.length} - quote a value that has spaces`
          : `setslot ${type} needs a value`);
      }
      value = values[0];
    }

    try {
      slotConfig.planSlotWrites({ [spec.field]: value }, slot);
    } catch (err) {
      throw usage(err.message);
    }

    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'setslot');
      const [applied] = await deviceWrite(() => device.setSlot(slot, { [spec.field]: value }));
      io.out(applied.response);
      return 0;
    });
  },
};

COMMANDS.wipeslot = {
  mirrors: 'wipeslot',
  usage: '<id>',
  writes: true,
  summary: 'erase every field of a slot',
  async run(io, opts, args) {
    if (args.length !== 1) throw usage('wipeslot takes one slot');
    const slot = parseSlot(args[0]);
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'wipeslot');
      /*
       * ONE LINE, where python prints eight. wipe_slot() answers once per
       * field it erases - ten "Successfully wiped ..." lines, Label through
       * 2FA Key (okcore.cpp:2028-2082 at eb25290). python reads eight of them
       * and leaves two in the buffer; the library's wipeSlot returns the
       * first (a library gap - it cannot return all ten).
       */
      io.out(await deviceWrite(() => device.wipeSlot(slot)));
      return 0;
    });
  },
};

/* ------------------------------------------------------------ writing: settings */

/*
 * python's settings commands, onto the device plugin's PREFERENCES rows. One
 * row per python command; webderivemode is python's alias for
 * webagentderivemode. The library holds the ranges, the version gates and
 * which writes are one-way - nothing here repeats them.
 */
const SETTINGS = [
  ['idletimeout', 'lockout', 'minutes idle before the key locks (0 = never)'],
  ['wipemode', 'wipeMode', 'what a wrong-PIN wipe erases (cannot be undone)'],
  ['keytypespeed', 'typeSpeed', 'typing speed for every slot'],
  ['keylayout', 'keyboardLayout', 'the keyboard layout the key types for'],
  ['ledbrightness', 'ledBrightness', 'LED brightness'],
  ['lockbutton', 'lockButton', 'the button that locks the key'],
  ['touchsense', 'touchSense', 'touch sensitivity 2-100, lower is more sensitive'],
  ['backupkeymode', 'backupKeyMode', 'lock the backup key (cannot be undone)'],
  ['sysadminmode', 'modKeyMode', 'sysadmin mode'],
  ['hmackeymode', 'hmacChallengeMode', 'HMAC challenge: button press or none'],
  ['storedkeymode', 'storedChallengeMode', 'how use of a stored key is approved'],
  ['derivedkeymode', 'derivedChallengeMode', 'how use of an SSH/GPG derived key is approved'],
  ['webagentderivemode', 'webAgentDeriveMode', 'how web and agent derived keys are approved (3.0.5+)'],
  ['webderivemode', 'webAgentDeriveMode', 'python\'s older name for webagentderivemode'],
  ['webcryptpolicy', 'webcryptPolicy', 'what the browser may do over FIDO2 (3.0.5+, cannot be undone)'],
];

for (const [name, preference, summary] of SETTINGS) {
  COMMANDS[name] = {
    mirrors: name,
    usage: '<value>',
    writes: true,
    summary,
    preference,
    async run(io, opts, args) {
      if (args.length !== 1 || !/^\d+$/.test(args[0])) throw usage(`${name} takes one number`);
      const value = Number(args[0]);
      return withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, name, { firstUse: true });
        /*
         * A ONE-WAY write asks first. python writes wipemode, backupkeymode
         * and webcryptpolicy as readily as the LED brightness; the library
         * marks them `oneWay` because the firmware gives no way back, so
         * this will not write one without --yes. The row can be absent -
         * webcryptpolicy on a key older than 3.0.5 - and then setPreference
         * refuses it by version without writing anything.
         */
        const row = device.preferences().find((p) => p.name === preference);
        if (row && row.oneWay && !opts.yes) {
          throw usage(`${name} cannot be undone once written. ${row.note || ''} `
            + 'Run it again with --yes to write it.');
        }
        const result = await deviceWrite(() => device.setPreference(preference, value));
        /*
         * A `silent` row has no acknowledgement to print (none of python's
         * commands map to one today); say what was done instead of nothing.
         */
        io.out(result.response !== null ? result.response : `${name} sent (the key does not acknowledge it)`);
        return 0;
      });
    },
  };
}

COMMANDS.settime = {
  mirrors: 'settime',
  summary: 'set the key\'s clock to this computer\'s, and print its status',
  device: true,
  /*
   * OKSETTIME IS OKCONNECT - the same message id, 0xE4 (src/protocol/msg.js)
   * - so every command here already sets the clock when it connects, as
   * every GUI does. python prints the reply, the status line; so does this.
   */
  async run(io, opts) {
    return withDevice(io, opts, ({ connected }) => {
      io.out(connected.status || '');
      return 0;
    });
  },
};

/* ------------------------------------------------------------ writing: keys */

/*
 * The all-FF generate trigger, python's 32 bytes of it. set_private() sums
 * buffer[7..14] and generates when the sum is 2040 (okcore.cpp:4900 at
 * eb25290). The device plugin keeps an 8-byte copy private for its
 * post-quantum generateKey, which is PQC-only (a library gap), so an ECC
 * generation goes through loadKey with this as the "key".
 *
 * loadKey RESENDS a write the key does not acknowledge, and a resent trigger
 * generates again over the first key. That is harmless here - nobody has seen
 * the first key, and the slot ends up holding one random key either way.
 */
const GENERATE_TRIGGER = new Uint8Array(32).fill(0xff);

COMMANDS.genkey = {
  mirrors: 'genkey',
  usage: '<ECC1-16> <x|n|s|c|m|w> [d|s|b]',
  writes: true,
  summary: 'make a new key inside the key (x Ed25519, n P-256, s secp256k1, c Curve25519, m/w post-quantum)',
  async run(io, opts, args) {
    const [slotArg, letter, feat, ...extra] = args;
    if (!slotArg || !letter || extra.length) throw usage('genkey takes a slot, a key type and its features');
    /*
     * ECC slots only. python lets any slot above 100 through, so
     * `genkey HMAC1 x d` sends an Ed25519 generation to HMAC slot 130.
     */
    const key = parseKeySlot(slotArg, ['ecc'], 'genkey');
    if (!['x', 'n', 's', 'c', 'm', 'w'].includes(letter)) {
      throw usage(`genkey makes x (Ed25519), n (NIST P-256), s (secp256k1), c (Curve25519), `
        + `m (ML-KEM-768) or w (X-Wing); got "${letter}"`);
    }
    const pqc = letter === 'm' || letter === 'w';
    let type = KEY_LETTERS[letter];
    if (!pqc) {
      if (feat === undefined) throw usage('genkey needs the key\'s use: d (decryption), s (signing) or b (backup)');
      type |= parseFeatures(feat).bits;
    } else if (feat !== undefined) {
      /* Accepted, as python accepts it; the firmware sets decryption itself (okcrypto.cpp:2059 at eb25290). */
      parseFeatures(feat);
    }

    return withDevice(io, opts, async ({ device, connected, identity }) => {
      requireUnlocked(identity, 'genkey');
      const caps = connected.capabilities || {};
      if (letter === 'c' && !caps.curve25519Keygen) {
        /*
         * The gate python does not have: before 3.0.5 the firmware has no
         * Curve25519 branch, stores the trigger itself as the key, and says
         * "Successfully set ECC Key" (capability curve25519Keygen).
         */
        throw new CliError(`Firmware ${identity.version} cannot generate a Curve25519 key: it would store the `
          + 'same fixed key every such OnlyKey gets, and report success. Nothing was written. Use 3.0.5 or '
          + 'later, or load a key made elsewhere with setkey or loadkey.');
      }
      if (pqc && !caps.postQuantum) {
        throw new CliError(`Firmware ${identity.version} has no post-quantum keys. Nothing was written.`);
      }
      if (pqc) {
        const publicKey = await deviceWrite(() => device.generateKey(key.slot, KEY_LETTERS[letter]));
        /*
         * python prints read_string() here - the first 64 bytes of the public
         * key as text. The key answers with the public key and no sentence, so
         * this says what happened instead.
         */
        io.out(`Successfully generated ${KEY_LETTER_NAMES[letter]} key in ${key.name} `
          + `(public key ${publicKey.length} bytes)`);
        return 0;
      }
      const result = await deviceWrite(() => loadKeyAck(device, key.slot, { type, key: GENERATE_TRIGGER }));
      if (result.response) io.out(result.response);
      return 0;
    });
  },
};

COMMANDS.setkey = {
  mirrors: 'setkey',
  usage: '<RSA1-4|ECC1-16|HMAC1-2> <type> [d|s|b] [hex]  |  <slot> label <text>',
  writes: true,
  summary: 'load a raw private key given in hex (prompted for when left off), or name a key slot',
  async run(io, opts, args) {
    const [slotArg, typeArg, ...rest] = args;
    if (!slotArg || !typeArg) throw usage('setkey takes a slot and a key type');
    const key = parseKeySlot(slotArg, ['rsa', 'ecc', 'hmac'], 'setkey');

    if (typeArg === 'label') {
      /*
       * python computes an HMAC slot's label index too (130 - 72 = 58) and
       * writes a label to a slot that is not one. The key label list has
       * RSA 1-4 and ECC 1-16 only.
       */
      const index = slotsLib.labelIndexForKeySlot(key.slot);
      if (index === null) throw usage(`${key.name} has no label`);
      if (rest.length !== 1) throw usage('setkey <slot> label takes one label - quote one that has spaces');
      try {
        slotConfig.planSlotWrites({ label: rest[0] }, index);
      } catch (err) {
        throw usage(err.message);
      }
      return withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, 'setkey');
        const [applied] = await deviceWrite(() => device.setSlot(index, { label: rest[0] }));
        io.out(applied.response);
        return 0;
      });
    }

    let base;
    if (key.kind === 'rsa') {
      if (!/^[1-4]$/.test(typeArg)) throw usage('an RSA slot takes type 1-4 (RSA 1024, 2048, 3072, 4096)');
      base = Number(typeArg);
    } else if (key.kind === 'ecc') {
      if (!['x', 'n', 's', 'c'].includes(typeArg)) {
        throw usage('an ECC slot takes x, n, s or c here - an m or w key is made on the key with genkey');
      }
      base = KEY_LETTERS[typeArg];
    } else {
      if (typeArg !== 'h') throw usage('an HMAC slot takes type h');
      base = KEY_LETTERS.h;
    }

    const more = rest.slice();
    const features = more.length && own(KEY_FEATURES, more[0]) ? KEY_FEATURES[more.shift()] : null;
    if (more.length > 1) throw usage(`unexpected arguments: ${more.slice(1).join(' ')}`);

    const hex = more.length ? more[0] : await promptSecret(io, 'Key (hex): ', 'key');
    let bytes;
    try {
      bytes = fromHex(hex.trim());
    } catch (err) {
      throw usage(`the key is not hex: ${err.message}`);
    }
    const expected = key.kind === 'rsa' ? 128 * base : key.kind === 'hmac' ? 20 : 32;
    if (bytes.length !== expected) {
      throw usage(`${key.name} type ${typeArg} takes ${expected} bytes (${expected * 2} hex characters); `
        + `got ${bytes.length}`);
    }
    const type = base | (features ? features.bits : 0);
    if (more.length) {
      /* python's form, kept - but it is a private key in the shell history. */
      io.err(`${NAME}: note: a key given on the command line stays in your shell history; `
        + 'leave it off to be prompted for it.');
    }

    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'setkey');
      const result = await deviceWrite(() => loadKeyAck(device, key.slot, { type, key: bytes }));
      if (result.response) io.out(result.response);
      warnPressFree(io, result);
      return 0;
    });
  },
};

COMMANDS.loadkey = {
  mirrors: 'loadkey',
  usage: '<keyfile> [auto|RSA1-4|ECC1-16] [d|s|b]',
  writes: true,
  summary: 'load an armored PGP private key from a file (auto: slot 1 decryption, slot 2 signing)',
  async run(io, opts, args) {
    const [file, slotArg = 'auto', feat, ...extra] = args;
    if (!file || extra.length) throw usage('loadkey takes a key file, and optionally a slot and features');
    const target = slotArg === 'auto' ? null : parseKeySlot(slotArg, ['rsa', 'ecc'], 'loadkey');
    /* python ignores features under auto; they would not be used, so say so. */
    if (!target && feat !== undefined) {
      throw usage('auto sets the uses itself (slot 1 decryption, slot 2 signing); give features with a named slot');
    }
    const features = feat === undefined ? null : parseFeatures(feat);

    let text;
    try {
      text = await io.readFile(file);
    } catch (err) {
      throw new CliError(`cannot read ${file}: ${err.message}`);
    }
    /* Loaded only here: the PGP implementation is 1.2 MB no other command needs. */
    const openpgp = require('../src/crypto/pgp');
    let pgpKey;
    try {
      pgpKey = await openpgp.readPrivateKey({ armoredKey: String(text) });
    } catch (err) {
      throw new CliError(`${file} is not an armored PGP private key (${err.message})`);
    }
    /* Asked only when the key is locked; python asks every time. */
    if (!pgpKey.isDecrypted()) {
      const passphrase = await promptSecret(io, 'Passphrase: ', 'passphrase');
      try {
        pgpKey = await openpgp.decryptKey({ privateKey: pgpKey, passphrase });
      } catch (err) {
        throw new CliError(`could not unlock ${file}: ${err.message}`);
      }
    }

    let candidates;
    try {
      candidates = deviceKeys.fromPgpKey(pgpKey);
    } catch (err) {
      throw new CliError(`cannot load ${file}: ${err.message}`);
    }

    /*
     * The plan, complete, before the key is opened - an unloadable second key
     * fails with nothing written. It is loadPgpKey's own plan (fromPgpKey,
     * assignPgpSlots, prepareKey with autoAssign), stepped here one key at a
     * time so each can be announced before it is written, as python does;
     * loadPgpKey has no per-key hook (a library gap).
     */
    let plan;
    try {
      if (!target) {
        plan = deviceKeys.assignPgpSlots(candidates).map(({ slot, key }) => ({
          material: key,
          ...deviceKeys.prepareKey(key, { slot, autoAssign: true }),
        }));
      } else {
        const primary = candidates[0];
        if ((primary.kind === 'rsa') !== (target.kind === 'rsa')) {
          throw usage(`the primary key is ${primary.kind.toUpperCase()}; name an ${primary.kind === 'rsa'
            ? 'RSA1-RSA4' : 'ECC1-ECC16'} slot for it`);
        }
        /*
         * python defaults an RSA key to d and crashes on an ECC key with none
         * (an odd-length hex type byte); an ECC key's use is asked for.
         */
        if (!features && primary.kind !== 'rsa') {
          throw usage('an ECC key needs its use: d (decryption), s (signing) or b (backup)');
        }
        const roles = (features || KEY_FEATURES.d).roles;
        plan = [{ material: primary, ...deviceKeys.prepareKey(primary, { slot: target.slot, ...roles }) }];
      }
    } catch (err) {
      if (err instanceof CliError) throw err;
      throw new CliError(`cannot load ${file}: ${err.message}`);
    }

    io.out(`Found ${candidates.length} key(s):`);
    candidates.forEach((c, i) => {
      const what = c.kind === 'rsa' ? `RSA ${(c.p.length + c.q.length) * 8} bits` : `ECC ${c.scalar.length} bytes`;
      io.out(`  [${i}] ${i === 0 ? 'Primary Key' : 'Subkey'} - ${what}`);
    });

    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'loadkey');
      if (target && candidates.length > 1) {
        io.out(`Multiple keys found. Loading primary key to slot ${plan[0].slot}.`);
      }
      for (const item of plan) {
        io.out(item.material.kind === 'rsa'
          ? `Loading RSA ${(item.type & 0x0f) * 1024} key to slot ${item.slot}...`
          : `Loading ECC key to slot ${item.slot}...`);
        const result = await deviceWrite(() => loadKeyAck(device, item.slot, { type: item.type, key: item.key }));
        if (result.response) io.out(result.response);
      }
      return 0;
    });
  },
};

COMMANDS.wipekey = {
  mirrors: 'wipekey',
  usage: '<RSA1-4|ECC1-16|HMAC1-2>',
  writes: true,
  summary: 'erase the private key in a key slot, and its label',
  async run(io, opts, args) {
    if (args.length !== 1) throw usage('wipekey takes one key slot');
    const key = parseKeySlot(args[0], ['rsa', 'ecc', 'hmac'], 'wipekey');
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'wipekey');
      /*
       * Two lines, as python prints: the wipe, then the label clear. The
       * library clears the label only after a wipe the key accepted, and
       * never for an HMAC slot, which has none (python writes one to label
       * index 57 or 58).
       */
      const result = await deviceWrite(() => device.wipeKey(key.slot));
      io.out(result.response);
      if (result.label) io.out(result.label);
      return 0;
    });
  },
};

/* ------------------------------------------------------------ main */

/**
 * Run one command line.
 *
 * @param {string[]} argv  the arguments after the program name
 * @param {object} [io]
 * @param {(line: string) => void} [io.out]  one line of output
 * @param {(line: string) => void} [io.err]  one line of error
 * @param {(opts: {path?: string}) => Promise<object>} [io.start]  compose and
 *   open the stack; defaults to startDesktop over node-hid
 * @param {(question: string) => Promise<string>} [io.prompt]  read one secret;
 *   defaults to cli/prompt.js (hidden on a terminal, one stdin line otherwise)
 * @param {(file: string) => Promise<string>} [io.readFile]  read a key file
 * @returns {Promise<number>} the exit code: 0 done, 1 failed, 2 usage
 */
async function main(argv, io = {}) {
  const full = {
    out: io.out || ((line) => process.stdout.write(`${line}\n`)),
    err: io.err || ((line) => process.stderr.write(`${line}\n`)),
    start: io.start || ((opts) => require('./desktop').startDesktop(opts)),
    prompt: io.prompt || ((question) => require('./prompt').promptSecret(question)),
    readFile: io.readFile || ((file) => require('fs').promises.readFile(file, 'utf8')),
  };

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        help: { type: 'boolean', short: 'h' },
        path: { type: 'string' },
        yes: { type: 'boolean' },
      },
    });
  } catch (err) {
    full.err(`${NAME}: ${err.message}`);
    full.err(`Run "${NAME} help" for the commands.`);
    return 2;
  }

  const [name, ...rest] = parsed.positionals;
  if (parsed.values.help || !name) return COMMANDS.help.run(full);

  const cmd = Object.prototype.hasOwnProperty.call(COMMANDS, name) ? COMMANDS[name] : null;
  if (!cmd) {
    full.err(`${NAME}: unknown command "${name}". Run "${NAME} help" for the commands.`);
    return 2;
  }
  if (rest.length && !cmd.usage) {
    full.err(`${NAME}: "${name}" takes no arguments (got: ${rest.join(' ')}).`);
    return 2;
  }

  try {
    return await cmd.run(full, parsed.values, rest);
  } catch (err) {
    /*
     * The key's own "no" is printed where python prints it - stdout - so the
     * line a script greps for is the same line from either CLI.
     */
    if (err instanceof DeviceRefusal) {
      full.out(err.said);
      if (err.hint) full.err(`${NAME}: ${err.hint}`);
      return err.exitCode;
    }
    /*
     * One sentence for the person, the stack only when asked for. The pipe's
     * errors (no key, two keys, no node-hid) are written to be read as-is.
     */
    full.err(`${NAME}: ${err && err.message ? err.message : err}`);
    if (err instanceof CliError && err.exitCode === 2 && cmd.usage) {
      full.err(`Usage: ${NAME} ${name} ${cmd.usage}`);
    }
    if (process.env.ONLYKEY_JS_DEBUG && err && err.stack) full.err(err.stack);
    return err instanceof CliError ? err.exitCode : 1;
  }
}

module.exports = {
  main, COMMANDS, CliError, DeviceRefusal, duoSlotName, classicSlotName, parseSlot, parseKeySlot,
};

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
