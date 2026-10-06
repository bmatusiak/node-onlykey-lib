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
 * AND lib-agent's SSH HALF. `agent` is onlykey-agent: the derived key line,
 * or an ssh-agent serving it (cli/ssh-agent.js, cli/ssh-wire.js), with Node
 * built-ins only - one library then answers ssh as well as the GUIs.
 * And its GPG half: `gpg init` is onlykey-gpg init, `gpg-agent` is
 * onlykey-gpg-agent (cli/gpg-key.js over the vendored openpgp fork,
 * cli/gpg-agent.js and cli/assuan.js on Node built-ins).
 *
 * TWO BUSES. By default a USB key over node-hid; with --ble a phone running
 * ok-rn, over Bluetooth LE (cli/transport-ble.js). The option is global, so
 * every device command - agent and gpg-agent included - takes it unchanged:
 * the bus is below the transport, and nothing above it knows which one it is.
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
 * Which key, and over which bus - the global options every device command
 * shares, as io.start() takes them.
 *
 * --ble reaches a phone running ok-rn over Bluetooth LE (cli/transport-ble.js)
 * instead of a USB key over node-hid; --address picks the phone. Kept in one
 * place because three things must agree on it: the command opening the key,
 * the agent's per-burst reopen (sharedDevice), and the command lines this
 * program writes for gpg to start later (deviceArgs) - a gpg-agent started
 * by gpg with the USB default while the home was made over --ble would ask a
 * key that is not there.
 */
function deviceOpts(opts) {
  return opts.ble ? { ble: true, address: opts.address } : { path: opts.path };
}

/** The same choice as command-line arguments, for a program this one starts later. */
function deviceArgs(opts) {
  if (opts.ble) return ['--ble', ...(opts.address ? ['--address', opts.address] : [])];
  return opts.path ? ['--path', opts.path] : [];
}

/**
 * Compose, open, connect, run `fn`, and always release the key.
 *
 * Every device command goes through here so none can forget the destroy: a
 * held hidapi handle keeps the process alive and the interface busy for the
 * next program that wants it.
 */
async function withDevice(io, opts, fn) {
  const app = await io.start(deviceOpts(opts));
  try {
    const { device, okcrypto, config, transport } = app.services;
    const connected = await device.connect();
    return await fn({ device, okcrypto, config, transport, connected, identity: connected.identity });
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
    io.out(`Usage: ${NAME} <command> [arguments] [--path <hid path> | --ble [--address <phone>]] [--yes]`);
    io.out('');
    io.out('Commands:');
    for (const [name, cmd] of Object.entries(COMMANDS)) {
      io.out(`  ${name.padEnd(14)} ${cmd.summary}${cmd.writes ? '  [writes]' : ''}`);
      if (cmd.usage) io.out(`  ${''.padEnd(14)}   ${name} ${cmd.usage}`);
    }
    io.out('');
    io.out('Options:');
    io.out(`  ${'--path <path>'.padEnd(14)} which OnlyKey, when more than one is plugged in`);
    io.out(`  ${'--ble'.padEnd(14)} reach a phone running ok-rn over Bluetooth LE instead of USB`);
    io.out(`  ${'--address <a>'.padEnd(14)} with --ble: the phone's address or Bluetooth name`);
    io.out(`  ${'--yes'.padEnd(14)} confirm a setting that cannot be undone (wipemode, backupkeymode, webcryptpolicy)`);
    io.out(`  ${'-h, --help'.padEnd(14)} this list`);
    io.out('');
    io.out('[writes] commands change what is on the key; most need it in config mode.');
    io.out('Secrets (password, gkey, totpkey, a PGP passphrase) are prompted for, or read as one');
    io.out('line from stdin when stdin is not a terminal - never taken as arguments. setkey also');
    io.out('takes its hex as an argument, as python\'s does, and prompts for it when left off.');
    io.out('There is no firmware update, backup or restore command; over --ble a firmware update');
    io.out('is refused by the transport itself.');
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

COMMANDS.config = {
  mirrors: '(new)',
  summary: 'the key\'s settings as INI (OKGETCONFIG: an ok-rn soft key with the config plugin only)',
  usage: '[export [file] | import <file> [--one-way]]',
  device: true,
  options: { 'one-way': { type: 'boolean' } },
  /*
   * OKGETCONFIG (owner, 2026-10-02): the soft key prints its settings as INI
   * with this library's preference names, so a file exports and imports with
   * no table in between. A hard key never answers it (not emulated: the app is
   * not in the middle), so this says so instead of guessing values.
   *
   * import is OKSETCONFIG (owner, 2026-10-02: config mode only, in the
   * firmware): the file goes to the key, which hands each value to its own
   * setting write, so the firmware's checks decide. Then the key is read back
   * and each value reported as taken or not. [input] is never sent (the key
   * works it out); [advanced] (one-way) only with --one-way.
   */
  async run(io, opts, args) {
    const [sub = 'export', file] = args;
    if (!['export', 'import'].includes(sub)) throw usage('config takes export [file] or import <file>');
    if (sub === 'import' && !file) throw usage('config import needs the INI file to read');
    if (opts['one-way'] && sub !== 'import') throw usage('--one-way is for config import');
    const fsm = require('fs');
    const parsedFile = sub === 'import' ? iniModule().parse(await io.readFile(file)) : null;
    return withDevice(io, opts, async ({ config, identity }) => {
      requireUnlocked(identity, `config ${sub}`);
      if (sub === 'export') {
        const text = await readConfigText(config);
        if (file) {
          fsm.writeFileSync(file, text.endsWith('\n') ? text : `${text}\n`);
          io.err(`wrote ${file}`);
        } else {
          io.out(text.replace(/\n$/, ''));
        }
        return 0;
      }
      const ini = iniModule();
      const planned = ini.plan(parsedFile, { oneWay: !!opts['one-way'] });
      for (const s of planned.skipped) io.out(`skip  ${s.name}: ${s.why}`);
      for (const n of planned.unknown) io.out(`skip  ${n}: not a setting this library knows`);
      if (!planned.writes.length) { io.out('nothing to import'); return 0; }
      if (!config) throw new CliError('This build of the command line has no config plugin.');
      try {
        await config.write(ini.format(planned));
      } catch (err) {
        if (err.code === 'ECONFIGMODE') {
          throw new CliError('The OnlyKey takes an import only in config mode. Put it in config mode (hold button 6, then your PIN), then run this again.');
        }
        if (err.code === 'EUNSUPPORTED') {
          throw new CliError('This OnlyKey does not answer OKSETCONFIG. Only an ok-rn soft key built with the config plugin does - a hard key never will.');
        }
        throw err;
      }
      /* what took is what the key now says - its own write decided each one */
      const now = await config.read();
      let missed = 0;
      for (const w of planned.writes) {
        const got = (w.oneWay ? now.advanced : now.preferences)[w.name];
        if (got === String(w.value)) io.out(`set   ${w.name}=${w.value}`);
        else { missed++; io.out(`no    ${w.name}=${w.value}: the key kept ${got === undefined ? 'it unset' : got}`); }
      }
      return missed ? 1 : 0;
    });
  },
};

/* the INI module and the plugin's reader, loaded only when `config` runs */
function iniModule() { return require('../src/config/ini'); }
async function readConfigText(config) {
  if (!config) throw new CliError('This build of the command line has no config plugin.');
  try {
    return await config.readText();
  } catch (err) {
    if (err.code === 'EUNSUPPORTED') {
      throw new CliError('This OnlyKey does not answer OKGETCONFIG. Only an ok-rn soft key built with the config plugin does - a hard key never will (it is not emulated, so the app is not in the middle).');
    }
    throw err;
  }
}

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
 * The library's device refusals attach it as `deviceText` (setSlot,
 * setPreference, wipeKey, and since G-3 loadKey and wipeSlot too). An error
 * that does not carry it - a caller's own, or one from a transport - may
 * still end in the device's words, so they are read off the message then.
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
       * EVERY LINE, as python prints them since e6d261c. wipe_slot() answers
       * once per field it erases - ten "Successfully wiped ..." lines, Label
       * through 2FA Key, on 3.x (okcore.cpp wipe_slot at 8d28305) - and the
       * library's wipeSlot collects them all until the device goes quiet.
       */
      const wiped = await deviceWrite(() => device.wipeSlot(slot));
      for (const line of wiped.responses) io.out(line);
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
    /* Checked before connecting, so a usage error never touches the device. */
    let roles = null;
    if (!pqc) {
      if (feat === undefined) throw usage('genkey needs the key\'s use: d (decryption), s (signing) or b (backup)');
      roles = parseFeatures(feat).roles;
    } else if (feat !== undefined) {
      /* Accepted, as python accepts it; the firmware sets decryption itself (okcrypto.cpp:2059 at eb25290). */
      parseFeatures(feat);
    }

    return withDevice(io, opts, async ({ device, connected, identity }) => {
      requireUnlocked(identity, 'genkey');
      const caps = connected.capabilities || {};
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
      /*
       * The library's generateEccKey: python's all-FF trigger, sent ONCE (a
       * resend generates again), and the Curve25519 gate python does not have
       * - before 3.0.5 the firmware stores the trigger itself as the key and
       * says "Successfully set ECC Key" (capability curve25519Keygen). The
       * gate's refusal is a plain Error and reaches the user as its message.
       */
      const result = await deviceWrite(() => device.generateEccKey(key.slot, KEY_LETTERS[letter], roles));
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
      const result = await deviceWrite(() => device.loadKey(key.slot, { type, key: bytes }));
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
        const result = await deviceWrite(() => device.loadKey(item.slot, { type: item.type, key: item.key }));
        if (result.response) io.out(result.response);
      }
      return 0;
    });
  },
};

/*
 * THE BACKUP PASSPHRASE - the desktop App's "Set Backup Passphrase" (python
 * has no command for it). The key never sees the passphrase, only its SHA-256,
 * so the bytes hashed ARE the key: UTF-8 by default, as every new backup is
 * made since 0.4.0.
 *
 * --latin-passphrase is the one-off: the bytes this library hashed up to 0.3.0
 * (and the classic App within Latin-1), truncation above U+00FF included, so a
 * backup made that way can be restored - set the key here, then restore with
 * the passphrase left blank so the key's own backup key is used. It lives
 * ONLY here, never in a GUI and never tried automatically (owner's decision):
 * a special case for a few people, not a choice to show everyone.
 *
 * Asked for twice and never read from argv (cli/prompt.js: argv lands in the
 * shell history). OKSETPRIV needs config mode on a set-up key; outside it the
 * firmware drops the frame without a word, which deviceWrite names.
 */
COMMANDS.setbackuppassphrase = {
  mirrors: '(new)',
  usage: '[--latin-passphrase]',
  writes: true,
  summary: 'set the backup passphrase (config mode; asked for twice); --latin-passphrase: the pre-0.4.0 bytes',
  options: { 'latin-passphrase': { type: 'boolean' } },
  async run(io, opts, args) {
    if (args.length) throw usage('setbackuppassphrase takes no arguments - the passphrase is asked for');
    const legacy = Boolean(opts['latin-passphrase']);
    const encoding = legacy
      ? deviceKeys.PASSPHRASE_ENCODING.TRUNCATED_LEGACY
      : deviceKeys.PASSPHRASE_ENCODING.UTF8;
    const passphrase = await promptSecret(io, 'Backup passphrase: ', 'passphrase');
    const again = await promptSecret(io, 'Again: ', 'passphrase');
    /* Checked before a key is opened: a mismatch or a short one writes nothing. */
    const problems = deviceKeys.validateBackupPassphrase(passphrase, again);
    if (problems.length) throw usage(`${problems.join(' ')} Nothing was written.`);
    if (legacy) {
      io.out('Using the pre-0.4.0 passphrase bytes, only to restore a backup made with them.');
    }
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'setbackuppassphrase');
      const result = await deviceWrite(() => device.setBackupPassphrase(passphrase, { encoding }));
      if (result.response) io.out(result.response);
      return 0;
    });
  },
};

/*
 * KEY CHAIN - generate, list, derive and export keys (owner, 2026-10-01).
 * The same lib calls ok-rn's Key Chain tab makes, so the kit can drive them
 * on the emulator. The rules are Key Chain's:
 *
 *   - made ON the OnlyKey where the firmware can (gen <type> --slot): the
 *     private key never exists anywhere else. Config mode, then a restart
 *     before its public key can be read (the key drops OKGETPUBKEY there).
 *   - made on THIS machine (gen <type> --host) only for what the device
 *     cannot make (RSA, a PGP key) or a key meant to be used elsewhere: in
 *     memory, stored (--slot) and/or exported encrypted (--export-pem /
 *     --export-pgp, passphrase asked twice, the backup passphrase's rule),
 *     then wiped. One of the two is required - a key made and dropped is
 *     nothing.
 *   - a slot that already has a label is refused without --yes: it holds
 *     something, and generating over it destroys it. (In config mode an
 *     UNLABELLED key cannot be seen - the device answers no public-key read
 *     there - so list the slots first.)
 */
const KEYCHAIN_DEVICE_TYPES = {
  ed25519: { ecc: 1, use: 'signature' },
  p256: { ecc: 2, use: 'signature' },
  secp256k1: { ecc: 3, use: 'signature' },
  x25519: { ecc: 4, use: 'decryption' },
  mlkem768: { pq: 5 },
  xwing: { pq: 6 },
};
const KEYCHAIN_SLOTS = [1, 2, 3, 4, ...Array.from({ length: 16 }, (_, i) => 101 + i)];

function keychainSlot(text) {
  const m = /^(?:(rsa|ecc)\s*)?(\d+)$/i.exec(String(text || '').trim());
  if (!m) throw usage(`"${text}" is not a key slot - RSA1-4 or ECC1-16 (or 1-4, 101-116)`);
  let n = Number(m[2]);
  if (m[1] && m[1].toLowerCase() === 'ecc') n += 100;
  if (!KEYCHAIN_SLOTS.includes(n)) throw usage(`"${text}" is not a key slot - RSA1-4 or ECC1-16`);
  return n;
}
const slotName = (n) => (n <= 4 ? `RSA${n}` : `ECC${n - 100}`);

function printArtifacts(io, a) {
  if (a.ssh) io.out(`ssh     ${a.ssh}`);
  if (a.age) io.out(`age     ${a.age}`);
  io.out(`hex     ${a.hex}`);
}

/* the key's Edge plugin over this transport, or null when the key has none (a hard key, a plugin-less build) */
async function edgeOf(transport) {
  let edge = null;
  try {
    require('../plugins/edge')({ transport }, (err, s) => { if (!err) edge = s.edge; });
    if (edge) await edge.head({ timeoutMs: 3000 });
    return edge;
  } catch (_) {
    return null;
  }
}

/* --expires 1y | <n>d | never -> seconds (0 = never); edge-agent and keychain cert */
function parseExpires(text) {
  const t = String(text).trim();
  if (/^(never|0)$/.test(t)) return 0;
  const m = /^(\d+)([yd])$/.exec(t);
  if (!m) throw usage('--expires takes 1y, <n>d (days) or never');
  return Number(m[1]) * (m[2] === 'y' ? 365 : 1) * 86400;
}

COMMANDS.keychain = {
  mirrors: '(new)',
  usage: 'list [--json] | show <label> [--json] | import <file> | export <label|fingerprint> --pgp|--ssh|--age [-o file] | cert <gpg-label> [--expires 1y] [--revoke [--reason N]] [--v2] | slots | pub <slot> | derive <label|ssh|gpg> <type> <label> [--v2] | gen <type> (--slot <slot> | --host ...)',
  writes: true,
  summary: 'Key Chain: the derived keys this machine has used (list, show), the key slots, derive/generate keys',
  options: {
    host: { type: 'boolean' },
    slot: { type: 'string' },
    label: { type: 'string' },
    bits: { type: 'string' },
    'export-pem': { type: 'string' },
    'export-pgp': { type: 'string' },
    'user-id': { type: 'string' },
    v2: { type: 'boolean' },
    json: { type: 'boolean' },
    pgp: { type: 'boolean' },
    ssh: { type: 'boolean' },
    age: { type: 'boolean' },
    output: { type: 'string', short: 'o' },
    expires: { type: 'string' },
    revoke: { type: 'boolean' },
    reason: { type: 'string' },
  },
  async run(io, opts, args) {
    const keychain = require('../src/keychain');
    const [sub, ...rest] = args;

    /*
     * list / show: the host's Key Chain list (~/.onlykey-js/keychain.json) -
     * every derived public key a command on this machine made, read-only and
     * with no device. --json for agents and scripts. Public data only.
     */
    if (sub === 'list' || sub === 'show') {
      const rec = require('./keychain-record');
      const entries = rec.load();
      const pick = sub === 'show' ? entries.filter((e) => e.label === rest[0] || e.id === rest[0]) : entries;
      if (sub === 'show' && (rest.length !== 1)) throw usage('keychain show takes one label (as `keychain list` prints it)');
      if (sub === 'show' && !pick.length) throw new CliError(`no derived key "${rest[0]}" in ${rec.keychainFile()}`);
      const shape = (e) => ({
        label: e.label, scheme: e.scheme, type: e.type, code: e.code, publicKey: Buffer.from(e.publicKey).toString('hex'),
        fingerprint: e.fingerprint || keychain.list.fingerprint(e.publicKey), firstSeen: e.firstSeen, lastSeen: e.lastSeen, tools: e.tools || [],
        ...(sub === 'show' ? { artifacts: e.artifacts || {} } : {}),
      });
      if (opts.json) {
        io.out(JSON.stringify(sub === 'show' ? shape(pick[0]) : pick.map(shape), null, 2));
        return 0;
      }
      if (!pick.length) {
        io.out(`no derived keys recorded yet (${rec.keychainFile()})`);
        return 0;
      }
      if (sub === 'show') {
        const e = shape(pick[0]);
        for (const [k, v] of Object.entries({ label: e.label, type: e.type, code: e.code, fingerprint: e.fingerprint, 'first seen': e.firstSeen, 'last seen': e.lastSeen, 'derived by': e.tools.join(', ') })) io.out(row(k, String(v ?? '')));
        printArtifacts(io, pick[0].artifacts || {});
        return 0;
      }
      for (const e of pick.map(shape)) io.out(`${e.label.padEnd(44)} ${e.type.padEnd(8)} ${e.fingerprint}  ${e.tools.join(', ')}`.trimEnd());
      return 0;
    }

    /*
     * export: what the host list saved for a key - its armored PGP certificate,
     * its authorized_keys line or its age recipient. No device, no press,
     * public only (spec session, 2026-10-03). A derived key has nothing private
     * to export; host-made keys keep their own encrypted-copy flow (gen --host).
     */
    if (sub === 'export') {
      const rec = require('./keychain-record');
      const want = ['pgp', 'ssh', 'age'].filter((k) => opts[k]);
      if (rest.length !== 1 || want.length !== 1) throw usage('keychain export takes one label or fingerprint and one of --pgp, --ssh, --age');
      const key = rest[0].replace(/\s+/g, '').toLowerCase();
      const e = rec.load().find((x) => x.label === rest[0] || x.id === rest[0]
        || String(x.fingerprint || '').replace(/\s+/g, '') === key || String(x.pgpFingerprint || '').toLowerCase() === key);
      if (!e) throw new CliError(`no key "${rest[0]}" in ${rec.keychainFile()} - keychain list shows what is there`);
      const text = want[0] === 'pgp' ? e.pgp : (e.artifacts || {})[want[0]];
      if (!text) {
        throw new CliError(want[0] === 'pgp'
          ? `no certificate saved for ${e.label} - make one: ${NAME} keychain cert ${e.label}`
          : `${e.label} (${e.type}) has no ${want[0]} form`);
      }
      if (opts.output) {
        await io.writeFile(opts.output, text.endsWith('\n') ? text : `${text}\n`);
        io.out(`wrote ${opts.output}`);
      } else {
        io.out(text.replace(/\n$/, ''));
      }
      return 0;
    }

    /*
     * cert: build (or renew) the PGP certificate of a derived gpg identity, or
     * --revoke it. Each self-signature is a PHYSICAL PRESS on the key - never an
     * Edge budget, even under a live one that covers the label (src/keychain/
     * cert.js never ARMs). The certificate is saved into the host list, where
     * `keychain export --pgp` finds it.
     */
    if (sub === 'cert') {
      if (rest.length !== 1) throw usage('keychain cert takes one gpg label: gpg://Name <email>');
      const rec = require('./keychain-record');
      const label = `gpg://${keychain.cert.uidOf(rest[0])}`;
      const saved = rec.load().find((x) => x.label === label && x.type === 'ed25519');
      const version = opts.v2 || (saved && saved.code === 232) ? 2 : 1;
      const expires = opts.expires !== undefined ? parseExpires(opts.expires) : (saved && saved.certExpires) || 0;
      const record = io.keychainRecord || rec.record;
      return withDevice(io, opts, async ({ okcrypto, identity, transport }) => {
        requireUnlocked(identity, 'keychain cert');
        const onPress = () => io.err('keychain: confirm on the OnlyKey (a press)');
        /*
         * Under R16 a press with a key a live budget covers owes a ticket (spec
         * session, 2026-10-03: no firmware exemption). So: refuse while anything
         * is already owed, and ticket our own presses right after (code OK,
         * "cert self-signature <fingerprint>"). A key without Edge skips this.
         */
        const edge = await edgeOf(transport);
        let startSeq;
        try {
          startSeq = await keychain.cert.guardOwed(edge);
        } catch (e) {
          throw new CliError(e.message);
        }
        const ticketOurs = async (fingerprint) => {
          for (const seq of await keychain.cert.ticketOwnPresses(edge, startSeq, fingerprint)) io.out(row('ticketed', `#${seq} (cert self-signature, R16)`));
        };
        const openpgp = require('../src/crypto/pgp');
        if (opts.revoke) {
          if (!saved || !saved.certCreated) throw new CliError(`no certificate saved for ${label} - there is nothing to revoke yet`);
          const r = await keychain.cert.makeRevocation(okcrypto, openpgp, { label, version, created: saved.certCreated, reason: Number(opts.reason) || 0, onPress });
          await ticketOurs(r.fingerprint);
          record({ scheme: 'gpg', label, type: 'ed25519', publicKey: saved.publicKey, code: version === 2 ? 232 : 132, revocation: r.armored, tool: `${NAME} keychain cert` });
          io.out(row('revoked', r.fingerprint));
          if (opts.output) { await io.writeFile(opts.output, r.armored); io.out(`wrote ${opts.output}`); } else io.out(r.armored.replace(/\n$/, ''));
          return 0;
        }
        /* a renewal keeps the creation time, so the fingerprint stays */
        const c = await keychain.cert.makeCertificate(okcrypto, openpgp, { label, version, created: saved && saved.certCreated, expires, onPress });
        await ticketOurs(c.fingerprint);
        record({
          scheme: 'gpg', label, type: 'ed25519', publicKey: c.signPublic, code: version === 2 ? 232 : 132,
          pgp: c.armored, pgpFingerprint: c.fingerprint, certCreated: c.created, certExpires: c.expires, tool: `${NAME} keychain cert`,
        });
        io.out(row('fingerprint', c.fingerprint));
        io.out(row('expires', c.expires ? new Date((c.created + c.expires) * 1000).toISOString().slice(0, 10) : 'never'));
        io.out(`saved - ${NAME} keychain export "${label}" --pgp`);
        return 0;
      });
    }

    /*
     * import: merge another Key Chain file (the phone's export) into this
     * machine's list - one entry per key: a phone's hash:… entry and this list's
     * named entry for the same public key become one, under the name. Public
     * data only (list.parse refuses anything private); "yours" never comes in.
     */
    if (sub === 'import') {
      if (rest.length !== 1) throw usage('keychain import takes one Key Chain file (the phone export)');
      const rec = require('./keychain-record');
      const incoming = keychain.list.parse(await io.readFile(rest[0]));
      const r = keychain.list.merge(rec.load(), incoming);
      rec.save(r.entries);
      io.out(`imported ${rest[0]}: ${r.added} added, ${r.paired} paired with a named entry, ${r.kept} already here`);
      return 0;
    }

    if (sub === 'slots') {
      return withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, 'keychain slots');
        const labels = new Map();
        try {
          const { keys } = await device.readKeyLabels();
          for (const k of keys) labels.set(k.slot, k.label || '');
        } catch (_) { /* names are a nicety; the probe is the answer */ }
        for (const slot of KEYCHAIN_SLOTS) {
          const label = labels.get(slot) || '';
          const tag = keychain.tag.parseTag(label);
          const p = await device.probeKeySlot(slot, { hint: tag && tag.hint });
          const what = p.kind === 'rsa' ? `rsa ${p.bits}` : p.wiped ? 'wiped' : p.kind;
          const fp = p.publicKey ? keychain.list.fingerprint(p.publicKey) : '';
          io.out(`${slotName(slot).padEnd(6)} ${what.padEnd(10)} ${label.padEnd(16)} ${fp}`.trimEnd());
        }
        return 0;
      });
    }

    if (sub === 'pub') {
      if (rest.length !== 1) throw usage('keychain pub takes one slot');
      const slot = keychainSlot(rest[0]);
      return withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, 'keychain pub');
        const p = await device.probeKeySlot(slot);
        if (!p.publicKey) throw new CliError(`${slotName(slot)} is ${p.kind}; there is no public key to show`);
        io.out(`${slotName(slot)} ${p.kind === 'rsa' ? `rsa ${p.bits}` : p.kind}`);
        printArtifacts(io, keychain.artifacts.forKey({ type: p.kind, publicKey: p.publicKey }));
        return 0;
      });
    }

    if (sub === 'derive') {
      const [scheme, type, label, ...extra] = rest;
      if (!scheme || !type || !label || extra.length) throw usage('keychain derive takes a scheme (label, ssh or gpg), a type and a label');
      return withDevice(io, opts, async ({ okcrypto, identity }) => {
        requireUnlocked(identity, 'keychain derive');
        let entry;
        try {
          entry = await keychain.derive.derivePublic(okcrypto, { scheme, type, label, version: opts.v2 ? 2 : 1 });
        } catch (err) {
          if (/derives|scheme|needs a label/.test(err.message)) throw usage(err.message);
          throw err;
        }
        io.out(`derived ${scheme} ${type} "${label}"`);
        printArtifacts(io, entry.artifacts);
        return 0;
      });
    }

    if (sub === 'gen') {
      const [type, ...extra] = rest;
      if (!type || extra.length) throw usage('keychain gen takes one key type');
      return opts.host ? keychainGenHost(io, opts, type, keychain) : keychainGenDevice(io, opts, type);
    }

    throw usage('keychain takes list, show, import, export, cert, slots, pub, derive or gen');
  },
};

async function keychainGenDevice(io, opts, type) {
  const spec = KEYCHAIN_DEVICE_TYPES[type];
  if (!spec) {
    throw usage(`the OnlyKey generates ${Object.keys(KEYCHAIN_DEVICE_TYPES).join(', ')}; for "${type}" use --host`);
  }
  if (!opts.slot) throw usage('keychain gen on the OnlyKey needs --slot (ECC1-16)');
  const slot = keychainSlot(opts.slot);
  if (slot < 101) throw usage('the OnlyKey generates into ECC1-16 only; RSA is made with --host');
  const label = opts.label === undefined ? null : opts.label;
  return withDevice(io, opts, async ({ device, identity }) => {
    requireUnlocked(identity, 'keychain gen');
    const { keys } = await device.readKeyLabels();
    const existing = (keys.find((k) => k.slot === slot) || {}).label;
    if (existing && !opts.yes) {
      throw new CliError(`${slotName(slot)} is named "${existing}" - it holds a key, and generating destroys it. Run again with --yes to replace it.`);
    }
    if (spec.ecc) {
      const r = await deviceWrite(() => device.generateEccKey(slot, spec.ecc, { [spec.use]: true, label }));
      io.out(r.response || `Generated ${type} in ${slotName(slot)}`);
      io.out(`Restart the key (leaving config mode), then: onlykey-js keychain pub ${slotName(slot)}`);
    } else {
      const key = await deviceWrite(() => device.generateKey(slot, spec.pq, { label }));
      const a = require('../src/keychain').artifacts.forKey({ type, publicKey: key });
      io.out(`Generated ${type} in ${slotName(slot)}`);
      printArtifacts(io, a);
    }
    return 0;
  });
}

async function keychainGenHost(io, opts, type, keychain) {
  const store = opts.slot !== undefined;
  const pem = opts['export-pem'];
  const pgpFile = opts['export-pgp'];
  if (!store && !pem && !pgpFile) {
    throw usage('a key made here must be stored (--slot) or exported (--export-pem / --export-pgp) - otherwise it is made and lost');
  }

  if (type === 'pgp') {
    if (pem) throw usage('a PGP key exports with --export-pgp; --export-pem is for a single key');
    if (store && opts.slot !== 'auto') throw usage('a PGP key is stored with --slot auto (decryption in 1, signing in 2, as loadkey does)');
    const userId = opts['user-id'];
    if (!userId) throw usage('a PGP key needs --user-id "Name <email>"');
    const m = /^(.*?)\s*<([^>]+)>\s*$/.exec(userId);
    const uid = m ? { name: m[1], email: m[2] } : { name: userId };
    const bits = opts.bits === undefined ? null : Number(opts.bits);
    if (bits !== null && !keychain.generate.RSA_BITS.includes(bits)) {
      throw usage(`RSA is ${keychain.generate.RSA_BITS.join(', ')} bits`);
    }
    const openpgp = require('../src/crypto/pgp');
    const { privateKey } = await openpgp.generateKey({
      ...(bits ? { type: 'rsa', rsaBits: bits } : { type: 'ecc', curve: 'curve25519' }),
      userIDs: [uid], format: 'object',
    });
    if (pgpFile) {
      const passphrase = await promptSecret(io, 'Passphrase for the copy: ', 'passphrase');
      const again = await promptSecret(io, 'Again: ', 'passphrase');
      const armored = await keychain.export.encryptedPgp(privateKey, passphrase, { confirm: again, openpgp })
        .catch((err) => { throw usage(`${err.message} Nothing was written.`); });
      await io.writeFile(pgpFile, armored);
      io.out(`Encrypted copy written to ${pgpFile}`);
    }
    if (store) {
      await withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, 'keychain gen');
        const loaded = await deviceWrite(() => device.loadPgpKey(privateKey, {}));
        io.out(`Loaded: ${loaded.map((l) => `${l.role} in slot ${l.slot}`).join(', ')}`);
      });
    }
    io.out(privateKey.toPublic().armor().trimEnd());
    return 0;
  }

  let key;
  try {
    key = await keychain.generate.hostKey(type, { bits: opts.bits === undefined ? 2048 : Number(opts.bits) });
  } catch (err) {
    throw usage(err.message);
  }
  try {
    if (pgpFile) throw usage('--export-pgp is for a PGP key (keychain gen pgp --host); a single key exports with --export-pem');
    if (pem) {
      const passphrase = await promptSecret(io, 'Passphrase for the copy: ', 'passphrase');
      const again = await promptSecret(io, 'Again: ', 'passphrase');
      const pemKey = type === 'rsa' ? { type, p: key.p, q: key.q, e: key.e } : { type, secret: key.secret };
      const text = await keychain.export.encryptedPem(pemKey, passphrase, { confirm: again })
        .catch((err) => { throw usage(`${err.message} Nothing was written.`); });
      await io.writeFile(pem, text);
      io.out(`Encrypted copy written to ${pem}`);
    }
    if (store) {
      const slot = keychainSlot(opts.slot);
      if ((slot <= 4) !== (type === 'rsa')) throw usage(type === 'rsa' ? 'an RSA key goes in RSA1-4' : 'an ECC key goes in ECC1-16');
      const use = type === 'x25519' ? { decryption: true } : { signature: true };
      const prepared = deviceKeys.prepareKey(key.material, { slot, ...use });
      await withDevice(io, opts, async ({ device, identity }) => {
        requireUnlocked(identity, 'keychain gen');
        const { keys } = await device.readKeyLabels();
        const existing = (keys.find((k) => k.slot === slot) || {}).label;
        if (existing && !opts.yes) {
          throw new CliError(`${slotName(slot)} is named "${existing}" - it holds a key, and loading over it destroys it. Run again with --yes to replace it.`);
        }
        const r = await deviceWrite(() => device.loadKey(slot, { type: prepared.type, key: prepared.key },
          { label: opts.label === undefined ? null : opts.label }));
        prepared.key.fill(0);
        if (r.response) io.out(r.response);
      });
    }
    io.out(`${type}${type === 'rsa' ? ` ${key.bits}` : ''} public key:`);
    printArtifacts(io, keychain.artifacts.forKey({ type, publicKey: key.publicKey }));
    return 0;
  } finally {
    keychain.generate.wipe(key);
  }
}

/*
 * EDGE FROM A COMPUTER (mcp-service.md 4.7a, step 2): ask the phone's app for
 * a budget over Bluetooth. The request goes to ok-rn, NOT to the key - the
 * phone's vendor bridge keeps OKEDGE_REQUEST (0xF7) for the app, which shows
 * the text and names, and the person presses. Then the opening is read back
 * from the key and checked here (client.js), never taken on the app's word.
 *
 * The agent's own key: an Ed25519 secret in ~/.onlykey-js/edge/agent.key
 * (made on first use, readable by this user only), registered ONCE with the
 * app (`edge register`, a press on the phone). Budgets this computer asked
 * for: ~/.onlykey-js/edge/budgets.json (for continue).
 */
function edgeHome(opts) {
  /* --edge-home, else OKEDGE_HOME, else ~/.onlykey-js/edge - one home for edge, edge-agent and okedge */
  return opts['edge-home'] || require('./edge-control').edgeHome();
}

function edgeAgent(opts) {
  const fsm = require('fs');
  const pathm = require('path');
  const { request } = require('../src/edge');
  const dir = edgeHome(opts);
  fsm.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = pathm.join(dir, 'agent.key');
  if (!fsm.existsSync(file)) {
    fsm.writeFileSync(file, Buffer.from(require('crypto').randomBytes(32)).toString('hex') + '\n', { mode: 0o600 });
  }
  const signer = request.signerFromSecret(Uint8Array.from(Buffer.from(fsm.readFileSync(file, 'utf8').trim(), 'hex')));
  const storeFile = pathm.join(dir, 'budgets.json');
  const read = () => (fsm.existsSync(storeFile) ? JSON.parse(fsm.readFileSync(storeFile, 'utf8')) : {});
  const store = {
    async get(k) { return read()[k] || null; },
    async set(k, v) { const all = read(); all[k] = v; fsm.writeFileSync(storeFile, JSON.stringify(all, null, 2), { mode: 0o600 }); },
  };
  return { signer, store };
}

/* "sign:222:5:ssh://agent@nitro16" -> {op, slot, cap, identity} - the identity keeps its own colons */
function parseScope(text) {
  const m = /^(sign|decrypt):(\d+):(\d+)(?::(.+))?$/.exec(text);
  if (!m) throw usage(`a scope is op:slot:cap[:identity] (e.g. sign:222:5:ssh://agent@host), not "${text}"`);
  return { op: m[1], slot: Number(m[2]), cap: Number(m[3]), ...(m[4] ? { identity: m[4] } : {}) };
}

COMMANDS.edge = {
  mirrors: '(new)',
  usage: 'register <name> | request <reason> <op:slot:cap[:identity]>... --ttl <minutes> | continue <budget> --ttl <minutes> [--caps n,n] | use <budget> <identity> <text> | ticket <budget> <seq> <message> | end <budget>',
  summary: 'Edge: register this computer\'s agent key with ok-rn, ask it for a budget, continue one',
  device: true,
  options: {
    ttl: { type: 'string' },
    caps: { type: 'string' },
    wait: { type: 'string' },
    'edge-home': { type: 'string' },
  },
  async run(io, opts, args) {
    const { client, wire } = require('../src/edge');
    const [sub, ...rest] = args;
    const ttl = () => {
      const n = Number(opts.ttl);
      if (!Number.isInteger(n)) throw usage('--ttl <minutes> is required (1 to 1440) - a budget never falls back to the key\'s default');
      return n;
    };
    if (!['register', 'request', 'continue', 'use', 'ticket', 'end'].includes(sub)) throw usage('edge register | request | continue | use | ticket | end');
    if (sub === 'use' && rest.length !== 3) throw usage('edge use takes a budget id, the identity (ssh://...) and the text to sign');
    if (sub === 'ticket' && rest.length !== 3) throw usage('edge ticket takes a budget id, the seq of the use and the message');
    if (sub === 'end' && rest.length !== 1) throw usage('edge end takes a budget id');
    if (sub === 'register' && rest.length !== 1) throw usage('edge register takes the name the phone shows');
    if (sub === 'request' && rest.length < 2) throw usage('edge request takes a reason and at least one scope');
    if (sub === 'continue' && rest.length !== 1) throw usage('edge continue takes a budget id');
    const { signer, store } = edgeAgent(opts);

    const app = await io.start(deviceOpts(opts));
    try {
      const { transport, device } = app.services;
      await device.connect();
      let edge = null;
      require('../plugins/edge')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
      const channel = wire.createWireChannel(transport, { timeoutMs: (Number(opts.wait) || 120) * 1000 });
      const c = client.createEdgeClient({ edge, channel, signer, store });
      try {
        if (sub === 'register') {
          const keyHex = Buffer.from(signer.publicKey).toString('hex');
          /* the phone's sheet shows the same fingerprint: compare them before you press */
          io.out(row('agent key', require('../src/edge').request.fingerprint(keyHex)));
          io.out(row('full key', keyHex));
          io.out('Check the phone shows the same key, Register there, then press the key...');
          const r = await c.register(rest[0]);
          io.out(r.already ? 'already registered' : 'registered');
          return 0;
        }
        if (sub === 'use') {
          /*
           * One agent sign (P-256, agent v2) paid by the budget: ARM over its
           * head and this request, sign, and the link it caused. The ticket is
           * NOT filed here - `edge ticket` does that - so a use can be left
           * owing on purpose (a test of ticket_owed).
           */
          const { grants } = require('../src/edge');
          const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
          const identity = grants.identityLabel(rest[1]);
          const message = sha256(new TextEncoder().encode(rest[2]));
          const b = await c.resume(Number(rest[0]));
          const { okcrypto } = app.services;
          const { link } = await b.use(new Uint8Array([...message, ...identity]), () => okcrypto.agent.sign(identity, message, { keyType: 2, version: 2 }));
          io.out(row('use', `#${link.seq}${link.paid ? `, paid by budget ${rest[0]} (step ${link.step})` : link.paidBy !== null ? `, paid by another live budget: ${link.paidBy}` : ', not paid by a budget (a direct use)'}`));
          io.out(row('ticket', `owed - file it with: edge ticket ${rest[0]} ${link.seq} "<what happened>"`));
          return 0;
        }
        if (sub === 'ticket') {
          /* the budget ended (a lock, its lifetime, its end) but the key still owes the ticket: file it without one */
          const b = await c.resume(Number(rest[0])).catch((e) => { if (e && e.code === 'EEDGE_GONE') return null; throw e; });
          const r = b
            ? await b.ticket({ seq: Number(rest[1]) }, { code: 'OK', message: rest[2] })
            : await c.ticketOwed(Number(rest[1]), { code: 'OK', message: rest[2] });
          io.out(row('ticket', `filed for #${rest[1]} (the key's head is now #${r.seq})`));
          return 0;
        }
        if (sub === 'end') {
          await (await c.resume(Number(rest[0]))).end();
          io.out(`budget ${rest[0]} ended`);
          return 0;
        }
        io.out('Waiting for the phone - read the request there, then press...');
        const b = sub === 'request'
          ? await c.request({ reason: rest[0], scopes: rest.slice(1).map(parseScope), ttlMinutes: ttl() })
          : await c.continue(Number(rest[0]), { ttlMinutes: ttl(), caps: opts.caps ? opts.caps.split(',').map(Number) : null });
        io.out(row('budget', String(b.grantId)));
        io.out(row('uses', String(b.uses)));
        io.out(row('lifetime', `${ttl()} min`));
        return 0;
      } catch (e) {
        if (e.code === 'EEDGE_REFUSED') { io.err(`refused: ${e.refusal}`); return 1; }
        if (e.code && String(e.code).startsWith('EEDGE_')) { io.err(e.message); return 1; }
        throw e;
      }
    } finally {
      await app.destroy();
    }
  },
};

/*
 * THE AGENT SERVICE (Edge Phase 2; onlykey-edge mcp-service.md §4.2 / §4.2a,
 * decided 2026-10-03). One long-running process, ONE link to the phone, the
 * agent's OWN keys (D2), the work budget, and the endpoints okedge and git
 * use. See cli/edge-agent.js for the rules (one-shot endpoints per exec, the
 * shared endpoint never pays, session-bind pins).
 */
/*
 * PART T (onlykey-edge features/BLUETOOTH-PAIRING-SPEC.md): pair THIS computer
 * user with ok-rn over Bluetooth. Brad opens "Pair a computer" in ok-rn's
 * Bluetooth tab (a ~2-minute window); both sides show the same 6-digit code; he
 * checks it and approves on the phone. Commit-then-reveal: this side commits to
 * its key before it sees the phone's (src/btpair). The pairing is kept in this
 * user's owner-only ~/.onlykey-js/bt-pairing.json - another account on this
 * computer has none and gets silence until it pairs on its own.
 */
COMMANDS.pair = {
  mirrors: '(new)',
  usage: '[--name <computer>]   (with --ble [--address <phone>])',
  summary: 'Part T: pair this computer with ok-rn over Bluetooth (keys in this user\'s home) - the phone shows the same 6-digit code',
  device: false,
  options: { name: { type: 'string' } },
  async run(io, opts) {
    if (!opts.ble) throw usage('pair works over Bluetooth only: onlykey-js --ble [--address <phone>] pair');
    const store = require('./btpair-store');
    const pipe = require('./transport-ble').createBlePipe({ address: opts.address }); /* no pairing yet: the pairing messages themselves */
    await pipe.start();
    try {
      const name = opts.name || store.computerName();
      io.out(`pairing ${name}: on the phone open ok-rn > Bluetooth > Pair a computer (it stays open about 2 minutes)`);
      let result;
      try {
        result = await store.pairOverPipe(pipe, { address: opts.address, name, out: (l) => io.out(l) });
      } catch (e) {
        throw new CliError(e.message);
      }
      io.out(`paired: ${name} with the phone (pairing ${result.record.id.slice(0, 8)}...); from now on this user's Bluetooth commands are encrypted`);
    } finally {
      await pipe.stop();
    }
  },
};

COMMANDS.pairing = {
  mirrors: '(new)',
  usage: '[--forget]   (with --ble --address <phone> to forget that one)',
  summary: 'Part T: this computer user\'s Bluetooth pairings (owner-only ~/.onlykey-js/bt-pairing.json)',
  device: false,
  options: { forget: { type: 'boolean' } },
  async run(io, opts) {
    const store = require('./btpair-store');
    if (opts.forget) {
      store.removePairing(opts.address);
      io.out(`forgot the pairing for ${opts.address || 'the default phone'} (revoke it on the phone too)`);
      return;
    }
    const all = store.list();
    if (!all.length) { io.out(`no pairings for this user on ${store.computerName()} (onlykey-js --ble pair)`); return; }
    for (const r of all) {
      io.out(`${r.name || store.computerName()}  phone ${r.address || '(default)'}  pairing ${String(r.id).slice(0, 8)}...  epoch ${r.epoch}  renewed ${new Date(r.renewedAt).toISOString().slice(0, 10)}`);
    }
  },
};

COMMANDS['edge-agent'] = {
  mirrors: '(new)',
  usage: '[--ssh ssh://user@host --gpg "Name <email>" --committer-name N --committer-email E --expires 1y|<n>d|never]',
  summary: 'Edge: the agent service - the agent\'s own ssh/gpg keys, its work budget, the endpoints okedge uses',
  device: true,
  options: {
    ssh: { type: 'string' },
    gpg: { type: 'string' },
    'committer-name': { type: 'string' },
    'committer-email': { type: 'string' },
    'edge-home': { type: 'string' },
    expires: { type: 'string' },
    wait: { type: 'string' },
  },
  async run(io, opts) {
    const fsm = require('fs');
    const pathm = require('path');
    const { client, wire } = require('../src/edge');
    const { startEdgeAgent } = require('./edge-agent');
    const home = edgeHome(opts);
    if (opts['edge-home']) process.env.OKEDGE_HOME = home; /* okedge and the gpg shim find the same home */
    const cfgFile = pathm.join(home, 'agent.json');
    const config = fsm.existsSync(cfgFile) ? JSON.parse(fsm.readFileSync(cfgFile, 'utf8')) : {};
    if (opts.ssh) config.ssh = opts.ssh;
    if (opts.gpg) config.gpgUid = opts.gpg;
    if (opts['committer-name'] || opts['committer-email']) {
      config.committer = { name: opts['committer-name'] || (config.committer || {}).name, email: opts['committer-email'] || (config.committer || {}).email };
    }
    /* the certificate's lifetime (Brad, 2026-10-03: one year for the real key): 1y, <n>d, or never */
    if (opts.expires !== undefined) config.expires = parseExpires(opts.expires);
    if (!config.ssh) throw usage('the first run needs --ssh ssh://user@host (the agent\'s own SSH identity) and --gpg "Name <email>"');
    const saveConfig = (c) => {
      fsm.mkdirSync(home, { recursive: true, mode: 0o700 });
      fsm.writeFileSync(cfgFile, JSON.stringify(c, null, 2), { mode: 0o600 });
    };
    saveConfig(config);
    const { signer, store } = edgeAgent(opts);

    const app = await io.start(deviceOpts(opts));
    try {
      const { transport, device, okcrypto } = app.services;
      await device.connect();
      let edge = null;
      require('../plugins/edge')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
      /* the phone gives the person 2 min to say Yes, then the key 25 s for the press (ok-rn, 2026-10-03) - wait past both */
      /* the envelope's dev: this computer's Part T pairing id (stable); stale answers are logged */
      const wired = wire.createWireChannel(transport, {
        timeoutMs: (Number(opts.wait) || 180) * 1000,
        device: () => (typeof transport.deviceId === 'function' ? transport.deviceId() : null),
        log: (l) => io.err(`edge-agent: ${l}`),
      });
      /*
       * OKEDGE_TIMES=1: every key request, sign and message to the phone, with how
       * long it took (Brad, 2026-10-06: where a signed commit's 7 s go). Times and
       * request names only.
       */
      const times = process.env.OKEDGE_TIMES === '1';
      const SUBNAMES = Object.fromEntries(Object.entries(edge.SUB || {}).map(([k, v]) => [v, k]));
      if (times) edge.onTiming = (sub, ms, ok) => io.err(`edge-agent: time key ${SUBNAMES[sub] || sub} ${ms} ms${ok ? '' : ' (failed)'}`);
      const channel = times
        ? { send: async (m, o) => { const t = Date.now(); try { return await wired.send(m, o); } finally { io.err(`edge-agent: time phone ${(m && m.type) || 'message'} ${Date.now() - t} ms`); } } }
        : wired;
      const timedCrypto = times
        ? { ...okcrypto, agent: { ...okcrypto.agent, sign: async (...a) => { const t = Date.now(); try { return await okcrypto.agent.sign(...a); } finally { io.err(`edge-agent: time key SIGN ${Date.now() - t} ms`); } } } }
        : okcrypto;
      const c = client.createEdgeClient({ edge, channel, signer, store });
      const svc = await startEdgeAgent({
        okcrypto: timedCrypto, client: c, edge, config, saveConfig, openpgp: require('../src/crypto/pgp'),
        shimCommand: pathm.resolve(__dirname, 'edge-gpg-shim.js').split(pathm.sep).join('/'),
        log: (l) => io.err(`edge-agent: ${l}`),
        confirm: () => io.err('edge-agent: confirm on the OnlyKey (a press)'),
        selfName: opts.address || null,
        linkStats: () => (typeof transport.linkStats === 'function' ? transport.linkStats() : null),
        /* a request nobody answered: let the Bluetooth link go (the next one connects fresh, hello first) */
        onSilence: opts.ble ? async () => { await transport.release('nobody answered').catch(() => {}); } : null,
        /* R29 (okedge sibling add): a second link, to the other phone, for one request */
        openOther: async (address) => {
          if (!opts.ble) throw new Error('pairing another phone needs --ble (the other phone is reached over Bluetooth)');
          const app2 = await io.start(deviceOpts({ ...opts, address }));
          try {
            await app2.services.device.connect();
            let edge2 = null;
            require('../plugins/edge')({ transport: app2.services.transport }, (err, s) => { if (err) throw err; edge2 = s.edge; });
            const channel2 = wire.createWireChannel(app2.services.transport, { timeoutMs: (Number(opts.wait) || 180) * 1000 });
            return { edge: edge2, client: client.createEdgeClient({ edge: edge2, channel: channel2, signer, store }), close: () => app2.destroy() };
          } catch (e) {
            await app2.destroy().catch(() => undefined);
            throw e;
          }
        },
      });
      io.out(row('ssh key', svc.sshLine));
      if (svc.fingerprint) io.out(row('gpg key', svc.fingerprint));
      /* the certificate into the host's Key Chain list too, so `keychain export --pgp` prints it (spec session, step 3) */
      if (io.keychainRecord && config.cert && config.gpgUid) {
        try {
          io.keychainRecord({
            scheme: 'gpg', label: `gpg://${config.gpgUid}`, type: 'ed25519', publicKey: config.cert.signPublic, code: 232,
            pgp: config.cert.armored, pgpFingerprint: config.cert.fingerprint, certCreated: config.cert.created,
            certExpires: config.cert.expires || 0, tool: 'onlykey-js edge-agent',
          });
        } catch (e) {
          io.err(`edge-agent: the certificate was not recorded in the Key Chain list (${e.message})`);
        }
      }
      if (svc.certArmored) {
        fsm.writeFileSync(pathm.join(home, 'agent-gpg.asc'), svc.certArmored);
        io.out(row('gpg cert', pathm.join(home, 'agent-gpg.asc')));
      }
      io.out(row('ssh agent', `${svc.sharedPath}  (shared: every sign here asks for a press)`));
      io.out(row('control', svc.controlPath));
      io.out('ready - okedge budget / exec / ticket; Ctrl-C to stop');
      /*
       * RELEASE WHEN IDLE (Brad, 2026-10-06): the link is let go once the key's
       * lane has been quiet this long - nothing running, nothing waiting (a press
       * wait and a budget sheet both sit in the lane, so neither is cut). The
       * phone goes back to advertising; the next request connects fresh and says
       * hello first, so a link the phone no longer holds a session for never
       * outlives one burst.
       */
      /* 60 s (Brad, 2026-10-06: both ends recover on their own now, so a working session stays connected) */
      const IDLE_MS = Number(process.env.OKEDGE_IDLE_MS) || 60000;
      const idleTick = opts.ble && typeof transport.laneState === 'function'
        ? setInterval(() => {
          const st = transport.laneState();
          if (st.idle && Date.now() - st.since >= IDLE_MS && transport.isOpen()) void transport.release('idle').catch(() => {});
        }, 1000)
        : null;
      if (idleTick && idleTick.unref) idleTick.unref();
      await new Promise((resolve) => {
        process.once('SIGINT', resolve);
        process.once('SIGTERM', resolve);
      });
      await svc.close();
      return 0;
    } finally {
      await app.destroy();
    }
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

/* ------------------------------------------------------------ ssh agent */

/**
 * The key, opened when an agent request needs it and let go when idle.
 *
 * WHY NOT withDevice() PER REQUEST. That would release the key between two
 * signatures, and the stale-timer guard in plugins/okcrypto
 * (settleStaleTimers) lives in ONE okcrypto instance: a fresh stack per
 * signature forgets the last one ended and cannot wait out the firmware's
 * leftover fade timers - the measured failure where the second signature of
 * a run times out. A `git fetch` over ssh signs more than once in a second.
 *
 * WHY NOT HOLD IT FOR THE AGENT'S LIFE. A held hidapi handle keeps the vendor
 * interface busy (see withDevice): with an agent running all day, onlykey-js,
 * the desktop app and lib-agent itself could not reach the key. lib-agent
 * opens per request for the same reason (JustInTimeConnection).
 *
 * So: one session for a burst, released after `idleMs` with nothing asked -
 * longer than the 6 s stale-timer window, so a request after a release never
 * needed the guard anyway. A failed operation releases at once: the next
 * request reconnects and reads the key's state afresh (it may have been
 * unlocked since, or replugged).
 */
function sharedDevice(io, opts, { idleMs = 10000 } = {}) {
  let opening = null;
  let timer = null;

  async function release() {
    clearTimeout(timer);
    const was = opening;
    opening = null;
    if (!was) return;
    try { await (await was).app.destroy(); } catch { /* it never opened, or is gone */ }
  }

  function open() {
    if (!opening) {
      opening = (async () => {
        const app = await io.start(deviceOpts(opts));
        try {
          const connected = await app.services.device.connect();
          return { app, identity: connected.identity };
        } catch (err) {
          await app.destroy().catch(() => {});
          throw err;
        }
      })();
      opening.catch(() => { opening = null; });
    }
    return opening;
  }

  async function use(fn) {
    clearTimeout(timer);
    try {
      const { app, identity } = await open();
      requireUnlocked(identity, 'agent');
      const out = await fn(app.services.okcrypto, app.services);
      timer = setTimeout(release, idleMs);
      if (timer.unref) timer.unref();
      return out;
    } catch (err) {
      await release();
      throw err;
    }
  }

  return { use, release };
}

/*
 * lib-agent's --skey values that name the DERIVED key (libagent/device/
 * onlykey.py convert_keyslot, _parse_slot_value): ECC32 / 132 is v1, the
 * default; derived-v2 / ECC32v2 / 232 is v2 (3.0.5 on).
 *
 * ECC1-16 - a key STORED in a slot - for gpg only (allowSlot; owner,
 * 2026-10-03: a PGP pair made in Key Chain, ECC2 signing and ECC1 decrypt,
 * signing git commits). -> {slot: 101..116, name}. Not for the ssh agent yet.
 */
function parseSkey(value, flag = '--skey', command = 'agent', { allowSlot = false } = {}) {
  const v = String(value).toLowerCase();
  if (['ecc32', '132', 'derived', 'derived-v1'].includes(v)) return 1;
  if (['derived-v2', 'ecc32v2', '232'].includes(v)) return 2;
  const ecc = /^ecc([1-9]|1[0-6])$/.exec(v);
  if (ecc && allowSlot) return { slot: 100 + Number(ecc[1]), name: `ECC${ecc[1]}` };
  if (/^(ecc([1-9]|1[0-6])|rsa[1-4])$/.test(v)) {
    throw usage(`${flag} ${value}: a key stored in an ECC slot (or an RSA slot) is not supported by "${NAME} ${command}" yet; `
      + 'it uses the derived key (ECC32, or derived-v2)');
  }
  throw usage(`${flag} takes ECC32 (derived v1, the default) or derived-v2, not "${value}"`);
}

/* `-e`: lib-agent's curve names, and the ssh name for P-256 as a convenience. */
function parseCurve(value) {
  const v = String(value).toLowerCase();
  if (v === 'ed25519') return 'ed25519';
  if (v === 'nist256p1' || v === 'nistp256') return 'nist256p1';
  throw usage(`-e takes ed25519 or nist256p1, not "${value}" (ssh has no key type for the other derivations)`);
}

/*
 * python ssh_args(): ssh to the identity, offering ONLY its key - an
 * IdentityFile holding the public half (ssh then asks the agent for the
 * matching private operation) and IdentitiesOnly, so ssh does not first try
 * every other key it can find and trip the server's MaxAuthTries.
 */
function sshArgs(id, pubFile) {
  const args = [];
  if (id.port) args.push('-p', id.port);
  if (id.user) args.push('-l', id.user);
  args.push('-o', `IdentityFile=${pubFile}`, '-o', 'IdentitiesOnly=true');
  return [...args, id.host];
}

/** What to tell a shell so ssh finds this agent. */
function agentEnvLines(sockPath, windows) {
  if (!windows) return { out: `SSH_AUTH_SOCK=${sockPath}; export SSH_AUTH_SOCK;`, notes: [] };
  return {
    out: `$env:SSH_AUTH_SOCK = '${sockPath}'`,
    notes: [
      `for Windows OpenSSH (ssh.exe, ssh-add.exe): set SSH_AUTH_SOCK as above (cmd: set SSH_AUTH_SOCK=${sockPath}),`,
      `or pass -o IdentityAgent=${sockPath} to ssh. Git Bash's own ssh cannot use a named pipe.`,
    ],
  };
}

COMMANDS.agent = {
  mirrors: 'onlykey-agent (lib-agent)',
  usage: '<[ssh://][user@]host | identity file> [-e ed25519|nist256p1] [--skey ECC32|derived-v2] '
    + '[-f | -s | -c | -- command...] [--sock-path <path>]',
  summary: 'SSH keys derived in the key: print the public key, or serve them as an ssh-agent',
  device: true,
  /*
   * lib-agent's names where it has one: -e/--ecdsa-curve-name, --skey (its
   * short form is `-sk`, which is two flags to every parser but argparse),
   * -f/--foreground, -s/--shell, -c/--connect, --sock-path. Not carried:
   * --daemonize (python-daemon's double fork; a Node process backgrounds
   * with the shell's `&` or a service manager), --mosh, and python's
   * --timeout/--debug/--log-file (stderr says what happened here).
   */
  options: {
    'ecdsa-curve-name': { type: 'string', short: 'e' },
    skey: { type: 'string' },
    foreground: { type: 'boolean', short: 'f' },
    shell: { type: 'boolean', short: 's' },
    connect: { type: 'boolean', short: 'c' },
    'sock-path': { type: 'string' },
  },
  /**
   * lib-agent's surface, one mode per run:
   *
   *   agent <identity>                  print its public key line; exit
   *   agent <identity> -f               serve until Ctrl-C, printing the
   *                                     SSH_AUTH_SOCK line to eval
   *   agent <identity> -- <command...>  serve while <command> runs with
   *                                     SSH_AUTH_SOCK set, exit with its code
   *   agent <identity> -s               the same, with $SHELL as the command
   *   agent <identity> -c [ssh args]    the same, with ssh to the identity
   *
   * <identity> is lib-agent's `[ssh://][user@]host[:port][/path]`, or a file
   * of `<identity|curve>` entries (python's form: an absolute path) - which
   * is how one agent serves several identities.
   */
  async run(io, opts, args) {
    const wire = require('./ssh-wire');
    const agentSrv = require('./ssh-agent');
    const [target, ...command] = args;
    if (!target) throw usage('agent needs an identity: [user@]host, or a file of <identity|curve> entries');

    const curve = opts['ecdsa-curve-name'] ? parseCurve(opts['ecdsa-curve-name']) : 'ed25519';
    const version = opts.skey ? parseSkey(opts.skey) : 1;
    const modes = ['foreground', 'shell', 'connect'].filter((m) => opts[m]);
    if (modes.length > 1) throw usage(`-f, -s and -c are one mode each; got ${modes.map((m) => `--${m}`).join(' ')}`);
    if (command.length && (opts.foreground || opts.shell)) throw usage(`--${modes[0]} takes no command`);

    let entries;
    if (require('path').isAbsolute(target)) {
      const text = await io.readFile(target);
      entries = wire.parseIdentityFile(text);
      if (!entries.length) throw new CliError(`${target} has no <identity|curve> entries`);
    } else {
      entries = [{ identity: wire.parseIdentity(target), curve }];
    }
    if (opts.connect && entries.length !== 1) throw usage('-c connects to ONE identity; the file names several');

    const dev = sharedDevice(io, opts);
    const keys = [];
    try {
      /*
       * Every public key up front - no press is needed for one - so a locked
       * key, firmware without v2, or an identity lib-agent could not hash
       * either fails HERE, before a socket exists or SSH_AUTH_SOCK is
       * printed, rather than as a bare "agent refused operation" inside ssh.
       */
      await dev.use(async (okcrypto) => {
        for (const e of entries) {
          const keyType = wire.CURVES[e.curve].keyType;
          const raw = await okcrypto.agent.publicKey(wire.derivationIdentity(e.identity), { keyType, version });
          keys.push({ ...e, raw, keyType, comment: wire.identityComment(e.identity, e.curve) });
        }
      });
    } catch (err) {
      await dev.release();
      throw err;
    }

    const serving = modes.length || command.length;
    if (!serving) {
      await dev.release();
      for (const k of keys) io.out(wire.publicKeyLine(k.curve, k.raw, k.comment));
      return 0;
    }

    /*
     * What the key will ask for, so the prompt says only that (the ssh practice,
     * 2026-10-02: in single-press mode it printed a code first). Read from the
     * soft key's OKGETCONFIG and kept a minute; a key that has no OKGETCONFIG -
     * every hard key - gives null, and the prompt names both, as before.
     */
    let mode = { at: 0, value: null };
    const derivedMode = async (services) => {
      if (Date.now() - mode.at < 60000) return mode.value;
      let value = null;
      try { value = services.config ? (await services.config.read({ timeoutMs: 1500 })).input.derived_keys || null : null; } catch (_) { value = null; }
      mode = { at: Date.now(), value };
      return value;
    };
    const sign = (key, data) => dev.use(async (okcrypto, services) => {
      const asks = await derivedMode(services);
      /*
       * THE BYTES SENT ARE lib-agent's: the data ssh asked to have signed,
       * then the identity hash (onlykey.py sign(): raw_message = blob + data).
       * For Ed25519 the device runs the whole of EdDSA over it. For ECDSA it
       * signs SHA-256 of any message that is not 32 or 64 bytes long, and a
       * 32- or 64-byte one AS GIVEN - so such a message is hashed here first,
       * which the device then signs as given: the same SHA-256 either way.
       * ssh's data never is that short (a session id alone is 32), but a
       * signature over the wrong thing would be a silent refusal at the
       * server, so it is not left to "never".
       */
      let message = data;
      if (key.keyType === 2 && (data.length === 32 || data.length === 64)) {
        message = require('crypto').createHash('sha256').update(data).digest();
      }
      return okcrypto.agent.sign(wire.derivationIdentity(key.identity), message, {
        keyType: key.keyType,
        version,
        /* the key is still clearing a request whose press timed out (its 5-second wipe) */
        onBusy: ({ waitMs }) => io.err(`The OnlyKey is still clearing an unanswered request; trying again in ${Math.round(waitMs / 1000)} s`),
        confirm: ({ digits }) => {
          if (asks === 'none') return; /* the key signs without asking */
          if (asks === 'press') io.err(`Confirm on the OnlyKey to sign for ${key.comment}: press any button`);
          else if (asks === 'code') io.err(`Confirm on the OnlyKey to sign for ${key.comment}: enter ${digits.join(' ')}`);
          else {
            io.err(`Confirm on the OnlyKey to sign for ${key.comment}: enter ${digits.join(' ')}`
              + ' (or press any button, if the key asks for a single press)');
          }
        },
      });
    });

    const handler = agentSrv.createAgentHandler({ keys, sign, log: (line) => io.err(`${NAME} agent: ${line}`) });
    const where = opts['sock-path'] ? agentSrv.resolveAgentPath(opts['sock-path']) : agentSrv.defaultAgentPath();
    let server;
    try {
      server = await agentSrv.serveAgent({ handler, where, log: (line) => io.err(`${NAME} ${line}`) });
    } catch (err) {
      where.cleanup();
      await dev.release();
      throw err;
    }
    const env = agentEnvLines(server.path, agentSrv.IS_WINDOWS);
    let pubDir = null;

    try {
      if (opts.foreground) {
        io.out(env.out);
        for (const n of env.notes) io.err(`${NAME}: ${n}`);
        io.err(`${NAME}: serving ${keys.length} key(s) on ${server.path}; Ctrl-C to stop`);
        await (io.untilStopped || untilSignalled)(server);
        return 0;
      }

      let argv = command;
      if (opts.shell) {
        argv = [process.env.SHELL || process.env.COMSPEC || (agentSrv.IS_WINDOWS ? 'cmd.exe' : '/bin/sh')];
      } else if (opts.connect) {
        const fsm = require('fs');
        pubDir = fsm.mkdtempSync(require('path').join(require('os').tmpdir(), 'onlykey-js-pub-'));
        const pubFile = require('path').join(pubDir, 'id.pub');
        fsm.writeFileSync(pubFile, `${wire.publicKeyLine(keys[0].curve, keys[0].raw, keys[0].comment)}\n`, { mode: 0o600 });
        argv = ['ssh', ...sshArgs(keys[0].identity, pubFile), ...command];
      }
      return await (io.runCommand || runWithAgent)(argv, { SSH_AUTH_SOCK: server.path, SSH_AGENT_PID: String(process.pid) });
    } finally {
      await server.close();
      await dev.release();
      if (pubDir) require('fs').rmSync(pubDir, { recursive: true, force: true });
    }
  },
};

/* ------------------------------------------------------------ gpg */

/*
 * lib-agent's GPG HALF: `gpg init` is `onlykey-gpg init`, `gpg-agent` is
 * `onlykey-gpg-agent` - two commands because they are two programs with two
 * callers. A person runs init once; gpg itself runs the agent (gpg.conf's
 * agent-program), whenever it needs a private key and finds none answering.
 * The OpenPGP side is cli/gpg-key.js, the agent cli/gpg-agent.js.
 */

const IS_WINDOWS_CLI = process.platform === 'win32';

/* The comment line init writes into run-agent.sh: how --force knows a home is ours to replace. */
const GPG_HOME_MARK = `# written by ${NAME} gpg init`;

/** lib-agent's default homedir: ~/.gnupg/<device name>. */
function defaultGpgHome() {
  return require('path').join(require('os').homedir(), '.gnupg', 'onlykey');
}

/*
 * -t/--time: the creation time, seconds since the epoch. lib-agent's default
 * is 0 - the key and every self-signature dated 1970-01-01 - and that is
 * deliberate: the fingerprint covers the creation time, so a fixed time is
 * what makes init on another machine give back the SAME key. Kept.
 */
function parseTime(value) {
  if (value === undefined) return 0;
  if (!/^\d{1,10}$/.test(String(value)) || Number(value) > 0xffffffff) {
    throw usage(`-t/--time takes seconds since the epoch (0 to ${0xffffffff}), not "${value}"`);
  }
  return Number(value);
}

/** Quote for a POSIX shell: single quotes, a ' as '\''. */
const shQuote = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;

/**
 * gpg, run to completion. `io.gpg` in a test; the one on PATH otherwise.
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
function runGpg(io, args) {
  if (io.gpg) return io.gpg(args);
  const { spawnSync } = require('child_process');
  const r = spawnSync(require('./gpg-agent').gnupgProgram('gpg'), args, { encoding: 'utf8', timeout: 60000 });
  if (r.error) return Promise.resolve({ code: 127, stdout: '', stderr: r.error.message });
  return Promise.resolve({ code: r.status === null ? 1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' });
}

/*
 * The agent program gpg.conf names, in the homedir. gpg starts it with
 * gpg-agent's own arguments (--homedir, --daemon, ...), which it ignores:
 * everything it needs is written here, with ABSOLUTE paths to this node and
 * this CLI, because gpg starts it with whatever PATH gpg had - lib-agent
 * bakes its PATH into the script for the same reason.
 */
function agentScript(homedir, skey, dkey, windows, device = []) {
  const node = process.execPath;
  const cli = require('path').resolve(__filename);
  /*
   * `device` is deviceArgs(): the bus and key `gpg init` used. gpg starts
   * this script later with none of our options, so a home made over --ble
   * must say --ble here, or its agent would go looking for a USB key.
   */
  const args = ['gpg-agent', '--homedir', homedir, '--skey', skey, '--dkey', dkey, ...device, '--daemon'];
  /*
   * NODE_PATH, when init ran with one: gpg starts this script with ITS
   * environment, and the optional BLE package (@stoprocent/noble) is an
   * optional peer that may live outside the lib (owner, 2026-10-03:
   * ~/.onlykey-js/node_modules) - without it the agent's --ble cannot load.
   */
  const nodePath = process.env.NODE_PATH;
  if (windows) {
    return {
      name: 'run-agent.cmd',
      text: `@echo off\r\nrem ${GPG_HOME_MARK.slice(2)}: gpg.conf's agent-program.\r\n`
        + (nodePath ? `set "NODE_PATH=${nodePath}"\r\n` : '')
        + `"${node}" "${cli}" ${args.map((a) => (a === homedir || /\s/.test(a) ? `"${a}"` : a)).join(' ')}\r\n`,
    };
  }
  return {
    name: 'run-agent.sh',
    text: `#!/bin/sh\n${GPG_HOME_MARK}: gpg.conf's agent-program. gpg starts it the first time\n`
      + '# it needs a private key; it serves until `gpgconf --kill gpg-agent`.\n'
      + (nodePath ? `NODE_PATH=${shQuote(nodePath)}\nexport NODE_PATH\n` : '')
      + `exec ${[node, cli, ...args].map(shQuote).join(' ')}\n`,
  };
}

COMMANDS.gpg = {
  mirrors: 'onlykey-gpg init (lib-agent)',
  usage: 'init "<user id>" [-e ed25519|nist256p1] [-t <time>] [--homedir <dir>] '
    + '[--skey ECC32|derived-v2|ECC1-16] [--dkey ECC32|derived-v2|ECC1-16] [--import-pub <key.asc>] [--force]',
  summary: 'a GPG key derived in the key: print it, and make a GnuPG home that uses it',
  device: true,
  /*
   * lib-agent's names: -e/--ecdsa-curve (here also -e's long name from
   * `agent`), -t/--time, --homedir, --skey/--dkey (its -sk/-dk are two
   * flags to every parser but argparse). Not carried: -s/--subkey (adding
   * device subkeys to an EXISTING gpg key, which signs through the real
   * gpg-agent) and -i/--import-pub (a key loaded into a slot) - neither is a
   * derived key; and -v, since stderr says what happened here. New:
   * --force, to replace a home this command made.
   */
  options: {
    'ecdsa-curve-name': { type: 'string', short: 'e' },
    'ecdsa-curve': { type: 'string' },
    time: { type: 'string', short: 't' },
    homedir: { type: 'string' },
    skey: { type: 'string' },
    dkey: { type: 'string' },
    /* a slot pair's certificate, already made (Key Chain -> Share PGP public key): imported, never re-signed */
    'import-pub': { type: 'string' },
    force: { type: 'boolean' },
  },
  /**
   * `gpg init "<user id>"`, lib-agent's run_init():
   *
   *   1. the two public keys, derived from "gpg://<user id>" (no press);
   *   2. the certificate, with its two self-signatures made by the device
   *      (two confirmations);
   *   3. the homedir: run-agent.sh, gpg.conf (agent-program, default-key),
   *      env, pubkey.asc - then gpg imports the key and trusts it
   *      ultimately (it is the person's own).
   *
   * The armored key is printed on stdout. Unlike lib-agent, init does not
   * end by listing the secret keys - which starts the agent and leaves it
   * running; the agent starts the first time gpg needs it.
   */
  async run(io, opts, args) {
    const fsm = require('fs');
    const pathm = require('path');
    const gpgKey = require('./gpg-key');
    const agentProto = require('../src/protocol/agent');

    const [action, givenUserId, ...extra] = args;
    if (action !== 'init') throw usage('gpg takes one action: init "<user id>"');
    if (extra.length) throw usage(`gpg init takes ONE user id - quote it: "${args.slice(1).join(' ')}"`);
    const slotMode = /^ecc([1-9]|1[0-6])$/i.test(String(opts.skey || '')) || /^ecc([1-9]|1[0-6])$/i.test(String(opts.dkey || ''));
    let userId = givenUserId;
    if (!slotMode) {
      if (!userId) throw usage('gpg init needs a user id, e.g. "Alice <alice@example.com>"');
      try {
        agentProto.identityHash({ gpg: userId });
      } catch (err) {
        throw usage(err.message);
      }
    }
    const curve = parseCurve(opts['ecdsa-curve'] || opts['ecdsa-curve-name'] || 'ed25519');
    const created = parseTime(opts.time);
    const skeyName = opts.skey || 'ECC32';
    const dkeyName = opts.dkey || 'ECC32';
    const skey = parseSkey(skeyName, '--skey', 'gpg', { allowSlot: true });
    const dkey = parseSkey(dkeyName, '--dkey', 'gpg', { allowSlot: true });
    if (slotMode && (typeof skey !== 'object' || typeof dkey !== 'object')) {
      throw usage('a key pair stored in slots takes both: --skey ECC<n> (signing) and --dkey ECC<n> (decrypt), e.g. --skey ECC2 --dkey ECC1');
    }
    if (slotMode && !opts['import-pub']) {
      throw usage('a key pair stored in slots already has its certificate: pass --import-pub <its .asc> '
        + '(Key Chain -> Share PGP public key). Re-signing would make a different PGP key - the fingerprint covers the creation time');
    }
    const homedir = pathm.resolve(opts.homedir || process.env.GNUPGHOME || defaultGpgHome());

    /*
     * gpg first, as lib-agent's verify_gpg_version(): with no gpg, or one
     * older than 2.1.11 (no agent-program, no keygrip-addressed agent),
     * there is nothing to set up, and finding out AFTER two confirmations
     * on the key would waste them.
     */
    const ver = await runGpg(io, ['--version']);
    const m = /^gpg \(GnuPG[^)]*\)\s+(\d+)\.(\d+)\.(\d+)/m.exec(ver.stdout);
    if (ver.code !== 0 || !m) throw new CliError(`gpg is needed and did not run: ${(ver.stderr || ver.stdout).trim().split('\n')[0]}`);
    const [maj, min, pat] = m.slice(1).map(Number);
    if (maj < 2 || (maj === 2 && (min < 1 || (min === 1 && pat < 11)))) {
      throw new CliError(`GnuPG ${m.slice(1).join('.')} is too old: the agent needs 2.1.11 or later`);
    }

    /*
     * An existing home is refused, as lib-agent refuses it: it may hold
     * someone's keys. --force replaces only a home THIS command made (its
     * run-agent script carries the mark) - and only after the new key is
     * made, so a refused confirmation leaves the old home as it was.
     */
    const script = agentScript(homedir, skeyName, dkeyName, IS_WINDOWS_CLI, deviceArgs(opts));
    if (fsm.existsSync(homedir)) {
      if (!opts.force) throw new CliError(`GPG home directory ${homedir} exists; remove it, or pass --force to replace a home ${NAME} made`);
      const ours = ['run-agent.sh', 'run-agent.cmd'].some((f) => {
        try { return fsm.readFileSync(pathm.join(homedir, f), 'utf8').includes(GPG_HOME_MARK.slice(2)); } catch { return false; }
      });
      if (!ours) throw new CliError(`--force replaces only a home ${NAME} made, and ${homedir} is not one; remove it yourself if it should go`);
    }

    let cert;
    let createdAt = created;
    /*
     * One session for the whole of it (sharedDevice, as the ssh agent uses):
     * the two public keys and the two signatures come back to back, and the
     * okcrypto stale-timer guard needs to see the first signature end to
     * wait out its fade before the second.
     */
    const dev = sharedDevice(io, opts);
    if (slotMode) {
      /*
       * IMPORT, NOT DERIVE: the slots hold the private keys, the file the
       * certificate. It is used only if it is genuine and its keys are the
       * ones the slots report (keychain.pgpImport - the checks the phone's
       * Import PGP key runs). Every signature the agent makes with it is
       * verified against it again before gpg gets it.
       */
      const pgpImport = require('../src/keychain/pgp-import');
      const openpgpLib = require('../src/vendor/openpgp/openpgp.js');
      let armored;
      try {
        armored = fsm.readFileSync(opts['import-pub'], 'utf8');
      } catch (err) {
        throw new CliError(`cannot read ${opts['import-pub']} (${err.code || err.message})`);
      }
      let info;
      try {
        info = await pgpImport.inspect(openpgpLib, armored);
      } catch (err) {
        throw new CliError(`${opts['import-pub']}: ${err.message}`);
      }
      if (givenUserId && givenUserId !== info.userId) {
        throw new CliError(`the certificate's user id is "${info.userId}", not "${givenUserId}" - leave the user id out to use the certificate's`);
      }
      userId = info.userId;
      let probes;
      try {
        probes = await dev.use(async (okcrypto, services) => [
          await services.device.probeKeySlot(skey.slot),
          await services.device.probeKeySlot(dkey.slot),
        ]);
      } finally {
        await dev.release();
      }
      const match = pgpImport.matchSlots(info, probes);
      if (match.signSlot !== skey.slot) {
        throw new CliError(`${skey.name} does not hold the certificate's signing key (it reads ${probes[0].kind}) - wrong slot, or another OnlyKey`);
      }
      if (info.encryption && match.ecdhSlot !== dkey.slot) {
        throw new CliError(`${dkey.name} does not hold the certificate's decrypt key (it reads ${probes[1].kind}) - wrong slot, or another OnlyKey`);
      }
      cert = { armored: info.key.armor(), fingerprint: info.fingerprint };
      createdAt = Math.floor(info.key.getCreationTime().getTime() / 1000);
    }
    const kinds = gpgKey.CURVES[curve];
    const identity = { gpg: userId };
    const label = `gpg://${userId}|${curve}`;
    if (!slotMode) try {
      const pub = await dev.use(async (okcrypto) => ({
        sign: await okcrypto.agent.publicKey(identity, { keyType: kinds.sign.keyType, version: skey }),
        ecdh: await okcrypto.agent.publicKey(identity, { keyType: kinds.ecdh.keyType, version: dkey }),
      }));
      cert = await gpgKey.buildCertificate({
        userId,
        curve,
        created,
        signPublic: pub.sign,
        ecdhPublic: pub.ecdh,
        sign: (digest) => dev.use((okcrypto) => okcrypto.agent.sign(identity, digest, {
          keyType: kinds.sign.keyType,
          version: skey,
          confirm: ({ digits }) => {
            io.err(`Confirm on the OnlyKey to sign the new key for <${label}>: enter ${digits.join(' ')}`
              + ' (or press any button, if the key asks for a single press)');
          },
        })),
      });
    } finally {
      await dev.release();
    }

    if (fsm.existsSync(homedir)) {
      /* Stop an agent still serving the old key from this home, then replace it. */
      if (io.gpgconf) io.gpgconf(['--kill', 'gpg-agent'], { ...process.env, GNUPGHOME: homedir });
      else {
        try {
          require('child_process').execFileSync(require('./gpg-agent').gnupgProgram('gpgconf'), ['--kill', 'gpg-agent'],
            { env: { ...process.env, GNUPGHOME: homedir }, stdio: 'ignore', timeout: 10000 });
        } catch { /* none running, or no gpgconf */ }
      }
      fsm.rmSync(homedir, { recursive: true, force: true });
    }

    const at = (name) => pathm.join(homedir, name);
    fsm.mkdirSync(homedir, { recursive: true, mode: 0o700 });
    fsm.chmodSync(homedir, 0o700);
    fsm.writeFileSync(at(script.name), script.text, { mode: 0o700 });
    fsm.chmodSync(at(script.name), 0o700);
    /* lib-agent's gpg.conf, line for line. */
    fsm.writeFileSync(at('gpg.conf'), '# Hardware-based GPG configuration\n'
      + `agent-program ${at(script.name)}\n`
      + 'personal-digest-preferences SHA512\n'
      + `default-key "${userId}"\n`, { mode: 0o600 });
    if (!IS_WINDOWS_CLI) {
      /* lib-agent's `env` helper: run a command, or a shell, with GNUPGHOME set. */
      fsm.writeFileSync(at('env'), `#!/bin/sh\nset -eu\nGNUPGHOME=${shQuote(homedir)}\nexport GNUPGHOME\n`
        + 'if [ "$#" -eq 0 ]; then exec "${SHELL:-/bin/sh}"; else exec "$@"; fi\n', { mode: 0o700 });
    }
    fsm.writeFileSync(at('pubkey.asc'), cert.armored, { mode: 0o600 });
    fsm.writeFileSync(at('ownertrust.txt'), `${cert.fingerprint}:6:\n`, { mode: 0o600 });

    /*
     * --no-autostart: importing a public key needs no agent, and gpg would
     * otherwise start the one gpg.conf names - which opens the key - for
     * nothing. The agent starts when a private key is first wanted.
     */
    for (const argv of [
      ['--homedir', homedir, '--batch', '--no-autostart', '--import', at('pubkey.asc')],
      ['--homedir', homedir, '--batch', '--no-autostart', '--import-ownertrust', at('ownertrust.txt')],
    ]) {
      const r = await runGpg(io, argv);
      if (r.code !== 0) {
        throw new CliError(`gpg ${argv.slice(4).join(' ')} failed (exit ${r.code}): ${r.stderr.trim().split('\n').slice(-2).join(' | ')}`);
      }
    }

    io.out(cert.armored.trimEnd());
    io.err(`${NAME}: ${slotMode ? `${skey.name} + ${dkey.name} certificate` : `${curve} key`} ${cert.fingerprint} for "${userId}" (created ${new Date(createdAt * 1000).toISOString()})`);
    io.err(`${NAME}: GnuPG home ${homedir}; use it with GNUPGHOME=${homedir} or gpg --homedir ${homedir}`);
    return 0;
  },
};

COMMANDS['gpg-agent'] = {
  mirrors: 'onlykey-gpg-agent (lib-agent)',
  usage: '[--homedir <dir>] [--skey ECC32|derived-v2|ECC1-16] [--dkey ECC32|derived-v2|ECC1-16] [--daemon]',
  summary: 'the gpg-agent for a home `gpg init` made (gpg starts it; run it by hand to watch it)',
  device: true,
  options: {
    homedir: { type: 'string' },
    skey: { type: 'string' },
    dkey: { type: 'string' },
    daemon: { type: 'boolean' },
  },
  /**
   * Serve until KILLAGENT (`gpgconf --kill gpg-agent`) or Ctrl-C.
   *
   * THE KEYS are the ones in the home's pubkey.asc, which init wrote -
   * lib-agent runs `gpg --export` instead; the file is the same certificate
   * and needs no gpg run from inside the agent gpg is waiting on.
   *
   * --daemon is what run-agent.sh passes, and it means what gpg-agent's
   * --daemon means: start the agent in the background, and EXIT once it is
   * serving. gpg depends on that - on POSIX it starts agent-program and
   * WAITS FOR IT TO EXIT before it connects (common/asshelp.c
   * start_new_service: gnupg_spawn_process_fd, then gnupg_wait_process), so
   * an agent that simply served in the foreground left gpg waiting forever
   * (measured: `gpg -K` hung until it was killed). Node cannot fork, so the
   * background agent is a detached child of this same command, which says
   * "ready" over an IPC channel once its socket is listening; this process
   * then exits 0 and gpg connects. lib-agent gets the same from
   * python-daemon's double fork.
   *
   * The background agent has no terminal: its lines go to
   * <homedir>/gpg-agent.log (the file lib-agent logs to), and the challenge
   * digits also to the terminal gpg named in OPTION ttyname - the one the
   * person is looking at.
   */
  async run(io, opts) {
    const fsm = require('fs');
    const pathm = require('path');
    const gpgKey = require('./gpg-key');
    const agentSrv = require('./gpg-agent');

    const homedir = opts.homedir || process.env.GNUPGHOME;
    if (!homedir) throw usage('gpg-agent needs --homedir (or GNUPGHOME): the home `gpg init` made');
    const skey = parseSkey(opts.skey || 'ECC32', '--skey', 'gpg-agent', { allowSlot: true });
    const dkey = parseSkey(opts.dkey || 'ECC32', '--dkey', 'gpg-agent', { allowSlot: true });
    const background = io.daemonChild !== undefined ? io.daemonChild : process.env[GPG_AGENT_CHILD] === '1';

    const logFile = opts.daemon || background ? pathm.join(homedir, 'gpg-agent.log') : null;
    const log = (line) => {
      io.err(`${NAME} gpg-agent: ${line}`);
      if (logFile) {
        try { fsm.appendFileSync(logFile, `${new Date().toISOString()} ${line}\n`, { mode: 0o600 }); } catch { /* the log is best effort */ }
      }
    };

    let text;
    try {
      text = fsm.readFileSync(pathm.join(homedir, 'pubkey.asc'), 'utf8');
    } catch (err) {
      throw new CliError(`cannot read ${pathm.join(homedir, 'pubkey.asc')} (${err.code || err.message}); is this a home \`${NAME} gpg init\` made?`);
    }
    const keys = await gpgKey.readDerivedKeys(text);
    if (!keys.length) throw new CliError(`${homedir}/pubkey.asc holds no OnlyKey-derived key`);

    /* Checked above, in THIS process, so a bad home fails where gpg sees the exit code. */
    if (opts.daemon && !background) return startBackgroundAgent(io, opts, homedir, logFile, log);

    const gpgconf = io.gpgconf ? { gpgconf: io.gpgconf } : {};
    const version = agentSrv.gnupgVersion(gpgconf) || PKG.version;
    const socketPath = agentSrv.agentSocketPath(homedir, gpgconf);

    const dev = sharedDevice(io, opts);
    const versionFor = (key) => (key.role === 'sign' ? skey : dkey);
    /* a stored key (--skey/--dkey ECC<n>): its slot; null = the derived key */
    const slotOf = (key) => {
      const k = versionFor(key);
      return typeof k === 'object' ? k.slot : null;
    };
    const confirm = (key, session, what) => ({ digits }) => {
      const line = `Confirm on the OnlyKey to ${what} for <gpg://${key.userId}|${key.curve}>: enter ${digits.join(' ')}`
        + ' (or press any button, if the key asks for a single press)';
      log(line);
      const tty = session.options.ttyname;
      if (typeof tty === 'string' && tty.startsWith('/dev/')) {
        try { fsm.appendFileSync(tty, `${line}\n`); } catch { /* not ours to write, or gone */ }
      }
    };

    const handler = agentSrv.createGpgAgentHandler({
      keys,
      version,
      log,
      /* a stored key: what its slot reports (the key computes it from the private key), its OKSIGN / OKDECRYPT */
      publicKey: (key) => (slotOf(key) !== null
        ? dev.use(async (okcrypto, services) => {
          const p = await services.device.probeKeySlot(slotOf(key));
          if (!p.publicKey) throw new Error(`slot ${slotOf(key)} holds no key (${p.kind})`);
          return p.publicKey;
        })
        : dev.use((okcrypto) => okcrypto.agent.publicKey({ gpg: key.userId },
          { keyType: key.keyType, version: versionFor(key) }))),
      sign: (key, digest, session) => (slotOf(key) !== null
        ? dev.use((okcrypto) => okcrypto.sign(slotOf(key), digest, { expectBytes: 64, confirm: confirm(key, session, 'sign') }))
        : dev.use((okcrypto) => okcrypto.agent.sign({ gpg: key.userId }, digest,
          { keyType: key.keyType, version: skey, confirm: confirm(key, session, 'sign') }))),
      ecdh: (key, point, session) => (slotOf(key) !== null
        ? dev.use((okcrypto) => okcrypto.decrypt(slotOf(key), point, { expectBytes: 32, confirm: confirm(key, session, 'decrypt') }))
        : dev.use((okcrypto) => okcrypto.agent.ecdh({ gpg: key.userId }, point,
          { keyType: key.keyType, version: dkey, confirm: confirm(key, session, 'decrypt') }))),
      askPassphrase: (session, request) => (io.askPassphrase || require('./pinentry').askPassphrase)(
        { options: session.options, ...request },
      ),
    });

    let killed;
    const stopped = new Promise((resolve) => { killed = resolve; });
    let server;
    try {
      server = await agentSrv.serveGpgAgent({ handler, socketPath, log, onKill: () => killed() });
    } catch (err) {
      await dev.release();
      log(err.message);
      throw new CliError(err.message);
    }
    log(`serving ${keys.length} key(s) of ${homedir} on ${server.path}`);
    if (background) {
      (io.notifyReady || (() => {
        if (process.send) {
          process.send('ready', () => process.disconnect());
        }
      }))();
    }
    try {
      await Promise.race([stopped, (io.untilStopped || untilSignalled)(server)]);
      return 0;
    } finally {
      await server.close();
      await dev.release();
      log('stopped');
    }
  },
};

/* Set in the environment of the background agent `gpg-agent --daemon` starts. */
const GPG_AGENT_CHILD = 'ONLYKEY_JS_GPG_AGENT_BACKGROUND';

/**
 * gpg-agent --daemon: start the agent as a detached child of this same
 * command, wait until it says it is serving, and return - so the process
 * gpg started exits, which is what gpg waits for (see COMMANDS['gpg-agent']).
 *
 * @returns {Promise<number>} 0 once the child serves; throws when it cannot
 */
function startBackgroundAgent(io, opts, homedir, logFile, log) {
  const args = [require('path').resolve(__filename), 'gpg-agent', '--homedir', homedir,
    '--skey', opts.skey || 'ECC32', '--dkey', opts.dkey || 'ECC32'];
  args.push(...deviceArgs(opts));
  const env = { ...process.env, [GPG_AGENT_CHILD]: '1' };
  const child = (io.spawnDaemon || ((file, argv, e) => require('child_process').spawn(file, argv, {
    /*
     * detached: its own session, so it outlives gpg and this process; no
     * stdio of gpg's - a pipe held open by the agent would keep whoever
     * reads gpg's output waiting; 'ipc' for the one "ready" message.
     */
    detached: true, env: e, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  })))(process.execPath, args, env);

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child.connected && child.disconnect) child.disconnect();
      if (child.unref) child.unref();
      if (err) {
        log(err);
        reject(new CliError(err));
      } else {
        resolve(0);
      }
    };
    const timer = setTimeout(() => done(`the background agent did not start serving within 20 s; see ${logFile}`), 20000);
    child.once('message', (m) => { if (m === 'ready') done(null); });
    child.once('exit', (code) => done(`the background agent exited (${code}) before it served; see ${logFile}`));
    child.once('error', (e) => done(`cannot start the background agent: ${e.message}`));
  });
}

/** Resolve on Ctrl-C or a TERM: the foreground agent's whole lifetime. */
function untilSignalled() {
  return new Promise((resolve) => {
    const done = () => {
      process.removeListener('SIGINT', done);
      process.removeListener('SIGTERM', done);
      resolve();
    };
    process.once('SIGINT', done);
    process.once('SIGTERM', done);
  });
}

/*
 * python server.run_process(): the command inherits the terminal and this
 * process's environment plus the agent's, and its exit code is ours. A
 * command killed by a signal exits 128+n, as a shell would report it.
 */
function runWithAgent(argv, env) {
  const { spawn } = require('child_process');
  const os = require('os');
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { stdio: 'inherit', env: { ...process.env, ...env } });
    child.once('error', (err) => reject(new CliError(`cannot run ${argv[0]}: ${err.message}`)));
    child.once('exit', (code, signal) => {
      resolve(code !== null ? code : 128 + ((signal && os.constants.signals[signal]) || 1));
    });
  });
}

/* ------------------------------------------------------------ main */

/**
 * Run one command line.
 *
 * @param {string[]} argv  the arguments after the program name
 * @param {object} [io]
 * @param {(line: string) => void} [io.out]  one line of output
 * @param {(line: string) => void} [io.err]  one line of error
 * @param {(opts: {path?: string, ble?: boolean, address?: string}) => Promise<object>} [io.start]
 *   compose and open the stack; defaults to startDesktop - over node-hid, or
 *   over Bluetooth LE with --ble
 * @param {(question: string) => Promise<string>} [io.prompt]  read one secret;
 *   defaults to cli/prompt.js (hidden on a terminal, one stdin line otherwise)
 * @param {(file: string) => Promise<string>} [io.readFile]  read a key file
 * @param {(server: object) => Promise<void>} [io.untilStopped]  agent -f:
 *   resolves when the agent should stop; defaults to Ctrl-C / SIGTERM
 * @param {(argv: string[], env: object) => Promise<number>} [io.runCommand]
 *   agent -- cmd / -s / -c: run the command under the agent; defaults to a
 *   child process on the terminal
 * @param {(args: string[]) => Promise<{code: number, stdout: string, stderr: string}>} [io.gpg]
 *   gpg init: run gpg; defaults to the gpg on PATH
 * @param {(args: string[], env: object) => string|null} [io.gpgconf]  gpg
 *   init / gpg-agent: run gpgconf (the socket path, the version, --kill)
 * @param {(request: object) => Promise<Buffer>} [io.askPassphrase]
 *   gpg-agent GET_PASSPHRASE; defaults to pinentry
 * @param {boolean} [io.daemonChild]  gpg-agent: this IS the background agent
 *   (default: the environment says so)
 * @param {(file: string, args: string[], env: object) => object} [io.spawnDaemon]
 *   gpg-agent --daemon: start the background agent (a ChildProcess)
 * @param {() => void} [io.notifyReady]  the background agent is serving
 * @returns {Promise<number>} the exit code: 0 done, 1 failed, 2 usage
 */
async function main(argv, io = {}) {
  const full = {
    out: io.out || ((line) => process.stdout.write(`${line}\n`)),
    err: io.err || ((line) => process.stderr.write(`${line}\n`)),
    start: io.start || ((opts) => require('./desktop').startDesktop(opts)),
    prompt: io.prompt || ((question) => require('./prompt').promptSecret(question)),
    readFile: io.readFile || ((file) => require('fs').promises.readFile(file, 'utf8')),
    /*
     * keychain only: an exported key. 'wx' never overwrites (a lost copy is
     * worse than an error), and 0600 keeps an encrypted private copy the
     * owner's alone.
     */
    writeFile: io.writeFile
      || ((file, text) => require('fs').promises.writeFile(file, text, { flag: 'wx', mode: 0o600 })),
    /* agent only: how long a foreground agent serves, and how a command runs under it. */
    untilStopped: io.untilStopped,
    runCommand: io.runCommand,
    /* gpg only: gpg and gpgconf runs, and pinentry - a test replaces all three. */
    gpg: io.gpg,
    gpgconf: io.gpgconf,
    askPassphrase: io.askPassphrase,
    /* gpg-agent --daemon: the background child, and how it is started and says it is up. */
    daemonChild: io.daemonChild,
    spawnDaemon: io.spawnDaemon,
    notifyReady: io.notifyReady,
  };

  /*
   * The global options, plus every command's own (`cmd.options` - only
   * `agent`, `gpg` and `gpg-agent` have any, lib-agent's names). parseArgs
   * has to know them all before it can find the command name among the
   * positionals, so the union is parsed and an option given to a command
   * that does not take it is refused afterwards.
   */
  const GLOBAL_OPTIONS = {
    help: { type: 'boolean', short: 'h' },
    path: { type: 'string' },
    ble: { type: 'boolean' },
    address: { type: 'string' },
    yes: { type: 'boolean' },
  };
  const options = { ...GLOBAL_OPTIONS };
  for (const c of Object.values(COMMANDS)) Object.assign(options, c.options || {});

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options,
    });
  } catch (err) {
    /*
     * Two commands may give one option name different shapes (edge-agent's
     * `--ssh ssh://user@host`, keychain export's bare `--ssh`): the union cannot
     * hold both. Find the command loosely, then parse again with ITS options.
     */
    const loose = parseArgs({ args: argv, allowPositionals: true, strict: false, options: GLOBAL_OPTIONS });
    const guess = loose.positionals[0];
    const own = guess && Object.prototype.hasOwnProperty.call(COMMANDS, guess) ? COMMANDS[guess] : null;
    try {
      if (!own) throw err;
      parsed = parseArgs({ args: argv, allowPositionals: true, strict: true, options: { ...GLOBAL_OPTIONS, ...(own.options || {}) } });
    } catch (err2) {
      full.err(`${NAME}: ${err2.message}`);
      full.err(`Run "${NAME} help" for the commands.`);
      return 2;
    }
  }

  const name = parsed.positionals[0];
  let rest = parsed.positionals.slice(1);
  if (parsed.values.help || !name) return COMMANDS.help.run(full);

  const cmd = Object.prototype.hasOwnProperty.call(COMMANDS, name) ? COMMANDS[name] : null;
  if (!cmd) {
    full.err(`${NAME}: unknown command "${name}". Run "${NAME} help" for the commands.`);
    return 2;
  }
  const foreign = Object.keys(parsed.values)
    .filter((k) => !(k in GLOBAL_OPTIONS) && !(cmd.options && k in cmd.options));
  if (foreign.length) {
    full.err(`${NAME}: "${name}" does not take ${foreign.map((k) => `--${k}`).join(', ')}.`);
    return 2;
  }
  /* the union gave a shared name the other command's shape: parse again with this command's own */
  if (cmd.options) {
    try {
      parsed = parseArgs({ args: argv, allowPositionals: true, strict: true, options: { ...GLOBAL_OPTIONS, ...cmd.options } });
      rest = parsed.positionals.slice(1);
    } catch (err) {
      full.err(`${NAME}: ${err.message}`);
      return 2;
    }
  }
  /*
   * Every derived public key this run makes goes into the host's Key Chain list
   * (cli/keychain-record.js; spec session, 2026-10-03). A test that supplies its
   * own start records nothing unless it supplies io.keychainRecord too.
   */
  const recordFn = io.keychainRecord !== undefined ? io.keychainRecord : (io.start ? null : require('./keychain-record').record);
  full.keychainRecord = recordFn;
  if (recordFn) full.start = require('./keychain-record').recordingStart(full.start, { tool: `${NAME} ${name}`, err: full.err, recordFn });
  /*
   * --path names a USB key and --address a phone: each without its bus, or
   * both buses at once, is a command line that cannot mean what it says.
   */
  if (parsed.values.ble && parsed.values.path) {
    full.err(`${NAME}: --path picks a USB key and --ble a phone; use one.`);
    return 2;
  }
  if (parsed.values.address && !parsed.values.ble) {
    full.err(`${NAME}: --address picks a phone for --ble; add --ble.`);
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
    /*
     * A timeout over Bluetooth that followed the PHONE's refusal is that
     * refusal: its gate diverted the write, so no reply was ever coming. Say
     * why instead of "no reply within N ms" (transport-ble.js CMD_ERROR).
     */
    let shown = err;
    if (parsed.values.ble && /no reply on interface/.test(String(err && err.message))) {
      const refused = require('./transport-ble').refusal();
      if (refused) shown = refused;
    }
    full.err(`${NAME}: ${shown && shown.message ? shown.message : shown}`);
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
