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
 * WHAT IT DOES NOT DO (YET). Everything here is READ-ONLY: it connects (the
 * OKCONNECT every client sends, which sets the key's clock) and reads. Nothing
 * writes a slot, a key or a setting, and there is no firmware update path -
 * that is deliberately not something this program can do.
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
function requireUnlocked(identity, what) {
  if (identity.state === 'unlocked') return;
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
    io.out(`Usage: ${NAME} <command> [--path <hid path>]`);
    io.out('');
    io.out('Commands:');
    for (const [name, cmd] of Object.entries(COMMANDS)) io.out(`  ${name.padEnd(14)} ${cmd.summary}`);
    io.out('');
    io.out('Options:');
    io.out(`  ${'--path <path>'.padEnd(14)} which OnlyKey, when more than one is plugged in`);
    io.out(`  ${'-h, --help'.padEnd(14)} this list`);
    io.out('');
    io.out('Every command is read-only: none changes what is on the key.');
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
 * @returns {Promise<number>} the exit code: 0 done, 1 failed, 2 usage
 */
async function main(argv, io = {}) {
  const full = {
    out: io.out || ((line) => process.stdout.write(`${line}\n`)),
    err: io.err || ((line) => process.stderr.write(`${line}\n`)),
    start: io.start || ((opts) => require('./desktop').startDesktop(opts)),
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
  if (rest.length) {
    full.err(`${NAME}: "${name}" takes no arguments (got: ${rest.join(' ')}).`);
    return 2;
  }

  try {
    return await cmd.run(full, parsed.values);
  } catch (err) {
    /*
     * One sentence for the person, the stack only when asked for. The pipe's
     * errors (no key, two keys, no node-hid) are written to be read as-is.
     */
    full.err(`${NAME}: ${err && err.message ? err.message : err}`);
    if (process.env.ONLYKEY_JS_DEBUG && err && err.stack) full.err(err.stack);
    return err instanceof CliError ? err.exitCode : 1;
  }
}

module.exports = { main, COMMANDS, CliError, duoSlotName, classicSlotName };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
