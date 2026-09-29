# onlykey-js - the OnlyKey command line, on this library

    npx onlykey-js status            # from a checkout or an install of node-onlykey-lib
    onlykey-js getlabels --path <p>  # when more than one OnlyKey is plugged in

## What it is, and why it lives here

python-onlykey's `onlykey-cli` is a second, separate implementation of the
OnlyKey protocol. Every time it, the desktop app, the web app and ok-rn have
disagreed, the disagreement had to be found by hand and settled one repo at a
time.

`onlykey-js` has **no protocol code of its own**. Each command is a few lines
over the device plugin, running on the same session and USB transport the GUIs
run (`cli/desktop.js` composes them). So:

- a command that works here works in every GUI built on this library, and a
  bug fixed in the library is fixed here in the same commit;
- the CLI is a way to *exercise* the library from a shell, not a fifth client
  to keep in step.

It is a `bin` of the library rather than its own package for the same reason:
one version, one pin, no second copy to drift.

## What it replaces, over time

It takes over `onlykey-cli`'s commands one at a time, read-only first. Until a
command is listed below, use python-onlykey for it. The two install side by
side: the bin is named `onlykey-js` so it can never shadow `onlykey-cli`.

| onlykey-js | mirrors (python-onlykey) | touches the key | notes |
|---|---|---|---|
| `help`, `-h`, `--help` | `help`, `-h`, `--help` | no | prints the commands instead of a URL |
| `version` | `version` | no | this program's version; like python's, needs no key |
| `fwversion` | `fwversion` | reads | same output (the version after the state word); a locked key gets a reason instead of python's `ZED` |
| `status` | - (new) | reads | status line, state, firmware, model, build, capability flags |
| `capabilities` | `capabilities` | reads | python's `%-14s` layout, but derived from the firmware version by `src/device/version.js`: no signed release sends the `c` report python asks for, so python prints "does not report capabilities" on every key in the field |
| `getlabels` | `getlabels` | reads | same layout: classic in pairs, DUO in colour runs of six |
| `getkeylabels` | `getkeylabels` | reads | same names: RSA Key 1-4, ECC Key 1-16 |

"Reads" means it connects - the OKCONNECT every client sends, which sets the
key's clock - and reads. Nothing here writes a slot, a key or a setting, and
there is no firmware update command: that is not something this program can
do. A locked key is refused straight from the connect reply, because a locked
key answers a label read with silence rather than an error.

## node-hid is an optional dependency

Reaching a USB key from Node needs `node-hid` (hidapi), a native addon. It is
in `optionalDependencies` and is `require`d only inside `cli/transport-hid.js`,
when a command first opens a key:

- nothing under `src/` or `plugins/` references it, so the web app and ok-rn
  never bundle it, and a failed native build never fails their install;
- if it is missing, a command that needs a key says so by name
  (`onlykey-js: ... needs the optional dependency "node-hid" ... npm install node-hid`),
  while `help` and `version` still work.

Note that npm still *installs* an optional dependency by default wherever the
library is installed; `npm install --omit=optional` skips it.

## How it reaches the key

`cli/transport-hid.js` is a byte pipe for `plugins/transport/usb` - the
contract in `src/transport/pipeTransport.js`, the same one ok-rn's USB module
and the emulator's bus implement. It opens the **vendor** interface only,
identified by HID usage page `0xffab` (never by interface number), adds the
`0x00` report ID hidapi expects on every write, and echoes its writes so the
transport can tell them from the key's replies. No OnlyKey, two OnlyKeys, or a
key whose interfaces hidapi cannot identify are each refused with a sentence
that says what to do.

`startDesktop()` (`node-onlykey-lib/cli/desktop`) is the composition, usable
from any Node script: `[host, transport/usb, session, device, okcrypto]` over
that pipe, transport opened.

## Tests

`test/cli.test.js` runs every command through `main(argv, io)` over the fake
firmware; `test/cli-transport-hid.test.js` drives the pipe through a fake
node-hid module. Neither can reach a real device.
