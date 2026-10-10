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

It takes over `onlykey-cli`'s commands one at a time: the reads, then the writes. Until a
command is listed below, use python-onlykey for it. The two install side by
side: the bin is named `onlykey-js` so it can never shadow `onlykey-cli`.

| onlykey-js | mirrors (python-onlykey) | touches the key | notes |
|---|---|---|---|
| `help`, `-h`, `--help` | `help`, `-h`, `--help` | no | prints the commands instead of a URL |
| `version` | `version` | no | this program's version; like python's, needs no key |
| `fwversion` | `fwversion` | reads | same output (the version after the state word); a locked key gets a reason instead of python's `ZED` |
| `status` | - (new) | reads | status line, state, firmware, model, build, capability flags |
| `config [export [file] | import <file> [--one-way]]` | - (new) | reads; import writes | the key's settings as INI (`OKGETCONFIG`) - an ok-rn soft key with the config plugin only; a hard key never answers it (it is not emulated, so the app is not in the middle). `import` sends the file with OKSETCONFIG - config mode only, and only a DEBUG soft-key build has it - then reads back and reports each value as taken or not; `[input]` is never sent, `[advanced]` (one-way) only with `--one-way` |
| `capabilities` | `capabilities` | reads | python's `%-14s` layout, but derived from the firmware version by `src/device/version.js`: no signed release sends the `c` report python asks for, so python prints "does not report capabilities" on every key in the field |
| `getlabels` | `getlabels` | reads | same layout: classic in pairs, DUO in colour runs of six |
| `getkeylabels` | `getkeylabels` | reads | same names: RSA Key 1-4, ECC Key 1-16 |
| `setslot <id> <field> [value]` | `setslot` | writes | every python field: `label url username password 2fa gkey totpkey addchar1-5 delay1-3 typespeed ecckeylabel rsakeylabel`, python's slot names (`1a`-`6b`, `green1a`-`purple3b`) or a number. Prints the key's answer, as python does. `password`, `gkey`, `totpkey` are prompted for and refused as arguments. Exactly one value: python stores the first word of an unquoted `label My Bank` and says it worked. `gkey` takes unpadded base32, which python's `b32decode` refuses |
| `wipeslot <id>` | `wipeslot` | writes | prints ONE line: the firmware answers ten ("Successfully wiped Label" ... "2FA Key"), python prints eight, the library's `wipeSlot` returns the first |
| `idletimeout` `wipemode` `keytypespeed` `keylayout` `ledbrightness` `lockbutton` `touchsense` `backupkeymode` `sysadminmode` `hmackeymode` `storedkeymode` `derivedkeymode` `webagentderivemode` (`webderivemode`) `webcryptpolicy` | the same | writes | one number, through the device plugin's `setPreference` - its ranges and its version gates (a value out of range is refused with nothing sent; `webagentderivemode`/`webcryptpolicy` need 3.0.5). The three one-way settings (`wipemode`, `backupkeymode`, `webcryptpolicy`) need `--yes`. Sent on the global slot 0, where python sends slot 1 (set_slot ignores it for settings) |
| `settime` | `settime` | writes (clock) | OKSETTIME is OKCONNECT; prints the status line, as python does |
| `genkey <ECC1-16> <x\|n\|s\|c\|m\|w> [d\|s\|b]` | `genkey` | writes | python's letters and uses. ECC slots only (python lets `genkey HMAC1 x d` through). `c` is refused below 3.0.5, where it stores a constant key (capability `curve25519Keygen`); `m`/`w` need `postQuantum` and print a summary line instead of python's first 64 key bytes as text |
| `setkey <slot> <type> [d\|s\|b] [hex]`, `setkey <slot> label <text>` | `setkey` | writes | RSA1-4 (type 1-4), ECC1-16 (`x n s c`), HMAC1-2 (`h`). The hex is length-checked before anything is sent; left off, it is prompted for; given, a stderr note says it is in the shell history. No `HMAC` label (python writes one to index 57/58). No `PQC`/`p` composite load |
| `loadkey <file> [auto\|RSA1-4\|ECC1-16] [d\|s\|b]` | `loadkey` | writes | armored PGP private key; python's lines ("Found 2 key(s):", "Loading ECC key to slot 102...", the key's answer). The passphrase is asked only for a locked key. A named slot must match the key's kind (python silently moves RSA to slot 1); an ECC key there needs its use (python crashes on an odd-length type byte) |
| `wipekey <RSA1-4\|ECC1-16\|HMAC1-2>` | `wipekey` | writes | two lines, as python: the wipe, then the label clear - which the library skips after a refused wipe and for HMAC |
| `agent <[user@]host \| file> [-e ed25519\|nist256p1] [--skey ECC32\|derived-v2] [-f \| -s \| -c \| -- cmd]` | lib-agent's `onlykey-agent` | reads, signs | SSH keys derived in the key. Prints the key line (the same line python prints, comment `<ssh://user@host\|curve>` included), or serves an ssh-agent: `-f` foreground, `-- cmd` / `-s` / `-c` under a command. POSIX: Unix socket in a private 0700 dir; Windows: a private named pipe (Windows OpenSSH only - Git Bash's ssh cannot use a pipe). v2 is `--skey derived-v2`, refused on firmware without it. Not carried: stored-slot keys (`--skey ECC1-16`), `--daemonize`, `--mosh`, `.pub` import. See below |
| `gpg init "<user id>" [-e ed25519|nist256p1] [-t <time>] [--homedir <dir>] [--skey|--dkey ECC32|derived-v2] [--force]` | lib-agent's `onlykey-gpg init` | reads, signs, writes files | A GPG key derived in the key from `gpg://<user id>`: signing primary + ECDH subkey, both self-signatures made by the device (two confirmations). Prints the armored key and writes lib-agent's GnuPG home (`run-agent.sh`, `gpg.conf`, `env`, `pubkey.asc`, ownertrust), then gpg imports it. Same key packets, fingerprint and keygrips as python for the same device, user id, curve and time. Refuses an existing home; `--force` replaces only one it made. Not carried: `-s/--subkey`, `-i/--import-pub` (stored keys). See below |
| `gpg-agent [--homedir <dir>] [--skey|--dkey ECC32|derived-v2] [--daemon]` | lib-agent's `onlykey-gpg-agent` | signs, decrypts | The gpg-agent gpg starts for that home (gpg.conf `agent-program`): lib-agent's Assuan command set on gpg's own socket path; on Windows libassuan's port-and-nonce socket file. See below |

"Reads" means it connects - the OKCONNECT every client sends, which sets the
key's clock - and reads. A locked key is refused straight from the connect
reply, because a locked key answers a label read with silence rather than an
error; every write refuses a locked key the same way.

"Writes" commands print what the KEY said, on stdout, success or refusal -
the line python prints. A refusal also exits 1 (python exits 0), with what to
do about it on stderr: "Error not in config mode" is followed by a note to put
the key in config mode. A key write the key never answers is reported as
that - outside config mode the firmware drops OKSETPRIV without a word - where
python prints an empty line. A command line that is wrong is refused, exit 2,
before any key is opened.


## agent - the SSH half of lib-agent

`onlykey-js agent` is `onlykey-agent` over this library: the key is derived
inside the OnlyKey from the identity (`sha256("user@host")`, lib-agent's
hash - port, path and proto are not part of it), v1 by default, v2 with
`--skey derived-v2`. The two are DIFFERENT keys; keep whichever a server
already trusts.

    onlykey-js agent okt@example.com                    # print the key line
    onlykey-js agent -e nist256p1 okt@example.com       # the ecdsa-sha2-nistp256 one
    onlykey-js agent -f okt@example.com                 # serve; eval the SSH_AUTH_SOCK line
    onlykey-js agent okt@example.com -- ssh okt@example.com
    onlykey-js agent -c okt@example.com                 # ssh to it, offering only its key
    onlykey-js agent -f /path/to/ids                    # every <identity|curve> in the file

Signing prints the challenge on stderr ("enter 1 1 6"). Every signature is
verified against the listed key before ssh gets it - a wrong identity hash
signs perfectly well with a different key, and ssh would only say
"Permission denied". The key is opened when a request needs it and released
after 10 s idle, so the agent does not keep it from other programs.

On Windows the agent listens on a private named pipe (never
`\\.\pipe\openssh-ssh-agent`, which is the OpenSSH Authentication Agent
service's) and prints `$env:SSH_AUTH_SOCK = '...'`; Windows OpenSSH's
`ssh.exe`/`ssh-add.exe` use it, or `ssh -o IdentityAgent=<pipe>`.

## gpg init, gpg-agent - the GPG half of lib-agent

`onlykey-js gpg init` is `onlykey-gpg init`: the device derives a signing key
and an ECDH key from `sha256("gpg://" + user id)` (Ed25519 + X25519 by
default, `-e nist256p1` for P-256 + P-256), and the certificate that carries
them is signed BY THE DEVICE - two confirmations. The packets are the vendored
openpgp fork's (`cli/gpg-key.js`); the agent is `cli/gpg-agent.js` and
`cli/assuan.js`, Node built-ins only.

    onlykey-js gpg init "Alice <alice@example.com>"            # ~/.gnupg/onlykey
    onlykey-js gpg init "Alice <alice@example.com>" --homedir ~/.gnupg/ok -e nist256p1
    GNUPGHOME=~/.gnupg/onlykey gpg --clearsign file             # gpg starts the agent
    GNUPGHOME=~/.gnupg/onlykey gpg --decrypt file.gpg
    gpgconf --homedir ~/.gnupg/onlykey --kill gpg-agent        # stop it

`-t/--time` is the key's creation time and defaults to 0, lib-agent's default:
the fingerprint covers it, so the same device, user id, curve and time give
the same key on any machine. The self-signatures of a key dated 0 are dated 1 -
GnuPG takes a signature at 0 as undated and then verifies the person's own
key's signatures as `[uncertain]` (measured; lib-agent's keys have that fault).
v2 is `--skey derived-v2` / `--dkey derived-v2`, written into `run-agent.sh`
so the agent uses the same derivation.

gpg starts the agent itself: `run-agent.sh` runs `gpg-agent --daemon`, which - like
gpg-agent's own `--daemon` - leaves the agent serving in the background and
exits, because gpg waits for that process to exit before it connects.

The agent reads its keys from the home's `pubkey.asc`, answers `HAVEKEY` and
`KEYINFO` without the device, verifies every signature against that key
before gpg gets it, and compares the device's ECDH key once before the first
decryption. The challenge ("enter 1 2 3") goes to `<home>/gpg-agent.log` and
to the terminal gpg named (`OPTION ttyname`). `gpg -c` passphrases go through
pinentry. On Windows it writes the Assuan socket FILE Gpg4win's gpg reads (a
loopback port and a 16-byte nonce) and `run-agent.cmd`; that path is covered
by the tests, not yet by a live Gpg4win.

There is no firmware update command - that is not something this program can
do - and no backup or restore, which need their own safety design first.

## keychain - the Key Chain plugin (`keychain/`)

`onlykey-js keychain list | show | export | import | cert | slots | pub | derive | gen`: the keys
an OnlyKey holds or derives, kept in a list on this computer (`~/.onlykey-js/keychain.json`) with
their names, public keys and artifacts. It is a plugin: the core never requires `keychain/`, and
without the folder the command is simply not there. It also decodes the soft key's press record
(`keychain/src/press.js`) and names a derived identity's label from the list
(`derive.labelHashOf`). Its spec: `onlykey-edge/features/KEY-CHAIN-SPEC.md`.

## edge - OnlyKey Edge (`edge/`)

`onlykey-js edge setup | budget | continue | end | status | exec | receipt | watch | sync | blocks |
agent`, and `--test-mode` for the testnet: an AI agent signs under a budget the person approved
on the phone, each use bound to its request and receipted. Another plugin, used the same way: the
core never requires `edge/`. Every option, and what each command may do: `onlykey-edge/CLI.md`.
The protocol and its rules: `onlykey-edge/edge/SPEC.md`.

Every press any command asks for is said first with the fingerprint of the exact bytes sent
(`(message ab12 cd34 ef56 0011)`); a soft key's press sheet shows the same fingerprint from the
firmware.

## node-hid is an optional PEER dependency

Reaching a USB key from Node needs `node-hid` (hidapi), a native addon. It is
declared in `peerDependencies` with `peerDependenciesMeta: { optional: true }`,
so npm does NOT install it with the library (owner's decision, 2026-09-29): the
web app and ok-rn, which install this library and never reach a key over
hidapi, never download a native module. Install it yourself where you use the
CLI:

    npm install node-onlykey-lib node-hid

It is `require`d only inside `cli/transport-hid.js`, when a command first
opens a key, so:

- nothing under `src/` or `plugins/` references it;
- if it is missing, a command that needs a key says so by name and says how to
  install it, while `help` and `version` still work.

The key is found by its USB id - `1d50:60fc`, or `16c0:0486`, the Teensy
RawHID id early OnlyKeys shipped under (python-onlykey accepts both) - and its
vendor interface by HID usage page `0xffab`, never by interface number.

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

## `--ble`: a phone running ok-rn, over Bluetooth LE

    onlykey-js --ble status
    onlykey-js --ble --address "Pixel 6a" getlabels      # or --address 24:29:34:86:EA:AF
    onlykey-js --ble agent me@example.com                # ssh, served from the phone
    onlykey-js --ble gpg init "Me <me@example.com>"      # the home's agent uses --ble too

ok-rn's soft key publishes the OnlyKey **vendor** interface as a GATT service
(`0c0ffab0-...`, request `...ffab1` write, response `...ffab2` notify), so
`--ble` swaps only the pipe: `cli/transport-ble.js` under
`plugins/transport/ble`, everything above it the code a USB key runs. The
option is global - every device command takes it, including `agent`,
`gpg init` (its `run-agent` script says `--ble`, since gpg starts the agent
later with none of our options) and `gpg-agent` (`--daemon` passes it to the
background agent). `--address` takes the phone's address or Bluetooth name;
without it, the one paired phone advertising FIDO (0xFFFD) is used.
`--path` with `--ble`, or `--address` without it, is refused.

On the wire each 64-byte report is one CTAP-over-BLE message
(`83 00 40` + report), one write when the MTU allows (the phone negotiates
517), 20-byte fragments otherwise. **Firmware update is refused** by the pipe.

It needs one more optional peer, per platform, exactly like `node-hid`:

| platform | stack | install |
| --- | --- | --- |
| Windows | WinRT, through `@stoprocent/noble` 2.8.0 | `npm install @stoprocent/noble@2.8.0` |
| Linux | BlueZ's own GATT API over D-Bus, through `dbus-next` | `npm install dbus-next` |

Pair the phone first: in Settings on Windows, with
`scripts/ble-linux-connect.sh` on Linux (below). Why not noble on Linux: its
default backend is raw HCI (root, and blind to BlueZ's bonds), and its D-Bus
backend waits forever on a phone that is already connected - which, with its
classic keyboard up, it always is. What the Linux path does instead:

- finds the vendor characteristics **by UUID under whatever device path BlueZ
  put them** (the Pi's phone lived at the path of a private address it was
  first seen on), and treats them as usable only when that device is
  `Connected` **and** `ServicesResolved` - BlueZ exports a bonded device's
  cached GATT table while LE is down, and the classic keyboard keeps
  `Connected` true with no LE link at all;
- otherwise sets `PreferredBearer = le` and calls `Connect()` **inside an LE
  discovery session** - without one the kernel scans for the phone's identity
  address only, and the phone advertises from rotating private addresses;
- never calls `Device1.Disconnect()`, which would drop the keyboard too.

Measured 2026-09-29, Pixel 6a with ok-rn, soft key unlocked (v3.1.0-testc):

| | Windows (NITRO16, WinRT) | Raspberry Pi 4 (BlueZ 5.82) |
| --- | --- | --- |
| found / connected / subscribed | 64-754 / ~110 / 1.0-2.6 s from start | LE connect 0.7 s, GATT resolved 1.8 s later |
| `fwversion`, fresh link | 2.9 s | 2.8 s |
| `status` / `getlabels` / `capabilities` / `agent` key | 2.9 / 3.1 / 1.5 / 3.5 s | 1.0 / 1.4 / 1.0 / 1.2 s (LE link already up) |

**One computer at a time.** ok-rn answers only the central that connected to
it LAST, and forgets it when any central disconnects. So after another
computer has used the phone, a Linux host whose LE link stayed up gets no
answer ("no reply on interface ... within 3000ms"); drop just that LE link
(`sudo hcitool ledc <handle>`, the handle from `hcitool con`; the classic
keyboard stays up) and the next command connects afresh. Windows makes a new
link per command and does not hit this.

## Bluetooth on Linux: `scripts/ble-linux-connect.sh`

The ok-rn phone app is a soft key that can also be reached over Bluetooth LE.
It is a classic Bluetooth keyboard AND an LE vendor pipe to the same computer
at once, as it is on Windows. On Windows, pairing once in Settings is all the
preparation it needs. On Linux (BlueZ) the host needs a few things first, and
the script does them, explaining each:

    scripts/ble-linux-connect.sh "Pixel 6a"           check, pair if needed, prefer LE
    scripts/ble-linux-connect.sh "Pixel 6a" --fix     also the one-time host fixes (sudo)
    scripts/ble-linux-connect.sh "Pixel 6a" --repair  pair again (forget this computer on the phone first)

The steps:
- **Adapter.** Not rfkill-blocked, and powered.
- **bluetoothd config.** It stays **dual-mode** (`ControllerMode = le` would stop the
  keyboard) and runs with **`Experimental = true`**. That flag is what gives BlueZ
  `Device1.PreferredBearer`, the only way to make a connect go LE instead of classic,
  as WinRT does.
- **The bond.** Paired by **numeric comparison**: accept the same number on the
  phone. A Just Works pair ended up bonded on one side only.
- **The device.** Trusted, with `PreferredBearer = le`.

Proven on a Raspberry Pi 4 (Debian 13, BlueZ 5.82) against a Pixel 6a:
2026-09-29. The pairing path was run by hand, and the script's check path on the
paired phone.

## Tests

`test/cli.test.js` (reads) and `test/cli-write.test.js` (writes) run every
command through `main(argv, io)` over the fake firmware - the writes pinned
frame by frame, message, slot, field and payload, as well as by what they
print; `test/cli-transport-hid.test.js` drives the pipe through a fake
node-hid module; `test/cli-transport-ble.test.js` drives the Bluetooth pipe
through a fake noble and a fake BlueZ (in the states the Pi was found in),
each with a fake ok-rn phone in front of the fake firmware; `test/ssh-agent.test.js` serves the agent on a real socket
(a named pipe on Windows) over the fake firmware's K132 derivation and talks
to it as ssh does; `test/gpg-agent.test.js` does the same for `gpg init` (with a
stand-in gpg) and `gpg-agent` (speaking Assuan as gpg does). None can reach a real device: `io.prompt` and `io.readFile`
are injected too.
