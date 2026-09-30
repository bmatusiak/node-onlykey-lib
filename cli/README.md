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

There is no firmware update command - that is not something this program can
do - and no backup or restore, which need their own safety design first.

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

## Tests

`test/cli.test.js` (reads) and `test/cli-write.test.js` (writes) run every
command through `main(argv, io)` over the fake firmware - the writes pinned
frame by frame, message, slot, field and payload, as well as by what they
print; `test/cli-transport-hid.test.js` drives the pipe through a fake
node-hid module; `test/ssh-agent.test.js` serves the agent on a real socket
(a named pipe on Windows) over the fake firmware's K132 derivation and talks
to it as ssh does. None can reach a real device: `io.prompt` and `io.readFile`
are injected too.
