# Changelog

Consumers pin this library by **commit hash**, never by a branch or a floating
tag:

    "node-onlykey-lib": "github:bmatusiak/node-onlykey-lib#<full commit hash>"

A GUI, the emulator and the test kit then all run exactly the same library
until someone moves the pin on purpose. Why that matters was measured, not
assumed: on 2026-09-27 the emulator's version matrix built v3.0.4 on a Raspberry
Pi whose checkout of this library was a few commits behind the one on the other
two hosts, and the Pi read the same firmware's capabilities differently in 11
flags. Nothing had failed - two copies of "the library" simply disagreed.

The version in package.json names the release being worked on; the tag names
the commit that release ended at.

## 0.3.0 - in progress

- **`onlykey-js --ble [--address <phone>]`: every device command over Bluetooth
  LE, to a phone running ok-rn.** `cli/transport-ble.js` is a byte pipe for
  `plugins/transport/ble` (CTAP-over-BLE framing of 64-byte vendor reports,
  one write per report at the phone's MTU of 517, 20-byte fragments below it;
  replies that beat their write's acknowledgement are held until after its
  echo). Windows goes through WinRT with `@stoprocent/noble` 2.8.0; Linux
  talks to BlueZ's GATT API over D-Bus with `dbus-next` (vendor
  characteristics found by UUID wherever BlueZ put them, cached GATT not
  trusted, `PreferredBearer = le` and `Connect()` inside an LE discovery
  session, never `Device1.Disconnect()`). Both are optional peers, loaded
  lazily, like `node-hid`. `agent`, `gpg init` (its run-agent script) and
  `gpg-agent --daemon` carry the option through. Firmware update is refused
  by the pipe. Proven live 2026-09-29 against a Pixel 6a from a Windows PC
  and a Raspberry Pi 4: status, fwversion, getlabels, capabilities and the
  agent's ssh key read the same on both.
- **`onlykey-js gpg init` and `onlykey-js gpg-agent`: the GPG half of lib-agent,
  dependency-less.** `gpg init "<user id>"` makes the certificate for the
  keys derived from `gpg://<user id>` (ed25519 + cv25519, or `-e nist256p1`),
  its two self-signatures made by the device through the vendored openpgp
  fork's `signer` hook, and writes lib-agent's GnuPG home; `gpg-agent` is
  the Assuan agent gpg.conf starts (`--daemon` backgrounds it and exits, as gpg
  waits for; lib-agent's command set; gpg's socket
  path from gpgconf; Windows' port-and-nonce socket file). Key packets,
  fingerprints and keygrips equal python's own encoder's for the same device
  keys, and keygrips equal what gpg prints. Differs from lib-agent toward
  gpg-agent's answers: unknown commands get ERR (lib-agent's silence hangs
  gpg), KEYINFO for a key it does not hold is "No secret key", ECDH values
  carry the 0x40/0x04 prefix, and a key dated 0 gets self-signatures dated 1
  (GnuPG otherwise shows the owner's own signatures as `[uncertain]`). The
  armor carries the CRC line (GnuPG 2.4.4 rejects openpgp.js v6's default
  armor without it). Proven live on the VM (GnuPG 2.4.4, the private kit
  emulator): init twice gives the same fingerprint; `gpg --clearsign` then
  `--verify` is "Good signature ... [ultimate]"; `gpg --encrypt` then
  `--decrypt` through the agent gives the plaintext back - both curves.
- **`onlykey-js agent`: the SSH half of lib-agent, dependency-less.** Prints
  the derived key line for `[user@]host` (byte for byte python
  `onlykey-agent`'s line, comment included), or serves an ssh-agent over it:
  `-f`, `-- command`, `-s`, `-c`; ed25519 by default, `-e nist256p1`;
  derivation v1 by default, `--skey derived-v2` (refused on firmware without
  it). POSIX serves a 0600 socket in a private 0700 directory; Windows a
  private named pipe for Windows OpenSSH. Every signature is verified against
  the listed key before ssh gets it; ECDSA signatures carry canonical mpints
  (lib-agent always prefixes 0x00 - OpenSSH tolerates it, RFC 4251 does not).
  Node built-ins only (`cli/ssh-wire.js`, `cli/ssh-agent.js`). Proven live on
  the VM against the real firmware (a private kit emulator): `ssh-add -L`,
  and an `ssh localhost` login with each key type. `main()` now takes
  per-command options and refuses one given to a command that does not take it.
- **versions: v3.0.5 dropped from the table.** It was never released or signed,
  and 3.1.0 supersedes it. v3.1.0 - the proposed release, pinned to its PR heads
  (libraries eb25290, OnlyKey-Firmware 9fceea1) - is treated like the signed
  release. `list()` no longer offers v3.0.5 and `pinsFor('v3.0.5')` refuses it
  by name. The firmware-version gates in `src/device/version.js` are unchanged:
  a key running a 3.0.5 build is still read correctly.
- **onlykey-js step 2: python's write commands.** `setslot` (every python
  field, python's slot names), `wipeslot`, the fifteen settings commands,
  `settime`, `genkey`, `setkey`, `loadkey` (armored PGP) and `wipekey`, each
  over the device plugin. What the key says is printed on stdout as python
  prints it, and a refusal also exits 1; secrets are prompted for
  (`cli/prompt.js`); the one-way settings need `--yes`. Still no firmware
  update, backup or restore. See cli/README.md for each command's
  differences from python's, most of them python bugs not copied.

- **`capabilities().curve25519Keygen`** - false below 3.0.5, where
  okcrypto_generate_random_key has no type-4 branch and a Curve25519
  "generation" flashes the all-FF trigger itself as the key. `genkey c`
  refuses there.

- **The desktop App's six lib gaps, closed from the firmware.** OnlyKey-App's
  port onto the library (its docs/LIB-PORT.md) kept raw frames for these; each
  was read against release 3.1.0 and fixed there. `device.wipeYubiAuth()` -
  the global Yubico OTP wipe, which the firmware performs WITHOUT replying
  (okcore.cpp wipe_slot has no hidprint for slot 0 field 10), so it listens
  only for a refusal. `setPreference('secProfileMode')` no longer spends three
  10 s timeouts: the firmware stores it silently on first use and refuses it
  later with "Second Profile Mode may only be changed on first use", which has
  no "Error" and now classifies as `refused`. `device.restartByRestore()` -
  the App's no-file restore named: one all-zero OKRESTORE, which RESTORE
  turns into CPU_RESTART, the restart a release build has (only in config
  mode or on first use). `pinStep` ends on any device refusal, not just the
  two PIN sentences; `committed` no longer waits the full timeout on a release
  build, whose console line is DEBUG-only; and `duoPin` skips the status
  broadcast that can arrive before the answer - by timing, since a locked DUO
  reads its PIN only in its broadcast tick and a wrong PIN's only "no" is the
  next INITIALIZED-D. These three silent operations return
  `confirmed: false` and are never retried.

- **"UNLOCKED BOOTLOADERv1" is the bootloader.** `version.parseStatus` and
  `okmsg.parseState` tested UNLOCKED first, so a key waiting for firmware
  parsed as an unlocked key with version " BOOTLOADERv1". Both desktops test
  BOOTLOADER first and read version "v1"; so does the library now.

- **Key import: secp256k1, and 33-byte scalars.** secp256k1 keys map to key
  type 3 (KEYTYPE_P256K1, which the firmware generates, signs and does ECDH
  with) from SSH (`secp256k1` / `k256`) and OpenPGP (OID 1.3.132.0.10); they
  were refused as unknown curves. A 33-byte ECC scalar with a zero sign byte -
  an SSH mpint whose top bit is set - is stripped to 32 instead of thrown.
  Vectors from the App rewrite's keyMaterial tests.

- **age docs match device custody.** `crypto/age_pqc` and `crypto/age_file`
  described the old split-custody X-Wing; from 3.0.5 the device returns the
  finished recipient and secret. `mlkemKeypairFromSeed`, `buildRecipient`,
  `splitDecapsulate` and `ctXOf` serve only the old design and are marked
  deprecated - still exported, since consumers pin by hash.

- **`onlykey-js` - a command line in the library, the start of replacing
  python-onlykey's `onlykey-cli`.** A `bin` with no protocol code of its own:
  each command is a few lines over the device plugin, on the stack
  `node-onlykey-lib/cli/desktop`'s `startDesktop()` composes (host, usb
  transport, session, device, okcrypto - the transport opened, which no plugin
  does). Read-only first: `help`, `version`, `fwversion`, `status`,
  `capabilities`, `getlabels`, `getkeylabels`, with python's names and output
  layout; `capabilities` is derived from the version, since no signed release
  sends the report python asks for. Named `onlykey-js` so it cannot shadow
  `onlykey-cli` while both are installed. The key is reached by
  `cli/transport-hid.js`, a pipe for transport/usb over node-hid: vendor
  interface by usage page 0xffab, the 0x00 report ID hidapi takes on every
  write, clear refusals for no key, two keys (`--path`) and no node-hid.
  `node-hid` is an OPTIONAL PEER (not installed with the library - the web app
  and ok-rn never download a native module; `npm install node-hid` where the
  CLI is used), required lazily under `cli/` only. Keys found by USB id
  1d50:60fc or 16c0:0486, the vendor interface by usage page. No firmware update path.
  Tested over the fake firmware and a fake node-hid; see `cli/README.md`.

- **Classic PGP keys on the device, in a browser too.** `crypto.classic
  .registerClassicHooks(openpgp, ok, { signSlot, decryptSlot })` routes an RSA or
  Ed25519/cv25519 key's private operations to device slots through the PGP fork's
  hardware hooks, as composite_pgp does for composite keys. `okcrypto.sign/decrypt`
  now run over the WebAuthn tunnel when a ctap is supplied, and a tunnelled
  operation no longer needs `expectBytes`: an RSA decrypt's plaintext length is
  collected by the firmware's short-chunk rule. Tests round-trip real openpgp
  messages against a fake device doing real RSA / Ed25519 / X25519.

- **Agent derivation: `okcrypto.agent` - SSH and GPG keys derived on the device.**
  What onlykey-agent / onlykey-gpg drive, now in the library:
  `agent.publicKey(identity, {keyType, version})`, `agent.sign(identity, message)`,
  `agent.ecdh(identity, peerPublicKey)`. `identity` is a 32-byte hash or
  `{ssh: {user, host}}` / `{gpg: userId}`, hashed as lib-agent does (non-ASCII
  refused: lib-agent transliterates it). v1 (132, 201-204; every release from
  2.1.0; the default) and v2 (232, 221-224; HKDF "onlykey/agent/v2"; 3.0.5 on)
  are different keys. New capabilities `agentDerivation`, `agentDerivationV2`;
  `src/protocol/agent.js` is the spec, read at release 3.1.0. The fake firmware
  carries a K132 and the real derivation, so the tests verify signatures and ECDH
  against the key the library reads.

- **`node-onlykey-lib/bundler-aliases` - the exports map for webpack 4.**
  The web app's bundler predates package "exports", so every subpath that is
  not a real path failed to resolve. `aliases()` generates one alias per
  export. Measured in a webpack 4.47 spike: with it, babel over the library
  and `node: { crypto: "empty" }`, the whole stack (host, tunnel transport,
  session, device, okcrypto, webauthn ctap, crypto, the PGP fork) bundles with
  no warnings and composes at runtime.

- **`device.generateKey` asks for no button challenge - the firmware dropped it.**
  libraries 97f0149 (2026-09-22) removed the PQC keygen gate; the bench key
  (b412e78), 3.0.5 and release 3.1.0 all generate on the one OKSETPRIV, and no
  signed release has PQC keygen. The lib still computed digits, emitted
  `challenge` and called `confirm` - so a caller pressing on the user's behalf
  typed slot contents on an unlocked key. Now no digits, no event; `confirm`,
  `duo`, `formula` are accepted and ignored. Also fixed the race that exposed:
  the collector marked the request sent only after `await write`, so a device
  answering inside the write (the emulator) lost the key's first reports.

- **One copy of every third-party library, vendored here.** `@noble/hashes`,
  `@noble/curves`, `@noble/ciphers` 2.4.0, `@noble/post-quantum` 0.7.1 and
  `tweetnacl` 1.0.3 are no longer npm dependencies. They are their npm tarballs,
  unmodified, under `src/vendor/node_modules/`, recorded by integrity and tree
  hash in `src/vendor/VENDORED.json`, and reached through
  `node-onlykey-lib/vendor/@noble/<pkg>/<module>.js` and
  `node-onlykey-lib/vendor/tweetnacl`. `scripts/vendor.js` re-vendors
  (`--check` verifies offline); `test/vendor.test.js` fails on an edited copy,
  on a second copy through npm, on code that bypasses the shims, and on a
  tarball that stops shipping them. Consumers drop their own @noble and use
  these subpaths - one place to audit, one place to swap. See
  `src/vendor/VENDORED.md`.
- **A browser can drive the tunnel: `node-onlykey-lib/transport/webauthn`.**
  `createWebAuthnCtap({ credentials, rpId?, timeoutMs? })` is the object
  `protocol/tunnel.js` already drives - `getAssertion(params) -> Map{2, 3}` -
  run by `navigator.credentials.get()` instead of CTAPHID, which is the only
  way a web page can reach the key. `credentials` is injected, never read from
  a global. The browser hashes its own clientData, so the tunnel's
  clientDataHash is replaced by a fresh random challenge. Browser failures
  come back as a `WebAuthnError` with a `code` (`NOT_ALLOWED`, `TIMEOUT`,
  `ABORTED`, `SECURITY`, `RPID_MISMATCH`, ...). A new package test also pins
  that nothing under `src/` requires a Node built-in.
- **okcrypto's tunnel ctap is injectable:
  `plugins.config = { okcrypto: { ctap } }`.** When supplied, the derives, the
  vault and the X-Wing pair run over it as given - no `CtapHid`, no CTAPHID
  INIT - which is how a browser hands in `createWebAuthnCtap()`. Omitted, which
  is every host today, the plugin builds and inits its own `CtapHid` exactly as
  before. A supplied object without `getAssertion` fails the composition.
- **A browser composes with no vendor interface:
  `node-onlykey-lib/plugins/transport/tunnel`.** A placeholder transport that
  satisfies the contract so session, device and okcrypto compose unchanged;
  every vendor write/request refuses with `code: 'NO_VENDOR_INTERFACE'`
  instead of timing out. Existing hosts keep composing embedded/usb/ble.
- **`okcrypto.connectTunnel()` - the key exchange and the firmware version over
  the tunnel.** A plain OKCONNECT (opt1 = 0, opt3 = 0), whose reply carries the
  status in the clear; it is fed to `session.observeStatus()`, so
  `capabilities()` (transitV2 and the rest) is known in a browser too. Refused
  without a supplied ctap. One WebAuthn ceremony.
- **Composite sign/decrypt over a supplied ctap.** `composite_sign`,
  `composite_decrypt` and the derived X-Wing decapsulation run as tunnelled
  OKSIGN/OKDECRYPT when a ctap is supplied: every keyhandle (and every OKPING)
  sealed under the tunnel's transit session - transit v2 frames from 3.0.5,
  the v1 box on 3.0.4 - with a counter that persists across operations and
  resets at each key exchange (a derive re-keys, and its reply becomes the
  session). Chunks are 171 bytes sealed (v2) or 228 (v1), whole 57-byte
  packets but the last, never a length the encoder would pad. opt2 marks the
  final chunk and opt3 never wraps inside an operation. Results are collected
  by OKPING and, from 3.0.5, opened as v2 frames (+20 bytes, libraries
  a29b063). The three-button challenge and `confirm({ digits, isAnswered })`
  are the vendor path's. The reply to each request chunk is CHECKED: a
  transit-authentication failure, a stale staged reply or a dropped duplicate
  fails at once with `code: 'REQUEST_NOT_ACCEPTED'`, and a device refusal
  ("stored key use over FIDO2 not enabled") comes back as its own sentence.
  Before the first chunk the operation waits out the firmware's 5-second
  staged-reply wipe (`settle` event), because a reply still staged is served
  again to the request and hides whether it was accepted. Cost per operation,
  in ceremonies (browser prompts): one connect per session, one per request
  keyhandle (Ed25519/X25519 1, ML-KEM 7 on v3.0.5 / 5 on v3.0.4), one per
  1-second poll while the user enters the challenge, and one per 512-byte
  result chunk (ML-DSA-65: 7). Vendor-HID behaviour is unchanged.
- `protocol/chunk`: `planKeyhandleChunks`, `reservePacketRun`, `PACKET_DATA`,
  and `sendChunked({ sizes, onReply })`; `protocol/ctap`: `dataRegionLength`.
- okcrypto's vendor `deviceOperation` now takes its listener and timer down
  when the write itself fails, instead of leaving an unhandled rejection
  `timeoutMs` later.

## 0.2.0 - `4b74b3e93b314cd0808b04bc7733695f0f008601` (tag `v0.2.0`)

Released 2026-09-27, after ok-rn ran this code through the full Pixel 6a
version matrix: every release equal to or better than its baseline (working
tree 104 passed / 0 failed, v3.0.4 84/0, v0.2-beta.8 still parked at 60/4).

- **The release table lives here now: `node-onlykey-lib/versions`.**
  `list()`, `pinsFor(version)` (the pinned `libraries` / `OnlyKey-Firmware`
  commits and the signed image; `null` for the named-but-not-cut working
  tree; a half-pinned row throws), `compatibilityOf(version)`,
  `signedStatus()`, `expectedCompatibility()`. The table used to be copied
  into ok-rn and node-onlykey-emulator (only the emulator's had the
  compatibility rows); consumers read this one. Each consumer keeps its own
  per-release stage scripts - those are build-system patches, not data.
  `scripts/versions-compat.js --write` regenerates the compatibility rows,
  and a test fails when they drift from `capabilities()`.
- `crypto.pqc` exports `bech32Encode`, `bech32Decode`, `RECIPIENT_HRP`,
  `IDENTITY_HRP` and `DERIVED_MARKER` - the encoding under the recipient and
  identity strings, which onlykey-testing's age-pqc.js carried its own copies
  of. Checked identical to the kit's (20/20); one frozen vector from it.
- `CtapHid` takes an `AbortSignal` (`new CtapHid(t, { signal })`, or
  `opts.signal` per call): an aborted wait rejects at once with an
  `AbortError` whose `cause` is the signal's reason, and an already-aborted
  one sends nothing. And `resendCutRequest` (default `true`) switches off the
  one resend of a multi-packet request refused as INVALID_COMMAND, for a
  client that must see the firmware's own answer. Both for onlykey-testing,
  whose runner stops stuck exchanges and whose test 32 is about exactly that
  refusal; GUI behaviour is unchanged.
- CTAP status names: the rest of the firmware's `ctap_errors.h` -
  `CTAP2_ERR_ACTION_TIMEOUT` (0x3A), `CTAP1_ERR_OTHER` (0x7F) and OnlyKey's
  vendor codes 0xF6 `DATA_READY`, 0xF7 `DATA_WIPE`, 0xF8/0xF9
  `OKSIGN`/`OKDECRYPT_ERR_USER_ACTION_PENDING`. The table stopped at 0x39;
  onlykey-testing's named 0x3A. Its 0x3E `UP_REQUIRED` is not added - a
  CTAP 2.1 code this firmware neither defines nor sends.
- **Transit v2, host -> device.** `session/transit` gains `session(key)`,
  `seal(session, data)` (advancing the session's counter) and
  `open(keyOrSession, frame)`, with `CTR_LEN`, `TAG_LEN`, `OVERHEAD`,
  `DIR_FROM_DEVICE`, `DIR_TO_DEVICE` and `transitIv`. The library had only the
  device -> host half (`crypto/okconnect`'s `openTransitV2`); onlykey-testing
  had both, run against the device, and they are ported from it. One
  implementation now: `openTransitV2` and `TRANSIT_V2_OVERHEAD` are the
  transit module's `open` and `OVERHEAD` under their old names. @noble's gcm,
  not Node's crypto, so it runs in every GUI. Frozen vectors from the kit's
  transit v2 (9eb1de6): 6 successive seals, 4 device frames the kit's own
  `open()` accepted.
- New exports-map subpaths: `./device/press`, `./device/version`,
  `./vendor/openpgp` - so consumers stop loading files by path.
- The cbor, ctaphid and transit cross-checks no longer load
  `../onlykey-testing` at test time. The kit's outputs are FROZEN in
  `test/vectors/kit-reference.json` by `scripts/freeze-kit-vectors.js`
  (onlykey-testing@adac782, the last commit whose transit still has `box()`),
  on inputs shared through `test/vectors/cases.js`. The kit is moving onto
  this library, which would make a live comparison circular - and it had
  already broken: the kit replaced `box()` with transit v2's seal/open.
  `npm test`: 861/861.
- `@bmatusiak/rectify` is pinned by commit hash
  (`a0d9f0e6e537053122273b1f763ac87ae461361c`), the commit the lockfile
  already resolved - it no longer floats with rectify's default branch.

Known at the tag: `npm test` is 861 of 862. The one failure is the transit
cross-check against onlykey-testing's own `lib/device/transit.js`, which no
longer exports `box` - the kit moved, the library did not. The same test
fails on 0.1.0 unmodified. It is the circularity the kit's move onto this
library has to deal with first (freeze the kit's originals as vectors).

## 0.1.0 - `f734c5e7654314df53691bafa13220a1ac38f91c` (tag `v0.1.0`)

The first pinned release: the library as every consumer ran it on 2026-09-27
(ok-rn; the emulator on Windows, Linux x64 and the Pi). Everything before this
point was untagged development.
