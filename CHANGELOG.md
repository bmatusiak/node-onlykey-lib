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
