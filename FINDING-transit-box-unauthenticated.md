# The transit box is not authenticated encryption

**Severity:** high
**Status:** reproduced deliberately in `src/session/transit.js`; needs a
coordinated firmware + client change to fix
**Applies to:** shipping OnlyKey firmware (STD edition), and every client that
talks to it — OnlyKey-App, onlykey.github.io, node-onlykey-fido2,
onlykey-testing, and now this library

## Summary

The session channel established by `OKCONNECT` is called a "crypto box" and is
built on `GCM<AES256>`, but it provides **confidentiality only**. There is no
authentication tag, no nonce variation, and no replay protection. What it
actually is: AES-256 in counter mode, with one key and one all-zero IV per
session, so every message in a session runs off **the same keystream from
offset zero**.

This is not a client bug. Every client is a faithful port of what the firmware
does. It is the wire format.

## Evidence

All line numbers from this workspace's `libraries/` checkout, verified by
reading, not recalled.

### The IV is zero on every message, and the counter that would have varied it is commented out

`libraries/onlykey/okcrypto.cpp:1014-1041`:

```c
void okcrypto_aes_crypto_box (uint8_t *buffer, int len, bool open) {
	uint8_t iv[12];
	memset(iv, 0, 12);
	//msgcount++;
	//int ctr = ((msgcount>>24)&0xff) | // move byte 3 to byte 0
	//  ((msgcount<<8)&0xff0000) | // move byte 1 to byte 2
	//  ((msgcount>>8)&0xff00) | // move byte 2 to byte 1
	//  ((msgcount<<24)&0xff000000); // byte 0 to byte 3
	//memcpy(iv, &ctr, 4);
```

`msgcount` appears **nowhere else in the tree** — not declared, not defined,
not extern. `grep -rn msgcount` returns only those five commented lines. The
intent existed and was abandoned.

### Both tag functions are commented out, and the signatures cannot support them

`okcrypto.cpp:1574` and `:1612` are the two wrappers the box calls:

```c
void okcrypto_aes_gcm_encrypt2(...)   // :1608  //gcm.computeTag(tag, sizeof(tag));
void okcrypto_aes_gcm_decrypt2(...)   // :1646  //if (!gcm.checkTag(tag, sizeof(tag))) {
                                      //          return 1;
                                      //        }
```

Note that both functions return **`void`**. The commented-out `return 1;` would
not compile if uncommented — so this is not dormant code that can be switched
back on, it is code that was removed and left as a comment. There is no channel
through which a tag failure could be reported even if one were computed.

The `uint8_t tag[16];` declarations at `:1576` and `:1614` are commented too, so
no buffer for a tag is allocated on either side.

### The wire confirms it: ciphertext length equals plaintext length

`libraries/fido2/device.cpp:156`. There is no room on the wire for 16 tag
bytes, so even a client that wanted to verify one would have nothing to verify.

### The transit box explicitly opts out of the firmware's own defence in depth

`okcrypto.cpp:1726`, `okcrypto_split_sundae()`, is a layered-cipher construction
the firmware applies around GCM elsewhere — "mixes the best crypto algorithms
together in variable order with multiple variable keys ... to mitigate side
channel attacks against a single algorithm or key."

It is guarded at `:1768`:

```c
if ((*certified_hw != 1 && *certified_hw != 3) || s==false) return;
```

`okcrypto_aes_crypto_box()` passes `s = false` in both directions
(`:1036`, `:1039`), so **the layer is a no-op for the transit box**. Other
call sites (`:1470`, `:1479`, `:1552`, `:1561`) pass `true`.

`STD_VERSION` and `FACTORYKEYS` are both defined (`libraries/onlykey/onlykey.h:84,86`),
so this is the shipping configuration, not a debug build. The transit box is
the one place the firmware turns the extra layer off.

A side effect worth recording: the sundae layer selects its algorithm order
from `iv1[0] % 2`. Wherever it *is* active with a zero IV, that selector is a
constant, and the "Even/Odd IV different encryption algorithms" diversity
degenerates to a single fixed order.

### The command selector is outside the encrypted region

`libraries/fido2/ok_extension.cpp:159-172`:

```c
int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * keyh, int handle_len, uint8_t * output) {
	handle_len-=10;
	uint8_t cmd  = keyh[0];
	uint8_t opt1 = keyh[1];
	uint8_t opt2 = keyh[2];
	uint8_t opt3 = keyh[3];
	...
	memcpy(client_handle, keyh+10, handle_len);
```

`cmd`, `opt1`, `opt2` and `opt3` are read straight from the keyhandle. Only
`keyh+10` onward is the boxed payload. So *which operation runs* — sign,
decrypt, connect — and *which slot it runs against* are plaintext, attacker
-editable, and covered by nothing.

### No replay protection

`set_time` is guarded by `if (timeStatus() == timeNotSet)`
(`libraries/onlykey/okcore.cpp:1375`). It only ever sets the clock; it never
compares against it and never rejects. Nothing anywhere counts, timestamps or
rejects a repeated message.

## Consequences

With one key and one zero IV per session, the keystream `K` is fixed:

- **Two-time pad.** Any two payloads of equal length satisfy
  `C₁ ⊕ C₂ = P₁ ⊕ P₂`. Structured, partially-known plaintexts (protocol frames
  with fixed headers) leak directly.
- **Bit-flipping.** `C ⊕ Δ` decrypts to `P ⊕ Δ`. Any chosen bit of any
  plaintext can be flipped, and nothing detects it.
- **Selector substitution.** The command byte is not even encrypted; it can be
  changed without touching the ciphertext at all.
- **Replay.** A recorded message replays cleanly.

## Why the client cannot fix this alone

`okcrypto_aes_crypto_box()` takes no IV parameter, and there is nowhere on the
wire to put one. A client that varied its IV would not be rejected — the device
would decrypt to noise and then dispatch the still-plaintext command byte
against that noise. Unilateral "hardening" makes things strictly worse.

A fix is necessarily coordinated: firmware and client both change, with version
negotiation so an updated host can still talk to an un-updated key. Concretely
it needs a real nonce on the wire, a tag appended to the ciphertext, the tag
actually checked (which means changing those two `void` return types), and the
command selector moved inside the authenticated region — or at minimum bound in
as AAD.

## What this library does about it

Reproduces the format exactly, and refuses to misname it. The export is
**`legacyUnauthenticatedTransitBox`**, not `aesGcmEncrypt`, so that:

1. no caller can mistake it for authenticated encryption;
2. the eventual firmware fix has an obvious seam to land against;
3. `grep` finds every affected call site in one search.

It is implemented as **AES-CTR starting at counter block 2**, which is
byte-identical to GCM with a 12-byte IV (`J0 = IV‖00000001`, data starts at
`J0+1`) while avoiding GHASH entirely — and sidestepping the fact that a
WebCrypto or Node *decipher* refuses to run at all without a tag to check.
The box is its own inverse, so one function serves both directions.

Reachability is restricted: `plugins/session/` declares
`setup.allowed = [['device'], ['okcrypto']]`, so no other plugin can consume
the session key from the Rectify registry.

Pinned by three independent vectors in `test/transit.test.js` — the published
NaCl alice/bob `beforenm`, its SHA-256, and `box(key, 32 zero bytes)` — so a
mistake in one derivation step cannot hide inside another.
