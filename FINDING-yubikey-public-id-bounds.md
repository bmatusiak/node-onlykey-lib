# The Yubikey public-id bounds are undiscoverable from any client

**Severity:** medium
**Status:** corrected in `src/device/encoders.js`; the upstream clients are
still wrong, each in a different direction
**Applies to:** `OnlyKey-App` (both encoders), and the earlier plan for this
library, which got it wrong in a third way

## Summary

OnlyKey-App contains two Yubico OTP encoders with different public-id limits.
They look like a stale copy and a current one, and every reading of them —
including my own, twice — has tried to pick a winner.

There is no winner. They are **two different device features with genuinely
different limits**, and the firmware is the only place that says so.

## What the firmware actually does

`libraries/onlykey/okcore.cpp:5772-5825`, `yubikeyinit(uint8_t slot)`:

```c
uint8_t publen = 16; // Max public size
...
if (slot == 0) {
    ...
    memcpy(pubID, temp, 6); // Old Yubikey method only supports default 6 len pubkey
    memcpy(privID, temp+EElen_public, 6);
    yubikey_hex_encode(public_id, (char *)pubID, 6);
} else if (slot > 0 && slot < 25) {
    ...
    for (int i = 37; i > 1; i--) { // Public ID 2-16 bytes
         if (temp[i]!=0) {
             break;
         }
         publen--;
    }
    memcpy(pubID, temp, publen);
    memcpy(privID, temp+publen, 6);
    yubikey_hex_encode(public_id, (char *)pubID, publen);
    ctx.publen = publen;
}
```

- **Slot 0** — the deprecated EEPROM path — copies exactly **6 bytes** and says
  so in a comment.
- **Slots 1-24** — the per-slot flash path — treats the public id as
  **2 to 16 bytes**, variable, recovered by trimming trailing zeros from the
  38-byte decrypted blob.

The length is never transmitted. It is *inferred*, which is why the range
exists at all and why neither bound appears in any client.

## What the clients do

| | public id | encoding | target |
|---|---|---|---|
| `OnlyKeyWizard.js:1052-1057` | `slice(0, 32)` — up to 16 bytes | modhex, converted via `hexToModhex(x, true)` | current slot |
| `OnlyKeyComm.js:1697` | `slice(0, 12)` — 6 bytes | hex, concatenated unchanged | slot 0 (`"XX"`) |

Each is **correct for its own path and wrong for the other's**, and neither
enforces the bound it needs:

- The wizard accepts a 1-byte public id, which slots cannot represent — the
  firmware's loop bottoms out at 2.
- Both `slice()` rather than reject, so an over-long public id is silently
  shortened. The credential is then built from a truncated identity and simply
  never authenticates. Nothing reports an error at any layer; the OTP is
  one-way, so the failure appears at the validator, not on the device.
- `OnlyKeyComm.js:1699`'s comment `// 64 bytes` on a 32-character slice is
  wrong twice over — 32 hex chars is 16 bytes.

There is also a third difference that makes "just pick one encoder" impossible:
the two paths disagree about the **input encoding**. The wizard is handed
modhex and converts it; `setYubiAuth` is handed hex and concatenates it
unchanged. An encoder shared between them would have to convert for one caller
and not the other.

## Why this was hard to see

The two functions are 600 lines apart, in different files, and both are named
for the form they serve rather than the path they write. Nothing in either says
which slot it targets — the slot is `"XX"` in one and an implicit "current" in
the other, and `"XX"` only becomes 0 by a `parseInt` coercion accident
(documented separately in `src/device/slots.js`).

I got this wrong in two different directions before reading the firmware. The
first plan for this library recorded "port one encoder with the wizard's
32/12/32 constants"; later analysis argued `OnlyKeyComm`'s 12 was the
spec-correct one. Both are half right, which is the characteristic shape of a
constant that is actually two constants.

## What this library does

`src/device/encoders.js` exposes **two entry points over one assembler**:

- `yubiCredential({publicId, privateId, secretKey})` — per-slot. Takes modhex,
  converts, enforces 2-16 bytes.
- `yubiGlobalCredential({publicId, privateId, secretKey})` — slot 0. Takes hex,
  enforces exactly 6 bytes.

Both **refuse** rather than slice, and the error carries the length that was
supplied, because "got 40" is the entire diagnosis and a truncated credential
gives none.

Pinned in `test/device.test.js`, including the boundary cases the firmware
implies but no client mentions: 2 bytes accepted, 1 rejected, 17 rejected.

## A consequence worth reporting separately: a secret ending in 0x00 mis-splits

The length is inferred by counting trailing zeros, and the bytes being counted
are not the public id's — they are the end of the AES key.

The decrypted blob is laid out (`okcore.cpp:5813-5822`, with `EElen_public 6`,
`EElen_private 6`, `EElen_aeskey 16` from `okeeprom.h:91-93`):

```
temp[0 .. P-1]        public id, P bytes
temp[P .. P+5]        private id, 6 bytes
temp[P+6 .. P+21]     AES key, 16 bytes
temp[P+22 .. 37]      zero padding, 16-P bytes
```

The decrypt covers a fixed 38 bytes, so for a public id shorter than 16 the
tail is zero-filled. The scan starts at index 37 and decrements `publen` for
each zero it meets, stopping at the first non-zero byte — which for a
correctly-stored credential is `aeskey[15]`, at `temp[P+21]`.

That gives the right answer *only if the AES key does not end in a zero byte*:

- `aeskey[15] != 0` → the scan counts exactly `16 - P` zeros → `publen = P`. ✅
- `aeskey[15] == 0` → it counts one more → `publen = P - 1`, and **all three
  fields are then read one byte out of place**: the public id loses its last
  byte, the private id and the AES key each shift down by one and take a byte
  that is not theirs. ❌

An AES key is uniformly random, so roughly **1 in 256** Yubico credentials
stored in a slot are read back wrong. Two zero bytes at the end shifts by two,
and so on. The device does not error — it derives an OTP from a mis-split
credential, which fails validation somewhere else entirely, on a key that was
written correctly.

This follows from reading the code rather than from an observed failure; it has
not been reproduced on a device. The arithmetic is set out above so it can be
checked rather than taken on trust, and the natural test is to store a
credential whose AES key ends in `0x00` and read back `public_id`.

Slot 0 is unaffected: it copies a fixed 6 bytes and never scans.

## Suggested firmware follow-up

Store the public-id length rather than inferring it. `ctx.publen` is already
carried at runtime, and one byte alongside the blob would remove both the 2-16
guess and the 1-in-256 mis-split above.

Until then a host cannot work around it safely: the length is decided entirely
on the device, from data the host cannot see after it is written. Rejecting
secrets that end in `0x00` at the host would avoid the common case, but it
weakens key generation to compensate for a parsing bug and should not be
necessary.
