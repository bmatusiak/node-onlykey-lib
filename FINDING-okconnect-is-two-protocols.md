# OKCONNECT means two different things depending on which interface it arrives on

**Severity:** high (as a client defect; it produced a silently unkeyed session)
**Status:** fixed in `src/session/transit.js` and `plugins/session/`; found by
running against real firmware on an Android device
**Applies to:** this library, and any client that assumes one OKCONNECT

## Summary

`OKCONNECT` (0xE4) is handled by two different pieces of firmware, and they
answer with two incompatible replies. Nothing on the wire distinguishes them —
same message id, same frame shape — so a client that assumes either one
silently misreads the other.

Over the **CTAP/FIDO** interface it is a key exchange. Over the **vendor HID**
interface it is `set_time()` plus a plaintext status broadcast, with no key
exchange at all.

## The evidence

`libraries/onlykey/okcore.cpp`, the vendor dispatch:

```c
case OKCONNECT:
    set_time(recv_buffer);
    return;
```

That is the whole case. `set_time()` then replies:

```c
Serial.print("UNLOCKED");
hidprint(HW_MODEL(UNLOCKED));
```

`hidprint()` writes a NUL-padded ASCII string through
`send_transport_response()` starting at **byte 0**. There is no public key in
it.

Over CTAP, `libraries/fido2/ok_extension.cpp:213-226` does the real thing:

```c
if (okcrypto_shared_secret (ecc_public_key, transit_key)) { ... }
// Hash the shared secret to generate the AES transit private key
sha256_update(&context, transit_key, 32);
sha256_final(&context, transit_key);
```

and answers with 32 bytes of X25519 public key followed by the status string
boxed under that key.

## What went wrong here

`parseConnectReply` was written from the CTAP reply, because that is the one
every JavaScript client implements — the web app has no raw HID access, so the
tunnel is the only path it has ever used. It read bytes 0..31 as the device's
public key and the remainder as a boxed status.

Given a vendor reply, that means the **first 32 characters of the status
string** were treated as an X25519 public key and fed into the transit-key
derivation. The consequences were all silent:

- `session.established` went **true** with a key derived from ASCII text.
- `box()` produced confident nonsense under that key.
- `status` came back as the empty string, because the "tail" was NUL padding
  and decoded to nothing — which reads as a device that answered with nothing
  to say, rather than as a parse that went off the rails at byte 0.

On the device this appeared as `OKCONNECT ok: ""`. It is worth dwelling on how
benign that looks: the request succeeded, no exception was thrown, and the only
symptom was an empty string.

## The fix

`parseConnectReply` now detects the form instead of assuming it, and reports
which one it saw as `kind: 'status' | 'exchange'`.

The discriminator is that a vendor reply, once its trailing NUL padding is
stripped, is **entirely printable ASCII**. A 32-byte X25519 public key that
satisfies that has probability around (95/256)^32 ≈ 1e-14. One non-printable
byte anywhere in the key half means it is an exchange.

`plugins/session` then keeps a derived key **only** for `kind: 'exchange'`. On
the vendor path `connect()` still succeeds and still reports the device's
status — that is genuinely what OKCONNECT is for there — but the session stays
unkeyed, so `box()` refuses rather than guessing.

Verified on a Samsung SM-S136DL (Android 13, armeabi-v7a) against the emulated
firmware: `OKCONNECT ok: "INITIALIZED"`, where it previously read `""`.

## The wider consequence

This is the third place the same boundary has surfaced, and it is worth stating
once: **the vendor interface and the CTAP interface are different protocols
that share a message-id namespace.**

- `derive_xwing_recipient` / `derive_xwing_decap` pass a key action in opt1, a
  key type in opt2 and an encrypt-response flag in opt3. Only
  `bridge_to_onlykey()` reads those; the vendor frame has nowhere to put them.
- The composite chunk framing differs by a slot byte between the two paths.
- And now OKCONNECT itself.

So "the session key" is a CTAP-path concept. Anything on the vendor interface
that needs one — the boxed composite payloads, in particular — needs the CTAP
transport too, not merely a translation of the framing. Any future transport
should declare which interface it speaks, because a plugin that answers on the
wrong one will look like it is working.
