# Findings

Defects found while porting OnlyKey-App, onlykey.github.io and
node-onlykey-fido2 into this library. Each was verified by reading the source
in this workspace — line numbers are real, not recalled.

Firmware and app repositories are **read-only** here. Nothing in this list has
been fixed in place; where the library works around something, that is noted.

`ok-rn/FINDINGS.md` holds a separate set, from the Android firmware port.
Those are hosting and toolchain defects. These are protocol and client
defects, and the first one is a live property of shipping firmware.

## Written up in full

| | severity | |
|---|---|---|
| [The transit box is not authenticated encryption](FINDING-transit-box-unauthenticated.md) | high | Zero IV, no tag, plaintext command selector, no replay protection. One keystream per session. Needs a coordinated firmware + client fix. |
| [The opt3 high-water mark has no timeout](FINDING-opt3-highwater-no-timeout.md) | medium | An aborted multi-chunk request can wedge the channel until reboot. Corrects a claim in the plan that blamed the wrong line. |

## Client defects fixed in the port

Each of these is reproduced-as-corrected in this library, with the reason in a
comment at the site and an assertion in `test/` that fails if someone
"restores" the original behaviour.

**1. The Curve25519 branch tests the wrong OID** — `OnlyKeyWizard.js:732`
re-tests the Ed25519 OID byte for byte, so a real cv25519 key never matches and
falls through to `CURVE.NONE`. Correct OID is `[43,6,1,4,1,151,85,1,5,1]`.
→ `src/device/keys.js`, `test/keys.test.js`

**2. OID comparison is `a.sort().join() === b.sort().join()`** —
`OnlyKeyWizard.js:730-734`. Wrong three ways: it **mutates both operands**; it
compares as a multiset, so a permuted OID matches; and `Uint8Array.sort` is
numeric while `Array.sort` is lexicographic, so a correct OID silently fails to
match whenever openpgp hands back a plain array.
→ `oidEquals()` is element-wise and order-sensitive

**3. `privKey.decrypt()` is not awaited** — `OnlyKeyComm.js:685`:

```js
var success = privKey.decrypt(passcode);
if (!success) { ... throw Error(error); }
```

`decrypt()` returns a Promise, which is always truthy, so the guard below can
never fire. A wrong passcode proceeds as if it had succeeded.

**4. base32 decoding mishandles padding and odd output** —
`OnlyKeyWizard.js:1529-1544`. `=` is not stripped before the alphabet lookup,
so `indexOf` returns `-1` and `"0" + -1` corrupts the bit string; a trailing
nibble is then dropped on odd-length output. Affects TOTP seeds.
→ `src/device/encoders.js`, `test/device.test.js`

**5. Three implicit globals holding secret material** —
`OnlyKeyWizard.js:1048-1050`:

```js
pubId  = formValue.toString().replace(/\s/g, "");
privId = privateId.toString().replace(/\s/g, "");
secKey = secret.toString().replace(/\s/g, "");
```

No `var`/`let`/`const`, so all three land on `window` and outlive the wizard.
`secKey` is the Yubikey AES secret. Two lines above, `console.info("secret", secret)`
also writes it to the console.

**6. Two divergent Yubikey encoders** — `OnlyKeyWizard.js:1038` uses 32/12/32
(spec-correct); `OnlyKeyComm.js:1687` truncates the public ID to 6 bytes and
its `// 64 bytes` comment does not match what it produces. The library has one
encoder on the former's constants, with two entry points over it, and refuses a
short credential rather than padding it.
→ `yubiCredential()` in `src/device/encoders.js`

## Behaviours reproduced deliberately, not defects

Recorded because each looks like a bug and removing it breaks something.

- **`slotId "XX"` → `NaN` → `0`.** The device-global pseudo-slot, arrived at by
  coercion accident upstream. Made explicit here.
- **`sendMessage` sleeps 100 ms after every send except `OKFWUPDATE`.** The
  asymmetry is load-bearing for firmware-update throughput.
- **Label slot tokens `1a`-`1e` map to 20-24 by table, not by hex.** `0x1a` is
  26; the table is right and the hex reading is wrong.
- **The first `OKGETLABELS` response is discarded** as a priming step. Miss it
  and label #1 goes missing.
- **`TFATYPE` is the literal ASCII `"googleAuthOtp"` / `"YubikeyOtp"`.** Not a
  numeric code.
- **`submitRsaKey` sends no length header.** Termination is device-side: `type`
  encodes the RSA size and the device counts to `128 * type`.
- **Restore/firmware chunk header:** `"FF"` means "full 57-byte chunk, more
  follow"; any value ≤ 57 means "last chunk, this many bytes". An exactly-114
  hex-char chunk is *final* and takes `"39"`, not `"FF"`.

## Open

- **`OKGETLABELS` has no timeout in any existing client** and hangs forever if
  the terminal message is lost. This library adds a deadline. Whether the
  firmware can genuinely drop that message, or the risk is only theoretical, is
  unresolved.
