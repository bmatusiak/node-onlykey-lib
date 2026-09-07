# Vendored openpgp.js (PQC-aware fork)

OpenPGP.js v6.0.0 fork, 2026-07-06, carrying the composite PGP-PQC algorithms
(ML-KEM-768 + X25519, ML-DSA-65 + Ed25519) and the hardware-hook API that lets
private-key operations route to an OnlyKey instead of holding key material in
the process.

Copied from `onlykey.github.io/src/onlykey-fido2/onlykey/vendor/openpgp/openpgp.js`.
That file's own `VENDORED.md` is the authoritative record of what the fork is,
why it is not stock upstream, and the draft-ietf-openpgp-pqc-10 conformance
corrections applied to it. **Read that file, not this one, for any question
about the crypto.** This note only covers what is different about *this* copy.

## The one modification: a CommonJS export

The shared file is a plain script — `var openpgp = (function (exports) {…})({})`
— with no `module.exports`. A top-level `var` in a CommonJS module is
module-scoped, so `require()` of it returns an empty object.

Both existing consumers work around this by evaluating the source:
`python-onlykey/onlykey/openpgp_bridge/bridge.js` with
`fs.readFileSync` + `new Function(source + ';return openpgp;')()`, and
`onlykey.github.io`'s `openpgp_loader.js` with the same trick over
`raw-loader!`.

**Neither works in React Native.** Hermes disables `eval` and `new Function` by
default, so both mechanisms throw at load and PGP would be unavailable on the
one platform this library exists to reach. There is no `fs` there either.

So this copy has exactly one thing appended:

```js
module.exports = openpgp;
```

27 bytes, CRLF-terminated to match the file. Nothing else is touched — no
reformatting, no line-ending conversion, no minification. The result is an
ordinary `require()`-able module in Node, browsers, nw.js and Hermes alike,
with no evaluation step anywhere.

## Staying in step with the other two copies

`onlykey.github.io`'s copy and `python-onlykey`'s copy are required to stay
**byte-identical to each other**. This copy cannot be byte-identical to them —
it is those bytes plus one line — so the relationship is checked a level down
instead:

> **this file, with its final `module.exports` line removed, must be
> byte-identical to both sibling copies.**

Body MD5: `7db75c5a2200c0aca65dccb7cda4202c` (1272214 bytes)
This file: 1272241 bytes

`test/openpgp-vendor.test.js` asserts exactly that. It checks the suffix, then
the stripped body against the pinned MD5, then against each sibling checkout
when present — skipping cleanly when they are not, the way the other
cross-checks in this suite do.

If you update the fork, update all three copies together, then re-run that
test. If it fails, the copies have drifted and the MD5 in this note plus the
one in the test both need updating deliberately — not silently.

## `.gitattributes`

This repo has `core.autocrlf` active. A line-ending rewrite on checkout would
change the file's bytes and break the checksum on every machine except the one
that committed it, so `/.gitattributes` marks this path `-text` to keep git out
of it.

## Load cost

1.2 MB, parsed on first `require()`. It is behind the `./crypto/pgp` subpath
export for that reason — `connect()` and the whole device-management surface
never touch it.
