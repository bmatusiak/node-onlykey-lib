# Vendored third-party libraries - the project's one copy

Every third-party library this project runs lives here, once:

| package | version | why |
|---|---|---|
| `@noble/hashes` | 2.4.0 | SHA-256/512, SHA3/SHAKE, HMAC, HKDF |
| `@noble/curves` | 2.4.0 | X25519/Ed25519, P-256; `abstract/fft` for ML-KEM |
| `@noble/ciphers` | 2.4.0 | AES-GCM/CBC, ChaCha20-Poly1305, XSalsa20 |
| `@noble/post-quantum` | 0.7.1 | ML-KEM-768 (the post-quantum half of X-Wing) |
| `tweetnacl` | 1.0.3 | `nacl.box` - the OKCONNECT / legacy transit key agreement |
| `openpgp` (PQC fork) | 6.0.0 fork | see `openpgp/VENDORED.md` - its own record |

`VENDORED.json` is the machine-readable record: each package's npm
`integrity`, tarball URL, file count and tree hash.

## Why one copy

Each repo used to carry its own: this library had @noble as caret npm
dependencies, the test kit older ones, ok-rn its own `@noble/curves`, and the
web app vendors 2.2.0 by hand. They drifted - the test kit's 03-gui parity guard
is that drift. One copy is:

- **one place to audit.** The files are the published npm tarball, unmodified.
  `VENDORED.json` names the tarball; `scripts/vendor.js --check` (and
  `test/vendor.test.js`, on every `npm test`) recompute each package's tree
  hash and fail on any edited, added or missing file.
- **one place to swap for the whole project.** Change a version in
  `scripts/vendor.js`, run it, run `npm test`. Every consumer - the kit, the
  emulator, ok-rn, and the web app and App once they move onto this library -
  gets it with its next pin of this library, instead of each repo being bumped
  (or forgotten) on its own.

## Layout

    src/vendor/
      node_modules/@noble/{hashes,curves,ciphers,post-quantum}/   the tarballs, unmodified
      node_modules/tweetnacl/
      exports/@noble/<pkg>/<module>.js + .d.ts                     generated shims
      exports/tweetnacl.js + .d.ts
      VENDORED.json                                                the record
      openpgp/                                                     the PQC fork (own record)

**Why a directory named `node_modules`.** @noble's packages import each other
by bare name (`@noble/hashes/utils.js` inside `@noble/curves`). Node, Metro and
webpack all resolve a bare name from the nearest `node_modules` directory up the
tree, so the copies work unedited with no alias or resolver setting in any
consumer. npm keeps a nested `node_modules` when it packs or git-installs this
library; `test/vendor.test.js` checks that with `npm pack --dry-run`.

**Why the shims.** Node refuses an `exports` target that passes through a
`node_modules` segment, so the public subpath cannot point into the copies.
`scripts/vendor.js` writes one CommonJS shim (and a `.d.ts` re-exporting the
package's own types) per module each package exports. No shim is written for a
package root: @noble's roots throw on import by design. This library's own code
uses the shims too, so the shims are the only files that name the copies.

## For consumers

    require('node-onlykey-lib/vendor/@noble/hashes/sha2.js')
    require('node-onlykey-lib/vendor/@noble/curves/ed25519.js')
    require('node-onlykey-lib/vendor/@noble/post-quantum/ml-kem.js')
    require('node-onlykey-lib/vendor/tweetnacl')

Drop your own `@noble/*` / `tweetnacl` dependency and use these. A bundler
that aliases `@noble/*` (the web app's webpack config) points the alias at
`node_modules/node-onlykey-lib/src/vendor/node_modules/@noble/<pkg>`.

**@noble v2 is ES modules.** Node loads them through `require()` (require(esm),
Node 20.19+ / 22.12+). Metro and webpack transform them; webpack 4 needs babel
over these files for BigInt literals, as the web app already configures for its
own copy.

## Known reach for Node built-ins

`tweetnacl` requires Node's `crypto` when there is no global
`crypto.getRandomValues`. That is the same file this library used from npm
before vendoring. `test/package.test.js` pins that list, so a version bump that
adds a built-in fails the test.

## Updating

1. Edit the version (and `why`) in `scripts/vendor.js`.
2. `node scripts/vendor.js` - fetches with `npm pack`, re-checks the integrity
   itself, replaces the copy, regenerates the shims and `VENDORED.json`.
3. `npm test` - the frozen vectors must pass on the new version.
4. Commit, then move each consumer's pin.
