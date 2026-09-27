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

## 0.2.0 - in progress

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
