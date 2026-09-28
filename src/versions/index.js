/*
 * The OnlyKey firmware releases, as one table every consumer reads.
 *
 *   const versions = require('node-onlykey-lib/versions');
 *   versions.list()                 -> ['v3.1.0', 'v3.0.5', 'v3.0.4', ...]
 *   versions.pinsFor('v3.0.4')      -> { libraries, 'OnlyKey-Firmware', file }
 *   versions.compatibilityOf('v3.0.4') -> what that release supports
 *
 * WHY IT LIVES HERE. The table used to be copied into each consumer - ok-rn's
 * ok-versions.json (pins only) and node-onlykey-emulator's (pins plus a
 * compatibility row per release) - and copies drift: the emulator's version
 * matrix already caught one host reading a release differently from the
 * others because its copy of THIS library was older. The compatibility rows are
 * this library's own capabilities(), so the library is the natural single
 * owner, and every GUI - the app, the emulator, the test kit - reads the same
 * list.
 *
 * What does NOT live here: each consumer's per-release stage scripts (the
 * patches that make an old release build under the Android NDK, or under
 * node-gyp and clang-cl). Those belong to a build system; this is data.
 *
 * ## A row
 *
 *   libraries, OnlyKey-Firmware   the pinned commits - the upstream release tags
 *   file                          the signed image's name (optional)
 *   compatibility                 { status, unreleased, capabilities } - what a
 *                                 signed build of the release reports and what
 *                                 capabilities() makes of it. GENERATED:
 *                                 scripts/versions-compat.js --write, and a test
 *                                 fails if it drifts from capabilities().
 *
 * A row with BOTH commits blank means "the working tree": a version that has
 * been named but not cut. A row with one pinned and one blank is an error, not
 * a third mode: the build would be neither the release nor the tree.
 *
 * The two newest rows are pinned to commits that are NOT release tags yet
 * (2026-09-28). A blank row builds whatever happens to be checked out, which
 * is not a version anyone can reproduce - so both are pinned to what was
 * actually built and tested:
 *
 *   v3.1.0  the release candidate: trustcrypto/libraries PR #33 and
 *           trustcrypto/OnlyKey-Firmware PR #183, branch release-3.1.0, at
 *           their current heads. Re-pin when the PRs move or the tag lands
 *           (upstream/watch.json and the maintainers' notes say when).
 *   v3.0.5  never released - the "3.0.5 compatibility tree" the test kit, ok-rn
 *           and the emulator were built against: 0c-coder's public libraries
 *           and OnlyKey-Firmware masters. It reports v3.0.5 and carries the
 *           CTAPHID wipe fix (0c-coder/libraries #20) that the 3.1.0 candidate
 *           does not.
 */
'use strict';

const TABLE = require('./ok-versions.json');
const { capabilities } = require('../device/version');

const REPOS = ['libraries', 'OnlyKey-Firmware'];

/** Every named release, newest first as the table lists them. */
function list() {
  return Object.keys(TABLE);
}

/**
 * A release's pinned commits, or null for a named-but-not-cut release (the
 * working tree). Throws on an unknown release or a half-pinned row.
 * @returns {{libraries: string, 'OnlyKey-Firmware': string, file?: string}|null}
 */
function pinsFor(version) {
  const row = TABLE[version];
  if (!row) {
    throw new Error(`${version} is not a known release; known: ${list().join(', ')}`);
  }
  const blank = REPOS.filter((k) => String(row[k] ?? '').trim() === '');
  const filled = REPOS.filter((k) => String(row[k] ?? '').trim() !== '');
  if (blank.length && filled.length) {
    throw new Error(
      `${version} pins ${filled.join(', ')} but leaves ${blank.join(', ')} blank. ` +
      'Blank means "the working tree", so a row has to be all pinned or all ' +
      'blank - otherwise the build is half a release and nothing records which half.');
  }
  if (blank.length) return null;
  const out = { libraries: row.libraries, 'OnlyKey-Firmware': row['OnlyKey-Firmware'] };
  if (row.file) out.file = row.file;
  return out;
}

/** The recorded compatibility of a release (see the header). */
function compatibilityOf(version) {
  if (!TABLE[version]) throw new Error(`${version} is not a known release`);
  return TABLE[version].compatibility || null;
}

/**
 * The OKCONNECT status a SIGNED Classic build of the release reports: '-prod'
 * on the x.y.z line; the beta line has no build suffix. (A DEBUG build reports
 * '-test', which capabilities() reads as the development tree.)
 */
function signedStatus(version) {
  const suffix = /^v\d+\.\d+\.\d+$/.test(version) ? '-prod' : '';
  return `UNLOCKED${version}${suffix}c`;
}

/** What the compatibility row SHOULD say, from capabilities() today. */
function expectedCompatibility(version) {
  const unreleased = pinsFor(version) === null;
  const status = signedStatus(version);
  return { status, unreleased, capabilities: capabilities(status, { unreleased }) };
}

module.exports = {
  TABLE,
  REPOS,
  list,
  pinsFor,
  compatibilityOf,
  signedStatus,
  expectedCompatibility,
};
