'use strict';

/**
 * cli/dev - THE DEV BUILD'S core switches (CLI.md §5, decided 2026-10-06).
 *
 * cli/index.js loads this folder only when it is there. The published package
 * leaves it out (package.json "files"), and scripts/release-check.js fails if any
 * of it is reachable from a packed install. Nothing here can be turned on in a
 * production package - not by an environment variable, not by a flag - because
 * the agent can set those itself.
 *
 * What lives here:
 *   ONLYKEY_JS_DEBUG                  stack traces on errors
 *
 * Edge's dev set (--edge-home, --identity, OKEDGE_TIMES, OKEDGE_IDLE_MS, `edge ping`)
 * lives with Edge, in edge/cli/dev (step 3b), so core never names it.
 */
module.exports = {
  debugStack: Boolean(process.env.ONLYKEY_JS_DEBUG),
};
