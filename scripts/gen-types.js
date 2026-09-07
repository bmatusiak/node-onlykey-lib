/*
 * Regenerate the .d.ts files that sit next to the sources.
 *
 * Declarations are emitted INTO src/ because package.json's exports map uses
 * plain string targets, and TypeScript finds types for `./src/bytes.js` by
 * looking for `./src/bytes.d.ts` beside it. Emitting into a separate types/
 * directory would need a typesVersions table restating all eleven subpaths by
 * hand, which is exactly the drift that generating them avoids.
 *
 * The cost of that choice is this script. On a second run the previously
 * emitted declarations are inputs to the compiler, and tsc refuses to overwrite
 * an input file (TS5055) - so they have to go first.
 *
 * src/vendor/ is spared. Its openpgp.d.ts is hand-written and is the type
 * source for a 1.2 MB generated bundle that tsc can only infer as `{}`.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const {execFileSync} = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const KEEP = path.join(SRC, 'vendor');

function removeGenerated(dir) {
  let removed = 0;
  for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (full === KEEP) continue;
      removed += removeGenerated(full);
    } else if (entry.name.endsWith('.d.ts')) {
      fs.unlinkSync(full);
      removed++;
    }
  }
  return removed;
}

const removed = removeGenerated(SRC);
if (removed) console.log(`cleaned ${removed} generated .d.ts`);

/*
 * Resolved through Node rather than shelled out to `npx tsc`. npx has no
 * portable executable name (npx.cmd on Windows) and goes through a shell, so a
 * spawn failure surfaces as an opaque ENOENT with no mention of TypeScript.
 * require.resolve finds the exact compiler this package installed.
 */
const tsc = require.resolve('typescript/bin/tsc');
execFileSync(process.execPath, [tsc, '-p', 'tsconfig.json'], {
  cwd: ROOT,
  stdio: 'inherit',
});

console.log('declarations regenerated');
