/*
 * THE FEATURE PLUGINS' BOUNDARY (step 3; CLI.md §6): core never requires a feature
 * plugin's folder. Only the boot (cli/boot.js) looks for them, and a missing folder is
 * then simply not listed. A feature plugin may require core.
 *
 * Until step 3b moves them into edge/, Edge's files still sit in core's folders
 * (src/edge, plugins/edge, cli/edge-*) and may use Key Chain - Edge consumes it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CORE = ['src', 'cli', 'plugins', 'scripts'];
const EDGE_UNTIL_3B = (f) => /^src\/edge\/|^plugins\/edge\/|^cli\/edge-[a-z-]+\.js$/.test(f);
const BOOT = 'cli/boot.js';

function walk(dir, out = []) {
  for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'vendor' || e.name === 'dev') continue;
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) walk(p, out);
    else if (p.endsWith('.js')) out.push(p);
  }
  return out;
}

/* every relative require in core that lands in a feature plugin's folder */
function reachingInto(folder) {
  const hits = [];
  for (const file of CORE.flatMap((d) => walk(d))) {
    if (file === BOOT || EDGE_UNTIL_3B(file)) continue;
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
    for (const m of src.matchAll(/require\((['"])(\.{1,2}\/[^'"]+)\1\)/g)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), m[2]));
      if (target === folder || target.startsWith(`${folder}/`)) hits.push(`${file} -> ${m[2]}`);
    }
  }
  return hits;
}

test('core never requires keychain/ (only the boot looks for it)', () => {
  assert.deepEqual(reachingInto('keychain'), []);
});

test('core never requires edge/ (only the boot looks for it)', () => {
  assert.deepEqual(reachingInto('edge'), []);
});
