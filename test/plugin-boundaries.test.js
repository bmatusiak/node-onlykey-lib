/*
 * THE FEATURE PLUGINS' BOUNDARY (step 3; CLI.md §6): core never requires a feature
 * plugin's folder. Only the boot (cli/boot.js) looks for them, and a missing folder is
 * then simply not listed. A feature plugin may require core.
 *
 * Between the plugins the arrow points one way: Edge consumes Key Chain, so Edge may
 * require keychain/, and Key Chain never requires edge/ (it never knows about Edge).
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CORE = ['src', 'cli', 'plugins', 'scripts'];
const BOOT = 'cli/boot.js';

function walk(dir, out = []) {
  /* a build without that plugin has nothing to scan */
  if (!fs.existsSync(path.join(ROOT, dir))) return out;
  for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'vendor' || e.name === 'dev') continue;
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) walk(p, out);
    else if (p.endsWith('.js')) out.push(p);
  }
  return out;
}

/* every relative require in core (or the given folders) that lands in a feature plugin's folder */
function reachingInto(folder, from = CORE) {
  const hits = [];
  for (const file of from.flatMap((d) => walk(d))) {
    if (file === BOOT) continue;
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

test('Key Chain never requires edge/ (Edge consumes Key Chain, not the other way)', () => {
  assert.deepEqual(reachingInto('edge', ['keychain']), []);
});
