#!/usr/bin/env node
/*
 * versions-compat.js - keep src/versions/ok-versions.json's compatibility rows
 * in step with capabilities().
 *
 *   node scripts/versions-compat.js --write   regenerate every row's compatibility
 *   node scripts/versions-compat.js           check; name every drifted flag
 *
 * The rows are GENERATED, never hand-typed - 29 flags times ten releases is a
 * table nobody keeps right by hand. Run --write after changing version.js or a
 * pin; test/versions.test.js fails until you do. (Moved here from
 * node-onlykey-emulator's scripts/versions/_compat.js with the table itself.)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const versions = require('../src/versions');

const FILE = path.join(__dirname, '..', 'src', 'versions', 'ok-versions.json');

/** Flatten nested objects to dotted keys, so a diff names the exact flag. */
function flat(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, key, out);
    else out[key] = v;
  }
  return out;
}

/** Flag paths where a recorded row and capabilities() disagree. */
function drift(version, table = versions.TABLE) {
  const a = flat((table[version] || {}).compatibility);
  const b = flat(versions.expectedCompatibility(version));
  return [...new Set([...Object.keys(a), ...Object.keys(b)])]
    .filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]))
    .map((k) => ({ flag: k, recorded: a[k], expected: b[k] }));
}

function main() {
  if (process.argv.includes('--write')) {
    const table = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    for (const v of Object.keys(table)) table[v].compatibility = versions.expectedCompatibility(v);
    fs.writeFileSync(FILE, JSON.stringify(table, null, 2) + '\n');
    console.log(`versions-compat: wrote ${Object.keys(table).length} rows`);
    return;
  }
  let bad = 0;
  for (const v of versions.list()) {
    const d = drift(v);
    if (!d.length) continue;
    bad++;
    console.log(`${v}: ${d.length} flag(s) differ from capabilities()`);
    for (const x of d) console.log(`  ${x.flag}: recorded ${JSON.stringify(x.recorded)}, expected ${JSON.stringify(x.expected)}`);
  }
  console.log(bad ? `versions-compat: ${bad} release(s) out of step` : 'versions-compat: all rows match');
  if (bad) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { flat, drift };
