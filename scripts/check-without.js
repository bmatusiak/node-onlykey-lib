#!/usr/bin/env node
'use strict';

/**
 * THE LIB WITHOUT A FEATURE PLUGIN (step 3; CLI.md §6): a copy with the plugin's
 * folder left out must still pass every test that is not the plugin's, and
 * `onlykey-js --help` must work and not list its command. A core file (or Key Chain)
 * that reaches into a left-out folder fails here, as it would for someone who builds
 * without it.
 *
 *   node scripts/check-without.js edge       core + Key Chain, no edge/
 *   node scripts/check-without.js keychain   core alone: Edge consumes Key Chain, so
 *                                            leaving keychain/ out takes edge/ with it
 *
 * Exit 0 = what is left stands alone.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const which = process.argv[2];
const LEFT_OUT = { edge: ['edge'], keychain: ['keychain', 'edge'] }[which];
if (!LEFT_OUT) {
  console.error('usage: node scripts/check-without.js edge|keychain');
  process.exit(2);
}
const KEPT_PLUGINS = ['keychain', 'edge'].filter((d) => !LEFT_OUT.includes(d));
const COMMAND = { keychain: 'keychain', edge: 'edge' };
const TAG = { keychain: 'Key Chain', edge: 'Edge' };
const SKIP = new Set(['.git', 'node_modules', ...LEFT_OUT]);

const dest = fs.mkdtempSync(path.join(os.tmpdir(), `onlykey-lib-without-${which}-`));
for (const e of fs.readdirSync(ROOT, { withFileTypes: true })) {
  if (SKIP.has(e.name)) continue;
  fs.cpSync(path.join(ROOT, e.name), path.join(dest, e.name), { recursive: true });
}
fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dest, 'node_modules'), 'junction');
/* published without them, the package would not export them either */
const pkgFile = path.join(dest, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
for (const [k, v] of Object.entries(pkg.exports)) {
  if (typeof v === 'string' && LEFT_OUT.some((d) => v.startsWith(`./${d}/`))) delete pkg.exports[k];
}
fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2));

/* their tests: anything that requires a left-out folder or runs its command */
const folders = LEFT_OUT.join('|');
const theirs = (src) => new RegExp(`require\\((['"])(\\.\\./)+(${folders})/`).test(src)
  || new RegExp(`node-onlykey-lib/(${folders})\\b`).test(src)
  || new RegExp(`\\b(main|run)\\(\\[?['"](${LEFT_OUT.map((d) => COMMAND[d]).join('|')})['"]`).test(src)
  /* needs the repo's git (the copy has none) */
  || /git ls-files/.test(src);
const tests = ['test', ...KEPT_PLUGINS.map((d) => `${d}/test`)].flatMap((dir) =>
  fs.readdirSync(path.join(dest, dir)).filter((f) => f.endsWith('.test.js')).map((f) => `${dir}/${f}`))
  .filter((f) => !theirs(fs.readFileSync(path.join(dest, f), 'utf8')));

let failed = 0;
const help = spawnSync(process.execPath, ['cli/index.js', '--help'], { cwd: dest, encoding: 'utf8' });
const listed = new RegExp(`^\\s+(${LEFT_OUT.map((d) => COMMAND[d]).join('|')})\\s`, 'm');
if (help.status !== 0) { failed++; console.error(`--help exited ${help.status}: ${help.stderr.split('\n').slice(0, 4).join(' | ')}`); }
else if (listed.test(help.stdout)) { failed++; console.error(`--help still lists ${LEFT_OUT.join(' or ')}`); }
else console.log(`--help: works, without ${LEFT_OUT.join(' and ')}`);

/* a test that names a plugin in its title is that plugin's: "(Key Chain) …", "(Edge) …" */
const skip = `--test-skip-pattern=^\\((${LEFT_OUT.map((d) => TAG[d]).join('|')})\\)`;
const run = spawnSync(process.execPath, ['--test', skip, ...tests], { cwd: dest, encoding: 'utf8' });
const pass = /ℹ pass (\d+)/.exec(run.stdout);
const fail = /ℹ fail (\d+)/.exec(run.stdout);
console.log(`tests without ${LEFT_OUT.join('/ and ')}/: ${tests.length} files, pass ${pass ? pass[1] : '?'}, fail ${fail ? fail[1] : '?'}`);
if (run.status !== 0) {
  failed++;
  const lines = run.stdout.split('\n').filter((l) => /^test at |✖ /.test(l)).slice(0, 20);
  console.error(lines.join('\n'));
}
fs.rmSync(dest, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
