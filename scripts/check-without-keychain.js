#!/usr/bin/env node
'use strict';

/**
 * THE LIB WITHOUT KEY CHAIN (step 3a; CLI.md §6): a copy with keychain/ left out - and
 * edge/ with it, since Edge consumes Key Chain - must still pass every test that is not
 * theirs, and `onlykey-js --help` must work and list neither command. A core file that
 * reaches into either folder fails here, as it would for someone who builds without them.
 *
 * Usage: node scripts/check-without-keychain.js   (exit 0 = core stands alone)
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const LEFT_OUT = ['keychain', 'edge'];
const SKIP = new Set(['.git', 'node_modules', ...LEFT_OUT]);

const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'onlykey-lib-without-keychain-'));
for (const e of fs.readdirSync(ROOT, { withFileTypes: true })) {
  if (SKIP.has(e.name)) continue;
  fs.cpSync(path.join(ROOT, e.name), path.join(dest, e.name), { recursive: true });
}
fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dest, 'node_modules'), 'junction');
/* published without them, the package would not export them either */
const pkgFile = path.join(dest, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
for (const [k, v] of Object.entries(pkg.exports)) {
  /* Edge's files still in core's folders until step 3b moves them into edge/ go with Edge */
  if (typeof v === 'string' && (LEFT_OUT.some((d) => v.startsWith(`./${d}/`)) || /^\.\/(src\/edge|plugins\/edge|cli\/edge-)/.test(v))) delete pkg.exports[k];
}
fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2));

/* their tests: anything that requires their folders or Edge's code (Edge consumes Key Chain) */
const theirs = (src) => /require\((['"])(\.\.\/)+(keychain|edge)\//.test(src)
  || /require\((['"])\.\.\/(src\/edge|plugins\/edge|cli\/edge-)/.test(src)
  || /node-onlykey-lib\/(keychain|edge)\b/.test(src)
  || /\b(main|run)\(\[?['"](keychain|edge)['"]/.test(src)
  || /helpers\/fake-edge-key/.test(src)
  /* needs the repo's git (the copy has none) */
  || /git ls-files/.test(src);
const tests = fs.readdirSync(path.join(dest, 'test')).filter((f) => f.endsWith('.test.js'))
  .filter((f) => !theirs(fs.readFileSync(path.join(dest, 'test', f), 'utf8')));

let failed = 0;
const help = spawnSync(process.execPath, ['cli/index.js', '--help'], { cwd: dest, encoding: 'utf8' });
if (help.status !== 0) { failed++; console.error(`--help exited ${help.status}: ${help.stderr.split('\n').slice(0, 4).join(' | ')}`); }
else if (/^\s+(keychain|edge)\s/m.test(help.stdout)) { failed++; console.error('--help still lists keychain or edge'); }
else console.log('--help: works, no keychain, no edge');

/* a test that names a plugin in its title is that plugin's: "(Key Chain) …", "(Edge) …" */
const run = spawnSync(process.execPath, ['--test', '--test-skip-pattern=^\\((Key Chain|Edge)\\)', ...tests.map((f) => `test/${f}`)], { cwd: dest, encoding: 'utf8' });
const pass = /ℹ pass (\d+)/.exec(run.stdout);
const fail = /ℹ fail (\d+)/.exec(run.stdout);
console.log(`tests without keychain/ and edge/: ${tests.length} files, pass ${pass ? pass[1] : '?'}, fail ${fail ? fail[1] : '?'}`);
if (run.status !== 0) {
  failed++;
  const lines = run.stdout.split('\n').filter((l) => /^test at |✖ /.test(l)).slice(0, 20);
  console.error(lines.join('\n'));
}
fs.rmSync(dest, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
