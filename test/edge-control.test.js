'use strict';

/* a desktop app running on the developer's machine is not this test's (desktop/trust.js) */
process.env.ONLYKEY_JS_DESKTOP = 'off';

/*
 * onlykey-js edge control (the workspace's edge skill, moved into the CLI - Brad, 2026-10-23) and
 * edge --claude-setup. No key: note / preview / ship --plan / settings read git and the Edge home
 * only, and --claude-setup writes one file. The budget steps themselves are the edge commands'
 * own tests; ship spends them as children.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const control = require('../edge/cli/edge-control');
const { main } = require('../cli/index.js');

const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const io = () => { const out = []; const err = []; return { out: (l) => out.push(l), err: (l) => err.push(l), lines: out, errs: err }; };
const git = (cwd, ...a) => {
  const r = spawnSync('git', a, { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${a.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
};

/* a repo with a base commit and one unsigned commit after it */
function repoWithWork() {
  const dir = tmp('okjs-ctl-repo-');
  git(dir, 'init', '-q');
  git(dir, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'base');
  git(dir, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'work to sign');
  return dir;
}

test('control note keeps the batch in the Edge home; preview shows the commit TO SIGN and the request', async () => {
  const home = tmp('okjs-ctl-home-');
  const repo = repoWithWork();
  try {
    const a = io();
    assert.equal(await control.run({ io: a, opts: {}, argv: ['note', `${repo}:HEAD~1`], net: 'live', home }), 0);
    const batch = JSON.parse(fs.readFileSync(path.join(home, control.BATCH_FILE), 'utf8'));
    assert.equal(batch.length, 1);
    assert.match(batch[0], /:HEAD~1$/);

    const p = io();
    /* --path: a USB key opened by this CLI itself, whether or not a desktop app runs on this machine */
    assert.equal(await control.run({ io: p, opts: { path: 'a-usb-key' }, argv: ['preview'], net: 'live', home }), 0);
    const said = p.lines.join('\n');
    assert.match(said, /TO SIGN [0-9a-f]{7} work to sign/);
    assert.match(said, /On this terminal, a budget request for the key on USB/);
    assert.match(said, /1 signature\(s\), 1 push\(es\), valid 30 min/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('control ship --plan counts without a key; --ble names the phone in the request; the testnet says so', async () => {
  const home = tmp('okjs-ctl-home-');
  const repo = repoWithWork();
  try {
    const a = io();
    assert.equal(await control.run({ io: a, opts: {}, argv: ['ship', `${repo}:HEAD~1`, '--plan'], net: 'live', home }), 0);
    assert.deepEqual(a.lines, ['plan: 1 signature(s), 1 push(es)']);

    fs.writeFileSync(path.join(home, control.SETTINGS_FILE), JSON.stringify({ ttl: 45 }));
    await control.run({ io: io(), opts: { ble: true, address: 'Pixel 6a' }, argv: ['note', `${repo}:HEAD~1`], net: 'test', home });
    const p = io();
    await control.run({ io: p, opts: { ble: true, address: 'Pixel 6a' }, argv: ['preview'], net: 'test', home });
    assert.match(p.lines.join('\n'), /On the phone \(Pixel 6a\), a budget request[\s\S]*valid 45 min - TESTNET/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('control: a path that is not a repo STOPs; an unknown verb is a usage error', async () => {
  const home = tmp('okjs-ctl-home-');
  try {
    const a = io();
    assert.equal(await control.run({ io: a, opts: {}, argv: ['note', path.join(home, 'nope')], net: 'live', home }), 1);
    assert.match(a.lines.join('\n'), /STOP: .* is not a git repository/);
    const b = io();
    assert.equal(await control.run({ io: b, opts: {}, argv: ['bogus'], net: 'live', home }), 2);
    assert.match(b.errs.join('\n'), /edge \[--test-mode\] control note/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('edge --claude-setup writes the edge-control skill; a file it did not write is left alone without --force', () => {
  const ws = tmp('okjs-ctl-ws-');
  try {
    const a = io();
    assert.equal(control.claudeSetup({ io: a, cwd: ws, cmdline: 'onlykey-js' }), 0);
    const file = path.join(ws, '.claude', 'skills', 'edge-control', 'SKILL.md');
    const text = fs.readFileSync(file, 'utf8');
    assert.match(text, /^---\nname: edge-control\n/);
    assert.match(text, /onlykey-js edge control ship/);
    assert.match(text, /onlykey-js --ble --address "<phone>" edge control/);
    /* its own file is rewritten (a newer CLI), a foreign one is not */
    assert.equal(control.claudeSetup({ io: io(), cwd: ws, cmdline: 'node "/x/cli/index.js"' }), 0);
    assert.match(fs.readFileSync(file, 'utf8'), /node "\/x\/cli\/index.js" edge control note/);
    fs.writeFileSync(file, 'my own skill\n');
    const b = io();
    assert.equal(control.claudeSetup({ io: b, cwd: ws }), 1);
    assert.equal(fs.readFileSync(file, 'utf8'), 'my own skill\n');
    assert.match(b.errs.join('\n'), /left alone \(--force replaces it\)/);
    assert.equal(control.claudeSetup({ io: io(), cwd: ws, force: true }), 0);
    assert.match(fs.readFileSync(file, 'utf8'), /name: edge-control/);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('the CLI dispatches edge control and edge --claude-setup without opening a key', async () => {
  const a = { out: () => {}, err: () => {}, start: () => assert.fail('opened a key') };
  assert.equal(await main(['edge', 'control', 'bogus'], a), 2);
  assert.equal(await main(['edge', '--claude-setup', '--nope'], a), 2);
});
