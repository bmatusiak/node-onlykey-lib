/*
 * --gui-prompt (cli/gui-prompt.js; Brad, 2026-10-25: "i need to be prompted to approve ... so you can run the
 * commands for me"): the y/N in a desktop dialog. The request's words are data - never on a command line, never
 * markup; anything but a clear Yes is a No.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { guiConfirm, PS_SCRIPT } = require('../cli/gui-prompt');

/* a fake execFile: records each call, answers with the scripted outcome */
function fakeRun(outcomes) {
  const calls = [];
  const run = (file, args, opts, cb) => {
    calls.push({ file, args, env: opts.env });
    const o = outcomes.shift();
    setImmediate(() => cb(o === 'yes' ? null : Object.assign(new Error(o), o === 'missing' ? { code: 'ENOENT' } : o === 'timeout' ? { killed: true } : { code: 1 })));
  };
  return { run, calls };
}
const quiet = { say: () => {} };
const HOSTILE = 'push"; Remove-Item C:\\ -Recurse; echo "<b>$(rm -rf ~)</b>';

test('Windows: a MessageBox; the request text reaches it through the environment, never the command line', async () => {
  const { run, calls } = fakeRun(['yes']);
  const yes = await guiConfirm('approve this budget? [y/N] ', { ...quiet, details: `budget request: "${HOSTILE}"`, platform: 'win32', env: {}, run });
  assert.equal(yes, true);
  assert.equal(calls[0].file, 'powershell.exe');
  assert.ok(!calls[0].args.join(' ').includes('Remove-Item'), 'the reason is not on the command line');
  assert.ok(calls[0].env.OKJS_GUI_TEXT.includes(HOSTILE));
  assert.ok(calls[0].env.OKJS_GUI_TEXT.endsWith('Approve this budget?'), 'the [y/N] is dropped');
  assert.ok(PS_SCRIPT.includes('TabStop = $false') && !PS_SCRIPT.includes('AcceptButton') && PS_SCRIPT.includes('Interval = 1500'), 'no key reaches Yes or No, and both wait 1.5 s');
});

test('Linux: zenity with markup off and Cancel as the default; no zenity, kdialog; neither, No', async () => {
  let f = fakeRun(['no']);
  assert.equal(await guiConfirm('keep this agent identity? [y/N]', { ...quiet, details: HOSTILE, platform: 'linux', env: { DISPLAY: ':10' }, run: f.run }), false);
  assert.equal(f.calls[0].file, 'zenity');
  assert.ok(f.calls[0].args.includes('--no-markup') && f.calls[0].args.includes('--default-cancel'));
  f = fakeRun(['missing', 'yes']);
  assert.equal(await guiConfirm('approve this budget? [y/N]', { ...quiet, platform: 'linux', env: { DISPLAY: ':10' }, run: f.run }), true);
  assert.deepEqual(f.calls.map((c) => c.file), ['zenity', 'kdialog']);
  f = fakeRun(['missing', 'missing']);
  assert.equal(await guiConfirm('approve this budget? [y/N]', { ...quiet, platform: 'linux', env: { DISPLAY: ':10' }, run: f.run }), false);
});

test('no desktop session, no answer in time, or a platform with no dialog: No, and it says why', async () => {
  const said = [];
  const say = (l) => said.push(l);
  const f = fakeRun([]);
  assert.equal(await guiConfirm('approve this budget? [y/N]', { say, platform: 'linux', env: {}, run: f.run }), false);
  assert.equal(f.calls.length, 0);
  assert.match(said.pop(), /no desktop session/);
  assert.equal(await guiConfirm('approve this budget? [y/N]', { say, platform: 'win32', env: {}, run: fakeRun(['timeout']).run, timeoutMs: 5000 }), false);
  assert.match(said.pop(), /no answer in 5 s/);
  assert.equal(await guiConfirm('approve this budget? [y/N]', { say, platform: 'darwin', env: {}, run: f.run }), false);
  assert.match(said.pop(), /no dialog for darwin/);
});
