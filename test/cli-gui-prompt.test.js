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

/*
 * A step the person does first says OK / Cancel (Brad, 2026-10-26: a locked key under --gui-prompt - "a prompt asking to
 * unlock the key, with OK and Cancel"); an approval keeps Yes / No. The labels reach each dialog program as data.
 */
test('gui-prompt: button labels reach every dialog program; Yes / No unless asked otherwise', () => {
  const { dialogsFor } = require('../cli/gui-prompt');
  const ok = { yes: 'OK', no: 'Cancel' };
  const [win] = dialogsFor({ title: 't', text: 'x', platform: 'win32', env: {}, labels: ok });
  assert.equal(win.env.OKJS_GUI_YES, 'OK');
  assert.equal(win.env.OKJS_GUI_NO, 'Cancel');
  assert.match(PS_SCRIPT, /\$yes\.Text = \$env:OKJS_GUI_YES/);
  const [zen, kde] = dialogsFor({ title: 't', text: 'x', platform: 'linux', env: {}, labels: ok });
  assert.ok(zen.args.includes('--ok-label=OK') && zen.args.includes('--cancel-label=Cancel'));
  assert.deepEqual(kde.args.slice(-4), ['--yes-label', 'OK', '--no-label', 'Cancel']);
  const [plain] = dialogsFor({ title: 't', text: 'x', platform: 'win32', env: {} });
  assert.equal(plain.env.OKJS_GUI_YES, 'Yes');
  assert.equal(plain.env.OKJS_GUI_NO, 'No');
});

/*
 * One progress window for a whole run (Brad, 2026-10-26): started once, it follows a file of zenity --progress lines -
 * percent, then "# step". The command only appends; the window's own timer reads.
 */
test('gui-prompt: guiProgress starts one window and appends percent + step lines; no desktop = no-op', () => {
  const fs = require('fs');
  const { guiProgress } = require('../cli/gui-prompt');
  const started = [];
  const spawn = (file, args, o) => { started.push({ file, args, env: o.env }); return { on() {}, unref() {} }; };
  const p = guiProgress({ title: 'OnlyKey - ship', total: 4, platform: 'win32', env: {}, spawn });
  assert.equal(started.length, 1);
  assert.equal(started[0].file, 'powershell.exe');
  assert.equal(started[0].env.OKJS_PROGRESS_FILE, p.file, 'the file reaches the window as environment, not a command line');
  p.note('budget open');
  p.step('signed 1');
  p.step('signed 2');
  p.step('pushed lib');
  p.finish('done: 2 signed, 1 pushed');
  const lines = fs.readFileSync(p.file, 'utf8').trim().split('\n');
  assert.deepEqual(lines.slice(-8), ['25', '# signed 1', '50', '# signed 2', '75', '# pushed lib', '100', '# done: 2 signed, 1 pushed']);
  assert.equal(started.length, 1, 'never restarted');
  const zen = [];
  guiProgress({ total: 1, platform: 'linux', env: { DISPLAY: ':0' }, spawn: (f, a, o) => { zen.push({ f, a, o }); return { on() {}, unref() {} }; } });
  assert.equal(zen[0].f, 'sh');
  assert.match(zen[0].a[1], /zenity --progress --no-cancel/);
  assert.doesNotMatch(zen[0].a[1], /okjs-progress-/, 'the file path is never spliced into the shell line');
  const quietP = guiProgress({ total: 1, platform: 'linux', env: {}, spawn: () => { throw new Error('no window without a desktop'); } });
  assert.equal(quietP.file, null);
});
