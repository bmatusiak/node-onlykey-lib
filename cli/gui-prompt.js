'use strict';
/*
 * THE PERSON'S YES IN A WINDOW (Brad, 2026-10-25: "i do like interacting with you not asking me to run commands, but
 * i do need to be prompted to approve ... add --gui-prompt to enable this in a way to ask me to approve budgets").
 *
 * `--gui-prompt` asks the questions a hard key's host asks on the terminal - approve this budget? keep this agent
 * identity? - in a Yes/No dialog on the person's desktop instead, so whoever runs the command (an agent's shell, a
 * pipe) never answers it. The key's press is still the key's: Yes only lets the request reach the key.
 *
 *   Windows   a MessageBox through PowerShell (Windows Forms), on top of other windows, No as the default button
 *   Linux     zenity --question (markup off, Cancel as the default), else kdialog --yesno; on DISPLAY / WAYLAND_DISPLAY
 *
 * THE TEXT IS DATA, NEVER A COMMAND. A budget's reason is written by whoever asks for the budget, so it must not be
 * spliced into a shell line: no shell runs - the dialog program is started with an argument list, and on Windows the
 * text reaches the script through environment variables. zenity's markup is switched off for the same reason.
 *
 * ANYTHING BUT A CLEAR YES IS A NO: closed, timed out, no dialog program, no desktop session - each says why.
 */
const { execFile } = require('child_process');

const TIMEOUT_MS = 120000;
/* the two buttons: Yes / No for an approval; a step the person does first (unlock the key) says OK / Cancel */
const LABELS = Object.freeze({ yes: 'Yes', no: 'No' });

/*
 * THE WINDOWS DIALOG: the text and title come from the environment, never from the command line.
 *
 * NO KEYSTROKE ANSWERS IT (Brad, 2026-10-25: the test window came up while he was typing - "i could have hit no with
 * spacebar"). A MessageBox takes the focus and its buttons take Space and Enter, so whatever the person was typing
 * elsewhere could answer a budget. So it is a form of its own: the request in a read-only text box that holds the
 * focus (typing lands there and does nothing), Yes and No as buttons with no tab stop and no Accept/Cancel role (no
 * key reaches them), both dead for the first 1.5 s (a click already on its way does not land), and closing = No.
 */
const PS_SCRIPT = [
  'Add-Type -AssemblyName System.Windows.Forms',
  '$f = New-Object System.Windows.Forms.Form',
  '$f.Text = $env:OKJS_GUI_TITLE; $f.TopMost = $true; $f.Width = 560; $f.Height = 360',
  "$f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.StartPosition = 'CenterScreen'",
  '$t = New-Object System.Windows.Forms.TextBox',
  '$t.Multiline = $true; $t.ReadOnly = $true; $t.ScrollBars = \'Vertical\'; $t.Left = 12; $t.Top = 12; $t.Width = 520; $t.Height = 250',
  "$t.Text = ($env:OKJS_GUI_TEXT -replace \"`r?`n\", \"`r`n\")",
  "$yes = New-Object System.Windows.Forms.Button; $yes.Text = $env:OKJS_GUI_YES; $yes.Left = 352; $yes.Top = 275; $yes.Width = 85; $yes.TabStop = $false; $yes.Enabled = $false",
  "$no = New-Object System.Windows.Forms.Button; $no.Text = $env:OKJS_GUI_NO; $no.Left = 447; $no.Top = 275; $no.Width = 85; $no.TabStop = $false; $no.Enabled = $false",
  '$script:answer = 1',
  '$yes.Add_Click({ $script:answer = 0; $f.Close() }); $no.Add_Click({ $script:answer = 1; $f.Close() })',
  '$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 1500',
  '$timer.Add_Tick({ $timer.Stop(); $yes.Enabled = $true; $no.Enabled = $true; $t.Focus() | Out-Null })',
  '$f.Controls.AddRange(@($t, $yes, $no)); $f.ActiveControl = $t',
  '$f.Add_Shown({ $t.Focus() | Out-Null; $t.SelectionLength = 0; $timer.Start() })',
  '[void]$f.ShowDialog(); exit $script:answer',
].join('; ');

/**
 * The dialog programs to try, in order, for this platform: [{file, args, env}].
 * @param {{title: string, text: string, platform?: string, env?: object}} o
 */
function dialogsFor({ title, text, platform = process.platform, env = process.env, labels = LABELS }) {
  if (platform === 'win32') {
    return [{
      file: 'powershell.exe',
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', PS_SCRIPT],
      env: { ...env, OKJS_GUI_TEXT: text, OKJS_GUI_TITLE: title, OKJS_GUI_YES: labels.yes, OKJS_GUI_NO: labels.no },
    }];
  }
  if (platform === 'linux') {
    return [
      { file: 'zenity', args: ['--question', '--no-markup', '--default-cancel', `--title=${title}`, `--text=${text}`, '--width=520', `--ok-label=${labels.yes}`, `--cancel-label=${labels.no}`], env },
      { file: 'kdialog', args: ['--title', title, '--yesno', text, '--yes-label', labels.yes, '--no-label', labels.no], env },
    ];
  }
  return [];
}

/**
 * Ask Yes/No in a desktop dialog. Resolves true only for Yes.
 * @param {string} question the terminal's question ("approve this budget? [y/N] ") - its [y/N] is dropped
 * @param {{details?: string, title?: string, labels?: {yes: string, no: string}, say?: (line: string) => void, platform?: string, env?: object, run?: typeof execFile, timeoutMs?: number}} [o]
 *   details: what the person is approving (the request's view, as the terminal prints it); run: for tests
 * @returns {Promise<boolean>}
 */
function guiConfirm(question, { details = '', title = 'OnlyKey', labels = LABELS, say = (l) => process.stderr.write(`${l}\n`), platform = process.platform, env = process.env, run = execFile, timeoutMs = TIMEOUT_MS } = {}) {
  const ask = String(question).replace(/\s*\[y\/N\]\s*$/i, '').trim();
  const text = `${details ? `${details}\n\n` : ''}${ask.charAt(0).toUpperCase()}${ask.slice(1)}`;
  if (platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    say('gui-prompt: no desktop session here (no DISPLAY / WAYLAND_DISPLAY) - answered No');
    return Promise.resolve(false);
  }
  const dialogs = dialogsFor({ title, text, platform, env, labels });
  if (!dialogs.length) {
    say(`gui-prompt: no dialog for ${platform} - answered No`);
    return Promise.resolve(false);
  }
  say(`gui-prompt: "${ask}" - asked in a window on the desktop`);
  return new Promise((resolve) => {
    const next = (i) => {
      if (i >= dialogs.length) {
        say('gui-prompt: no dialog program found (Linux: install zenity or kdialog) - answered No');
        resolve(false);
        return;
      }
      const d = dialogs[i];
      run(d.file, d.args, { env: d.env, timeout: timeoutMs, windowsHide: false }, (err) => {
        if (!err) { say(`gui-prompt: ${labels.yes}`); resolve(true); return; }
        if (err.code === 'ENOENT') { next(i + 1); return; }
        say(err.killed ? `gui-prompt: no answer in ${Math.round(timeoutMs / 1000)} s - answered ${labels.no}` : `gui-prompt: ${labels.no}`);
        resolve(false);
      });
    };
    next(0);
  });
}

module.exports = { guiConfirm, dialogsFor, PS_SCRIPT, LABELS };
