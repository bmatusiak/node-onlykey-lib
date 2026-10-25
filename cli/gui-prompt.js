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

/* the Windows script: the text and title come from the environment, never from the command line */
const PS_SCRIPT = [
  'Add-Type -AssemblyName System.Windows.Forms',
  '$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}',
  "$r = [System.Windows.Forms.MessageBox]::Show($owner, $env:OKJS_GUI_TEXT, $env:OKJS_GUI_TITLE, 'YesNo', 'Question', 'Button2')",
  "if ($r -eq 'Yes') { exit 0 } else { exit 1 }",
].join('; ');

/**
 * The dialog programs to try, in order, for this platform: [{file, args, env}].
 * @param {{title: string, text: string, platform?: string, env?: object}} o
 */
function dialogsFor({ title, text, platform = process.platform, env = process.env }) {
  if (platform === 'win32') {
    return [{
      file: 'powershell.exe',
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', PS_SCRIPT],
      env: { ...env, OKJS_GUI_TEXT: text, OKJS_GUI_TITLE: title },
    }];
  }
  if (platform === 'linux') {
    return [
      { file: 'zenity', args: ['--question', '--no-markup', '--default-cancel', `--title=${title}`, `--text=${text}`, '--width=520'], env },
      { file: 'kdialog', args: ['--title', title, '--yesno', text], env },
    ];
  }
  return [];
}

/**
 * Ask Yes/No in a desktop dialog. Resolves true only for Yes.
 * @param {string} question the terminal's question ("approve this budget? [y/N] ") - its [y/N] is dropped
 * @param {{details?: string, title?: string, say?: (line: string) => void, platform?: string, env?: object, run?: typeof execFile, timeoutMs?: number}} [o]
 *   details: what the person is approving (the request's view, as the terminal prints it); run: for tests
 * @returns {Promise<boolean>}
 */
function guiConfirm(question, { details = '', title = 'OnlyKey', say = (l) => process.stderr.write(`${l}\n`), platform = process.platform, env = process.env, run = execFile, timeoutMs = TIMEOUT_MS } = {}) {
  const ask = String(question).replace(/\s*\[y\/N\]\s*$/i, '').trim();
  const text = `${details ? `${details}\n\n` : ''}${ask.charAt(0).toUpperCase()}${ask.slice(1)}`;
  if (platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    say('gui-prompt: no desktop session here (no DISPLAY / WAYLAND_DISPLAY) - answered No');
    return Promise.resolve(false);
  }
  const dialogs = dialogsFor({ title, text, platform, env });
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
        if (!err) { say('gui-prompt: Yes'); resolve(true); return; }
        if (err.code === 'ENOENT') { next(i + 1); return; }
        say(err.killed ? `gui-prompt: no answer in ${Math.round(timeoutMs / 1000)} s - answered No` : 'gui-prompt: No');
        resolve(false);
      });
    };
    next(0);
  });
}

module.exports = { guiConfirm, dialogsFor, PS_SCRIPT };
