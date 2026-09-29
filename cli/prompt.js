/*
 * cli/prompt.js - read one secret (a password, a TOTP seed, a key passphrase).
 *
 * WHY SECRETS ARE PROMPTED, NOT PASSED. A value on the command line is in the
 * shell's history and, while the program runs, in every other user's `ps`.
 * python-onlykey prompts for the same fields (setslot password / gkey /
 * totpkey, loadkey's passphrase) for the same reason, so this keeps its
 * behaviour rather than adding an argument that would undo it.
 *
 * TWO MODES, decided by what stdin is:
 *
 *   a terminal   the prompt goes to STDERR and nothing typed is echoed.
 *                Stderr, so stdout carries only what the key said and a
 *                script capturing it does not capture "Password: ".
 *   anything     one line is read from stdin, with no prompt. This is how a
 *   else         script, a test kit or `printf '%s\n' "$PW" | onlykey-js ...`
 *                supplies the secret without a terminal. python's
 *                prompt_toolkit needs a real terminal and cannot be fed this
 *                way, which is a difference, not a copy target.
 *
 * Node built-ins only, and only here in cli/: nothing under src/ or plugins/
 * may reach for process.stdin (test/package.test.js).
 */
'use strict';

/**
 * @param {string} question  e.g. 'Password: '
 * @param {object} [opts]
 * @param {NodeJS.ReadStream} [opts.input]   default process.stdin
 * @param {NodeJS.WriteStream} [opts.output] default process.stderr
 * @returns {Promise<string>} what was typed, without the line ending
 */
function promptSecret(question, { input = process.stdin, output = process.stderr } = {}) {
  if (input.isTTY && typeof input.setRawMode === 'function') return fromTerminal(question, input, output);
  return fromPipe(input);
}

function fromTerminal(question, input, output) {
  return new Promise((resolve, reject) => {
    output.write(question);
    const wasRaw = input.isRaw;
    let value = '';

    const finish = (err) => {
      input.removeListener('data', onData);
      input.setRawMode(wasRaw);
      input.pause();
      output.write('\n');
      if (err) reject(err);
      else resolve(value);
    };

    function onData(chunk) {
      for (const ch of String(chunk)) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') { finish(); return; }
        /*
         * Raw mode swallows the terminal's own Ctrl-C handling, so it has to
         * be honoured here or the prompt cannot be escaped.
         */
        if (ch === '\u0003') { finish(new Error('cancelled')); return; }
        if (ch === '\u007f' || ch === '\b') { value = value.slice(0, -1); continue; }
        value += ch;
      }
    }

    input.setRawMode(true);
    input.setEncoding('utf8');
    input.on('data', onData);
    input.resume();
  });
}

function fromPipe(input) {
  return new Promise((resolve) => {
    let buffered = '';
    const finish = (line) => {
      input.removeListener('data', onData);
      input.removeListener('end', onEnd);
      input.pause();
      resolve(line.replace(/\r$/, ''));
    };
    function onData(chunk) {
      buffered += chunk;
      const at = buffered.indexOf('\n');
      if (at !== -1) finish(buffered.slice(0, at));
    }
    function onEnd() { finish(buffered); }
    input.setEncoding('utf8');
    input.on('data', onData);
    input.on('end', onEnd);
    input.resume();
  });
}

module.exports = { promptSecret };
