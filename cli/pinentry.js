/*
 * cli/pinentry.js - ask the person for a passphrase through GnuPG's pinentry.
 *
 * WHY IT EXISTS. `gpg -c` (symmetric encryption) and decrypting a
 * passphrase-only message ask the AGENT for the passphrase (GET_PASSPHRASE),
 * because gpg-agent owns the dialog. The agent gpg starts has no terminal of
 * its own; the dialog is pinentry, told which terminal or display to use by
 * the OPTIONs gpg sent the agent. lib-agent does the same (device/ui.py
 * interact()).
 *
 * pinentry speaks Assuan too, with the agent as the CLIENT this time: the
 * same lines and escaping as cli/assuan.js, so the codec is shared.
 */
'use strict';

const A = require('./assuan');

/* The OPTIONs from gpg that pinentry understands, passed through as gpg-agent passes them. */
const PASSED_OPTIONS = ['ttyname', 'ttytype', 'lc-ctype', 'lc-messages', 'display'];

/* Text in a pinentry command: percent-escape what would end or confuse the line. */
function escapeText(text) {
  return String(text).replace(/[%\r\n]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`);
}

/**
 * Ask once (or twice, when `repeat` - both answers must match).
 *
 * @param {object} opts
 * @param {object} [opts.options]  the OPTIONs gpg sent (ttyname=..., display=...)
 * @param {string} [opts.description]
 * @param {string} [opts.prompt]
 * @param {string} [opts.error]
 * @param {number} [opts.repeat]
 * @param {string} [opts.program]  the pinentry binary (PATH lookup)
 * @param {Function} [opts.spawn]  child_process.spawn, for a test
 * @returns {Promise<Buffer>} the passphrase; rejects when cancelled
 */
async function askPassphrase({
  options = {}, description = '', prompt = '', error = '', repeat = 0, program = 'pinentry',
  spawn = require('child_process').spawn,
} = {}) {
  const ask = () => transact({ options, description, prompt, error, program, spawn });
  const first = await ask();
  if (repeat) {
    const again = await transact({ options, description: 'Please re-enter this passphrase', prompt, error: '', program, spawn });
    if (!again.equals(first)) throw new Error('the passphrases do not match');
  }
  return first;
}

function transact({ options, description, prompt, error, program, spawn }) {
  const env = { ...process.env };
  if (typeof options.display === 'string') env.DISPLAY = options.display;
  const child = spawn(program, [], { stdio: ['pipe', 'pipe', 'ignore'], env });

  return new Promise((resolve, reject) => {
    const replies = [];
    let waiter = null;
    let data = [];
    let failed = null;

    /* Every reply line up to its OK/ERR, handed to whoever is waiting. */
    const feed = A.createLineSplitter((line) => {
      const text = line.toString('latin1');
      if (text.startsWith('D ')) data.push(A.unescapeData(line.subarray(2)));
      else if (text === 'OK' || text.startsWith('OK ') || text.startsWith('ERR ')) {
        const r = { ok: !text.startsWith('ERR'), text, data: Buffer.concat(data) };
        data = [];
        if (waiter) { const w = waiter; waiter = null; w(r); } else replies.push(r);
      }
    });
    child.stdin.on('error', () => { /* pinentry exited first; the exit handler answers */ });
    child.stdout.on('data', (c) => { try { feed(c); } catch (e) { failed = e; child.kill(); } });
    child.once('error', (e) => reject(new Error(`cannot run ${program}: ${e.message}`)));
    child.once('exit', () => {
      if (waiter) { const w = waiter; waiter = null; w({ ok: false, text: failed ? failed.message : 'pinentry exited' }); }
    });

    const next = () => new Promise((r) => { if (replies.length) r(replies.shift()); else waiter = r; });
    const send = async (line) => {
      child.stdin.write(`${line}\n`);
      return next();
    };

    (async () => {
      const hello = await next();
      if (!hello.ok) throw new Error(`${program}: ${hello.text}`);
      for (const k of PASSED_OPTIONS) {
        if (typeof options[k] === 'string') await send(`OPTION ${k}=${options[k]}`);   // an unknown one is ERR; carry on
      }
      if (description) await send(`SETDESC ${escapeText(description)}`);
      if (prompt) await send(`SETPROMPT ${escapeText(prompt)}`);
      if (error) await send(`SETERROR ${escapeText(error)}`);
      const pin = await send('GETPIN');
      child.stdin.end('BYE\n');
      if (!pin.ok) throw new Error(`cancelled (${pin.text})`);
      return pin.data;
    })().then(resolve, (e) => { child.kill(); reject(e); });
  });
}

module.exports = { askPassphrase, escapeText };
