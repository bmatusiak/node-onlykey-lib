/*
 * cli/assuan.js - the bytes GnuPG and its agent speak: Assuan lines and
 * canonical S-expressions.
 *
 * WHAT ASSUAN IS. gpg does not do private-key operations itself; it asks
 * gpg-agent, over a socket, in a line protocol called Assuan (the GnuPG
 * "Assuan" manual, "Server responses"). One command per line from the client;
 * the server answers with any number of
 *
 *   D <data>        data, with '%', CR and LF percent-escaped
 *   S <kw> <args>   a status line
 *   INQUIRE <kw>    "send me <kw>": the client answers with D lines and END
 *
 * and exactly one closing OK or ERR <code> <text>. A line is at most 1000
 * bytes. That is the whole framing - cli/gpg-agent.js does the conversation.
 *
 * WHAT A CANONICAL S-EXPRESSION IS. The payloads inside the D lines - a
 * signature, an ECDH ciphertext, a decrypted value - are libgcrypt's
 * S-expressions in canonical form (Rivest's draft, as libgcrypt writes it):
 * `(` a list `)`, and every atom as `<decimal length>:<bytes>`. No spaces, no
 * quoting: the lengths make it binary-safe, which is why a 32-byte signature
 * half can sit in one.
 *
 * Node built-ins only, no protocol state: a test drives every function here
 * with literal bytes.
 */
'use strict';

/* The longest line either side may send, LF included (assuan.h ASSUAN_LINELENGTH is 1002 with CR LF). */
const MAX_LINE = 1000;

/*
 * A D line's payload budget. Escaping can triple a byte, so the data is cut
 * BEFORE escaping with room to spare: "D " plus 330 bytes escaped at worst to
 * 990 still fits a line.
 */
const DATA_CHUNK = 330;

/* ------------------------------------------------------------ errors */

/*
 * An ERR line's number is a libgpg-error code: the error SOURCE in the top
 * byte and the code below it. gpg reads the number, not the text - "No
 * secret key" is what makes gpg say "gpg: signing failed: No secret key" - so
 * these are the real codes (libgpg-error err-codes.h), with GPG Agent (4) as
 * the source, as gpg-agent itself sends them. lib-agent sends two of them
 * as literals (67108881 No secret key, 100696144 No such device <SCD>).
 */
const SOURCE = { GPGAGENT: 4, SCD: 6 };
const ERR = {
  GENERAL: 1,
  BAD_SIGNATURE: 8,
  NO_SECKEY: 17,
  INV_VALUE: 55,
  NOT_SUPPORTED: 60,
  CANCELED: 99,
  FALSE: 256,
  ASS_UNKNOWN_CMD: 275,
  ASS_SYNTAX: 276,
  ASS_CANCELED: 277,
  ENODEV: 32768 + 80,
};

/** An error that becomes the command's ERR line rather than a log line. */
class AssuanError extends Error {
  constructor(code, text, source = SOURCE.GPGAGENT) {
    super(text);
    this.code = code;
    this.source = source;
  }

  get line() {
    const label = this.source === SOURCE.SCD ? 'SCD' : 'GPG Agent';
    return `ERR ${(this.source << 24) + this.code} ${oneLine(this.message)} <${label}>`;
  }
}

/* An ERR/status text is one line: a device's message with a newline in it would end it early. */
function oneLine(text) {
  return String(text).replace(/[\r\n]+/g, ' ').slice(0, 200);
}

/* ------------------------------------------------------------ escaping */

/**
 * Percent-escape what may not appear raw in a D line: '%', CR and LF (the
 * three lib-agent's util.assuan_serialize escapes, and libassuan's
 * assuan_send_data). Everything else - NULs, high bytes - goes as is.
 */
function escapeData(bytes) {
  const out = [];
  for (const b of Buffer.from(bytes)) {
    if (b === 0x25 || b === 0x0a || b === 0x0d) out.push(...Buffer.from(`%${b.toString(16).toUpperCase().padStart(2, '0')}`));
    else out.push(b);
  }
  return Buffer.from(out);
}

/**
 * Undo percent-escaping: any `%XX` becomes the byte. The client escapes at
 * least what escapeData() does and may escape more, so every well-formed
 * `%XX` is decoded, not just those three.
 */
function unescapeData(bytes) {
  const b = Buffer.from(bytes);
  const out = [];
  for (let i = 0; i < b.length; i += 1) {
    if (b[i] === 0x25 && i + 2 < b.length && /^[0-9a-fA-F]{2}$/.test(b.subarray(i + 1, i + 3).toString('latin1'))) {
      out.push(parseInt(b.subarray(i + 1, i + 3).toString('latin1'), 16));
      i += 2;
    } else {
      out.push(b[i]);
    }
  }
  return Buffer.from(out);
}

/** The D lines for `bytes`, each within MAX_LINE, LF-terminated. */
function dataLines(bytes) {
  const b = Buffer.from(bytes);
  const lines = [];
  for (let i = 0; i < b.length || i === 0; i += DATA_CHUNK) {
    lines.push(Buffer.concat([Buffer.from('D '), escapeData(b.subarray(i, i + DATA_CHUNK)), Buffer.from('\n')]));
    if (!b.length) break;
  }
  return lines;
}

/**
 * Split a byte stream into lines (LF, an optional CR before it dropped).
 *
 * @param {(line: Buffer) => void} onLine
 * @returns {(chunk: Buffer) => void} feed; throws on a line longer than the
 *   protocol allows, so a client cannot grow the buffer without bound
 */
function createLineSplitter(onLine) {
  let pending = Buffer.alloc(0);
  return (chunk) => {
    pending = pending.length ? Buffer.concat([pending, chunk]) : Buffer.from(chunk);
    let at;
    while ((at = pending.indexOf(0x0a)) !== -1) {
      let line = pending.subarray(0, at);
      pending = pending.subarray(at + 1);
      if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, -1);
      onLine(Buffer.from(line));
    }
    if (pending.length > MAX_LINE) throw new Error(`an Assuan line longer than ${MAX_LINE} bytes`);
  };
}

/**
 * The command and its argument string: `SETHASH 8 ABCD` -> ['SETHASH', '8 ABCD'].
 * Assuan command names are case-insensitive (libassuan compares them so);
 * gpg sends them upper case.
 */
function splitCommand(line) {
  const text = Buffer.from(line).toString('latin1');
  const sp = text.indexOf(' ');
  if (sp === -1) return [text.toUpperCase(), ''];
  return [text.slice(0, sp).toUpperCase(), text.slice(sp + 1).replace(/^ +/, '')];
}

/* ------------------------------------------------------------ S-expressions */

/**
 * Parse ONE canonical S-expression.
 *
 * A list is a JS array, an atom a Buffer. Anything that is not canonical -
 * the advanced (spaced, quoted) form, display hints, trailing bytes - is
 * refused rather than guessed at: what gpg sends here is always canonical.
 */
function parseSexp(bytes) {
  const b = Buffer.from(bytes);
  let pos = 0;

  function atom() {
    const colon = b.indexOf(0x3a, pos);
    const digits = colon === -1 ? '' : b.subarray(pos, colon).toString('latin1');
    if (!/^(0|[1-9][0-9]{0,6})$/.test(digits)) throw new Error(`not a canonical S-expression: bad length at byte ${pos}`);
    const n = Number(digits);
    const start = colon + 1;
    if (start + n > b.length) throw new Error('not a canonical S-expression: an atom runs past the end');
    pos = start + n;
    return b.subarray(start, pos);
  }

  function value(depth) {
    if (depth > 32) throw new Error('not a canonical S-expression: nested too deep');
    if (b[pos] !== 0x28) return atom();
    pos += 1;
    const list = [];
    while (pos < b.length && b[pos] !== 0x29) list.push(value(depth + 1));
    if (b[pos] !== 0x29) throw new Error('not a canonical S-expression: a list is not closed');
    pos += 1;
    return list;
  }

  if (b[0] !== 0x28) throw new Error('not a canonical S-expression: it does not start with "("');
  const out = value(0);
  if (pos !== b.length) throw new Error('not a canonical S-expression: bytes after the end');
  return out;
}

/** Write a tree of arrays and atoms (Buffer, Uint8Array or string) canonically. */
function encodeSexp(tree) {
  if (Array.isArray(tree)) return Buffer.concat([Buffer.from('('), ...tree.map(encodeSexp), Buffer.from(')')]);
  const bytes = typeof tree === 'string' ? Buffer.from(tree, 'latin1') : Buffer.from(tree);
  return Buffer.concat([Buffer.from(`${bytes.length}:`), bytes]);
}

/**
 * The first list in `tree`, at any depth, whose name (first atom) is `name` -
 * how libgcrypt's gcry_sexp_find_token looks a token up. Returns the list, or
 * null.
 */
function findToken(tree, name) {
  if (!Array.isArray(tree)) return null;
  if (Buffer.isBuffer(tree[0]) && tree[0].toString('latin1') === name) return tree;
  for (const child of tree.slice(1)) {
    const hit = findToken(child, name);
    if (hit) return hit;
  }
  return null;
}

module.exports = {
  MAX_LINE,
  ERR,
  SOURCE,
  AssuanError,
  escapeData,
  unescapeData,
  dataLines,
  createLineSplitter,
  splitCommand,
  parseSexp,
  encodeSexp,
  findToken,
  oneLine,
};
