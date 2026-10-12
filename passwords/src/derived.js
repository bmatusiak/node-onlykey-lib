'use strict';

/**
 * DERIVED PASSWORDS (onlykey-edge features/PASSWORD-MANAGER-SPEC.md "Derived passwords"): a
 * password made from the key and a name, never stored - the entry keeps only the recipe, as a
 * wallet phrase does (mnemonic.js).
 *
 *   name -> the key's derive on `password:<name>` (deriveSharedSecretFor: the label's own ECDH
 *   secret) -> HKDF-SHA256, info okrn-password-v1, a 4096-byte stream -> the characters, drawn the
 *   way the app's random generator draws them (ok-rn src/passwordGenerator.ts): one of each chosen
 *   class first, the rest from all of them, a Fisher-Yates shuffle, each draw without modulo bias.
 *
 * Same key (or one restored from its backup) + same name + same length and classes -> the same
 * password. Rotating = another name (a counter in it). The recipe's CHECK (4 bytes of SHA-256 of
 * the password) is checked on every re-derive: a key that no longer gives the saved password is
 * refused, never shown as if it were the same one.
 */

const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');

const PREFIX = 'password:';
const INFO = utf8ToBytes('okrn-password-v1');
const STREAM = 4096;
const NAME_MAX = 64;
const MIN_LENGTH = 8;
const MAX_LENGTH = 56;
/* the app's generator's sets, character for character (ok-rn src/passwordGenerator.ts CHARSETS) */
const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '~!@#$%^&*+=-_"\';:,.?(){}[]<>',
};
const CLASS_ORDER = ['upper', 'lower', 'digits', 'symbols'];

/** The derive label of a password name: trimmed, printable, short. */
function labelOf(name) {
  if (typeof name !== 'string') throw new TypeError('passwords: a password name is text');
  const n = name.trim();
  if (!n || n.length > NAME_MAX || /[\u0000-\u001f\u007f]/.test(n)) {
    throw new TypeError(`passwords: a password name is 1 to ${NAME_MAX} printable characters`);
  }
  return PREFIX + n;
}

/** The recipe's classes, checked and in a fixed order. */
function classesOf(classes) {
  const list = CLASS_ORDER.filter((c) => Array.isArray(classes) && classes.includes(c));
  if (!list.length) throw new TypeError('passwords: pick at least one kind of character');
  return list;
}

/** The password a 32-byte secret gives, for this length and these classes. */
function passwordFrom(secret, length, classes) {
  if (!(secret instanceof Uint8Array) || secret.length < 32) throw new TypeError('passwords: the derive secret is 32 bytes');
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new TypeError(`passwords: length is a whole number ${MIN_LENGTH}..${MAX_LENGTH}`);
  }
  const sets = classesOf(classes).map((c) => CHARSETS[c]);
  if (sets.length > length) throw new TypeError(`passwords: ${length} characters cannot hold one of each of ${sets.length} kinds`);
  const stream = hkdf(sha256, secret, undefined, INFO, STREAM);
  let at = 0;
  /* one index in [0, max), as passwordGenerator.ts randomIndex: reject the biased top */
  const index = (max) => {
    const limit = Math.floor(0x100000000 / max) * max;
    for (;;) {
      if (at + 4 > stream.length) throw new Error('passwords: the derive stream ran out');
      const v = ((stream[at] << 24) | (stream[at + 1] << 16) | (stream[at + 2] << 8) | stream[at + 3]) >>> 0;
      at += 4;
      if (v < limit) return v % max;
    }
  };
  const all = sets.join('');
  const chars = sets.map((set) => set[index(set.length)]);
  while (chars.length < length) chars.push(all[index(all.length)]);
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = index(i + 1);
    const swap = chars[i];
    chars[i] = chars[j];
    chars[j] = swap;
  }
  stream.fill(0);
  return chars.join('');
}

const checkOf = (password) => toHex(sha256(utf8ToBytes(password)).subarray(0, 4));

/** A recipe as stored, checked: {label, out: 'password', length, classes, press, check}. */
function shapeRecipe(r) {
  if (!r || typeof r !== 'object' || r.out !== 'password') throw new TypeError('passwords: a derived password recipe has out: password');
  if (!String(r.label).startsWith(PREFIX)) throw new TypeError('passwords: a derived password label starts with password:');
  labelOf(String(r.label).slice(PREFIX.length));
  if (!Number.isInteger(r.length) || r.length < MIN_LENGTH || r.length > MAX_LENGTH) throw new TypeError(`passwords: length is ${MIN_LENGTH}..${MAX_LENGTH}`);
  const classes = classesOf(r.classes);
  if (typeof r.press !== 'boolean') throw new TypeError('passwords: a recipe records its press flag');
  if (!/^[0-9a-f]{8}$/.test(r.check)) throw new TypeError('passwords: a recipe check is 8 hex characters');
  return { label: r.label, out: 'password', length: r.length, classes, press: r.press, check: r.check };
}

/** Make one from the key. -> {password, recipe} */
async function derivePasswordFor({ okcrypto, name, length = 20, classes = CLASS_ORDER, press, onKeepAlive = undefined }) {
  if (typeof press !== 'boolean') throw new TypeError('passwords: press is true or false, and is recorded');
  const label = labelOf(name);
  const secret = await okcrypto.deriveSharedSecretFor(label, { pressForPublicKey: false, pressForSecret: press, onKeepAlive });
  const password = passwordFrom(secret, length, classes);
  secret.fill(0);
  return { password, recipe: { label, out: 'password', length, classes: classesOf(classes), press, check: checkOf(password) } };
}

/** Thrown when the key's password no longer matches the recipe's check. */
class DerivedDriftError extends Error {
  constructor() {
    super('this key no longer produces the password you saved - it is NOT shown. Check that this is the same key (or one restored from its backup)');
    this.name = 'DerivedDriftError';
  }
}

/** The saved password again, from its recipe - checked; a mismatch throws DerivedDriftError. */
async function openRecipe({ okcrypto, recipe, onKeepAlive = undefined }) {
  const r = shapeRecipe(recipe);
  const secret = await okcrypto.deriveSharedSecretFor(r.label, { pressForPublicKey: false, pressForSecret: r.press, onKeepAlive });
  const password = passwordFrom(secret, r.length, r.classes);
  secret.fill(0);
  if (checkOf(password) !== r.check) throw new DerivedDriftError();
  return password;
}

const nameOf = (recipe) => String(recipe.label).slice(PREFIX.length);

module.exports = {
  PREFIX, CHARSETS, MIN_LENGTH, MAX_LENGTH, labelOf, passwordFrom, checkOf, shapeRecipe,
  derivePasswordFor, openRecipe, nameOf, DerivedDriftError,
};
