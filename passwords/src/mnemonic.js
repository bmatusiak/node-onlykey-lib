'use strict';

/**
 * WALLET PHRASES DERIVED FROM THE KEY (onlykey-edge features/PASSWORD-MANAGER-SPEC.md
 * "Wallet mnemonics"; Brad, 2026-10-11: "i give it a derived name, it generates a bip39, so it
 * can be re-derived using same backup if lost").
 *
 *   name -> the key's derive on `mnemonic:<name>` (deriveSharedSecretFor: the label's own
 *   ECDH secret, 32 bytes) -> HKDF-SHA256, info okrn-mnemonic-v1 -> 16 or 32 bytes of entropy ->
 *   12 or 24 BIP39 English words (@scure/bip39, vendored).
 *
 * Nothing secret is stored. The entry keeps only the RECIPE: the label, 12 or 24, the press flag
 * the derive was made with (an input to the derive: the same label with and without a press gives
 * two different secrets), and a CHECK value - the first 4 bytes of SHA-256 of the entropy. Every
 * re-derive is checked against it, and a mismatch is a hard stop: a key that no longer produces
 * the saved phrase must never hand out another phrase as if it were the same wallet.
 *
 * Same key (or a key restored from its backup) + same name -> the same words, forever. Another
 * name gives an unrelated phrase. An optional BIP39 passphrase is the wallet's business and is
 * never seen here.
 */

const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const bip39 = require('../../src/vendor/exports/@scure/bip39/index.js');
const { wordlist } = require('../../src/vendor/exports/@scure/bip39/wordlists/english.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');

const PREFIX = 'mnemonic:';
const INFO = utf8ToBytes('okrn-mnemonic-v1');
/** the phrase lengths a recipe may ask for, by entropy bytes */
const OUTS = { 'bip39-12': 16, 'bip39-24': 32 };
const NAME_MAX = 64;

/** The derive label of a phrase name. A name is what the person types: trimmed, printable, short. */
function labelOf(name) {
  if (typeof name !== 'string') throw new TypeError('passwords: a phrase name is text');
  const n = name.trim();
  if (!n || n.length > NAME_MAX || /[\u0000-\u001f\u007f]/.test(n)) {
    throw new TypeError(`passwords: a phrase name is 1 to ${NAME_MAX} printable characters`);
  }
  return PREFIX + n;
}

/** 16 or 32 bytes of entropy from the derive's secret. */
function entropyFrom(secret, out) {
  const n = OUTS[out];
  if (!n) throw new TypeError(`passwords: out must be one of ${Object.keys(OUTS).join(', ')}`);
  if (!(secret instanceof Uint8Array) || secret.length < 32) throw new TypeError('passwords: the derive secret is 32 bytes');
  return hkdf(sha256, secret, undefined, INFO, n);
}

/** The recipe's check: the first 4 bytes of SHA-256 of the entropy, hex. */
const checkOf = (entropy) => toHex(sha256(entropy).subarray(0, 4));

/** The words of an entropy, BIP39 English (checksum included). */
const wordsOf = (entropy) => bip39.entropyToMnemonic(entropy, wordlist).split(' ');

/** Whether a phrase is valid BIP39 English (words + checksum). */
const isValidPhrase = (words) => bip39.validateMnemonic(Array.isArray(words) ? words.join(' ') : String(words), wordlist);

/**
 * Derive a phrase from the key. -> {words, recipe}
 * okcrypto: a backend's okcrypto (deriveSharedSecretFor); press: the derive's press flag, recorded.
 */
async function deriveMnemonic({ okcrypto, name, out = 'bip39-24', press, onKeepAlive = undefined }) {
  if (typeof press !== 'boolean') throw new TypeError('passwords: press is true or false, and is recorded');
  const label = labelOf(name);
  const secret = await okcrypto.deriveSharedSecretFor(label, { pressForPublicKey: false, pressForSecret: press, onKeepAlive });
  const entropy = entropyFrom(secret, out);
  secret.fill(0);
  const words = wordsOf(entropy);
  const recipe = { label, out, press, check: checkOf(entropy) };
  entropy.fill(0);
  return { words, recipe };
}

/** Thrown when the key's phrase no longer matches the recipe's check. */
class PhraseDriftError extends Error {
  constructor() {
    super('this key no longer produces the phrase you saved - it is NOT shown. Check that this is the same key (or one restored from its backup)');
    this.name = 'PhraseDriftError';
  }
}

/** The saved phrase again, from its recipe - checked; a mismatch throws PhraseDriftError. */
async function openRecipe({ okcrypto, recipe, onKeepAlive = undefined }) {
  shapeRecipe(recipe);
  const secret = await okcrypto.deriveSharedSecretFor(recipe.label, { pressForPublicKey: false, pressForSecret: recipe.press, onKeepAlive });
  const entropy = entropyFrom(secret, recipe.out);
  secret.fill(0);
  if (checkOf(entropy) !== recipe.check) {
    entropy.fill(0);
    throw new PhraseDriftError();
  }
  const words = wordsOf(entropy);
  entropy.fill(0);
  return words;
}

/** A recipe as stored, checked: {label, out, press, check}. */
function shapeRecipe(r) {
  if (!r || typeof r !== 'object') throw new TypeError('passwords: a recipe is an object');
  if (!String(r.label).startsWith(PREFIX)) throw new TypeError('passwords: a phrase recipe label starts with mnemonic:');
  labelOf(String(r.label).slice(PREFIX.length));
  if (!OUTS[r.out]) throw new TypeError(`passwords: out must be one of ${Object.keys(OUTS).join(', ')}`);
  if (typeof r.press !== 'boolean') throw new TypeError('passwords: a recipe records its press flag');
  if (!/^[0-9a-f]{8}$/.test(r.check)) throw new TypeError('passwords: a recipe check is 8 hex characters');
  return { label: r.label, out: r.out, press: r.press, check: r.check };
}

/** The name a recipe was made from. */
const nameOf = (recipe) => String(recipe.label).slice(PREFIX.length);

module.exports = {
  PREFIX, OUTS, labelOf, entropyFrom, checkOf, wordsOf, isValidPhrase,
  deriveMnemonic, openRecipe, shapeRecipe, nameOf, PhraseDriftError,
};
