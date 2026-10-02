/*
 * config/ini - the soft key's OKGETCONFIG text, read and planned for import.
 *
 * The firmware plugin (ok-rn/android/okemu/plugins/config) prints the key's
 * settings as INI, with THIS library's preference names (src/device/
 * preferences.js PREFERENCES), so a file exported from one key imports into
 * another with no table in between. Pure: no device access, Hermes-clean.
 *
 *   [input]       the firmware's own resolution - what a sign will ask for
 *                 (code | press | none). Read-only: never imported.
 *   [preferences] settings that can be changed back.
 *   [advanced]    the one-way ones (PREFERENCES[name].oneWay); an import
 *                 changes them only when asked to (oneWay: true).
 *
 * Owner, 2026-10-02: soft key only - a hard key is not emulated, so the app
 * is not in the middle; OKGETCONFIG is never on one.
 */
'use strict';

const { PREFERENCES } = require('../device/preferences');

const SECTIONS = ['input', 'preferences', 'advanced'];
const INPUT_KEYS = ['derived_keys', 'stored_keys', 'web_derive', 'hmac'];
const INPUT_WORDS = ['code', 'press', 'none'];

/**
 * text -> {version, input, preferences, advanced, unset}
 * `unset`: the names a "; <name> unset" comment says the key has no value for.
 * Throws on anything that is not this file's INI (a line outside a section,
 * an unknown section) - an import must never guess.
 */
function parse(text) {
  const out = { version: null, input: {}, preferences: {}, advanced: {}, unset: [] };
  const head = /^; OnlyKey soft key config - OKGETCONFIG v(\d+)/.exec(text);
  if (head) out.version = Number(head[1]);
  let sec = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith(';')) {
      const u = /^;\s*(\w+) unset\b/.exec(line);
      if (u && sec) out.unset.push(u[1]);
      continue;
    }
    const s = /^\[(\w+)\]$/.exec(line);
    if (s) {
      if (!SECTIONS.includes(s[1])) throw new Error(`config: unknown section [${s[1]}]`);
      sec = s[1];
      continue;
    }
    const kv = /^(\w+)\s*=\s*(.*)$/.exec(line);
    if (!kv || !sec) throw new Error(`config: not a line of this INI: ${JSON.stringify(line)}`);
    out[sec][kv[1]] = kv[2];
  }
  return out;
}

/**
 * What an import would write, from a parsed file: [{name, value}] in the
 * file's order, plus what it leaves alone and why.
 *   oneWay: also write [advanced] (they cannot be undone)
 * -> {writes, skipped: [{name, why}], unknown: [names]}
 */
function plan(ini, { oneWay = false } = {}) {
  const writes = [];
  const skipped = [];
  const unknown = [];
  for (const name of Object.keys(ini.input || {})) skipped.push({ name, why: 'read-only: the key works it out from the others' });
  for (const sec of ['preferences', 'advanced']) {
    for (const [name, raw] of Object.entries(ini[sec] || {})) {
      const spec = PREFERENCES[name];
      if (!spec) { unknown.push(name); continue; }
      if (!/^\d{1,3}$/.test(raw) || Number(raw) > 255) { skipped.push({ name, why: `not a byte: ${JSON.stringify(raw)}` }); continue; }
      if (spec.oneWay && !oneWay) { skipped.push({ name, why: 'one-way: only with oneWay (--one-way)' }); continue; }
      writes.push({ name, value: Number(raw), oneWay: !!spec.oneWay, requires: spec.requires || 'always' });
    }
  }
  return { writes, skipped, unknown };
}

module.exports = { parse, plan, SECTIONS, INPUT_KEYS, INPUT_WORDS };
