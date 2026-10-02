'use strict';
/*
 * OKGETCONFIG on the library side: the INI the soft key's config plugin
 * prints (ok-rn/android/okemu/plugins/config/src/okplugin_config.cpp - the
 * sample below is that file's exact layout), read and planned for import, and
 * the plugin's read over a fake transport. The firmware half is proven on the
 * emulator (the plugin's tests/kit.test.js, the kit's 38).
 */
const test = require('node:test');
const assert = require('node:assert');
const ini = require('../src/config/ini');
const { PREFERENCES } = require('../src/device/preferences');
const setup = require('../plugins/config');
const { IFACE } = require('../src/protocol/msg');

const SAMPLE = `; OnlyKey soft key config - OKGETCONFIG v1
[input]
; resolved: what the key will ask for (code | press | none) - read-only
derived_keys=press
stored_keys=code
web_derive=none
hmac=press

[preferences]
typeSpeed=4
keyboardLayout=1
ledBrightness=8
lockout=30
lockButton=0
touchSense=12
modKeyMode=0
hmacChallengeMode=0
derivedChallengeMode=1
storedChallengeMode=0
webAgentDeriveMode=2
secProfileMode=0

[advanced]
; one-way: an import changes these only when asked to
; webcryptPolicy unset (the firmware default)
wipeMode=0
backupKeyMode=0
`;

test('config: the INI reads into its three sections, with the version and what is unset', () => {
  const c = ini.parse(SAMPLE);
  assert.equal(c.version, 1);
  assert.deepEqual(c.input, { derived_keys: 'press', stored_keys: 'code', web_derive: 'none', hmac: 'press' });
  assert.equal(c.preferences.lockout, '30');
  assert.deepEqual(c.advanced, { wipeMode: '0', backupKeyMode: '0' });
  assert.deepEqual(c.unset, ['webcryptPolicy']);
});

test('config: every key the firmware prints is a preference this library knows - one name on both sides', () => {
  const c = ini.parse(SAMPLE);
  for (const name of [...Object.keys(c.preferences), ...Object.keys(c.advanced), ...c.unset]) {
    assert.ok(PREFERENCES[name], `${name} is not in PREFERENCES`);
  }
  /* and [advanced] is exactly the library's one-way set */
  const oneWay = Object.keys(PREFERENCES).filter((n) => PREFERENCES[n].oneWay).sort();
  assert.deepEqual([...Object.keys(c.advanced), ...c.unset].sort(), oneWay);
});

test('config: an import plan writes preferences, never [input], and [advanced] only when asked', () => {
  const c = ini.parse(SAMPLE + '\n[preferences]\nnotASetting=3\nlockButton=999\n');
  const p = ini.plan(c);
  assert.ok(p.writes.some((w) => w.name === 'lockout' && w.value === 30));
  assert.ok(!p.writes.some((w) => w.name in c.input), '[input] was planned');
  assert.ok(!p.writes.some((w) => w.oneWay), 'a one-way setting was planned without oneWay');
  assert.ok(p.skipped.some((s) => s.name === 'wipeMode' && /one-way/.test(s.why)));
  assert.ok(p.skipped.some((s) => s.name === 'lockButton' && /not a byte/.test(s.why)));
  assert.deepEqual(p.unknown, ['notASetting']);
  assert.ok(ini.plan(c, { oneWay: true }).writes.some((w) => w.name === 'wipeMode' && w.oneWay));
});

test('config: anything that is not this INI is refused, never guessed', () => {
  assert.throws(() => ini.parse('lockout=3\n'), /not a line of this INI/);
  assert.throws(() => ini.parse('[secrets]\npin=1\n'), /unknown section/);
});

/* a fake key that answers OKGETCONFIG with `answer` (reports), after a status broadcast */
function fakeKey(answer, { broadcast = true } = {}) {
  const listeners = new Set();
  const emit = (r) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), 1);
  return {
    open: async () => {}, close: async () => {}, isOpen: () => true, request: async () => null,
    on(name, cb) { if (name !== 'report') return () => {}; listeners.add(cb); return () => listeners.delete(cb); },
    write(iface, bytes) {
      if (bytes[4] !== (0x80 | 0x79)) return;
      if (broadcast) emit(Uint8Array.from(Buffer.from('UNLOCKEDv3.1.0-testc'.padEnd(64, '\0'))));
      for (const r of answer) emit(r);
    },
  };
}
const reportsOf = (text) => {
  const b = Buffer.alloc(Math.ceil((text.length + 1) / 64) * 64);
  b.write(text, 'latin1');
  const out = [];
  for (let i = 0; i < b.length; i += 64) out.push(new Uint8Array(b.subarray(i, i + 64)));
  return out;
};
const over = (transport) => { let config = null; setup({ transport }, (err, s) => { if (err) throw err; config = s.config; }); return config; };

test('config: read() collects whole reports to the NUL, past a status broadcast', async () => {
  const reports = reportsOf(SAMPLE);
  assert.ok(reports.length > 1, 'the sample spans several reports');
  const c = await over(fakeKey(reports)).read();
  assert.equal(c.text, SAMPLE);
  assert.equal(c.input.derived_keys, 'press');
});

test('config: a refusal is EREFUSED, silence (a hard key, a key without the plugin) is EUNSUPPORTED', async () => {
  const refused = over(fakeKey([Uint8Array.from(Buffer.from('Error OKGETCONFIG is vendor API only'.padEnd(64, '\0')))], { broadcast: false }));
  await assert.rejects(refused.read(), (e) => e.code === 'EREFUSED');
  await assert.rejects(over(fakeKey([])).read({ timeoutMs: 300 }), (e) => e.code === 'EUNSUPPORTED' && /hard key never does/.test(e.message));
});

test('config: an import file holds [preferences], [advanced] only when planned with oneWay, never [input]', () => {
  const c = ini.parse(SAMPLE);
  const text = ini.format(ini.plan(c));
  assert.match(text, /^; OnlyKey soft key config - OKGETCONFIG v1\n\[preferences\]\n/);
  assert.ok(!/\[input\]|\[advanced\]|derived_keys/.test(text), text);
  const again = ini.parse(text);
  assert.equal(again.preferences.lockout, '30');
  assert.match(ini.format(ini.plan(c, { oneWay: true })), /\[advanced\]\nwipeMode=0\nbackupKeyMode=0\n$/);
});

/* a fake key that collects OKSETCONFIG chunks and answers once, after the last */
function importKey({ configMode = true } = {}) {
  const listeners = new Set();
  const got = { chunks: [], text: '' };
  const emit = (t) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: Uint8Array.from(Buffer.from(t.padEnd(64, '\0'))) })), 1);
  return {
    got,
    open: async () => {}, close: async () => {}, isOpen: () => true, request: async () => null,
    on(name, cb) { if (name !== 'report') return () => {}; listeners.add(cb); return () => listeners.delete(cb); },
    write(iface, bytes) {
      if (bytes[4] !== (0x80 | 0x7a)) return;
      if (!configMode) { emit('Error OKSETCONFIG needs config mode'); return; }
      const mark = bytes[5];
      const n = mark === 0xff ? 58 : mark;
      got.chunks.push(mark);
      got.text += Buffer.from(bytes.subarray(6, 6 + n)).toString('latin1');
      if (mark !== 0xff) emit('OKSETCONFIG applied 12 unknown 0');
    },
  };
}

test('config: write() sends the INI in 58-byte chunks (0xFF = more, then the last length) and reads the summary', async () => {
  const key = importKey();
  const text = ini.format(ini.plan(ini.parse(SAMPLE)));
  const r = await over(key).write(text, { chunkGapMs: 1 });
  assert.deepEqual(r, { applied: 12, unknown: 0 });
  assert.equal(key.got.text, text, 'the key did not get the file back whole');
  assert.ok(key.got.chunks.length > 1, 'the sample fits one chunk - it proves nothing about chunking');
  assert.ok(key.got.chunks.slice(0, -1).every((m) => m === 0xff), 'a chunk before the last is not marked "more"');
  assert.equal(key.got.chunks.at(-1), (text.length % 58) || 58, 'the last chunk does not carry its length');
  await assert.rejects(over(importKey({ configMode: false })).write(text, { chunkGapMs: 1 }), (e) => e.code === 'ECONFIGMODE');
});
