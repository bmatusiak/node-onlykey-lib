'use strict';
/*
 * cli/firmware-plugins.js - soft-key firmware plugins, staged into an emulated
 * OnlyKey's firmware by ok-rn's okemu and node-onlykey-emulator. Driven on a
 * temporary plugins folder and a temporary "staged tree".
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const plugins = require('../cli/firmware-plugins');

const OKCORE = '#include "onlykey.h"\nvoid recvmsg() {\n  switch (x) {\n    case A: return;\n    default:\n      fido();\n  }\n}\n';

function fixture({ hooks, audit = true, minBase = '3.1.0', okcore = OKCORE } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okplugins-'));
  const dir = path.join(root, 'plugins');
  const p = path.join(dir, 'demo');
  fs.mkdirSync(path.join(p, 'src'), { recursive: true });
  fs.writeFileSync(path.join(p, 'src', 'okplugin_demo.cpp'), '// demo\n');
  if (audit) fs.writeFileSync(path.join(p, 'AUDIT.md'), '# demo\n');
  const manifest = {
    name: 'demo',
    minBase,
    hooks: hooks || [
      { file: 'okcore.cpp', anchor: '#include "onlykey.h"\n', insert: 'after', text: '#include "plugins/demo/okplugin_demo.h"\n' },
      { file: 'okcore.cpp', anchor: '    default:\n      fido();\n', insert: 'before', text: '    case DEMO: return;\n' },
    ],
  };
  fs.writeFileSync(path.join(p, 'plugin.js'), `module.exports = ${JSON.stringify(manifest)};\n`);
  const stage = path.join(root, '.stage');
  fs.mkdirSync(path.join(stage, 'libraries', 'onlykey'), { recursive: true });
  fs.writeFileSync(path.join(stage, 'libraries', 'onlykey', 'okcore.cpp'), okcore);
  return { root, dir, stage, okcorePath: path.join(stage, 'libraries', 'onlykey', 'okcore.cpp') };
}

test('selected: a comma list, trimmed, without repeats; a bad name is refused', () => {
  assert.deepEqual(plugins.selected(''), []);
  assert.deepEqual(plugins.selected(undefined), []);
  assert.deepEqual(plugins.selected(' edge, hello ,edge'), ['edge', 'hello']);
  assert.throws(() => plugins.selected('../evil'), /not a plugin name/);
});

test('apply: the source is copied and each hook lands exactly where it was anchored', () => {
  const f = fixture();
  const loaded = plugins.load(['demo'], { dir: f.dir, release: {} });
  const [r] = plugins.apply(loaded, f.stage);
  assert.deepEqual([r.name, r.hooks, r.files], ['demo', 2, 1]);
  const out = fs.readFileSync(f.okcorePath, 'utf8');
  assert.match(out, /#include "onlykey.h"\n#include "plugins\/demo\/okplugin_demo.h"\n/);
  assert.match(out, /    case DEMO: return;\n    default:\n/);
  assert.ok(fs.existsSync(path.join(f.stage, 'libraries', 'onlykey', 'plugins', 'demo', 'okplugin_demo.cpp')));
});

test('an anchor that is missing, or occurs twice, stops the stage', () => {
  const missing = fixture({ okcore: OKCORE.replace('    default:\n      fido();\n', '') });
  assert.throws(() => plugins.apply(plugins.load(['demo'], { dir: missing.dir }), missing.stage), /anchor is not in the staged file/);
  const twice = fixture({ okcore: OKCORE + '    default:\n      fido();\n' });
  assert.throws(() => plugins.apply(plugins.load(['demo'], { dir: twice.dir }), twice.stage), /occurs more than once/);
});

test('a CRLF staged file is hooked in its own line endings', () => {
  const f = fixture({ okcore: OKCORE.replace(/\n/g, '\r\n') });
  plugins.apply(plugins.load(['demo'], { dir: f.dir }), f.stage);
  const out = fs.readFileSync(f.okcorePath, 'utf8');
  assert.match(out, /#include "plugins\/demo\/okplugin_demo.h"\r\n/);
  assert.ok(!/[^\r]\n/.test(out), 'every line still ends CRLF');
});

test('a plugin staged by an earlier run does not linger in the next stage', () => {
  const f = fixture();
  plugins.apply(plugins.load(['demo'], { dir: f.dir }), f.stage);
  plugins.apply([], f.stage);
  assert.ok(!fs.existsSync(path.join(f.stage, 'libraries', 'onlykey', 'plugins')));
});

test('load refuses a plugin with no AUDIT.md, an unknown name, and a release older than minBase', () => {
  assert.throws(() => plugins.load(['demo'], { dir: fixture({ audit: false }).dir }), /no AUDIT\.md/);
  const f = fixture();
  assert.throws(() => plugins.load(['nope'], { dir: f.dir }), /available: demo/);
  assert.throws(() => plugins.load(['demo'], { dir: f.dir, release: { version: 'v3.0.4', pins: {} } }), /needs firmware 3\.1\.0/);
  assert.doesNotThrow(() => plugins.load(['demo'], { dir: f.dir, release: { version: 'v3.1.0', pins: {} } }));
  assert.throws(() => plugins.load(['demo'], {}), /no plugins folder was given/);
  assert.deepEqual(plugins.load([], {}), [], 'no plugins asked for: nothing to load, no folder needed');
});

test('slotSuffix: a plugin build gets its own storage; none = the base slot', () => {
  assert.equal(plugins.slotSuffix([]), '');
  assert.equal(plugins.slotSuffix(['hello', 'edge']), 'plugins-edge.hello');
});
