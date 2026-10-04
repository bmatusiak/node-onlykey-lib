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

/* the two backup/restore spots, as the 3.1.0 (and v3.0.4) okcore.cpp spells them */
const WITH_BACKUP = OKCORE
  + 'void backup() {\n    //Copy U2F key/Cert to buffer\n}\n'
  + 'void RESTORE() {\n        while (*ptr) {\n            if (*ptr == 0xFF) {\n            } else {\n                break;\n            }\n        }\n        hidprint("Successfully loaded backup");\n}\n';

test('backup: a plugin that asks for it gets the 0xFB section - generated code and the loader\'s own hooks', () => {
  const f = fixture({ okcore: WITH_BACKUP });
  const manifest = require(path.join(f.dir, 'demo', 'plugin.js'));
  fs.writeFileSync(path.join(f.dir, 'demo', 'plugin.js'), `module.exports = ${JSON.stringify({ ...manifest, backup: true })};\n`);
  delete require.cache[require.resolve(path.join(f.dir, 'demo', 'plugin.js'))]; /* the loader requires it too */
  const loaded = plugins.load(['demo'], { dir: f.dir, release: {} });
  const [r] = plugins.apply(loaded, f.stage);
  assert.equal(r.backup, true);
  const out = fs.readFileSync(f.okcorePath, 'utf8');
  assert.match(out, /#include "plugins\/okplugins_backup.h"\n/);
  assert.match(out, /okplugins_backup\(large_temp, &large_buffer_offset, \(int\)sizeof\(large_temp\)\);[^\n]*\n {4}\/\/Copy U2F key\/Cert to buffer/);
  /* the plugin branch comes before the walk's own break, so older firmware never reaches it */
  assert.match(out, /} else if \(\*ptr == 0xFB\) {[^\n]*\n {16}okplugins_restore\(ptr \+ 1, offset - 1\);\n {16}break;\n {12}} else {\n {16}break;/);
  const gen = fs.readFileSync(path.join(f.stage, 'libraries', 'onlykey', 'plugins', 'okplugins_backup.cpp'), 'utf8');
  assert.match(gen, /#include "demo\/okplugin_demo.h"/);
  assert.match(gen, /put\(buf, p, end, "demo", okplugin_demo_backup\)/);
  assert.match(gen, /okplugin_demo_restore\(data, n\)/);
  assert.match(gen, new RegExp(`#define OKPLUGINS_BACKUP_MAX ${plugins.BACKUP_MAX}`));
  assert.equal(plugins.BACKUP_MAX, 512, 'the owner\'s budget for all plugins together');
});

test('backup: no plugin asks for it - no section, no hooks', () => {
  const f = fixture({ okcore: WITH_BACKUP });
  plugins.apply(plugins.load(['demo'], { dir: f.dir, release: {} }), f.stage);
  assert.ok(!fs.readFileSync(f.okcorePath, 'utf8').includes('okplugins_'));
  assert.ok(!fs.existsSync(path.join(f.stage, 'libraries', 'onlykey', 'plugins', 'okplugins_backup.cpp')));
});

test('slotSuffix: a plugin build gets its own storage; none = the base slot', () => {
  assert.equal(plugins.slotSuffix([]), '');
  assert.equal(plugins.slotSuffix(['hello', 'edge']), 'plugins-edge.hello');
});

test('slotPlugins: a stateless plugin does not name the storage slot (key_chain joins without moving the soft key)', () => {
  const fp = require('../cli/firmware-plugins');
  const set = [{ name: 'edge' }, { name: 'key_chain', stateless: true }, { name: 'config' }];
  assert.deepEqual(fp.slotPlugins(set), ['edge', 'config']);
  assert.equal(fp.slotSuffix(fp.slotPlugins(set)), 'plugins-config.edge');
});
