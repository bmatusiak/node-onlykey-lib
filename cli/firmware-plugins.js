'use strict';
/*
 * cli/firmware-plugins.js - stage SOFT-KEY FIRMWARE PLUGINS into an emulated
 * OnlyKey's firmware. Node only (fs, path), so it lives under cli/ beside the
 * other host tools, never in src/.
 *
 * WHY HERE (owner, 2026-10-01). Experimental firmware features are plugins,
 * each in its own folder - removed by deleting it, audited by reading it - and
 * they are for emulated keys only: ok-rn's soft key (android/okemu) and
 * node-onlykey-emulator, "where node-onlykey-emulator is not forced to use
 * ok-rn". Both stagers already depend on this library (they read its version
 * table), so the one loader lives here and each stager passes the folder its
 * plugins are in. The plugins themselves live wherever that folder is - today
 * ok-rn/android/okemu/plugins/ - and the emulator is pointed at one only when
 * asked (OKEMU_PLUGINS_DIR); without it the emulator is what it always was.
 *
 * A plugin folder <dir>/<name>/ holds:
 *   plugin.js   manifest: name (= folder), minBase ('3.1.0' - an older pinned
 *               release is refused; a working tree is allowed), hooks, notes
 *   src/        its own C/C++, prefixed okplugin_<name>_
 *   AUDIT.md    every hook, every new message, every byte it stores
 *
 * A hook is {file, anchor, insert: 'before'|'after', text}. Its anchor must
 * occur EXACTLY ONCE in the staged file, or staging stops - unlike a stager's
 * literal patches, which warn on a miss and replace every occurrence: a plugin
 * that cannot hook exactly where it was written to hook must not build at all.
 *
 * Staged code goes to <stage>/libraries/onlykey/plugins/<name>/: inside the
 * include path both stagers already use, so a hook includes
 * "plugins/<name>/<header>.h". Each stager's source generator walks that one
 * folder recursively (it only exists in a plugin build).
 */
const fs = require('node:fs');
const path = require('node:path');

const NAME_RE = /^[a-z][a-z0-9_]*$/;

/** The plugins asked for (OKEMU_PLUGINS, a comma list), in order, without repeats. */
function selected(env = process.env.OKEMU_PLUGINS) {
  if (!env) return [];
  const names = String(env).split(',').map((s) => s.trim()).filter(Boolean);
  for (const n of names) {
    if (!NAME_RE.test(n)) throw new Error(`OKEMU_PLUGINS: "${n}" is not a plugin name (lower case, digits, _)`);
  }
  return [...new Set(names)];
}

/** Every plugin in `dir` (a folder starting with _ is ignored). */
function available(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('_') && fs.existsSync(path.join(dir, d.name, 'plugin.js')))
    .map((d) => d.name);
}

const versionKey = (v) => String(v).replace(/^v/, '').split('.').map((n) => parseInt(n, 10) || 0);
function atLeast(v, min) {
  const a = versionKey(v);
  const b = versionKey(min);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return true;
}

/**
 * Load and check the selected plugins' manifests. Throws naming what is wrong.
 * @param {string[]} names
 * @param {{dir: string, release?: {version?: string, pins?: object}}} opts
 *   dir: the plugins folder; release: the stager's version record (a pinned
 *   release has `pins`; the working tree does not)
 */
function load(names, { dir, release = {} } = {}) {
  if (!names.length) return [];
  if (!dir) throw new Error('plugins were asked for, but no plugins folder was given (OKEMU_PLUGINS_DIR)');
  return names.map((name) => {
    const pdir = path.join(dir, name);
    const manifestPath = path.join(pdir, 'plugin.js');
    if (!fs.existsSync(manifestPath)) {
      throw new Error(`OKEMU_PLUGINS asks for "${name}", but there is no ${manifestPath} (available: ${available(dir).join(', ') || 'none'})`);
    }
    const m = require(manifestPath);
    if (m.name !== name) throw new Error(`${name}/plugin.js says its name is "${m.name}"`);
    if (!Array.isArray(m.hooks)) throw new Error(`${name}/plugin.js has no hooks list`);
    if (!fs.existsSync(path.join(pdir, 'src'))) throw new Error(`plugin ${name} has no src/ folder`);
    if (!fs.existsSync(path.join(pdir, 'AUDIT.md'))) throw new Error(`plugin ${name} has no AUDIT.md - a plugin says what it changes`);
    if (release.pins && m.minBase && !atLeast(release.version, m.minBase)) {
      throw new Error(`plugin "${name}" needs firmware ${m.minBase} or newer; this build stages ${release.version}`);
    }
    return { ...m, dir: pdir };
  });
}

function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  let files = 0;
  for (const ent of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, ent.name);
    const d = path.join(to, ent.name);
    if (ent.isDirectory()) files += copyTree(s, d);
    else { fs.copyFileSync(s, d); files += 1; }
  }
  return files;
}

/* Where an anchor is, in the file's own line endings, and whether it is unique. */
function locate(text, anchor) {
  for (const a of [anchor, anchor.replace(/\r?\n/g, '\r\n')]) {
    const first = text.indexOf(a);
    if (first < 0) continue;
    return { anchor: a, at: first, count: text.indexOf(a, first + 1) < 0 ? 1 : 2 };
  }
  return { count: 0 };
}

/**
 * Stage plugins into a staged tree: clear any left from an earlier run, copy
 * each one's src/, apply its hooks (each anchor exactly once).
 * @param {object[]} plugins from load()
 * @param {string} stageDir the stager's staged tree (holding libraries/onlykey)
 * @returns {{name: string, hooks: number, files: number, notes: string}[]}
 */
function apply(plugins, stageDir) {
  const libOnlykey = path.join(stageDir, 'libraries', 'onlykey');
  /* a plugin staged by an EARLIER run must not linger in this one */
  fs.rmSync(path.join(libOnlykey, 'plugins'), { recursive: true, force: true });
  return plugins.map((p) => {
    const files = copyTree(path.join(p.dir, 'src'), path.join(libOnlykey, 'plugins', p.name));
    for (const [i, h] of p.hooks.entries()) {
      const where = `plugin "${p.name}" hook ${i + 1} (${h.file})`;
      const file = [path.join(libOnlykey, h.file), path.join(stageDir, h.file)].find((f) => fs.existsSync(f));
      if (!file) throw new Error(`${where}: no such staged file`);
      const text = fs.readFileSync(file, 'utf8');
      const found = locate(text, h.anchor);
      if (found.count === 0) throw new Error(`${where}: the anchor is not in the staged file - the firmware moved; re-anchor the plugin`);
      if (found.count > 1) throw new Error(`${where}: the anchor occurs more than once - make it unique`);
      const insert = found.anchor.includes('\r\n') ? h.text.replace(/\r?\n/g, '\r\n') : h.text;
      const cut = h.insert === 'before' ? found.at : found.at + found.anchor.length;
      fs.writeFileSync(file, text.slice(0, cut) + insert + text.slice(cut));
    }
    return { name: p.name, hooks: p.hooks.length, files, notes: p.notes || '' };
  });
}

/** The storage-slot suffix a plugin build uses, so it never shares the base build's flash. */
function slotSuffix(names) {
  return names.length ? `plugins-${[...names].sort().join('.')}` : '';
}

module.exports = { selected, available, load, apply, slotSuffix };
