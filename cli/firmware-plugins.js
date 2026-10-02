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
function applyHook(stageDir, h, where) {
  const libOnlykey = path.join(stageDir, 'libraries', 'onlykey');
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

function apply(plugins, stageDir) {
  const libOnlykey = path.join(stageDir, 'libraries', 'onlykey');
  /* a plugin staged by an EARLIER run must not linger in this one */
  fs.rmSync(path.join(libOnlykey, 'plugins'), { recursive: true, force: true });
  const staged = plugins.map((p) => {
    const files = copyTree(path.join(p.dir, 'src'), path.join(libOnlykey, 'plugins', p.name));
    for (const [i, h] of p.hooks.entries()) applyHook(stageDir, h, `plugin "${p.name}" hook ${i + 1} (${h.file})`);
    return { name: p.name, hooks: p.hooks.length, files, notes: p.notes || '', backup: Boolean(p.backup) };
  });
  stageBackups(plugins.filter((p) => p.backup), stageDir);
  return staged;
}

/*
 * PLUGIN BACKUPS (owner, 2026-10-02: "if I add plugins I want to back up the
 * important bits, but I don't want to affect production backups on hard keys
 * with older firmware").
 *
 * A plugin whose manifest says `backup: true` provides two functions:
 *   int  okplugin_<name>_backup(uint8_t *out, int max)  - its bytes, <= max
 *   void okplugin_<name>_restore(const uint8_t *in, int len)
 * and the loader writes ONE section for all of them, LAST in the backup:
 *
 *   0xFB | per plugin: name length (u8) . name . data length (u16 LE) . data
 *
 * Why this is safe on older firmware (format survey of the staged 3.1.0 tree
 * and .stage-src/v3.0.4, which match line for line): RESTORE walks records by
 * their first byte - 0xFF slots, 0xFE keys / auth state / resident keys, 0xFD
 * legacy U2F - and ANY OTHER byte ends the walk (`} else { break; }`) with
 * everything before it already applied, then reports "Successfully loaded
 * backup". 0xFB is used by no firmware, so a key without the plugin restores
 * everything else and stops there. The section sits inside the backup's
 * encryption and its digest, so the same backup key protects it.
 *
 * SIZE: a backup is at most 18000 bytes (the backup array and the restore
 * buffer, both versions) and a full key is about 16.7 KB, so all plugins
 * together get BACKUP_MAX = 512 bytes (owner: "we can start at 512 bytes"),
 * and the section is left out entirely when it would not fit.
 */
const BACKUP_MAX = 512;
const BACKUP_HOOKS = [
  { file: 'okcore.cpp', anchor: '#include "onlykey.h"\n', insert: 'after', text: '#include "plugins/okplugins_backup.h"\n' },
  /* backup(): after the resident keys, before the (commented-out) U2F copy - inside the encrypted body */
  { file: 'okcore.cpp', anchor: '    //Copy U2F key/Cert to buffer\n', insert: 'before',
    text: '    okplugins_backup(large_temp, &large_buffer_offset, (int)sizeof(large_temp)); /* the plugin section, 0xFB */\n' },
  /* RESTORE(): the walk's last branch - older firmware breaks here on 0xFB */
  { file: 'okcore.cpp', anchor: '            } else {\n                break;\n            }\n        }\n        hidprint("Successfully loaded backup");\n', insert: 'before',
    text: '            } else if (*ptr == 0xFB) { /* the plugin section (plugins/okplugins_backup.cpp) */\n                okplugins_restore(ptr + 1, offset - 1);\n                break;\n' },
];

function stageBackups(backers, stageDir) {
  if (!backers.length) return;
  const dir = path.join(stageDir, 'libraries', 'onlykey', 'plugins');
  const includes = backers.map((p) => `#include "${p.name}/okplugin_${p.name}.h"`).join('\n');
  const writes = backers.map((p) => `  p = put(buf, p, end, "${p.name}", okplugin_${p.name}_backup);`).join('\n');
  const reads = backers.map((p) => `    if (nl == ${p.name.length} && memcmp(name, "${p.name}", nl) == 0) okplugin_${p.name}_restore(data, n);`).join('\n');
  fs.writeFileSync(path.join(dir, 'okplugins_backup.h'), `/* GENERATED by node-onlykey-lib/cli/firmware-plugins.js - the plugin backup section (0xFB). */
#ifndef OKPLUGINS_BACKUP_H
#define OKPLUGINS_BACKUP_H
#include <stdint.h>
void okplugins_backup(uint8_t *buf, int *off, int cap);
void okplugins_restore(const uint8_t *in, int len);
#endif
`);
  fs.writeFileSync(path.join(dir, 'okplugins_backup.cpp'), `/*
 * GENERATED by node-onlykey-lib/cli/firmware-plugins.js - do not edit; see the
 * loader's PLUGIN BACKUPS comment. The plugin section of a backup:
 *   0xFB | per plugin: name length (u8) . name . data length (u16 LE) . data
 * at most ${BACKUP_MAX} bytes for all plugins; older firmware stops its restore at 0xFB.
 */
#include <string.h>
#include "okplugins_backup.h"
${includes}

#define OKPLUGINS_BACKUP_MAX ${BACKUP_MAX}

typedef int (*backup_fn)(uint8_t *out, int max);

/* one entry, if the plugin has bytes and they fit */
static int put(uint8_t *buf, int p, int end, const char *name, backup_fn fn) {
  int nl = (int)strlen(name);
  int room = end - (p + 1 + nl + 2);
  if (room <= 0) return p;
  int n = fn(buf + p + 1 + nl + 2, room);
  if (n <= 0 || n > room) return p;
  buf[p] = (uint8_t)nl;
  memcpy(buf + p + 1, name, nl);
  buf[p + 1 + nl] = n & 0xff;
  buf[p + 2 + nl] = (n >> 8) & 0xff;
  return p + 1 + nl + 2 + n;
}

void okplugins_backup(uint8_t *buf, int *off, int cap) {
  int start = *off;
  if (start + OKPLUGINS_BACKUP_MAX > cap) return; /* no room: the backup stays valid without plugins */
  int end = start + OKPLUGINS_BACKUP_MAX;
  int p = start + 1;
${writes}
  if (p == start + 1) return; /* nothing to keep: no section */
  buf[start] = 0xFB;
  *off = p;
}

/* hand each entry to its plugin; an entry for a plugin this build lacks is skipped by its length */
void okplugins_restore(const uint8_t *in, int len) {
  int p = 0;
  while (p < len) {
    int nl = in[p];
    if (nl == 0 || nl > 32 || p + 1 + nl + 2 > len) return; /* the end of the section */
    const char *name = (const char *)(in + p + 1);
    int n = in[p + 1 + nl] | (in[p + 2 + nl] << 8);
    const uint8_t *data = in + p + 3 + nl;
    if (p + 3 + nl + n > len) return;
${reads}
    p += 3 + nl + n;
  }
}
`);
  for (const [i, h] of BACKUP_HOOKS.entries()) applyHook(stageDir, h, `plugin backups hook ${i + 1} (${h.file})`);
}

/** The storage-slot suffix a plugin build uses, so it never shares the base build's flash. */
function slotSuffix(names) {
  return names.length ? `plugins-${[...names].sort().join('.')}` : '';
}

module.exports = { selected, available, load, apply, slotSuffix, BACKUP_MAX };
