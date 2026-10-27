'use strict';

/**
 * THE BUCKET, THE CLI PLUGIN (ok-edge stage 3): `onlykey-js bucket …` - what this computer keeps
 * about its keys (bucket/cli/home.js) as the one portable file every front end reads.
 *
 *   bucket show                what the bucket holds: each store and how many entries
 *   bucket export <file>       the bucket SEALED with the key (a derive on the key) - the file that travels
 *   bucket import <file>       a bucket merged in: sealed ones open with the key; an unsealed one
 *                              only in a development build. Nothing is dropped: what both sides
 *                              changed is listed with both dates and this computer's value kept
 *   bucket dump [--test-mode]  the Edge chain only, as JSON blocks checked against the key's public
 *                              keys - public, for anyone to verify (Brad, 2026-10-21: the bucket
 *                              may hold passwords, so the dump is the Edge chain alone)
 *
 * Sealed when it travels, plain on this disk (Brad, 2026-10-21): everyday commands never need the
 * key to read their own state; export and import do.
 */
const fs = require('fs');
const path = require('path');
const bucket = require('../src/bucket');
const rules = require('../src/rules');
const home = require('./home');

/* a development checkout has cli/dev; the published package leaves it out (package.json files) */
const DEV_BUILD = fs.existsSync(path.join(__dirname, '..', '..', 'cli', 'dev'));

/* the merge rule for each store the CLI keeps; a store without one is taken key by key, newest wins */
function storeRules() {
  const r = {};
  try { const list = require('../../keychain/src/list'); r.keychain = rules.keychain(list); r['keychain-test'] = rules.keychain(list); } catch { /* no keychain folder in this build */ }
  try { const copyfile = require('../../edge/src/copyfile'); r['edge.copies'] = rules.edgeCopies(copyfile); r['edge-test.copies'] = rules.edgeCopies(copyfile); } catch { /* no edge folder */ }
  return r;
}

function setup(imports, register) {
  const { cli } = imports;
  const { CliError, row, usage, withDevice } = cli.helpers;
  const file = () => path.join(home.root(), home.FILE);
  const bucketKey = async (okcrypto) => okcrypto.deviceVault.key('bucket');
  const randomBytes = (n) => new Uint8Array(require('crypto').randomBytes(n));
  /* how this computer shows in a room: one id for good (kept beside the bucket), the machine's name */
  const thisDevice = () => {
    const f = path.join(home.root(), 'device.json');
    let id = null;
    try { id = JSON.parse(fs.readFileSync(f, 'utf8')).id; } catch { /* first time */ }
    if (!/^[0-9a-f]{16}$/.test(String(id))) {
      id = require('crypto').randomBytes(8).toString('hex');
      fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
      fs.writeFileSync(f, `${JSON.stringify({ id })}\n`, { mode: 0o600 });
    }
    return { id, name: require('os').hostname().slice(0, 64) || 'computer', kind: 'cli' };
  };

  const BUCKET = {
    mirrors: '(new)',
    usage: 'show | export <file> | import <file> | dump [--test-mode] | sync --server <url> [--test-mode]',
    summary: 'the bucket: what this computer keeps about its keys, as one file - export it sealed, import one, dump the Edge chain',
    device: false,
    /* sync's server; dump's and sync's net (the soft key's net itself is read from argv by --soft-key) */
    options: { server: { type: 'string' }, 'test-mode': { type: 'boolean' } },
    async run(io, opts, [sub, arg]) {
      if (!sub || sub === 'help') { io.out(`onlykey-js bucket ${BUCKET.usage}`); return sub ? 0 : 2; }

      if (sub === 'show') {
        const b = home.read();
        const names = Object.keys(b.stores).sort();
        io.out(row('bucket', fs.existsSync(file()) ? file() : `${file()} (nothing kept yet)`));
        for (const n of names) io.out(row(`  ${n}`, `${bucket.kv(b, n).keys().length} entr${bucket.kv(b, n).keys().length === 1 ? 'y' : 'ies'}`));
        return 0;
      }

      if (sub === 'dump') {
        const net = opts['test-mode'] ? 'test' : 'live';
        let copyfile;
        try { copyfile = require('../../edge/src/copyfile'); } catch { throw new CliError('this build has no Edge folder: nothing to dump'); }
        const found = rules.edgeBlocks(home.read(), copyfile, { net, store: net === 'test' ? 'edge-test.copies' : 'edge.copies' });
        io.out(JSON.stringify(found.flatMap((d) => d.blocks.map((x) => x.block)), null, 2));
        return found.every((d) => d.blocks.every((x) => x.ok)) ? 0 : 1;
      }

      if (sub === 'export') {
        if (!arg) throw usage('bucket export <file>');
        if (fs.existsSync(arg)) throw new CliError(`${arg} exists - export never writes over a file`);
        return withDevice(io, opts, async ({ okcrypto }) => {
          const text = bucket.seal(home.read(), await bucketKey(okcrypto), randomBytes);
          fs.writeFileSync(arg, `${text}\n`, { mode: 0o600 });
          io.out(`exported, sealed with this key: ${arg}`);
          return 0;
        });
      }

      if (sub === 'import') {
        if (!arg) throw usage('bucket import <file>');
        const text = fs.readFileSync(arg, 'utf8');
        const sealed = (() => { try { return JSON.parse(text).format === bucket.SEALED_FORMAT; } catch { return false; } })();
        const merge = (key) => {
          const { bucket: theirs } = bucket.open(text, { key, allowUnsealed: DEV_BUILD });
          return home.update(file(), (mine) => {
            const r = bucket.merge(mine, theirs, { rules: storeRules() });
            mine.stores = r.bucket.stores;
            return r.report;
          });
        };
        const report = sealed
          ? await withDevice(io, opts, async ({ okcrypto }) => merge(await bucketKey(okcrypto)))
          : merge(null);
        const taken = Object.entries(report.taken || {}).filter(([, n]) => n);
        io.out(taken.length ? `imported: ${taken.map(([s, n]) => `${s} ${n}`).join(', ')}` : 'imported: nothing new');
        for (const c of report.conflicts || []) {
          io.out(row(`  kept this computer's ${c.store || ''} ${c.key || ''}`.trimEnd(), c.into && c.from
            ? `here ${c.into.at}, theirs ${c.from.at}${c.reason ? ` - ${c.reason}` : ''}`
            : (c.reason || 'both changed')));
        }
        return 0;
      }

      /*
       * SYNC OVER THE USER'S SERVER (ok-edge plan M2): join this bucket identity's room on the server the user runs
       * (ok-edge mcp-server/ - the key's proof, no code), then trade with every device of the identity online there,
       * one after another, as the cli pair's trade does side by side. Frames are sealed between the devices
       * (room.js); the server passes ciphertext.
       */
      if (sub === 'sync') {
        const url = opts.server;
        if (!url || url === true) throw usage('bucket sync --server <url> [--test-mode]');
        if (typeof globalThis.WebSocket !== 'function') throw new CliError('this Node has no WebSocket - Node 22 or later');
        const net = opts['test-mode'] ? 'test' : 'live';
        const { tradeWith, meFor, tradeTimeoutMs } = require('./trade');
        const { connectRoom } = require('../src/room-client');
        const say = (l) => io.out(l);
        return withDevice(io, opts, async ({ okcrypto }) => {
          const me = await meFor({ okcrypto, net, say });
          const room = await connectRoom({ url, me, device: thisDevice(), WebSocket: globalThis.WebSocket, randomBytes });
          try {
            const host = new URL(url).host;
            const peers = room.peers();
            if (!peers.length) { io.out(`sync: ${host}: no other device of this identity is online`); return 0; }
            let failed = 0;
            for (const p of peers) {
              io.out(`sync: ${host}: with ${p.name} (${p.kind})`);
              let first = true;
              const send = (m) => { const t = tradeTimeoutMs(m, first); first = false; return room.request(p.id, m, { timeoutMs: t }); };
              try {
                const r = await tradeWith({ send, okcrypto, net, say, id: me.id });
                if (!r.traded) { failed++; io.out(`sync: not traded with ${p.name}: ${r.why || 'no reason given'}`); }
              } catch (e) {
                failed++;
                io.out(`sync: not traded with ${p.name}: ${e.message}`);
              }
            }
            return failed ? 1 : 0;
          } finally {
            room.close();
          }
        });
      }

      throw usage(`unknown bucket command "${sub}" - onlykey-js bucket help`);
    },
  };
  cli.command('bucket', BUCKET);
  register(null, { bucket: { home } });
}

setup.consumes = ['cli'];
setup.provides = ['bucket'];
module.exports = setup;
