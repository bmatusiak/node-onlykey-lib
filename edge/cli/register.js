'use strict';

/**
 * edge/cli/register.js - the `edge` command group of onlykey-js (CLI.md §2, decided
 * 2026-10-06: one CLI, `onlykey-js edge` and `onlykey-edge-gpg` are gone).
 *
 *   onlykey-js edge register <name> [--ssh ssh://user@host --gpg "Name <email>"
 *                               --committer-name N --committer-email E --expires 1y|<n>d|never]
 *                                         register the agent's key with the phone (a press); the
 *                                         first time, also name the agent's own identities
 *   onlykey-js edge agent [--wait s]      the OPTIONAL service (CLI.md §4): keeps the Bluetooth
 *                                         link open between commands - for speed only
 *   onlykey-js edge budget | continue | end | status | exec | ticket | watch | sync | peer | sibling
 *                                         edge/cli/commands.js
 *
 * NO SERVICE BY DEFAULT (CLI.md §4): a command finds the `edge agent` service if one
 * is running and asks it; otherwise it builds the same stack in this process for this
 * one command - connect, run, disconnect - and leaves nothing listening. The
 * service can do nothing a command can't do alone; it never starts on its own.
 *
 * cli/index.js loads this file only if it is there (CLI.md §6: Edge is a plugin).
 */
const fs = require('fs');
const net = require('net');
const path = require('path');

const USAGE = [
  'onlykey-js edge register <name> [--ssh ssh://user@host --gpg "Name <email>" --committer-name N --committer-email E --expires 1y|<n>d|never]',
  'onlykey-js edge budget --reason "…" --ssh N [--gpg N] --ttl MINUTES',
  'onlykey-js edge continue --ttl MINUTES [--caps n,n] | end | status',
  'onlykey-js edge exec --head H --intent "…" -- <command…>     the only way to spend a budget',
  'onlykey-js edge ticket <seq> [--code OK] --msg "…"',
  'onlykey-js edge watch [--once] | sync [--status] | sync --with <address>',
  'onlykey-js edge blocks [--json]                               the copy on this PC as JSON blocks (no phone)',
  'onlykey-js edge peer add | list · sibling add <address> | list',
  'onlykey-js edge agent                                         the optional service',
];

const opt = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

/* the agent's request key (made once, owner-only) and the budgets this computer asked for */
function agentKeys(home) {
  const { request } = require('../src');
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const file = path.join(home, 'agent.key');
  if (!fs.existsSync(file)) fs.writeFileSync(file, require('crypto').randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  const signer = request.signerFromSecret(Uint8Array.from(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex')));
  const storeFile = path.join(home, 'budgets.json');
  const read = () => (fs.existsSync(storeFile) ? JSON.parse(fs.readFileSync(storeFile, 'utf8')) : {});
  const store = {
    async get(k) { return read()[k] || null; },
    async set(k, v) { const all = read(); all[k] = v; fs.writeFileSync(storeFile, JSON.stringify(all, null, 2), { mode: 0o600 }); },
  };
  return { signer, store };
}

/* agent.json: the agent's own identities, its certificate, its budget */
function loadConfig(home) {
  const file = path.join(home, 'agent.json');
  const config = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const save = (c) => {
    fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify(c, null, 2), { mode: 0o600 });
  };
  return { config, save };
}

function applySetup(config, args, h) {
  const ssh = opt(args, '--ssh');
  const gpg = opt(args, '--gpg');
  const cn = opt(args, '--committer-name');
  const ce = opt(args, '--committer-email');
  const expires = opt(args, '--expires');
  if (ssh) config.ssh = ssh;
  if (gpg) config.gpgUid = gpg;
  if (cn || ce) config.committer = { name: cn || (config.committer || {}).name, email: ce || (config.committer || {}).email };
  /* the certificate's lifetime (Brad, 2026-10-03: one year for the real key): 1y, <n>d, or never */
  if (expires !== undefined) config.expires = h.parseExpires(expires);
  return Boolean(ssh || gpg || cn || ce || expires !== undefined);
}

/* is the optional service running? a connect, no request */
function serviceUp(controlPath) {
  return new Promise((resolve) => {
    const sock = net.connect(controlPath);
    const done = (v) => { clearTimeout(t); sock.destroy(); resolve(v); };
    const t = setTimeout(() => done(false), 1500);
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

/*
 * THE KEY MUST BE THERE AND OPEN before anything is asked of it (Brad,
 * 2026-10-07): a halted soft key (ok-rn's inactivity lockout) or a locked key
 * stops the command here with what to do - the agent reads it and tells Brad -
 * instead of a request timing out as "no reply on interface 2".
 */
function keyAnswers(connected, h, what) {
  if (h.requireAnswered) h.requireAnswered(connected && connected.identity);
  if (h.requireUnlocked && connected && connected.identity) h.requireUnlocked(connected.identity, what);
}

/*
 * The stack - the phone, the key's Edge, the wire to the app, the agent with its
 * own keys - for one command (serve: false) or for the service (serve: true).
 */
async function openStack(io, opts, h, { serve, dev, wait }) {
  const control = require('./control');
  const { client, wire } = require('../src');
  const { startEdgeAgent, openWithOneRetry } = require('./agent');
  const home = control.edgeHome();
  const { config, save } = loadConfig(home);
  if (!config.ssh) {
    throw h.usage('set up the agent once first: onlykey-js edge register <name> --ssh ssh://user@host --gpg "Name <email>"');
  }
  const { signer, store } = agentKeys(home);
  const say = (l) => io.err(`edge: ${l}`);
  /* ENOVENDOR at start: one more try after ~5 s (agent.js openWithOneRetry) */
  const app = await openWithOneRetry(async () => {
    const a = await io.start(h.deviceOpts(opts));
    try { keyAnswers(await a.services.device.connect(), h, 'edge'); } catch (e) { await Promise.resolve(a.destroy()).catch(() => undefined); throw e; }
    return a;
  }, { log: say });
  try {
    const { transport, okcrypto } = app.services;
    let edge = null;
    require('../plugin')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
    /* the phone gives the person 2 min to say Yes, then the key 25 s for the press (ok-rn, 2026-10-03) - wait past both */
    const wired = wire.createWireChannel(transport, {
      timeoutMs: (Number(wait) || 180) * 1000,
      device: () => (typeof transport.deviceId === 'function' ? transport.deviceId() : null),
      log: say,
    });
    /* timing logs are a dev-build switch only (edge/cli/dev; CLI.md §5) */
    const timed = dev && dev.timed ? dev.timed({ edge, wired, okcrypto, say }) : { channel: wired, okcrypto };
    const c = client.createEdgeClient({ edge, channel: timed.channel, signer, store });
    const svc = await startEdgeAgent({
      okcrypto: timed.okcrypto, client: c, edge, config, saveConfig: save, openpgp: require('../../src/crypto/pgp'),
      shimCommand: path.resolve(__dirname, 'gpg-shim.js').split(path.sep).join('/'),
      /* for one command the command itself prints the signed line; the service logs it to its own console */
      log: serve ? say : (l) => { if (!l.startsWith('signed: link')) say(l); },
      /* no confirm: under budget or no go a sign is paid or refused, never pressed (CLI.md §3) */
      selfName: opts.address || null,
      linkStats: () => (typeof transport.linkStats === 'function' ? transport.linkStats() : null),
      /* a request nobody answered: let the Bluetooth link go (the next one connects fresh, hello first) */
      onSilence: opts.ble ? async () => { await transport.release('nobody answered').catch(() => {}); } : null,
      /* R29 (edge sibling add): a second link, to the other phone, for one request */
      openOther: async (address) => {
        if (!opts.ble) throw new Error('pairing another phone needs --ble (the other phone is reached over Bluetooth)');
        const app2 = await io.start(h.deviceOpts({ ...opts, address }));
        try {
          keyAnswers(await app2.services.device.connect(), h, 'edge');
          let edge2 = null;
          require('../plugin')({ transport: app2.services.transport }, (err, s) => { if (err) throw err; edge2 = s.edge; });
          const channel2 = wire.createWireChannel(app2.services.transport, { timeoutMs: (Number(wait) || 180) * 1000 });
          return { edge: edge2, client: client.createEdgeClient({ edge: edge2, channel: channel2, signer, store }), close: () => app2.destroy() };
        } catch (e) {
          await app2.destroy().catch(() => undefined);
          throw e;
        }
      },
      serve,
    });
    return { app, transport, svc, config, home, close: async () => { await svc.close(); await app.destroy(); } };
  } catch (e) {
    await app.destroy().catch(() => undefined);
    throw e;
  }
}

/*
 * EDGE'S DEV-BUILD SET (CLI.md §5): edge/cli/dev, loaded only when that folder is
 * there. The published package leaves it out (package.json "files") and
 * scripts/release-check.js fails if any of it is reachable.
 */
const DEV = (() => {
  try {
    return require('./dev');
  } catch (e) {
    /* only edge/cli/dev itself missing - a broken require inside it still throws */
    if (e && e.code === 'MODULE_NOT_FOUND' && /'\.\/dev'/.test(e.message)) return null;
    throw e;
  }
})();

module.exports = function register(COMMANDS, h) {
  const dev = DEV;
  COMMANDS.edge = {
    mirrors: '(new)',
    raw: true, /* its own arguments: `exec … -- <command>` must reach it as typed */
    usage: 'register | budget | continue | end | status | exec | ticket | watch | sync | blocks | peer | sibling | agent',
    summary: 'Edge: an agent uses the key inside a budget you approve on the phone - budget or no go',
    device: true,
    async run(io, opts, argv) {
      const args = dev && dev.prepare ? dev.prepare(argv) : argv;
      const [sub, ...rest] = args;
      if (!sub || sub === 'help') {
        for (const l of USAGE) io.out(l);
        return sub ? 0 : 2;
      }
      /* an unknown subcommand is refused here, before anything connects to the phone */
      const KNOWN = ['register', 'agent', 'budget', 'continue', 'end', 'status', 'exec', 'ticket', 'watch', 'sync', 'blocks', 'peer', 'sibling', ...Object.keys((dev && dev.commands) || {})];
      if (!KNOWN.includes(sub)) throw h.usage(`unknown edge command "${sub}" - onlykey-js edge help`);
      const control = require('./control');
      const wait = opt(rest, '--wait');

      /* BLOCKS (BLOCKS.md §3, Brad 2026-10-07): this PC's copy cut at the key's seals into JSON blocks - local, no phone */
      if (sub === 'blocks') {
        const found = require('./copy').blocks(control.edgeHome(), { net: 'live' });
        if (rest.includes('--json')) {
          io.out(JSON.stringify(found.flatMap((d) => d.blocks.map((b) => b.block)), null, 2));
          return found.every((d) => d.blocks.every((b) => b.ok)) ? 0 : 1;
        }
        if (!found.length) io.out('no copy yet - onlykey-js edge sync');
        for (const d of found) {
          io.out(h.row(`key ${d.deviceId.slice(0, 16)}`, `${d.blocks.length} block(s), ${d.open} link(s) after the last seal${d.reason ? ` - ${d.reason}` : ''}`));
          for (const b of d.blocks) {
            const L = b.block.links;
            io.out(h.row(`  #${b.block.start.seq}-#${b.block.checkpoint.seq}`, `${b.id.slice(0, 16)}  ${L.length} link(s)  ${b.ok ? 'verified' : `does not verify: ${b.reason}`}`));
          }
        }
        return found.every((d) => d.blocks.every((b) => b.ok)) ? 0 : 1;
      }

      if (sub === 'register') {
        const name = rest[0] && !rest[0].startsWith('--') ? rest[0] : null;
        if (!name) throw h.usage('edge register <name the phone shows> [--ssh … --gpg …]');
        const home = control.edgeHome();
        const { config, save } = loadConfig(home);
        if (applySetup(config, rest, h)) save(config);
        const { client, wire, request } = require('../src');
        const { signer, store } = agentKeys(home);
        const app = await io.start(h.deviceOpts(opts));
        try {
          const { transport, device } = app.services;
          keyAnswers(await device.connect(), h, 'edge register');
          let edge = null;
          require('../plugin')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
          const c = client.createEdgeClient({ edge, channel: wire.createWireChannel(transport, { timeoutMs: (Number(wait) || 120) * 1000 }), signer, store });
          const keyHex = Buffer.from(signer.publicKey).toString('hex');
          /* the phone's sheet shows the same fingerprint: compare them before you press */
          io.out(h.row('agent key', request.fingerprint(keyHex)));
          io.out(h.row('full key', keyHex));
          io.out('Check the phone shows the same key, Register there, then press the key...');
          const r = await c.register(name);
          io.out(r.already ? 'already registered' : 'registered');
          return 0;
        } finally {
          await app.destroy();
        }
      }

      if (sub === 'agent') {
        /* the optional service: one link kept open between commands; nothing it can do that a command can't */
        const home = control.edgeHome();
        const { config, save } = loadConfig(home);
        if (applySetup(config, rest, h)) save(config);
        const st = await openStack(io, opts, h, { serve: true, dev, wait });
        try {
          const { svc, transport } = st;
          io.out(h.row('ssh key', svc.sshLine));
          if (svc.fingerprint) io.out(h.row('gpg key', svc.fingerprint));
          /* the certificate into the host's Key Chain list too, so `keychain export --pgp` prints it */
          if (io.keychainRecord && st.config.cert && st.config.gpgUid) {
            try {
              io.keychainRecord({
                scheme: 'gpg', label: `gpg://${st.config.gpgUid}`, type: 'ed25519', publicKey: st.config.cert.signPublic, code: 232,
                pgp: st.config.cert.armored, pgpFingerprint: st.config.cert.fingerprint, certCreated: st.config.cert.created,
                certExpires: st.config.cert.expires || 0, tool: 'onlykey-js edge agent',
              });
            } catch (e) {
              io.err(`edge: the certificate was not recorded in the Key Chain list (${e.message})`);
            }
          }
          if (svc.certArmored) {
            fs.writeFileSync(path.join(st.home, 'agent-gpg.asc'), svc.certArmored);
            io.out(h.row('gpg cert', path.join(st.home, 'agent-gpg.asc')));
          }
          io.out(h.row('control', svc.controlPath));
          io.out('ready - onlykey-js edge budget / exec / ticket use this service; Ctrl-C to stop');
          /*
           * RELEASE WHEN IDLE (Brad, 2026-10-06): the link is let go once the key's
           * lane has been quiet 60 s - nothing running, nothing waiting. The phone
           * goes back to advertising; the next request connects fresh, hello first.
           */
          const IDLE_MS = (dev && dev.idleMs) || 60000;
          const idleTick = opts.ble && typeof transport.laneState === 'function'
            ? setInterval(() => {
              const s = transport.laneState();
              if (s.idle && Date.now() - s.since >= IDLE_MS && transport.isOpen()) void transport.release('idle').catch(() => {});
            }, 1000)
            : null;
          if (idleTick && idleTick.unref) idleTick.unref();
          await (io.untilStopped ? io.untilStopped() : new Promise((resolve) => {
            process.once('SIGINT', resolve);
            process.once('SIGTERM', resolve);
          }));
          if (idleTick) clearInterval(idleTick);
          return 0;
        } finally {
          await st.close();
        }
      }

      const commands = require('./commands');
      const outs = { out: io.out, err: io.err, dev };
      /* the service, if Brad started one (CLI.md §4: for speed only) */
      if (await serviceUp(control.controlPath())) return commands.main(args, { ...outs, ask: control.ask });
      /* no service (the default): this one command, in-process - connect, run, disconnect.
       * The phone is opened on the command's first request, not before: a usage error
       * (exec without --head) answers at once instead of after a Bluetooth connect. */
      let st = null;
      try {
        const ask = async (op, fields = {}, o = {}) => {
          if (!st) st = await openStack(io, opts, h, { serve: false, dev, wait });
          const fn = st.svc.handlers[op];
          if (!fn) throw new Error(`no such request: ${op}`);
          if (o.onSent) o.onSent();
          return { ok: true, ...(await fn(fields)) };
        };
        return await commands.main(args, { ...outs, ask });
      } finally {
        if (st) await st.close();
      }
    },
  };
};

module.exports.USAGE = USAGE;
