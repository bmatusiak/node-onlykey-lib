'use strict';

/**
 * edge/cli/register.js - the `edge` command group of onlykey-js (CLI.md §2, decided
 * 2026-10-06: one CLI, `onlykey-js edge` and `onlykey-edge-gpg` are gone).
 *
 *   onlykey-js edge setup --ssh ssh://user@host [--gpg "Name <email>"
 *                               --committer-name N --committer-email E --expires 1y|<n>d|never]
 *                                         name the agent's own identities, once (no phone). No
 *                                         registration with the phone since 2026-10-08 (Brad: "so
 *                                         the claude key thing is overkill"): the phone trusts this
 *                                         computer by its cli pair (onlykey-js pair)
 *   onlykey-js edge agent [--wait s]      the OPTIONAL service (CLI.md §4): keeps the Bluetooth
 *                                         link open between commands - for speed only
 *   onlykey-js edge budget | continue | end | status | exec | receipt | watch | sync
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
const { edgeCmd } = require('./control');
const bucketHome = require('../../bucket/cli/home');

const USAGE = [
  'onlykey-js edge setup --ssh ssh://user@host --gpg "Name <email>" [--committer-name N --committer-email E --expires 1y|<n>d|never --created <unix>]',
  '                                                              the agent identity: made here, kept by the phone (approve on its Edge sheet)',
  '                                                              - or, for a hard key on USB, by this computer (approve here, y/N)',
  'onlykey-js edge budget --reason "…" --ssh N [--gpg N] --ttl MINUTES',
  'onlykey-js edge continue --ttl MINUTES [--caps n,n] | end | status',
  'onlykey-js edge exec --head H --intent "…" [--receipt "…"] -- <command…>     the only way to spend a budget',
  'onlykey-js edge receipt <seq> [--code OK] --msg "…"',
  'onlykey-js edge watch [--once] | sync [--status | --all]',
  'onlykey-js edge sync --all                                    every paired phone: pull each into this PC first (writes nothing), then push each what it lacks',
  'onlykey-js edge blocks [--json]                               the copy on this PC as JSON blocks (no phone)',
  'onlykey-js edge name [<a name>]                              the name of this device in its identity: shown, or set / changed (signed by the key, no press)',
  'onlykey-js edge migrate --dry-run                             what of the records from before identities is this key\'s (the first command copies them by itself)',
  'onlykey-js edge loss [<from> [<to>]]                          a hard key: accept links gone before this PC read them as lost (y, then the press);',
  '                                                              no numbers = the range the copy check finds missing',
  'onlykey-js edge agent                                         the optional service',
  'onlykey-js edge control note <repo>… | preview | ship [<repo>…] [--plan] | status | settings',
  '                                                              commits to sign and push, shipped in ONE budget (the batch lives in the Edge home)',
  'onlykey-js edge --claude-setup [--force]                      write the edge-control skill into this workspace (.claude/skills/edge-control)',
  'add --test-mode to any of them: the testnet - its own home, its own chain on the phone (Enter testing mode)',
  'onlykey-js edge --test-mode clear                             delete the testnet on this computer (its home and Key Chain file)',
];

const opt = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

/*
 * The budgets this computer asked for (no agent key since 2026-10-08: the cli pair says
 * who asks): the home's `budgets` store in the CLI's bucket (bucket/cli/home.js), one key per
 * budget, its JSON.
 */
function budgetStore(home) {
  const kv = bucketHome.kv(bucketHome.edgeAt(home, 'budgets'));
  const store = {
    async get(k) { const t = kv.getItem(k); return t ? JSON.parse(t) : null; },
    async set(k, v) { kv.setItem(k, JSON.stringify(v)); },
  };
  return { store };
}

/*
 * THIS COMPUTER'S OWN EDGE STATE: one budget pointer per key (edge/src/store.js), the home's
 * `pointers` store in the CLI's bucket, through the host-store seam (getItem/setItem/removeItem).
 * The agent's identity is NOT here: the phone keeps it (SPEC H7, 2026-10-20 - it was
 * agent.json, one per computer folder; a new computer had to be given a copy by hand).
 */
function pointerKv(home) {
  return bucketHome.kv(bucketHome.edgeAt(home, 'pointers'));
}

/* edge setup's flags: only what was given (the rest comes from the identity the phone keeps) */
function parseSetup(args, h) {
  const ssh = opt(args, '--ssh');
  const gpg = opt(args, '--gpg');
  const cn = opt(args, '--committer-name');
  const ce = opt(args, '--committer-email');
  const expires = opt(args, '--expires');
  const created = opt(args, '--created');
  const s = {};
  if (ssh) s.ssh = ssh;
  if (gpg) s.gpgUid = gpg;
  if (cn || ce) s.committer = { name: cn, email: ce };
  /* the certificate's lifetime (Brad, 2026-10-03: one year for the real key): 1y, <n>d, or never */
  if (expires !== undefined) s.expires = h.parseExpires(expires);
  /*
   * --created <unix seconds>: remake the certificate with that creation time. The time is
   * part of the fingerprint, so the same key and the same time give the SAME fingerprint -
   * how an identity made elsewhere moves to the phone without changing a key on GitHub.
   */
  if (created !== undefined) {
    const n = Number(created);
    if (!Number.isInteger(n) || n <= 0 || n > 0xffffffff) throw h.usage('--created takes the certificate\'s creation time in unix seconds');
    s.created = n;
  }
  return s;
}

/*
 * THE LABELS A FIRST IDENTITY GETS WHEN NONE ARE NAMED (Brad, 2026-10-29: "edge setup should be checking itself to see
 * if its setup and autosetup itself - plug it in and go"): ssh://agent@<this computer>, and the person's own git name
 * and email for the gpg user ID - the email is what GitHub matches to show a signature as Verified. Only proposed: the
 * identity is shown and kept only on the person's Yes (setUpIdentity). No git email set: null - an email is never guessed.
 */
function defaultIdentity() {
  const os = require('os');
  const { spawnSync } = require('child_process');
  const git = (k) => { try { return String(spawnSync('git', ['config', '--global', k], { encoding: 'utf8' }).stdout || '').trim(); } catch (_) { return ''; } };
  const name = git('user.name');
  const email = git('user.email');
  if (!name || !/^[^\s<>@]+@[^\s<>@]+$/.test(email)) return null;
  const host = (os.hostname() || 'computer').toLowerCase().replace(/[^a-z0-9.-]/g, '-').slice(0, 40);
  return { ssh: `ssh://agent@${host}`, gpgUid: `${name.replace(/[<>()]/g, '')} (agent on ${host}) <${email}>` };
}

/*
 * THE AGENT IDENTITY, SET FROM A COMPUTER AND KEPT BY ITS HOST (SPEC H7; Brad, 2026-10-20: "computer sets, phone
 * keeps"). The certificate is made HERE - the key signs it, two presses - and sent with the labels; the host (the phone
 * over Bluetooth, this computer for a key on USB) shows it and keeps it only when the person approves. Labels not given
 * keep the host's current ones, and a first identity takes defaultIdentity(); a certificate is remade only when the gpg
 * user ID, the lifetime or --created changes it. One function for `edge setup` and for a command that finds none (openStack).
 * -> {record, host, changed}
 */
async function setUpIdentity(io, d, h, given, { wait } = {}) {
  const lib = require('../src/identity');
  const now = await askIdentity(d.channel);
  const def = now ? null : defaultIdentity();
  const record = {
    ssh: given.ssh || (now && now.ssh) || (def && def.ssh),
    gpgUid: given.gpgUid || (now && now.gpgUid) || (def && def.gpgUid),
    committer: given.committer
      ? { name: given.committer.name || (now && now.committer && now.committer.name), email: given.committer.email || (now && now.committer && now.committer.email) }
      : (now ? now.committer : null),
    expires: given.expires !== undefined ? given.expires : (now ? now.expires : 0),
  };
  if (!record.ssh || !record.gpgUid) throw h.usage(`no git name and email on this computer to name the agent by - set them (git config --global user.name / user.email), or name the identity: ${edgeCmd('setup --ssh ssh://user@host --gpg "Name <email>"')}`);
  if (record.committer && (!record.committer.name || !record.committer.email)) throw h.usage('a committer takes both --committer-name and --committer-email');
  const keep = now && now.gpgUid === record.gpgUid && now.expires === record.expires && given.created === undefined;
  if (keep) {
    record.cert = now.cert;
  } else {
    d.say('making the agent\'s PGP certificate - two signatures by the OnlyKey (press when asked)');
    const { makeCertificate } = require('../../keychain/src/cert');
    const { subjectFingerprint } = require('../../src/protocol/challenge');
    const made = await makeCertificate(d.okcrypto, require('../../src/crypto/pgp'), {
      label: record.gpgUid, version: 2, expires: record.expires,
      ...(given.created !== undefined ? { created: given.created } : {}),
      /* each press said with what is sent (the fingerprint a soft key's sheet shows too) - on a hard key this line is all there is */
      onPress: ({ subject } = {}) => d.say(`press on the OnlyKey: sign the agent's PGP certificate for gpg://${record.gpgUid}${subject ? ` (message ${subjectFingerprint(subject)})` : ''}`),
    });
    record.cert = { armored: made.armored, fingerprint: made.fingerprint, created: made.created, expires: made.expires, signPublic: Buffer.from(made.signPublic).toString('hex') };
  }
  const host = d.channel.local ? 'this computer' : 'the phone';
  if (now && lib.same(now, record)) return { record, host, changed: false };
  io.out(d.channel.local ? 'approve the identity here' : 'the phone shows the identity on its Edge sheet - approve it there');
  const a = await d.channel.send(lib.buildSet({ record }), { timeoutMs: (Number(wait) || 180) * 1000 });
  if (!a) throw new h.CliError('the phone did not answer (its sheet ran out, or ok-rn is not up to date) - nothing was kept');
  if (a.ok === false) {
    throw new h.CliError(`${host} did not keep it: ${a.refusal}${a.detail ? ` - ${a.detail}` : ''}${def ? ` - to name it yourself: ${edgeCmd('setup --ssh ssh://user@host --gpg "Name <email>"')}` : ''}`);
  }
  recordCert(io, record, 'onlykey-js edge setup');
  return { record, host, changed: true };
}

/* the phone's identity record (or null), asked over the paired channel */
async function askIdentity(channel) {
  const lib = require('../src/identity');
  const a = await channel.send(lib.buildGet(), { timeoutMs: 20000 });
  if (!a) throw new Error('the phone did not answer the identity question (EDGE_IDENTITY_GET) - is ok-rn up to date and open?');
  if (a.ok === false) throw new Error(`the phone refused the identity question: ${a.detail || a.refusal}`);
  if (!a.record) return null;
  const c = lib.checkRecord(a.record);
  if (!c.ok) throw new Error(`the phone's agent identity is not usable (${c.reason}) - set it again: ${edgeCmd('setup')}`);
  return lib.clean(a.record);
}

/*
 * WHOSE KEY CHAIN, WHEN THIS COMPUTER KEEPS MORE THAN ONE IDENTITY (2026-10-29: the packaged desktop app's soft key
 * kept a second bucket on this PC, and from then on every edge command warned "more than one identity keeps its
 * bucket" and recorded nothing - the certificate and the derived keys of a whole ship). An edge command does not learn
 * the key's identity at its first record (keychain/cli/record.js: that question would land between an exec's arming
 * and its signature), so it is read here, once, while the key is being opened and nothing is armed yet - and only when
 * there is a choice to make, so a computer with one identity asks the key nothing more.
 */
async function pickKeychainIdentity(io, app) {
  if (!io.keychainRecord) return;
  if (require('../../bucket/cli/home').keptIdentities(NET).length < 2) return;
  try {
    await require('../../keychain/cli/record').learnIdentityOf(app);
  } catch (_) { /* not read: the first record's warning says what to do */ }
}

/*
 * WHOSE BUCKET THIS KEY'S RECORDS GO IN (PROPOSAL-sync-and-identity.md Phase 1): the key's BUCKET identity - the Edge
 * logs (copy.js useIdentityBucket) and the Key Chain list are kept in its bucket, the one a trade carries. Read once,
 * through the identity plugin, and kept beside the Edge home it belongs to (`<home>` store `bucket-identity`): the
 * Edge identity names the home and both come from the same backup, so the pair never changes and later commands ask
 * the key nothing for it (Brad, 2026-10-29: "don't hammer the key"). Read before anything is armed.
 * An app without the identity plugin (a test's own) keeps the old pick.
 */
async function knowTheBucket(io, app, edge, netHome) {
  const svc = app.services && app.services.identity;
  if (!svc) return pickKeychainIdentity(io, app);
  const bucketHome = require('../../bucket/cli/home');
  const { isBucketIdentityId } = require('../../bucket/src/bucket-identity');
  let id = null;
  try {
    const kept = bucketHome.kv(bucketHome.edgeAt(path.join(netHome, await edge.identityId()), 'bucket-identity'));
    id = kept.getItem('id');
    if (!id || !isBucketIdentityId(id)) {
      id = (await svc.load({ site: false })).id;
      kept.setItem('id', id);
    }
  } catch (_) {
    /* no Edge on this key (or it would not say): the identity plugin's read alone */
    try { id = (await svc.load({ site: false })).id; } catch { return; }
  }
  require('./copy').useIdentityBucket({ id, net: NET });
  if (io.keychainRecord) require('../../keychain/cli/record').setIdentity(id);
}

/* the certificate into the host's Key Chain list, so `keychain export --pgp` prints the fingerprint git signs with (audit F10/F11) */
function recordCert(io, record, tool) {
  if (!io.keychainRecord || !record) return;
  try {
    io.keychainRecord({
      scheme: 'gpg', label: record.gpgUid, type: 'ed25519', publicKey: record.cert.signPublic, code: 232,
      pgp: record.cert.armored, pgpFingerprint: record.cert.fingerprint, certCreated: record.cert.created,
      certExpires: record.cert.expires || 0, tool,
    });
  } catch (e) {
    io.err(`edge: the certificate was not recorded in the Key Chain list (${e.message})`);
  }
}

/* what a budget request waits on, in words: the phone over Bluetooth, the desktop app's window, or this terminal for a hard key on USB (local-host.js) */
/* the person's y/N for a hard key's host: on this terminal, or in a desktop dialog with --gui-prompt (cli/gui-prompt.js) */
function personConfirm(opts) {
  return opts && opts['gui-prompt'] ? require('../../cli/gui-prompt').guiConfirm : require('./local-host').terminalConfirm;
}

function waitingLine(opts, h) {
  if (opts.ble) return 'Waiting for the phone - read the request there, then press…';
  if (h && h.deviceOpts(opts).desktop) return 'Waiting for the desktop app - answer the request in its window, then press the key…';
  return 'The request is shown here - answer y/N, then press the key…';
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
 * A LOCKED KEY UNDER --gui-prompt (Brad, 2026-10-26: "if using --gui-prompt and the key is locked, create a prompt asking
 * to unlock the key, with OK and Cancel; loop OK until key is unlocked or cancel to cancel the op"). The person enters
 * the PIN on the key itself; the window only waits for them: OK reads the key again and asks again while it is still
 * locked, Cancel ends the command. Without --gui-prompt a locked key stops at once with what to do (keyAnswers).
 */
async function untilUnlocked(app, opts, h) {
  let connected = await app.services.device.connect();
  if (!opts || !opts['gui-prompt']) return connected;
  const { guiConfirm } = require('../../cli/gui-prompt');
  while (connected && connected.identity && connected.identity.state === 'locked') {
    const ok = await guiConfirm('The OnlyKey is locked. Enter your PIN on the key, then click OK.', {
      title: 'OnlyKey - unlock the key',
      labels: { yes: 'OK', no: 'Cancel' },
      details: 'The command waits for the key: OK checks it again, Cancel stops the command.',
    });
    if (!ok) throw new h.CliError('cancelled: the OnlyKey stayed locked');
    connected = await app.services.device.connect();
  }
  return connected;
}

/*
 * The phone and the key's Edge, with the wire to the app - what `edge setup` needs, and
 * what the stack below is built on.
 */
async function openDevice(io, opts, h, { dev, wait, migrating = false }) {
  const { wire } = require('../src');
  const { openWithOneRetry } = require('./agent');
  const say = (l) => io.err(`edge: ${l}`);
  /* ENOVENDOR at start: one more try after ~5 s (agent.js openWithOneRetry) */
  const dopts = h.deviceOpts(opts);
  const app = await openWithOneRetry(async () => {
    const a = await span('open: lib + USB', () => io.start(dopts));
    try { keyAnswers(await span('open: connect', () => untilUnlocked(a, opts, h)), h, 'edge'); } catch (e) { await Promise.resolve(a.destroy()).catch(() => undefined); throw e; }
    return a;
  }, { log: say });
  const { transport, okcrypto } = app.services;
  let edge = null;
  require('../plugin')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
  /* before the first derive below (the identity home) records anything */
  await span('open: whose bucket', () => knowTheBucket(io, app, edge, require('./control').edgeHome()));
  /*
   * WHOSE RECORDS (ok-edge B3.0; Brad, 2026-10-24: "one identity, one store"): the key's identity -
   * its owner key, one read, the same on every device of one backup - picks its home inside the net's:
   * <net home>/<identity id>. Everything this command keeps (the identity record, budgets, pointers,
   * copies, notes) files there, so a key from another backup never reads or writes this one's.
   */
  /*
   * BY ITSELF, ONCE (Brad, 2026-10-24: "something more automatic ... as simple and seamless as
   * possible"): the first time this identity is used on this computer, what of the records from before
   * identities is provably this key's is copied in (copy-first) and the command goes on with it - the
   * one function every host uses (migrate-identity.js identityHome; the desktop app's host too).
   * edge migrate --dry-run looks without it.
   */
  const netHome = require('./control').edgeHome();
  const home = migrating
    ? path.join(netHome, await edge.identityId())
    : await span('open: identity home', () => require('./migrate-identity').identityHome({ edge, okcrypto, netHome, say }));
  /* every log of this identity into its bucket, once each (copy.adoptAll): a wiped key's history too */
  try { const n = require('./copy').adoptAll(home); if (n) say(`${n} older log(s) of this identity copied into its bucket`); } catch (e) { say(`older logs not copied into the bucket this time (${e.message})`); }
  /*
   * WHO HOSTS EDGE. Over Bluetooth the phone does: the wire to its app. A key on USB is a hard key
   * (or Linux's emulated one on the bus) - no phone behind it answers the wire, so this computer is
   * the host (local-host.js: the y/N on this terminal, then the press on the key; B4, 2026-10-23).
   * The phone gives the person 2 min to say Yes, then the key 25 s for the press (ok-rn,
   * 2026-10-03) - the wire waits past both.
   *
   * The ok-edge desktop app (--desktop, or plain while it runs) is the phone's twin on this machine:
   * it holds the key and hosts it, answering the same wire (desktop/serve.js) from the same records -
   * so the wire channel, not local-host.js, which then runs inside the app.
   */
  const wired = (opts.ble || dopts.desktop)
    ? wire.createWireChannel(transport, {
      timeoutMs: (Number(wait) || 180) * 1000,
      device: () => (typeof transport.deviceId === 'function' ? transport.deviceId() : null),
      log: say,
      net: NET,
    })
    : require('./local-host').createLocalHost({
      edge, home, say, confirm: personConfirm(opts),
    });
  /* timing logs are a dev-build switch only (edge/cli/dev; CLI.md §5) */
  const timed = dev && dev.timed ? dev.timed({ edge, wired, okcrypto, say }) : { channel: wired, okcrypto };
  return { app, transport, okcrypto: timed.okcrypto, edge, channel: timed.channel, say, home };
}

/*
 * The stack - the phone, the key's Edge, the wire to the app, the agent with its
 * own keys - for one command (serve: false) or for the service (serve: true).
 * The agent's identity comes from the phone (SPEC H7); the budget pointer is this
 * computer's, per key.
 */
async function openStack(io, opts, h, { serve, dev, wait, share = false }) {
  const control = require('./control');
  const { client, store: edgeStore } = require('../src');
  const { startEdgeAgent } = require('./agent');
  /* the key's identity home (openDevice): its budgets, pointers and copies - not the net's */
  const d = await openDevice(io, opts, h, { dev, wait });
  const { app, transport, okcrypto, edge, channel, say, home } = d;
  const { store } = budgetStore(home);
  try {
    let identity = await span('open: agent identity', () => askIdentity(channel));
    /*
     * NONE YET: MADE NOW, IN THIS RUN (Brad, 2026-10-29: "edge setup should be checking itself to see if its setup and
     * autosetup itself - plug it in and go - but we dont want to remove best security practices"). The same setup as
     * `edge setup` with no labels named (setUpIdentity: the defaults, the certificate's two presses, the person's Yes on
     * the identity) - nothing kept without that Yes. The long-lived service (serve) runs its sync without an agent
     * instead (the code below), and asks nobody.
     */
    if (!identity && !serve) {
      say('this computer has no agent identity for this key yet - making one now (approve it, then press when asked)');
      await setUpIdentity(io, d, h, {}, { wait });
      identity = await askIdentity(channel);
    }
    if (!identity) {
      /* coded: a long-lived service runs its sync without an agent (the agent branch below) */
      throw Object.assign(h.usage(channel.local
        ? `this computer keeps no agent identity for this key yet - set it once: ${edgeCmd('setup --ssh ssh://user@host --gpg "Name <email>"')}`
        : `${opts.ble ? 'the phone' : 'the desktop app'} keeps no agent identity yet - set it once, from any paired computer: ${edgeCmd('setup --ssh ssh://user@host --gpg "Name <email>"')}`), { code: 'ENOAGENTID' });
    }
    recordCert(io, identity, serve ? 'onlykey-js edge agent' : 'onlykey-js edge');
    const { deviceId } = await span('open: edge public key', () => edge.publicKey());
    const c = client.createEdgeClient({ edge, channel, store });
    const svc = await span('open: start agent', () => startEdgeAgent({
      okcrypto, client: c, edge, home, identity, deviceId,
      /* a service on USB reads each request's new links into this computer's copy (copy.catchUp) */
      keepCopy: serve && !opts.ble,
      pointers: edgeStore.createPointerStore(pointerKv(home)),
      openpgp: require('../../src/crypto/pgp'),
      shimCommand: path.resolve(__dirname, 'gpg-shim.js').split(path.sep).join('/'),
      /* for one command the command itself prints the signed line; the service logs it to its own console */
      log: serve ? say : (l) => { if (!l.startsWith('signed: link')) say(l); },
      /* no confirm: under budget or no go a sign is paid or refused, never pressed (CLI.md §3) */
      linkStats: () => (typeof transport.linkStats === 'function' ? transport.linkStats() : null),
      /* a request nobody answered: let the Bluetooth link go (the next one connects fresh, hello first) */
      onSilence: opts.ble ? async () => { await transport.release('nobody answered').catch(() => {}); } : null,
      serve,
    }));
    /*
     * A HARD KEY'S LINKS ARE PICKED UP AFTER EVERY COMMAND (key 1, 2026-10-23). The key keeps only its
     * newest links in a ring; the phone keeps its copy current all the time, but for a hard key this
     * computer's copy moved only when a budget opened - a ship (grant, five uses, five receipts, end)
     * pushed #387-#389 out of the ring before anyone read them, and the next budget was refused
     * "copy does not verify (gap at #387)" for good. So on USB, and through the desktop app (the
     * same homes), the copy is brought to the key's head before the key is let go. Over Bluetooth
     * the phone keeps its own copy.
     */
    const pickUp = async () => {
      if (opts.ble) return;
      const r = await span('close: copy - read + verify', () => require('./copy').sync(edge, home)).catch((e) => ({ error: e }));
      if (r && r.error) say(`could not bring this computer's copy to the key's head (${r.error.message})`);
      else if (r && r.verdict && r.verdict.kind !== 'verified' && r.verdict.kind !== 'unsigned') say(`this computer's copy of the chain: ${r.verdict.kind}${r.verdict.seq !== undefined ? ` at #${r.verdict.seq}` : ''}`);
      /* and its log kept ready to offer to the identity's other devices (nametag.js offerOwnLog - as a phone's pull does) */
      else await span('close: copy - own log kept to offer', () => require('./nametag').offerOwnLog({ edge, home })).catch(() => undefined);
    };
    /*
     * LOGS GO EVERYWHERE BY THEMSELVES (Brad, 2026-10-24: "sync is invisible and a user should never
     * have to do it"; "if a hacker gets on my PC, this should show it if it used my key across any one
     * of my devices"). Whenever this computer and the phone talk, they swap logs before the link is
     * let go - the phone's comes here, every log here goes to the phone - the same work as edge sync.
     */
    const shareLogs = async () => {
      if (!opts.ble || !share) return;
      const r = await svc.handlers.sync({}).catch((e) => ({ error: e }));
      if (r.error) { say(`logs: not swapped with the phone this time (${r.error.message})`); return; }
      const given = (r.offered || []).filter((o) => o.held).map((o) => `"${o.nametag}"`);
      say(`logs: swapped with the phone${given.length ? ` - it now has ${given.join(', ')}` : ''}`);
      /*
       * AND THE BUCKET, TRADED (bucket/cli/trade.js; Brad, 2026-10-25: "the CLI pair is our hook to try and sync with -
       * those are the pre-set-up trusted devices"): this paired phone and this computer prove their bucket identity to
       * each other, then each takes the other's changes. The first hello may wait on the phone's presses (its bucket
       * key, made once); later rounds are quick.
       */
      let round = 0;
      const send = (m) => channel.send(m, { timeoutMs: require('../../bucket/cli/trade').tradeTimeoutMs(m, round++ === 0) }).catch((e) => { say(`sync: the phone gave no answer to ${m.type} (${e.message})`); return null; });
      const t = await require('../../bucket/cli/trade').tradeWith({ send, okcrypto, net: NET, say })
        .catch((e) => ({ traded: false, why: e.message }));
      const n = (o) => Object.values(o || {}).reduce((a, b) => a + b, 0);
      say(t.traded && t.same ? 'sync: in sync with the phone' : t.traded ? `sync: traded with the phone - took ${n(t.taken)}, gave ${n(t.gave)}` : `sync: not traded this time (${t.why})`);
    };
    return { app, transport, svc, identity, home, channel, okcrypto, say, close: async () => {
      await span('close: logs to the phone', shareLogs);
      await span('close: agent', () => svc.close());
      await span('close: copy to the key\'s head', pickUp);
      await span('close: lib + USB', () => app.destroy());
    } };
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
/*
 * a step on the ship's timeline (edge/cli/dev/times.js) when the dev set is here; and in the ship's progress window when
 * it named one (progress-feed.js: the steps where the key works silently, with their result); else the step as it is
 */
const FEED = require('./progress-feed');
function span(name, fn) { const run = () => FEED.span(name, fn); return DEV && DEV.times ? DEV.times.span(name, run) : run(); }

/*
 * THE TESTNET (BLOCKS.md; Brad, 2026-10-07: "we should treat --test-mode as test
 * net for cli for edge"; "everthing for test is throwaway"). --test-mode (anywhere
 * before --) puts this run on the test chain: its own home (~/.onlykey-js/edge-test:
 * agent, budgets, copies, control pipe), its own Key Chain file, every wire message
 * stamped net: test - a phone on the live chain refuses it, and the other way round.
 */
let NET = 'live';
/* takeTestMode moved the home itself last run: only then is it its to move back */
let MOVED_HOME = false;
function takeTestMode(argv, io, usage) {
  const control = require('./control');
  const record = require('../../keychain/cli/record');
  const os = require('os');
  const live = path.join(os.homedir(), '.onlykey-js', 'edge');
  const test = path.join(os.homedir(), '.onlykey-js', 'edge-test');
  /*
   * Each run starts live: a run before it in the same process (a test) may
   * have been on the testnet. Only a home THIS function moved goes back - one
   * chosen with --edge-home stays where it was put.
   */
  NET = 'live';
  control.setNet(NET);
  if (MOVED_HOME) { control.setHome(null); MOVED_HOME = false; }
  record.setFile(null);
  /* and no bucket picked yet for the Edge logs: this run's key decides (knowTheBucket) */
  require('./copy').useIdentityBucket(null);
  const a = argv.slice();
  const dd = a.indexOf('--');
  const i = a.indexOf('--test-mode');
  if (i < 0 || (dd >= 0 && i > dd)) {
    /* the testnet's copy driven as the live chain: neither chain would be right */
    if (path.resolve(control.edgeHome()) === test) throw usage(`${test} is the testnet's home - add --test-mode`);
    return a;
  }
  a.splice(i, 1);
  NET = 'test';
  control.setNet(NET);
  /* a home chosen with --edge-home (dev) stays; the default moves to the testnet's */
  if (control.edgeHome() === live) { control.setHome(test); MOVED_HOME = true; }
  record.setFile(record.testFile());
  io.err("edge: TESTNET - the test chain (" + control.edgeHome() + ")");
  return a;
}

module.exports = function register(COMMANDS, h) {
  const dev = DEV;
  COMMANDS.edge = {
    mirrors: '(new)',
    raw: true, /* its own arguments: `exec … -- <command>` must reach it as typed */
    usage: 'setup | budget | continue | end | status | exec | receipt | watch | sync | blocks | agent | control … | --claude-setup | --test-mode … | --test-mode clear',
    summary: 'Edge: an agent uses the key inside a budget you approve (on the phone, or here for a hard key on USB) - budget or no go',
    device: true,
    async run(io, opts, argv) {
      /* the edge-control skill into this workspace (Brad, 2026-10-23: "edge --claude-setup that dumps a skill into the workspace") - no key */
      if (argv[0] === '--claude-setup') {
        if (argv.slice(1).some((a) => a !== '--force')) throw h.usage('edge --claude-setup [--force]');
        return require('./edge-control').claudeSetup({ io, force: argv.includes('--force') });
      }
      const args = takeTestMode(dev && dev.prepare ? dev.prepare(argv) : argv, io, h.usage);
      const [sub, ...rest] = args;
      if (!sub || sub === 'help') {
        for (const l of USAGE) io.out(l);
        return sub ? 0 : 2;
      }
      /* an unknown subcommand is refused here, before anything connects to the phone */
      const KNOWN = ['setup', 'agent', 'budget', 'continue', 'end', 'status', 'exec', 'receipt', 'watch', 'sync', 'blocks', 'clear', 'control', 'loss', 'migrate', 'name', ...Object.keys((dev && dev.commands) || {}), ...(dev && dev.reset ? ['reset'] : [])];
      if (!KNOWN.includes(sub)) throw h.usage(`unknown edge command "${sub}" - ${edgeCmd('help')}`);
      /* a ship's step (its window named for its children): every `edge:` line said here also goes to the window, as said */
      if (sub !== 'control') FEED.teeErr(io);
      /* this process on a ship's timeline (the ship itself, `control`, opens the timeline instead) */
      if (dev && dev.times && sub !== 'control') dev.times.started(`edge ${sub}`);

      /*
       * EDGE SYNC --ALL (Brad, 2026-10-11: "pull from all devices,, (dont update them) then on the
       * host,, after we have both sync state in the host, merging them into the host then we push
       * to both devices at same time"). Every phone paired with this computer: first each one is
       * PULLED into this PC's copies (nothing written to any phone), then each one is PUSHED what
       * it lacks - so every phone is offered every other device's newest log in one run, not after
       * a second round. One phone at a time over Bluetooth (one link is the reliable path); a phone
       * that cannot be reached is reported and the run goes on with the others.
       */
      if (sub === 'sync' && rest.includes('--all')) {
        const phones = require('../../cli/clipair-store').list().map((p) => ({ address: p.address, name: p.name })).filter((p) => p.address);
        if (!phones.length) throw h.usage('no phone is paired with this computer - onlykey-js --ble pair');
        const { spawnSync } = require('child_process');
        const cli = path.join(__dirname, '..', '..', 'cli', 'index.js');
        const one = (address, mode) => {
          const r = spawnSync(process.execPath, [cli, '--ble', '--address', address, 'edge', ...(NET === 'test' ? ['--test-mode'] : []), 'sync', mode], { encoding: 'utf8', timeout: 240000 });
          for (const l of `${r.stdout || ''}${r.stderr || ''}`.split('\n')) if (l.trim() && !/^edge: TESTNET|ble: /.test(l)) io.out(`  ${l}`);
          return r.status === 0;
        };
        let ok = true;
        for (const [mode, label] of [['--pull-only', 'pull'], ['--push-only', 'push']]) {
          for (const p of phones) {
            io.out(`${label} ${p.address}`);
            if (!one(p.address, mode)) { ok = false; io.out(`  ${label} ${p.address}: did not finish`); }
          }
        }
        return ok ? 0 : 1;
      }
      const control = require('./control');

      /*
       * EDGE CONTROL (Brad, 2026-10-23: the workspace's edge skill, "integrate it into the cli",
       * its info "with its other home files"): the batch, the preview, one budget for all of it.
       * It opens no key itself - each step is this CLI run as a child with the same flags.
       */
      if (sub === 'control') {
        return require('./edge-control').run({ io, opts, argv: rest, net: NET, home: control.edgeHome(), dev });
      }
      const wait = opt(rest, '--wait');

      /*
       * CLEAR THE TESTNET on this computer (BLOCKS.md; Brad, 2026-10-07: "test-mode
       * can help separate the storage side too, both phone and cli, so it can be
       * cleared"): its home and its Key Chain file, gone. The testnet's only - the
       * live chain's data is never cleared - and only the default test home, never a
       * folder named with --edge-home.
       */
      /* the clean start on this computer (edge/cli/dev reset; dev builds only - the published package has no such command) */
      if (sub === 'reset' && dev && dev.reset) {
        dev.reset(control.edgeHome(), io.out);
        return 0;
      }

      if (sub === 'clear') {
        if (NET !== 'test') throw h.usage('clear is the testnet\'s only: onlykey-js edge --test-mode clear (the live chain is never cleared)');
        const os = require('os');
        const testHome = path.join(os.homedir(), '.onlykey-js', 'edge-test');
        if (control.edgeHome() !== testHome) throw h.usage(`clear removes only the testnet's own home (${testHome}), not ${control.edgeHome()}`);
        /* its machine files (keys) go with the folder; its data - copies, budgets, pointers, Key Chain list - leaves the bucket */
        /*
         * EVERY TESTNET STORE, the per-identity ones too (edge-test.<identity>.identity / .copies / .budgets …, since
         * B3.0): on key 1, 2026-10-29, clear left the agent identity this computer keeps, so the next ship never had to
         * make one. And the testnet's Edge logs in its identity buckets (buckets/test/*.json, edge-logs-test).
         */
        const b = bucketHome.read();
        const stores = [...new Set([...Object.keys(b.stores || {}).filter((s) => s.startsWith('edge-test.')), 'keychain-test'])];
        const held = stores.filter((s) => Object.values(b.stores[s] || {}).some((r) => r.v !== null));
        if (held.length) bucketHome.clear(bucketHome.at('edge-test.copies').file, held);
        const logs = [];
        const testBuckets = path.join(bucketHome.root(), 'buckets', 'test');
        for (const f of fs.existsSync(testBuckets) ? fs.readdirSync(testBuckets).filter((n) => /^[0-9a-f]{32}\.json$/.test(n)) : []) {
          const file = path.join(testBuckets, f);
          if (Object.values((bucketHome.read(file).stores || {})['edge-logs-test'] || {}).some((r) => r.v !== null)) {
            bucketHome.clear(file, ['edge-logs-test']);
            logs.push(`edge-logs-test in buckets/test/${f.slice(0, 8)}…`);
          }
        }
        const gone = fs.existsSync(testHome) ? [testHome] : [];
        for (const p of gone) fs.rmSync(p, { recursive: true, force: true });
        const what = [...gone, ...held.map((s) => `bucket ${s}`), ...logs];
        io.out(what.length ? `testnet cleared on this computer: ${what.join(', ')}` : 'nothing to clear: no testnet data on this computer');
        return 0;
      }

      /* BLOCKS (BLOCKS.md, Brad 2026-10-07): this PC's copy cut at the key's seals into JSON blocks - local, no phone */
      /*
       * EDGE LOSS (R24) for a hard key: links gone from the key's ring before this computer read them
       * are accepted as lost - the key links a LOSS (op 11) for #from..#to with a PHYSICAL press, and a
       * copy then passes R27 with that gap. Key 1, 2026-10-23: #387-#389 rolled out of the ring
       * unread, and every budget after was refused "copy does not verify". The person says yes here,
       * then presses. Over Bluetooth the phone has its own Accept loss.
       */
      /*
       * EDGE MIGRATE (B3.0): the records from before identities, copied into THIS key's identity home -
       * only what is provably this key's (migrate-identity.js); --dry-run says what it would copy and
       * writes nothing. The net's old stores are left as they were.
       */
      /*
       * EDGE NAME ("my device name", Brad 2026-10-24): this device's nametag in its identity - shown, or
       * set / changed through the key's signed statement (nametag.js: a read, no press). The desktop
       * app's Edge Management calls the same function.
       */
      if (sub === 'name') {
        const nametag = rest.join(' ').trim();
        const d = await openDevice(io, opts, h, { dev, wait });
        try {
          const names = require('./nametag');
          const { toHex } = require('../../src/bytes');
          const deviceIdHex = toHex((await d.edge.publicKey()).deviceId);
          if (!nametag) {
            const n = names.getName(d.home, deviceIdHex);
            io.out(n ? `this device: "${n.nametag}" (set ${new Date(n.at).toLocaleString()})` : `this device has no name yet - ${edgeCmd('name "<a name>"')}`);
            for (const o of names.listNames(d.home).filter((x) => x.deviceId !== deviceIdHex)) io.out(`  another device of this identity: ${o.deviceId.slice(0, 16)} "${o.nametag}"`);
            return 0;
          }
          const r = await names.setName({ edge: d.edge, home: d.home, nametag });
          io.out(`this device is "${r.nametag}" (device ${r.deviceId.slice(0, 16)}, identity ${path.basename(d.home).slice(0, 12)}…)`);
          io.out(r.log && r.log.kept ? 'its log goes to your other devices the next time they connect' : `its log is not shared yet:${(r.log && r.log.why) || 'unknown'}`);
          return 0;
        } finally {
          await Promise.resolve(d.app.destroy()).catch(() => undefined);
        }
      }

      if (sub === 'migrate') {
        const dry = rest.includes('--dry-run');
        if (rest.some((a) => a !== '--dry-run')) throw h.usage(edgeCmd('migrate [--dry-run]'));
        const d = await openDevice(io, opts, h, { dev, wait, migrating: true });
        try {
          const { toHex } = require('../../src/bytes');
          const { agentPublicKey } = require('./agent');
          const deviceIdHex = toHex((await d.edge.publicKey()).deviceId);
          const r = await require('./migrate-identity').migrateToIdentity({
            netHome: control.edgeHome(), idHome: d.home, deviceIdHex,
            signPublicOf: async (gpgUid) => toHex(await agentPublicKey(d.okcrypto, { gpg: gpgUid })),
            dryRun: dry,
          });
          io.out(`identity ${path.basename(d.home)}, device ${deviceIdHex.slice(0, 16)}${NET === 'test' ? ' (testnet)' : ''}`);
          if (r.already) { io.out('already migrated - nothing to do'); return 0; }
          io.out(`${dry ? 'would copy' : 'copied'}: the agent identity record: ${r.identity ? 'yes' : 'no'} · this device's chain copy: ${r.copy ? 'yes' : 'no'} · budgets: ${r.budgets.length ? r.budgets.join(', ') : 'none'} · pointer: ${r.pointers ? 'yes' : 'no'}`);
          for (const s of r.skipped) io.out(`left where it is: ${s}`);
          io.out(dry ? 'nothing written (--dry-run)' : 'done - the records from before identities are left as they were');
          return 0;
        } finally {
          await Promise.resolve(d.app.destroy()).catch(() => undefined);
        }
      }

      if (sub === 'loss') {
        if (opts.ble) throw h.usage('over Bluetooth a loss is accepted on the phone (its Edge tab: Accept loss)');
        const nums = rest.filter((x) => /^\d+$/.test(x)).map(Number);
        if (nums.length > 2 || rest.length !== nums.length) throw h.usage(edgeCmd('loss [<from> [<to>]]'));
        const d = await openDevice(io, opts, h, { dev, wait });
        try {
          /*
           * NO NUMBERS: the range the copy check itself finds missing - the only range a person should be
           * offered (spec APP.md), as the phone offers it. A guessed range came up short on key 1: #387-
           * #389 accepted, the check still missing #387-#390 (#390 could not be welded or vouched for).
           */
          let from;
          let to;
          if (nums.length) {
            [from, to = nums[0]] = nums;
          } else {
            const st = await require('./copy').sync(d.edge, d.home, { status: true });
            const gaps = (st.verdict && st.verdict.gaps) || [];
            if (st.verdict.kind !== 'gap' || !gaps.length) { io.out(`nothing to accept: this computer's copy is ${st.verdict.kind}`); return 0; }
            from = Math.min(...gaps.map((g) => g.from));
            to = Math.max(...gaps.map((g) => g.to));
            io.out(`the copy check finds missing: ${gaps.map((g) => `#${g.from}-#${g.to}`).join(', ')}`);
          }
          if (to < from) throw h.usage(`a loss is #from..#to with from <= to, not ${from}..${to}`);
          const head = await d.edge.head();
          if (head.seq === null || to > head.seq) throw h.usage(`the key's head is #${head.seq}: a loss cannot reach past it`);
          io.out(`#${from}-#${to} would be accepted as LOST: the key links a LOSS for them (it pays no debt, it is on the chain for good),`);
          io.out('and this computer\'s copy then verifies past the gap. Only for links that are gone - from the key\'s ring and from every copy.');
          const yes = await personConfirm(opts)(`accept #${from}-#${to} as lost? [y/N] `, { details: `#${from}-#${to} would be accepted as LOST: the key links a LOSS for them, for good.`, title: 'OnlyKey Edge: accept a loss' });
          if (!yes) { io.out('nothing written'); return 1; }
          const r = await d.edge.loss({ from, to, onPress: () => d.say('PRESS the key now - the loss is linked with the press') });
          io.out(`loss linked at #${r.seq}`);
          const s = await require('./copy').sync(d.edge, d.home);
          io.out(`this computer's copy: ${s.verdict.kind}`);
          return 0;
        } finally {
          await Promise.resolve(d.app.destroy()).catch(() => undefined);
        }
      }

      if (sub === 'blocks') {
        const found = require('./copy').blocks(control.edgeHome(), { net: NET });
        if (rest.includes('--json')) {
          io.out(JSON.stringify(found.flatMap((d) => d.blocks.map((b) => b.block)), null, 2));
          return found.every((d) => d.blocks.every((b) => b.ok)) ? 0 : 1;
        }
        if (!found.length) io.out(`no copy yet - ${edgeCmd('sync')}`);
        for (const d of found) {
          io.out(h.row(`key ${d.deviceId.slice(0, 16)}`, `${d.blocks.length} block(s), ${d.open} link(s) after the last seal${d.reason ? ` - ${d.reason}` : ''}`));
          for (const b of d.blocks) {
            const L = b.block.links;
            io.out(h.row(`  #${b.block.start.seq}-#${b.block.checkpoint.seq}`, `${b.id.slice(0, 16)}  ${L.length} link(s)  ${b.ok ? 'verified' : `does not verify: ${b.reason}`}`));
          }
        }
        return found.every((d) => d.blocks.every((b) => b.ok)) ? 0 : 1;
      }

      if (sub === 'setup') {
        /*
         * THE AGENT IDENTITY, SET FROM A COMPUTER AND KEPT BY THE PHONE (SPEC H7; Brad,
         * 2026-10-20: "computer sets, phone keeps"). The certificate is made HERE - the key
         * signs it, two presses - and sent with the labels; the phone shows it on its Edge
         * sheet and keeps it only when the person approves. Flags not given keep the
         * phone's current values; a certificate is remade only when the gpg user ID, the
         * lifetime or --created changes it.
         */
        /* no labels named: a first identity takes the defaults (defaultIdentity), an existing one stays as it is */
        const given = parseSetup(rest, h);
        const d = await openDevice(io, opts, h, { dev, wait });
        try {
          const { record, host, changed } = await setUpIdentity(io, d, h, given, { wait });
          if (!changed) { io.out(`${host} already keeps this identity - nothing to change`); recordCert(io, record, 'onlykey-js edge setup'); }
          for (const [k, v] of require('../src/identity').rows(record)) io.out(h.row(k, v));
          return 0;
        } finally {
          await d.app.destroy().catch(() => undefined);
        }
      }

      if (sub === 'agent') {
        /*
         * THE SERVER IT JOINS (Brad, 2026-10-27: --service joins the key's server): --server <url>, else the key's own
         * site (ctap_bridge, okcrypto.keySite) - the same server the apps use; --no-server keeps it off the network.
         */
        let serverOpt = null;
        let noServer = false;
        let noSync = false;
        {
          const i = rest.indexOf('--server');
          if (i >= 0) { serverOpt = rest[i + 1]; rest.splice(i, 2); if (!serverOpt || serverOpt.startsWith('--')) throw h.usage('edge agent --server <url>'); }
          const j = rest.indexOf('--no-server');
          if (j >= 0) { noServer = true; rest.splice(j, 1); }
          /* --no-sync: the key and the budget only - no bucket trades (a ship's own service: edge-control.js shipService) */
          const k = rest.indexOf('--no-sync');
          if (k >= 0) { noSync = true; rest.splice(k, 1); }
        }
        /* the optional service: one link kept open between commands; nothing it can do that a command can't */
        if (Object.keys(parseSetup(rest, h)).length) throw h.usage(`the identity is set with ${edgeCmd('setup')} (the phone keeps it); edge agent takes no identity flags`);
        /*
         * ONE SERVICE, THE SYNC EVEN WITHOUT AN AGENT: a key with no agent identity yet (a fresh soft key, the desktop
         * app's) cannot run the Edge agent, but its bucket still syncs - the device is opened for the sync alone, and
         * the reason the agent is not here is said.
         */
        let st;
        let agentOff = null;
        try {
          st = await openStack(io, opts, h, { serve: true, dev, wait });
        } catch (e) {
          if (e.code !== 'ENOAGENTID') throw e;
          agentOff = e.message;
          /*
           * the stack's own connection was just closed (openStack's catch), but through the desktop app its close can
           * reach the app after this new hello - which the app then refuses "busy" (the Windows desktop, 2026-10-25):
           * a few tries, a moment apart
           */
          const openOnce = async () => {
            for (let n = 0; ; n++) {
              try {
                return await openDevice(io, opts, h, { dev, wait });
              } catch (e2) {
                if (n >= 4 || !/busy/.test(String(e2 && e2.message))) throw e2;
                await new Promise((r) => setTimeout(r, 700));
              }
            }
          };
          if (opts.ble) {
            /* over Bluetooth the phone is the device AND the channel the trades go over: kept open */
            const d = await openOnce();
            st = { ...d, close: () => Promise.resolve(d.app.destroy()).catch(() => undefined) };
          } else {
            /*
             * NOTHING HELD BETWEEN TRADES (the Windows desktop, 2026-10-25): through the desktop app one CLI at a time,
             * and a service holding the key refused every other onlykey-js "busy" - a ship included. The sync needs the
             * key only to make this computer's bucket key, once (bucket/cli/trade.js takes a function for it): the key is
             * opened then, and let go.
             */
            const d = await openOnce();
            const say = d.say;
            await Promise.resolve(d.app.destroy()).catch(() => undefined);
            const okcryptoBriefly = async () => {
              const k = await openOnce();
              return { okcrypto: k.okcrypto, close: () => Promise.resolve(k.app.destroy()).catch(() => undefined) };
            };
            st = { say, okcrypto: okcryptoBriefly, transport: {}, channel: null, home: d.home, close: async () => {} };
          }
        }
        try {
          const { svc, transport } = st;
          if (agentOff) {
            io.out(`no Edge agent here: ${agentOff}`);
            io.out('ready - the sync service runs; Ctrl-C to stop');
          } else {
            io.out(h.row('ssh key', svc.sshLine));
            if (svc.fingerprint) io.out(h.row('gpg key', svc.fingerprint));
            if (svc.certArmored) {
              /* a key this computer has not kept anything for yet has no identity home until now (the box's testnet, 2026-10-25) */
              fs.mkdirSync(st.home, { recursive: true, mode: 0o700 });
              fs.writeFileSync(path.join(st.home, 'agent-gpg.asc'), svc.certArmored);
              io.out(h.row('gpg cert', path.join(st.home, 'agent-gpg.asc')));
            }
            io.out(h.row('control', svc.controlPath));
            io.out(`ready - ${edgeCmd('budget / exec / receipt')} use this service; Ctrl-C to stop`);
          }
          /*
           * AND THE SYNC SERVICE (bucket/cli/service.js; Brad, 2026-10-25: "--service will be our long-lived"; "the
           * service can do bluetooth stuff"): this computer's kept buckets watched, and traded with the paired phone this
           * service reaches - when they change (the desktop app writes the same files), on a slow timer, and once now.
           */
          /*
           * WHATEVER KEY THIS SERVICE USES (Brad, 2026-10-25: "cli without desktop == --service, and --soft-key also runs
           * the service while it's alive"): over Bluetooth the phone is this service's own device and its channel carries
           * the trade; with a key on USB, the soft key or the desktop app, the sync service opens its own Bluetooth link to
           * each phone this computer is cli-paired with, for trade messages only. The key is asked for the bucket key once
           * (bucket/cli/trade.js makeMe, the same backup's key); later trades use the remembered identity and need none.
           */
          const pairStore = require('../../cli/clipair-store');
          /* the phones switched on (the Sync tab's Paired devices toggle; off: left alone) */
          const pairedPhones = () => pairStore.list().filter((p) => p.address && !p.off);
          const links = new Map();
          const linkTo = async (address) => {
            if (links.has(address)) return links.get(address);
            const { wire } = require('../src');
            const a = await io.start({ ble: true, address });
            const tr = a.services.transport;
            const l = { app: a, transport: tr, used: Date.now(), channel: wire.createWireChannel(tr, { timeoutMs: 60000, device: () => (typeof tr.deviceId === 'function' ? tr.deviceId() : null), log: st.say, net: NET }) };
            links.set(address, l);
            return l;
          };
          const bucketSvc = !noSync && (opts.ble || pairedPhones().length || !noServer) ? (() => {
            const { tradeWith, tradeTimeoutMs } = require('../../bucket/cli/trade');
            const bucketHome = require('../../bucket/cli/home');
            const bucketDir = path.join(bucketHome.root(), 'buckets', NET === 'test' ? 'test' : 'live');
            const tradeOver = (channel) => {
              let round = 0;
              const send = (m) => channel.send(m, { timeoutMs: tradeTimeoutMs(m, round++ === 0) }).catch((e) => { st.say(`sync: the phone gave no answer to ${m.type} (${e.message})`); return null; });
              return tradeWith({ send, okcrypto: st.okcrypto, net: NET, say: st.say });
            };
            const n = (o) => Object.values(o || {}).reduce((x, y) => x + y, 0);
            /*
             * THE KEY'S SERVER ROOM (Brad, 2026-10-27: "--service" joins the key's server): this identity's room on the
             * server the key names (its ctap_bridge site; --server for another, --no-server for none), held open while
             * the service runs - the web app and the phones meet this computer there with no Bluetooth. Joined with the
             * key's proof (room.js); every device of the identity online is traded with, as the paired phones are, and a
             * device that comes online starts a trade at once. Lost: joined again at the next trade (the slow timer).
             * This side starts the trades; a trade another device starts is not answered yet (room.serve unset).
             */
            let roomP = null;
            const roomOpen = () => {
              if (noServer) return Promise.resolve(null);
              if (!roomP) {
                roomP = (async () => {
                  let url = serverOpt;
                  if (!url) {
                    const r = typeof st.okcrypto.keySite === 'function' ? await st.okcrypto.keySite().catch(() => null) : null;
                    url = r && r.on && r.site ? `https://${r.site}` : null;
                  }
                  if (!url) return null;
                  if (typeof globalThis.WebSocket !== 'function') throw new Error('this Node has no WebSocket - Node 22 or later');
                  const host = new URL(url).host;
                  const { meFor } = require('../../bucket/cli/trade');
                  const { connectRoom } = require('../../bucket/src/room-client');
                  const me = await meFor({ okcrypto: st.okcrypto, net: NET, say: st.say });
                  const randomBytes = (k) => new Uint8Array(require('crypto').randomBytes(k));
                  const room = await connectRoom({ url, me, device: bucketHome.thisDevice(), WebSocket: globalThis.WebSocket, randomBytes });
                  room.on('peer', (e) => { if (e.up) void svcBucket.trade(`${e.up.name} came online on ${host}`); });
                  room.on('close', () => { roomP = null; st.say(`sync: left the room on ${host} (joined again at the next trade)`); });
                  st.say(`sync: in this identity's room on ${host}${room.peers().length ? ` - ${room.peers().map((p) => p.name).join(', ')} online` : ''}`);
                  return { room, host, id: me.id };
                })().catch((e) => { roomP = null; st.say(`sync: the server's room was not joined (${e.message})`); return null; });
              }
              return roomP;
            };
            /* each device online in the room, one after another - the room's request is the trade's send */
            const tradeRoom = async () => {
              const r = await roomOpen();
              if (!r) return [];
              const out = [];
              for (const p of r.room.peers()) {
                let first = true;
                const send = (m) => { const t = tradeTimeoutMs(m, first); first = false; return r.room.request(p.id, m, { timeoutMs: t }); };
                try {
                  out.push({ name: `${p.name} on ${r.host}`, ...(await tradeWith({ send, okcrypto: st.okcrypto, net: NET, say: st.say, id: r.id })) });
                } catch (e) {
                  out.push({ name: `${p.name} on ${r.host}`, traded: false, why: e.message });
                }
              }
              return out;
            };
            const svcBucket = require('../../bucket/cli/service').startBucketService({
              dir: bucketDir,
              say: st.say,
              lockFile: path.join(bucketHome.root(), 'sync.json'),
              who: process.env.OKEDGE_SYNC_WHO || `onlykey-js --service (pid ${process.pid})`,
              tradeOnce: async () => {
                /* the phone this service runs over (--ble), or each paired phone in turn over its own link; then the room */
                const results = [];
                if (opts.ble) results.push({ name: 'the phone', ...(await tradeOver(st.channel)) });
                for (const p of opts.ble ? [] : pairedPhones()) {
                  const name = p.phoneName || p.address;
                  try {
                    const l = await linkTo(p.address);
                    /*
                     * IN USE FOR THE WHOLE TRADE (Windows desktop + A13, 2026-10-25: the first trade makes this computer's
                     * bucket key - two presses - and with the idle clock started only before it, the link was let go
                     * between HAVE and its answer; the phone answered into a closed link, "took 0, gave 0 - NOT settled").
                     * The idle clock starts again when the trade ends.
                     */
                    l.trading = true;
                    let r;
                    try { r = await tradeOver(l.channel); } finally { l.trading = false; l.used = Date.now(); }
                    if (r.traded) pairStore.markUsed(p.address);
                    results.push({ name, ...r });
                  } catch (e) {
                    results.push({ name, traded: false, why: e.message });
                  }
                }
                results.push(...(await tradeRoom()));
                if (!results.length) return { traded: false, why: noServer ? 'no phone is cli-paired with this computer' : 'no phone is cli-paired with this computer, and no other device of this identity is in the server room' };
                const ok = results.filter((r) => r.traded);
                if (!ok.length) return { traded: false, why: results.map((r) => `${r.name}: ${r.why}`).join('; ') };
                return {
                  traded: true,
                  same: ok.every((r) => r.same),
                  settled: ok.every((r) => r.settled !== false),
                  taken: { all: ok.reduce((x, r) => x + n(r.taken), 0) },
                  gave: { all: ok.reduce((x, r) => x + n(r.gave), 0) },
                };
              },
            });
            void svcBucket.trade('the service started');
            return svcBucket;
          })() : null;
          /* its own links let go when idle (60 s, as the --ble link below); the 30 s check usually keeps them up */
          const linkTick = setInterval(() => {
            for (const l of links.values()) {
              if (!l.trading && Date.now() - l.used >= 60000 && typeof l.transport.isOpen === 'function' && l.transport.isOpen()) void l.transport.release('idle').catch(() => {});
            }
          }, 5000);
          if (linkTick.unref) linkTick.unref();

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
          /*
           * STOP, ASKED OVER THE CONTROL SOCKET (owner-only, as every request): the same close as Ctrl-C - the copy brought
           * to the key's head, the key let go. Windows has no signal another process can send that Node catches, so a
           * ship that started this service ends it this way (edge-control.js shipService).
           */
          let stopAsked = null;
          if (st.svc && st.svc.handlers) st.svc.handlers.stop = async () => { setTimeout(() => stopAsked && stopAsked(), 50); return { stopping: true }; };
          await Promise.race([new Promise((resolve) => { stopAsked = resolve; }), io.untilStopped ? io.untilStopped() : new Promise((resolve) => {
            process.once('SIGINT', resolve);
            process.once('SIGTERM', resolve);
          })]);
          if (idleTick) clearInterval(idleTick);
          clearInterval(linkTick);
          if (bucketSvc) bucketSvc.stop();
          for (const l of links.values()) await Promise.resolve(l.app.destroy()).catch(() => undefined);
          return 0;
        } finally {
          await st.close();
        }
      }

      const commands = require('./commands');
      const outs = { out: io.out, err: io.err, dev };
      /* the service, if Brad started one (CLI.md §4: for speed only) */
      if (await serviceUp(control.controlPath())) return commands.main(args, { ...outs, ask: control.ask, waiting: waitingLine(opts, h) });
      /* no service (the default): this one command, in-process - connect, run, disconnect.
       * The phone is opened on the command's first request, not before: a usage error
       * (exec without --head) answers at once instead of after a Bluetooth connect. */
      let st = null;
      try {
        const ask = async (op, fields = {}, o = {}) => {
          /* a budget's own steps leave the swap to its end; sync is the swap */
          if (!st) st = await openStack(io, opts, h, { serve: false, dev, wait, share: !['exec', 'receipt', 'sync'].includes(sub) });
          const fn = st.svc.handlers[op];
          if (!fn) throw new Error(`no such request: ${op}`);
          if (o.onSent) o.onSent();
          return { ok: true, ...(await fn(fields)) };
        };
        return await commands.main(args, { ...outs, ask, waiting: waitingLine(opts, h) });
      } finally {
        if (st) await st.close();
      }
    },
  };
};

module.exports.USAGE = USAGE;
/* the PC store's two files, for tests (version 1 since the clean start) */
module.exports.pointerKv = pointerKv;
module.exports.parseSetup = parseSetup;
module.exports.setUpIdentity = setUpIdentity;
module.exports.defaultIdentity = defaultIdentity;
module.exports.budgetStore = budgetStore;
