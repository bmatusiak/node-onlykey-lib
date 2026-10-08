'use strict';

/**
 * edge/cli/agent.js - the agent service (Edge Phase 2; onlykey-edge
 * build/mcp-service.md §4.2 / §4.2a, decided 2026-10-03; PROPOSAL-edge-agent.md).
 *
 * WHAT IT IS FOR. git calls an ssh-agent and a gpg program; neither protocol
 * can carry "this signature is for this reason, after this head". So the
 * agent service holds the session's work budget, and `onlykey-js edge exec` tells it
 * what the NEXT signature is for - then runs the real command unchanged.
 *
 * THE ONE RULE THAT MAKES IT SAFE (the spec session's fix): each exec gets its
 * OWN endpoint - a fresh owner-only SSH_AUTH_SOCK and a one-time gpg-shim
 * token - closed when the command exits (cap 10 min). The budget pays only
 * for a sign that arrives on THAT endpoint, once. The shared ssh-agent
 * endpoint never pays: a sign there is always a press. So another process
 * signing while an exec runs cannot spend the exec's use - it is not on the
 * exec's endpoint, and does not know its token.
 *
 * And for ssh, the budget pays only when the connection is bound
 * (session-bind@openssh.com, verified) to a PINNED host - github.com by
 * default - and the request is for that bound session (cli/ssh-session-bind.js).
 *
 * This file is the logic, with the device and the budget handed in, so it is
 * testable on the fake key; cli/index.js composes it over a real transport.
 * Node only (sockets, pipes).
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const agentSrv = require('../../cli/ssh-agent');
const bindLib = require('../../cli/ssh-session-bind');
const agentProto = require('../../src/protocol/agent');
const { chain, tickets, codes } = require('../src');

const EXEC_CAP_MS = 10 * 60 * 1000;

const fail = (code, message) => Object.assign(new Error(message), { code });

/*
 * A one-shot endpoint's path: POSIX a socket in a fresh 0700 directory (the
 * socket itself 0600, set by serveAgent); Windows a named pipe whose name has
 * 128 random bits. Node cannot set a pipe's security descriptor; Windows'
 * default gives write only to the creator, SYSTEM and Administrators (read to
 * Everyone, which cannot send a request), and the unguessable name keeps
 * other processes of the same user from finding it.
 */
function oneShotPath({ windows = agentSrv.IS_WINDOWS } = {}) {
  const tag = crypto.randomBytes(16).toString('hex');
  if (windows) return { path: `\\\\.\\pipe\\okedge-exec-${tag}`, cleanup: () => {} };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-exec-'));
  fs.chmodSync(dir, 0o700);
  const sock = path.join(dir, 'agent.sock');
  return {
    path: sock,
    cleanup: () => {
      try { fs.unlinkSync(sock); } catch { /* gone */ }
      try { fs.rmdirSync(dir); } catch { /* gone */ }
    },
  };
}

/**
 * @param {object} o
 * @param {{publicKey: (identity) => Promise<Uint8Array>, sign: (identity, message: Uint8Array) => Promise<Uint8Array>}} o.device
 *   the device's derived-key calls (okcrypto.agent with this service's keyType/version)
 * @param {{identity: object, name: string, comment: string, curve: 'ed25519', raw: Uint8Array}} o.ssh
 *   the agent's OWN ssh identity (D2): `identity` the derivation identity,
 *   `name` its R11a scope name ("ssh://claude@nitro16")
 * @param {string[]} [o.pins] host key fingerprints the budget may pay for (default github.com's)
 * @param {(line: string) => void} [o.log]
 */
function createEdgeAgent({ device, ssh, pins = bindLib.GITHUB_FINGERPRINTS, log = () => {}, endpointPath = oneShotPath, edge = null, onGone = null, client = null }) {
  /* budgets an automatic continue was already asked for - once each, never a loop */
  const continued = new Set();
  /* the key's ring: its recent links, oldest first (R5) */
  const ring = async (h) => (h.seq === null || h.oldest === null ? [] : edge.pickup(h.oldest, h.seq - h.oldest + 1));
  /*
   * R16: what the KEY says is owed. HEAD gives the count; the seqs come from
   * replaying the ring - an owed use is older than its ticket, so every owed use
   * still in the ring is found; the rest are older than the ring.
   */
  const keyOwed = async (h, rows = null) => {
    if (!h.owed && !h.overflow) return { seqs: [], older: 0 };
    const seqs = tickets.keyDebts(rows || await ring(h)).owed;
    return { seqs, older: Math.max(0, h.owed - seqs.length) + (h.overflow ? 1 : 0) };
  };
  /* edge watch: what this agent knows about a link (reason, ticket), and its own events - kept short */
  const notes = new Map();
  const note = (seq, add) => {
    notes.set(seq, { ...(notes.get(seq) || {}), ...add });
    while (notes.size > 256) notes.delete(notes.keys().next().value);
  };
  const events = [];
  let eventN = 0;
  const event = (kind, message) => {
    events.push({ n: ++eventN, at: new Date().toISOString(), kind, message });
    while (events.length > 64) events.shift();
  };
  const owedText = (k) => [k.seqs.length ? `tickets for #${k.seqs.join(', #')}` : '', k.older ? `${k.older} older than the key's ring (waive on the phone)` : ''].filter(Boolean).join(' and ');
  let budget = null;          /* the work budget (edge/src/client.js budget), once asked for or resumed */
  const execs = new Map();    /* token -> the open exec */

  /*
   * BUDGET OR NO GO, EVERYWHERE (CLI.md §3-4, Brad 2026-10-06): Edge has no shared
   * endpoint and nothing that forwards a sign for a press. A sign it cannot pay
   * (an exec's second use, a host not pinned, a gpg sign outside an exec) is
   * refused. A pressed sign is the ordinary `onlykey-js agent` / `gpg-agent`.
   */
  const refuse = (why) => {
    log(`refused (budget or no go): ${why}`);
    event('refused', why);
    throw fail('EEDGE_BUDGET_ONLY', `Edge signs only when a budget pays - ${why}`);
  };

  /*
   * One paid use: TX start over the budget's head and exactly the bytes the
   * firmware will be given (message || identity hash - okcrypto.agent.sign's
   * payload, R13a), the sign, the link read back and checked (client.js).
   */
  async function paid(exec, identity, message, what) {
    exec.used = true;
    const bytes = new Uint8Array([...message, ...agentProto.identityHash(identity)]);
    let used;
    try {
      used = await budget.use(bytes, () => device.sign(identity, message), { reason: exec.reason });
    } catch (e) {
      /*
       * THE KEY SIGNED, THE ANSWER DID NOT COME BACK (the A13, 2026-10-07: a push's
       * use #738 was spent and owed, exec said "nothing under the budget", and no
       * ticket was filed). An exec opens only when the key owes nothing, so what it
       * owes now is this exec's: kept as its link, marked failed, for the ticket.
       */
      if (edge) {
        const k = await keyOwed(await edge.head()).catch(() => ({ seqs: [] }));
        for (const seq of k.seqs) {
          if (!exec.links.some((l) => l.seq === seq)) exec.links.push({ seq, paid: true, what, failed: String(e && e.message || e) });
        }
      }
      throw e;
    }
    const { result, link } = used;
    exec.links.push({ ...link, what });
    note(link.seq, { reason: exec.reason, what });
    log(`signed: link #${link.seq} (${what})${link.paid ? '' : ' - NOT paid by the budget'} - ticket owed for #${link.seq}`);
    return result;
  }

  /**
   * Open an exec: `head` must be the budget's head (the agent saw its last
   * ticket's reply), then a fresh endpoint and token for this one command.
   * -> {sshPath, token, close}
   */
  async function openExec(o) {
    try {
      return await openExecChecked(o);
    } catch (e) {
      event('refused', `exec "${o && o.reason}" refused: ${e.message}`);
      throw e;
    }
  }
  async function openExecChecked({ head, reason, capMs = EXEC_CAP_MS }) {
    if (typeof reason !== 'string' || !reason.trim()) throw fail('EEDGE_REASON', 'an exec needs a reason');
    if (!budget) throw fail('EEDGE_NO_BUDGET', 'no work budget - ask for one first (onlykey-js edge budget)');
    /*
     * Refused BEFORE the command runs (daily-loop §3, must fail safely): a
     * ticket still owed (R18 - the key would refuse the TX start anyway, mid-git),
     * the budget held or gone on the key (Hold from the phone), a stale head.
     */
    const owed = budget.pending();
    if (owed.length) throw fail('EEDGE_TICKET_OWED', `ticket owed for #${owed.join(', #')} - onlykey-js edge ticket first`);
    if (edge) {
      const h = await edge.head();
      const k = await keyOwed(h);
      if (k.seqs.length || k.older) throw fail('EEDGE_KEY_OWED', `the key owes ${owedText(k)} - onlykey-js edge ticket them first`);
      if (!h.live.includes(budget.grantId) && onGone && !continued.has(budget.grantId)) {
        /*
         * The budget is gone - the soft key's idle restart, a lock (spec session,
         * 2026-10-03). Ask the phone ONCE to continue it (your Yes and a press);
         * the exec is not run: its --head belongs to the old budget. No retry.
         */
        const old = budget;
        continued.add(old.grantId);
        log(`budget ${old.grantId} is gone - asking the phone to continue it`);
        const nb = await onGone(old);
        if (nb) {
          budget = nb;
          event('continue', `budget ${old.grantId} was gone; continued as budget ${nb.grantId}`);
          throw fail('EEDGE_CONTINUED', `budget ${old.grantId} ended (the key locked or restarted); continued as budget ${nb.grantId} with your Yes and press - head = ${nb.head()} - run the exec again with that head`);
        }
      }
      if (!h.live.includes(budget.grantId)) throw fail('EEDGE_GONE', `budget ${budget.grantId} is not live on the key (ended, expired, or the key locked) - ask for a new one`);
      if ((h.held || []).includes(budget.grantId)) throw fail('EEDGE_HELD', `budget ${budget.grantId} is on hold (from the phone) - Resume there first`);
    }
    if (String(head || '').toLowerCase() !== budget.head()) {
      throw fail('EEDGE_STALE_HEAD', `--head is not the budget's head (${budget.head().slice(0, 16)}…): file the last ticket and use the head it printed`);
    }
    return openEndpoint({ reason, capMs });
  }

  /* the exec's own endpoints (one ssh socket/pipe, one gpg token) */
  async function openEndpoint({ reason, capMs }) {
    const exec = { token: crypto.randomBytes(32).toString('hex'), reason, used: false, closed: false, links: [] };
    const handler = agentSrv.createAgentHandler({
      keys: [{ curve: ssh.curve, raw: ssh.raw, comment: ssh.comment }],
      sessionBind: true,
      log,
      sign: async (key, data, conn) => {
        if (exec.closed || exec.used) return refuse('this exec has used its one paid sign (or closed)');
        const ok = bindLib.boundToPinned(conn && conn.bind, data, pins);
        if (!ok.ok) return refuse(`a budget pays only for a pinned host: ${ok.reason}`);
        return paid(exec, ssh.identity, data, `ssh ${ok.host}`);
      },
    });
    const served = await agentSrv.serveAgent({ handler, where: endpointPath(), log });
    exec.close = async () => {
      if (exec.closed) return exec.links;
      exec.closed = true;
      clearTimeout(exec.timer);
      execs.delete(exec.token);
      await served.close();
      return exec.links;
    };
    exec.timer = setTimeout(() => { log(`exec "${reason}" hit its ${capMs / 60000} min cap - closed`); exec.close(); }, capMs);
    if (exec.timer.unref) exec.timer.unref();
    execs.set(exec.token, exec);
    return { sshPath: served.path, token: exec.token, close: exec.close };
  }

  /**
   * The gpg shim's sign, by token: the open exec's one paid use, else refused.
   * `identity` the agent's gpg derivation identity, `digest` what the device signs.
   */
  async function shimSign(token, identity, digest) {
    const exec = token ? execs.get(token) : null;
    if (!exec || exec.closed || exec.used || !budget) return refuse('a gpg sign outside an open exec (or its one use is spent)');
    return paid(exec, identity, digest, 'gpg');
  }

  return {
    openExec,
    shimSign,
    setBudget(b) { budget = b; },
    execByToken: (token) => execs.get(token) || null,
    budget: () => budget,
    async ticket(seq, { code = 'OK', message }) {
      if (budget) {
        await budget.ticket({ seq }, { code, message });
        note(seq, { ticket: { code, message } });
        return budget.head();
      }
      /*
       * No budget in this process (it restarted, or the budget ended) but the key
       * still owes a ticket for this use: file it straight to the key - the key
       * only checks the seq is owed (R16). Spec rule 10 (2026-10-04): an owed
       * ticket is filed, never waived by a script.
       */
      if (!edge && !client) throw fail('EEDGE_NO_BUDGET', 'no work budget');
      /* through the client when there is one: it also sends the message to the phone (a pressed use's ticket showed "No message synced", Pixel #432) */
      const r = client ? await client.ticketOwed(seq, { code, message }) : await edge.ticket(seq, codes.ticketByte(code), tickets.messageHash(message));
      note(seq, { ticket: { code, message } });
      /* hex like budget.head(): raw bytes reach the CLI as an object ("head = [object Object]") */
      return Buffer.from(r.head).toString('hex');
    },
    /*
     * edge watch's feed (mcp-service.md: "the same live feed in a terminal",
     * okrn-edge-tab.md B7) - READ-ONLY: the key's links from `from` on, each with
     * what this agent knows about it (the exec's reason, the ticket's message -
     * the agent's own claims, shown as such), the links that fell out of the
     * key's ring before they were read, and this agent's events (refusals,
     * presses) since `since`.
     */
    async feed({ from = null, since = 0 } = {}) {
      const out = { seq: null, links: [], missed: 0, events: events.filter((e) => e.n > since), budget: null };
      if (budget) out.budget = { id: budget.grantId, uses: budget.uses, head: budget.head() };
      if (!edge) return out;
      const h = await edge.head();
      out.seq = h.seq;
      if (h.seq === null) return out;
      /* null: just the newest; below 0: everything the key's ring still holds (edge watch starts there) */
      const first = from === null ? h.seq : from < 0 ? (h.oldest === null ? h.seq : h.oldest) : from;
      const start = Math.max(first, h.oldest === null ? first : h.oldest);
      out.missed = Math.max(0, start - first);
      if (start <= h.seq) {
        for (const row of await edge.pickup(start, h.seq - start + 1)) {
          const f = chain.decodeLink(row.link);
          out.links.push({ seq: f.seq, op: f.op, decision: f.decision, slot: f.slot, flags: f.flags, grantId: f.grantId, grantStep: f.grantStep, code: f.code, refSeq: f.refSeq,
            /* R13b: the intent welded into the link (hex), and the format version (R3) */
            intent: f.intent ? Buffer.from(f.intent).toString('hex') : null, version: f.version,
            /* a ticket's message was noted on the use it answers */
            note: notes.get(f.op === codes.OP.TICKET ? f.refSeq : f.seq) || null });
        }
      }
      out.live = h.live;
      out.held = h.held;
      return out;
    },
    /*
     * The agent's own view plus the KEY's (spec session, 2026-10-03, bug 1): the
     * seqs the key says are owed - this agent's paid uses and any pressed sign
     * with its key (R16) - and the uses spent, from the budget's steps.
     */
    async status() {
      if (!budget) return { budget: null, execs: execs.size };
      const r = { budget: budget.grantId, uses: budget.uses, spent: null, head: budget.head(), owed: budget.pending(), keyOwed: [], keyOwedOlder: 0, execs: execs.size };
      if (edge) {
        const h = await edge.head();
        const rows = await ring(h);
        const k = await keyOwed(h, rows);
        r.keyOwed = k.seqs;
        r.keyOwedOlder = k.older;
        const steps = rows.map((row) => chain.decodeLink(row.link))
          .filter((f) => f.grantId === budget.grantId && f.decision === codes.DECISION.SELF_PRESS)
          .map((f) => f.grantStep);
        if (steps.length) r.spent = Math.max(...steps);
      }
      return r;
    },
    async closeAll() { for (const e of [...execs.values()]) await e.close(); },
  };
}

/**
 * The control endpoint's requests (edge/cli/control.js), over a service and
 * the L7 client. `gpg` the agent's own PGP identity: {identity, name, raw,
 * created, fingerprint, committer: {name, email}}; `shimCommand` what git runs
 * as gpg.program. Scopes are the agent's own identities on the ed25519 v2
 * sign code (221), told apart by label (R11a); sizes come from the request
 * (D4, at most 300 together).
 */
function controlHandlers({ agent, client, ssh, gpg = null, openpgp = null, shimCommand = null, signCode = 221, edge = null, home = null, openOther = null, selfName = null }) {
  /*
   * identity: name another identity in the ssh scope (edge budget --identity) - for
   * rule-10 tests with an identity the phone marks as test. Such a budget cannot
   * pay this agent's own signs (the key derives a different key); it only asks.
   */
  const scopes = ({ ssh: nSsh = 0, gpg: nGpg = 0, identity = null }) => [
    ...(nSsh ? [{ op: 'sign', slot: signCode, cap: nSsh, identity: identity || ssh.name }] : []),
    ...(nGpg && gpg ? [{ op: 'sign', slot: signCode, cap: nGpg, identity: gpg.name }] : []),
  ];
  const summary = (b) => ({ budget: b.grantId, uses: b.uses, head: b.head() });
  const gpgSign = async ({ token, data }) => {
    if (!gpg || !openpgp) throw new Error('this agent has no PGP identity');
    const { signDetached } = require('../../src/crypto/pgp-cert');
    return signDetached(openpgp, {
      data: Buffer.from(String(data), 'base64'), signPublic: gpg.raw, curve: 'ed25519', created: gpg.created,
      sign: (digest) => agent.shimSign(token, gpg.identity, digest),
    });
  };
  /* token -> the exec's own gpg endpoint (closed with the exec) */
  const gpgEndpoints = new Map();
  return {
    status: async () => agent.status(),
    /* edge watch: read-only */
    feed: async ({ from = null, since = 0 }) => agent.feed({ from, since }),
    /* edge ping: a pure link test - the phone echoes (testing mode, encrypted only); no key, no budget */
    ping: async ({ size, wait }) => client.ping({ size, ...(wait ? { timeoutMs: Math.min(120, Number(wait)) * 1000 } : {}) }),
    budget: async ({ reason, uses, ttl }) => {
      const b = await client.request({ reason, scopes: scopes(uses || {}), ttlMinutes: ttl });
      agent.setBudget(b);
      return summary(b);
    },
    continue: async ({ ttl, caps }) => {
      const old = agent.budget();
      if (!old) throw Object.assign(new Error('no budget to continue'), { code: 'EEDGE_NO_BUDGET' });
      const b = await client.continue(old.grantId, { ttlMinutes: ttl, caps: caps || null });
      agent.setBudget(b);
      return summary(b);
    },
    'exec-open': async ({ head, reason }) => {
      const ex = await agent.openExec({ head, reason });
      const git = {};
      let gpgEndpoint = null;
      if (gpg && shimCommand) {
        git['gpg.program'] = shimCommand;
        git['gpg.format'] = 'openpgp';
        git['user.signingkey'] = gpg.fingerprint;
        /*
         * THE EXEC'S OWN GPG ENDPOINT (2026-10-06): a fresh owner-only path and key,
         * like its ssh endpoint, closed with the exec. The shim gets both in its
         * environment, so it needs no fixed control path and no home - and no
         * running service (`edge exec` alone serves it too).
         */
        const key = crypto.randomBytes(32).toString('hex');
        const { serveControl } = require('./control');
        const spot = oneShotPath();
        const served = await serveControl({ handlers: { 'gpg-sign': (req) => gpgSign({ data: req.data, token: ex.token }) }, where: spot.path, key });
        gpgEndpoints.set(ex.token, { close: async () => { await served.close(); spot.cleanup(); } });
        gpgEndpoint = { path: served.path, key };
      }
      return { sshPath: ex.sshPath, token: ex.token, git, committer: gpg ? gpg.committer : null, gpg: gpgEndpoint };
    },
    'exec-close': async ({ token }) => {
      const ex = agent.execByToken(token);
      const links = ex ? await ex.close() : [];
      const g = gpgEndpoints.get(token);
      if (g) { gpgEndpoints.delete(token); await g.close(); }
      return { links, head: agent.budget() ? agent.budget().head() : null };
    },
    ticket: async ({ seq, code, message }) => ({ head: await agent.ticket(seq, { code: code || 'OK', message }) }),
    /* edge sync, phase 1: the PC's own copy - reads only (R8), no press; --status changes nothing */
    sync: async ({ status, phone = true }) => {
      if (!edge) throw new Error('this agent service has no Edge key to sync from');
      const where = home || require('./control').edgeHome();
      const copy = require('./copy');
      const r = await copy.sync(edge, where, { status: !!status });
      if (status || !phone) return r;
      /*
       * Phase 2 (Brad, 2026-10-05): this PC's copy fills the phone's - only a copy
       * that verifies (R27), only from a place on the key's list (R20). The phone
       * shows its sheet only when it lacks something; Yes and a press write the
       * `sync` link there. Never repairs: a fork on the phone stops it, reported.
       */
      if (r.verdict.kind !== 'verified' && r.verdict.kind !== 'gap') {
        r.phone = { skipped: `this PC's copy does not verify (${r.verdict.kind}) - nothing is offered` };
        return r;
      }
      const signer = copy.peerSigner(where);
      const mine = Buffer.from(signer.publicKey).toString('hex');
      const list = await edge.peers();
      if (!list.peers.some((p) => Buffer.from(p.publicKey).toString('hex') === mine)) {
        r.phone = { skipped: 'this PC is not on the key\'s list of places that keep copies - onlykey-js edge peer add' };
        return r;
      }
      const c = copy.load(where, Buffer.from(r.deviceId, 'hex'));
      /* this PC's public Key Chain list goes too, merged on the phone under the same sheet and press */
      const kcFile = require('../../keychain/cli/record');
      const myList = kcFile.load();
      try {
        r.phone = await client.syncToPhone(signer, { deviceId: c.deviceId, records: c.links, name: `${require('os').hostname()} copies`, keychain: myList });
        if (r.phone.keychain) {
          /* the merged list back: kept only if it still holds every entry this PC had */
          const check = require('../src').sync.checkTaken(myList, r.phone.keychain);
          if (check.ok) kcFile.save(check.entries);
          r.phone.keychainSaved = check.ok;
          if (!check.ok) r.phone.keychainMissing = check.missing;
          r.phone.keychain = r.phone.keychain.length;
        }
        /* the seals and the anchored sibling checkpoints that cut this copy into JSON blocks (BLOCKS.md §3) */
        try {
          r.phone.blocks = copy.keepSeals(where, c.deviceId, await client.sealsFromPhone(signer, { deviceId: c.deviceId }));
        } catch (e) {
          r.phone.blocksError = e.message;
        }
      } catch (e) {
        r.phone = { refused: e.message };
      }
      return r;
    },
    /*
     * edge sync phase 2, P2a (R20): add this PC's copy store to the KEY's list
     * of places that keep copies - the phone's sheet, Yes, a press. The store's
     * own P-256 key (edge-copy.peerSigner), never this agent's.
     */
    'peer-add': async ({ name }) => {
      const signer = require('./copy').peerSigner(home || require('./control').edgeHome());
      const key = Buffer.from(signer.publicKey).toString('hex');
      const r = await client.peerAdd(signer, name || `${require('os').hostname()} copies`);
      return { ...r, key };
    },
    /* the key's list (no press, R8); `thisPc` marks this PC's copy store */
    peers: async () => {
      if (!edge) throw new Error('this agent service has no Edge key to read the list from');
      const mine = Buffer.from(require('./copy').peerSigner(home || require('./control').edgeHome()).publicKey).toString('hex');
      const l = await edge.peers();
      return {
        k: l.k, max: l.max, mine,
        peers: l.peers.map((p) => {
          const key = Buffer.from(p.publicKey).toString('hex');
          return { index: p.index, key, thisPc: key === mine };
        }),
      };
    },
    /*
     * R29 (P2b): pair this agent's key with the key on another phone, both
     * ways. openOther(address) opens a second link to that phone for the
     * length of this request -> {edge, client, close}. This PC's copy store
     * must be on both keys' lists first (each phone refuses a place it does
     * not know): any key missing it gets the peer sheet + a press first.
     * Then BOTH sibling sheets at once, so the person sees the two codes side
     * by side; each phone pairs on its own Yes + press. One may pair while the
     * other is declined - each result is reported.
     */
    'sibling-add': async ({ address, name = null, otherName = null }) => {
      if (!edge) throw new Error('this agent service has no Edge key');
      if (!openOther) throw new Error('this agent service cannot open a second phone');
      if (!address) throw new Error('sibling-add needs the other phone\'s Bluetooth address');
      const signer = require('./copy').peerSigner(home || require('./control').edgeHome());
      const mine = Buffer.from(signer.publicKey).toString('hex');
      const other = await openOther(address);
      try {
        const [ka, kb] = [await edge.publicKey(), await other.edge.publicKey()];
        if (Buffer.compare(Buffer.from(ka.publicKey), Buffer.from(kb.publicKey)) === 0) throw new Error('both links reach the same key - give the OTHER phone\'s address');
        const listed = async (e) => (await e.peers()).peers.some((p) => Buffer.from(p.publicKey).toString('hex') === mine);
        const copies = `${require('os').hostname()} copies`;
        const added = [];
        if (!(await listed(other.edge))) { await other.client.peerAdd(signer, copies); added.push('other'); }
        if (!(await listed(edge))) { await client.peerAdd(signer, copies); added.push('this'); }
        /* the names each sheet shows: what was typed, else what each phone calls itself (a label - renamable on the phone) */
        const thisName = name || (await client.phoneName(signer, { deviceId: ka.deviceId }).catch(() => null)) || selfName || 'the other phone';
        const thatName = otherName || (await other.client.phoneName(signer, { deviceId: kb.deviceId }).catch(() => null)) || address;
        const hex = (b) => Buffer.from(b).toString('hex');
        const one = (p) => p.then((r) => ({ ok: true, ...r }), (e) => ({ ok: false, refusal: e.refusal || null, error: e.message }));
        const [onOther, onThis] = await Promise.all([
          one(other.client.siblingAdd(signer, { deviceId: kb.deviceId, key: ka.publicKey, name: thisName })),
          one(client.siblingAdd(signer, { deviceId: ka.deviceId, key: kb.publicKey, name: thatName })),
        ]);
        return { peersAdded: added, this: { deviceId: hex(ka.deviceId), ...onThis }, other: { deviceId: hex(kb.deviceId), ...onOther } };
      } finally {
        await other.close().catch(() => undefined);
      }
    },
    /*
     * R30 (P2c): a sync between this agent's key and the key on another phone
     * (paired both ways, R29), by cross-anchors. Each key's signed checkpoint is
     * read from the key itself; each phone's copy of its own chain comes from
     * that phone (GIVE, no press); then each phone gets the OTHER's chain up to
     * the other's checkpoint and anchors it - both sheets at once, a press on
     * each. Each phone checks the chain against the paired key and against what
     * it anchored before (a rollback or a changed head is its alarm). One may
     * anchor while the other is declined - each result is reported.
     */
    'sync-with': async ({ address, name = null, otherName = null }) => {
      if (!edge) throw new Error('this agent service has no Edge key');
      if (!openOther) throw new Error('this agent service cannot open a second phone');
      if (!address) throw new Error('sync --with needs the other phone\'s Bluetooth address');
      const signer = require('./copy').peerSigner(home || require('./control').edgeHome());
      const hex = (b) => Buffer.from(b).toString('hex');
      const other = await openOther(address);
      try {
        const [ka, kb] = [await edge.publicKey(), await other.edge.publicKey()];
        if (hex(ka.publicKey) === hex(kb.publicKey)) throw new Error('both links reach the same key - give the OTHER phone\'s address');
        const paired = async (e, k) => (await e.siblings()).siblings.some((s) => hex(s.publicKey) === hex(k.publicKey));
        if (!(await paired(edge, kb)) || !(await paired(other.edge, ka))) throw new Error('the two keys are not paired both ways - onlykey-js edge sibling add first');
        /* the checkpoints first: each phone's copy, read after, reaches at least that far */
        const [cpA, cpB] = [await edge.checkpoint(), await other.edge.checkpoint()];
        const thisName = name || (await client.phoneName(signer, { deviceId: ka.deviceId }).catch(() => null)) || selfName || 'the other phone';
        const thatName = otherName || (await other.client.phoneName(signer, { deviceId: kb.deviceId }).catch(() => null)) || address;
        const [recA, recB] = [await client.copyFromPhone(signer, { deviceId: ka.deviceId }), await other.client.copyFromPhone(signer, { deviceId: kb.deviceId })];
        const one = (p) => p.then((r) => ({ ok: true, ...r }), (e) => ({ ok: false, refusal: e.refusal || null, error: e.message }));
        const [onThis, onOther] = await Promise.all([
          one(client.anchorToPhone(signer, { deviceId: ka.deviceId, chain: kb.deviceId, records: recB, checkpoint: cpB, name: thatName })),
          one(other.client.anchorToPhone(signer, { deviceId: kb.deviceId, chain: ka.deviceId, records: recA, checkpoint: cpA, name: thisName })),
        ]);
        return {
          this: { deviceId: hex(ka.deviceId), anchored: { seq: cpB.seq }, ...onThis },
          other: { deviceId: hex(kb.deviceId), anchored: { seq: cpA.seq }, ...onOther },
        };
      } finally {
        await other.close().catch(() => undefined);
      }
    },
    /* R29: the keys this agent's key is paired with (no press) */
    siblings: async () => {
      if (!edge) throw new Error('this agent service has no Edge key to read the list from');
      const l = await edge.siblings();
      return { max: l.max, siblings: l.siblings.map((s) => ({ index: s.index, key: Buffer.from(s.publicKey).toString('hex'), deviceId: Buffer.from(s.deviceId).toString('hex') })) };
    },
    end: async () => {
      const b = agent.budget();
      if (b) await b.end();
      agent.setBudget(null);
      return { ended: b ? b.grantId : null };
    },
    'gpg-sign': gpgSign,
  };
}

/**
 * The agent service, put together over a running app (the CLI's `edge-agent`
 * command, and the kit's emulator test). Derives the agent's OWN keys (D2:
 * derived identities, separate from the person's - ed25519, agent derivation
 * v2), makes its PGP certificate ONCE (two signatures by the device - presses
 * on a real key) and keeps it in agent.json, resumes a budget the store still
 * has, and serves: the shared ssh-agent endpoint (never paid), the control
 * endpoint (onlykey-js edge, the gpg shim). Exec endpoints open per command.
 *
 * @param {object} o
 * @param {object} o.okcrypto the app's okcrypto service (agent.publicKey / agent.sign)
 * @param {object} o.client the L7 client (createEdgeClient) for this key and channel
 * @param {object} o.config {ssh: 'ssh://user@host', gpgUid, committer: {name, email}, pins?, expires?}
 *   expires: the certificate's lifetime in seconds after it is made (absent or 0: it
 *   never expires). Changing it makes a new certificate - two presses again.
 * @param {(cfg: object) => void} o.saveConfig persists config changes (the certificate, the budget id)
 * @param {object} o.openpgp the openpgp fork (src/crypto/pgp)
 * @param {string} [o.shimCommand] what git runs as gpg.program
 */
/*
 * Silence: the key or the phone sent nothing at all back - not a refusal, not
 * a press that ran out (the key spoke then), not a reply cut short.
 */
function isSilence(e) {
  for (let x = e; x; x = x.cause) {
    if (x.code === 'EEDGE_UNSUPPORTED') return true;
    if (x.code === 'ETIMEDOUT' && !x.pressTimeout && !x.pressRefused && !x.partial) return true;
  }
  return false;
}

/*
 * Opening the phone at the agent's start (Brad, 2026-10-06): an agent restarted
 * right after the old one quit met a phone still tearing the old link down -
 * discovery found no vendor service (ENOVENDOR) and the agent quit; the next
 * start worked. So that one error gets one more try after ~5 s. Anything else,
 * or a second ENOVENDOR, is thrown as it was: a phone that really has no
 * soft key still fails, just 5 s later.
 * open() -> app (with destroy()) whose device is connected.
 */
async function openWithOneRetry(open, { waitMs = 5000, log = () => {} } = {}) {
  try {
    return await open();
  } catch (e) {
    if (!e || e.code !== 'ENOVENDOR') throw e;
    log(`${String(e.message).split('. ')[0]} - the phone may still be dropping the last link; trying once more in ${Math.round(waitMs / 1000)} s`);
    await new Promise((r) => setTimeout(r, waitMs));
    return open();
  }
}

async function startEdgeAgent({ okcrypto, client, edge = null, config, saveConfig = () => {}, openpgp, shimCommand = null, log = () => {}, confirm, openOther = null, selfName = null, onSilence = null, linkStats = null, serve = true }) {
  const wire = require('../../cli/ssh-wire');
  const sshPub = require('../../src/crypto/ssh-pub');
  const pgpCert = require('../../src/crypto/pgp-cert');
  const { serveControl } = require('./control');
  const VERSION = 2;
  const ED25519 = 1;
  const X25519 = 4;
  const device = {
    publicKey: (identity) => okcrypto.agent.publicKey(identity, { keyType: ED25519, version: VERSION }),
    sign: (identity, message) => okcrypto.agent.sign(identity, message, { keyType: ED25519, version: VERSION, ...(confirm ? { confirm } : {}) }),
  };

  const sshId = wire.parseIdentity(config.ssh);
  const sshName = `ssh://${sshId.user ? `${sshId.user}@` : ''}${sshId.host}`;
  const sshIdentity = wire.derivationIdentity(sshId);
  const sshRaw = await device.publicKey(sshIdentity);
  const ssh = { identity: sshIdentity, name: sshName, comment: sshName, curve: 'ed25519', raw: sshRaw };

  let gpg = null;
  if (config.gpgUid) {
    const gpgIdentity = { gpg: config.gpgUid };
    const gpgRaw = await device.publicKey(gpgIdentity);
    if (!config.cert || config.cert.signPublic !== Buffer.from(gpgRaw).toString('hex') || (config.cert.expires || 0) !== (config.expires || 0)) {
      log('making the agent\'s PGP certificate - two signatures by the OnlyKey (press when asked)');
      const created = Math.floor(Date.now() / 1000);
      const ecdhPublic = await okcrypto.agent.publicKey(gpgIdentity, { keyType: X25519, version: VERSION });
      const cert = await pgpCert.buildCertificate(openpgp, {
        userId: config.gpgUid, curve: 'ed25519', created, signPublic: gpgRaw, ecdhPublic,
        ...(config.expires ? { expires: config.expires } : {}),
        sign: (digest) => device.sign(gpgIdentity, digest),
      });
      config.cert = { armored: cert.armored, fingerprint: cert.fingerprint, created, expires: config.expires || 0, signPublic: Buffer.from(gpgRaw).toString('hex') };
      saveConfig(config);
    }
    gpg = {
      identity: gpgIdentity, name: `gpg://${config.gpgUid}`, raw: gpgRaw, created: config.cert.created,
      fingerprint: config.cert.fingerprint, committer: config.committer || null,
    };
  }

  /*
   * The automatic continue (spec session, 2026-10-03): only for a budget the
   * key lost to a lock or restart - one it ENDED (revoked on the phone, ended by
   * okedge end) has a grant-end link in the ring, and is left ended.
   */
  const onGone = async (old) => {
    if (edge) {
      const h = await edge.head();
      if (h.seq !== null && h.oldest !== null) {
        const rows = await edge.pickup(h.oldest, h.seq - h.oldest + 1);
        if (rows.some((r) => { const f = chain.decodeLink(r.link); return f.op === codes.OP.GRANT_END && f.grantId === old.grantId; })) return null;
      }
    }
    const nb = await client.continue(old.grantId, {});
    config.budget = nb.grantId;
    saveConfig(config);
    return nb;
  };
  const agent = createEdgeAgent({ device, ssh, pins: config.pins || bindLib.GITHUB_FINGERPRINTS, log, edge, onGone, client });
  if (config.budget) {
    try {
      agent.setBudget(await client.resume(config.budget));
      log(`resumed budget ${config.budget}`);
    } catch (e) {
      log(`budget ${config.budget} is not live any more (${e.message})`);
      config.budget = null;
      saveConfig(config);
    }
  }

  const handlers = controlHandlers({ agent, client, ssh, gpg, openpgp, shimCommand, edge, openOther, selfName });
  /* okedge status also says how the Bluetooth link has been: connects, reconnects, failures */
  const plainStatus = handlers.status;
  handlers.status = async (req) => ({ ...(await plainStatus(req)), link: linkStats ? linkStats() : null });
  for (const op of ['budget', 'continue', 'end']) {
    const h = handlers[op];
    handlers[op] = async (req) => {
      const r = await h(req);
      config.budget = op === 'end' ? null : r.budget;
      saveConfig(config);
      return r;
    };
  }
  /*
   * NOBODY ANSWERED (Brad, 2026-10-06): a request that ended in silence - no
   * report at all from the key or the phone - means this link may be one the
   * phone no longer holds a session for (it drops sealed requests in silence).
   * onSilence lets the link go; the next request connects fresh, hello first.
   * The request is not sent again.
   */
  const base = {
    agent,
    handlers,
    sshLine: sshPub.publicKeyLine('ed25519', sshRaw, sshName),
    certArmored: config.cert ? config.cert.armored : null,
    fingerprint: gpg ? gpg.fingerprint : null,
  };
  /* no service (CLI.md §4, the default): the caller runs the handlers in-process for one command */
  if (!serve) return { ...base, controlPath: null, async close() { await agent.closeAll(); } };
  const control = await serveControl({ handlers, log, onError: async (e) => { if (onSilence && isSilence(e)) await onSilence(e); } });
  return { ...base, controlPath: control.path, async close() { await agent.closeAll(); await control.close(); } };
}

module.exports = {
  isSilence, openWithOneRetry, createEdgeAgent, controlHandlers, startEdgeAgent, oneShotPath, EXEC_CAP_MS };
