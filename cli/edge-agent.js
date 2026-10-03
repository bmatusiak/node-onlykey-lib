'use strict';

/**
 * cli/edge-agent.js - the agent service (Edge Phase 2; onlykey-edge
 * build/mcp-service.md §4.2 / §4.2a, decided 2026-10-03; PROPOSAL-edge-agent.md).
 *
 * WHAT IT IS FOR. git calls an ssh-agent and a gpg program; neither protocol
 * can carry "this signature is for this reason, after this head". So the
 * agent service holds the session's work budget, and `okedge exec` tells it
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
const agentSrv = require('./ssh-agent');
const bindLib = require('./ssh-session-bind');
const agentProto = require('../src/protocol/agent');

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
function createEdgeAgent({ device, ssh, pins = bindLib.GITHUB_FINGERPRINTS, log = () => {}, endpointPath = oneShotPath }) {
  let budget = null;          /* the work budget (src/edge/client.js budget), once asked for or resumed */
  const execs = new Map();    /* token -> the open exec */

  const plainSign = (identity, message) => device.sign(identity, message); /* no ARM: the key asks for a press */

  /* the shared ssh-agent endpoint's handler: the agent's key, NEVER paid by the budget */
  const sharedHandler = agentSrv.createAgentHandler({
    keys: [{ curve: ssh.curve, raw: ssh.raw, comment: ssh.comment }],
    sessionBind: true,
    log,
    sign: (key, data) => plainSign(ssh.identity, data),
  });

  /*
   * One paid use: ARM over the budget's head and exactly the bytes the
   * firmware will be given (message || identity hash - okcrypto.agent.sign's
   * payload, R13a), the sign, the link read back and checked (client.js).
   */
  async function paid(exec, identity, message, what) {
    exec.used = true;
    const bytes = new Uint8Array([...message, ...agentProto.identityHash(identity)]);
    const { result, link } = await budget.use(bytes, () => device.sign(identity, message), { reason: exec.reason });
    exec.links.push({ ...link, what });
    log(`signed: link #${link.seq} (${what})${link.paid ? '' : ' - NOT paid by the budget'} - ticket owed for #${link.seq}`);
    return result;
  }

  /**
   * Open an exec: `head` must be the budget's head (the agent saw its last
   * ticket's reply), then a fresh endpoint and token for this one command.
   * -> {sshPath, token, close}
   */
  async function openExec({ head, reason, capMs = EXEC_CAP_MS }) {
    if (!budget) throw fail('EEDGE_NO_BUDGET', 'no work budget - ask for one first (okedge budget)');
    if (typeof reason !== 'string' || !reason.trim()) throw fail('EEDGE_REASON', 'an exec needs a reason');
    if (String(head || '').toLowerCase() !== budget.head()) {
      throw fail('EEDGE_STALE_HEAD', `--head is not the budget's head (${budget.head().slice(0, 16)}…): file the last ticket and use the head it printed`);
    }
    const exec = { token: crypto.randomBytes(32).toString('hex'), reason, used: false, closed: false, links: [] };
    const handler = agentSrv.createAgentHandler({
      keys: [{ curve: ssh.curve, raw: ssh.raw, comment: ssh.comment }],
      sessionBind: true,
      log,
      sign: async (key, data, conn) => {
        if (exec.closed || exec.used) return plainSign(ssh.identity, data); /* one paid use per exec */
        const ok = bindLib.boundToPinned(conn && conn.bind, data, pins);
        if (!ok.ok) {
          log(`not paid by the budget: ${ok.reason} - the key asks for a press`);
          return plainSign(ssh.identity, data);
        }
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
   * The gpg shim's sign, by token: the open exec's one paid use, or a press.
   * `identity` the agent's gpg derivation identity, `digest` what the device signs.
   */
  async function shimSign(token, identity, digest) {
    const exec = token ? execs.get(token) : null;
    if (!exec || exec.closed || exec.used || !budget) {
      log('gpg sign outside an exec (or its use is spent) - the key asks for a press');
      return plainSign(identity, digest);
    }
    return paid(exec, identity, digest, 'gpg');
  }

  return {
    sharedHandler,
    openExec,
    shimSign,
    setBudget(b) { budget = b; },
    execByToken: (token) => execs.get(token) || null,
    budget: () => budget,
    async ticket(seq, { code = 'OK', message }) {
      if (!budget) throw fail('EEDGE_NO_BUDGET', 'no work budget');
      await budget.ticket({ seq }, { code, message });
      return budget.head();
    },
    status() {
      return budget
        ? { budget: budget.grantId, uses: budget.uses, head: budget.head(), owed: budget.pending(), execs: execs.size }
        : { budget: null, execs: execs.size };
    },
    async closeAll() { for (const e of [...execs.values()]) await e.close(); },
  };
}

/**
 * The control endpoint's requests (cli/edge-control.js), over a service and
 * the L7 client. `gpg` the agent's own PGP identity: {identity, name, raw,
 * created, fingerprint, committer: {name, email}}; `shimCommand` what git runs
 * as gpg.program. Scopes are the agent's own identities on the ed25519 v2
 * sign code (221), told apart by label (R11a); sizes come from the request
 * (D4, at most 300 together).
 */
function controlHandlers({ agent, client, ssh, gpg = null, openpgp = null, shimCommand = null, signCode = 221 }) {
  const scopes = ({ ssh: nSsh = 0, gpg: nGpg = 0 }) => [
    ...(nSsh ? [{ op: 'sign', slot: signCode, cap: nSsh, identity: ssh.name }] : []),
    ...(nGpg && gpg ? [{ op: 'sign', slot: signCode, cap: nGpg, identity: gpg.name }] : []),
  ];
  const summary = (b) => ({ budget: b.grantId, uses: b.uses, head: b.head() });
  return {
    status: async () => agent.status(),
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
      if (gpg && shimCommand) {
        git['gpg.program'] = shimCommand;
        git['gpg.format'] = 'openpgp';
        git['user.signingkey'] = gpg.fingerprint;
      }
      return { sshPath: ex.sshPath, token: ex.token, git, committer: gpg ? gpg.committer : null };
    },
    'exec-close': async ({ token }) => {
      const ex = agent.execByToken(token);
      const links = ex ? await ex.close() : [];
      return { links, head: agent.budget() ? agent.budget().head() : null };
    },
    ticket: async ({ seq, code, message }) => ({ head: await agent.ticket(seq, { code: code || 'OK', message }) }),
    end: async () => {
      const b = agent.budget();
      if (b) await b.end();
      agent.setBudget(null);
      return { ended: b ? b.grantId : null };
    },
    'gpg-sign': async ({ token, data }) => {
      if (!gpg || !openpgp) throw new Error('this agent service has no PGP identity');
      const { signDetached } = require('../src/crypto/pgp-cert');
      return signDetached(openpgp, {
        data: Buffer.from(String(data), 'base64'), signPublic: gpg.raw, curve: 'ed25519', created: gpg.created,
        sign: (digest) => agent.shimSign(token, gpg.identity, digest),
      });
    },
  };
}

module.exports = { createEdgeAgent, controlHandlers, oneShotPath, EXEC_CAP_MS };
