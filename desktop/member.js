'use strict';

/**
 * desktop/member.js - WHICH PROCESS IS THIS COMPUTER IN THE ROOM (the structure track S5b; Brad, 2026-11-02: "if the
 * --service is taken over from the desktop, it shows up as 1 device? right?" - yes).
 *
 * The desktop app and `onlykey-js --service` are one concept on one computer (the desktop app is the whole thing, the
 * CLI is the same headless; "the --service runs in desktop, so the desktop acts as a service while its open"). So one of
 * them at a time is this computer's MEMBER - the device in the identity's room, its sync, its local MCP: the desktop app
 * while it is open, a service when it is not.
 *
 * ONE ENDPOINT DECIDES IT, NOT A TIMER: the member listens on one local endpoint per computer, which the operating system
 * gives to one process only, and takes back when that process ends - a crash included:
 *
 *   POSIX    ~/.onlykey-js/member.sock   (0600)
 *   Windows  \\.\pipe\okedge-member-<16 hex of the home>
 *
 *   - to become the member, a process listens there. Taken: it connects and STANDS BY on that link; when the link
 *     closes (the member quit or died) it tries again.
 *   - the desktop app comes first: its hello says `priority: 'desktop'`, and a service that is the member answers
 *     'stepping-down', lets go of what it serves (onStandBy), closes the endpoint and says 'released' - then the app
 *     listens. A service that connects to a member just stands by ('held').
 *   - a hello carries the token in ~/.onlykey-js/member.key (owner-only, made once) - the same user on this machine.
 *
 * Lines are desktop/protocol.js's (one JSON object per line):
 *   -> { t: 'hello', token, who, priority }
 *   <- { t: 'held', who } | { t: 'stepping-down', who } then { t: 'released' }
 *
 * Races (two processes listening at once after a member went) end the same way: the loser connects, and a desktop's
 * hello moves the member to it.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const trust = require('./trust');
const { HELLO_MS, send, readLines } = require('./protocol');

function endpoint(root, platform = process.platform) {
  const home = trust.homeRoot(root);
  if (platform === 'win32') return `\\\\.\\pipe\\okedge-member-${crypto.createHash('sha256').update(home).digest('hex').slice(0, 16)}`;
  return path.join(home, 'member.sock');
}

/* the hello's token: made once, owner-only - reading it IS the trust (desktop/trust.js's rule) */
function memberToken(root) {
  const file = path.join(trust.homeRoot(root), 'member.key');
  try { return fs.readFileSync(file, 'utf8').trim(); } catch { /* first time */ }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const token = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(file, `${token}\n`, { mode: 0o600, flag: 'wx' }); } catch { /* another process made it first */ }
  return fs.readFileSync(file, 'utf8').trim();
}

/* after stepping down: how many connect-only tries before this side may listen again (the asker died mid-way) */
const YIELD_TRIES = 12;

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

/**
 * @param {object} o
 * @param {string} o.who how this process is named to the others ("the desktop app", "onlykey-js --service (pid 123)")
 * @param {'desktop'|'service'} [o.priority] the desktop app takes the place of a service
 * @param {() => Promise<void>|void} o.onServe this process is the member now: serve
 * @param {(by: string) => Promise<void>|void} o.onStandBy stop serving (asked by `by`); resolves once let go
 * @param {(line: string) => void} [o.log]
 * @param {string} [o.root] the shared home (tests)
 * @returns {{start: () => Promise<void>, stop: () => Promise<void>, readonly serving: boolean}}
 */
function createMember({ who, priority = 'service', onServe, onStandBy, log = () => {}, root, platform = process.platform }) {
  const where = endpoint(root, platform);
  const token = memberToken(root);
  let server = null;
  let link = null;
  let serving = false;
  let stopped = false;
  const sockets = new Set();

  function listen() {
    return new Promise((resolve) => {
      const s = net.createServer(onConnection);
      s.once('error', (e) => {
        if (e.code !== 'EADDRINUSE' || platform === 'win32') { resolve(false); return; }
        /* POSIX: a socket file a dead member left behind answers nothing - it is removed, then listened on once more */
        const probe = net.connect(where);
        probe.once('connect', () => { probe.destroy(); resolve(false); });
        probe.once('error', () => {
          try { fs.unlinkSync(where); } catch { /* gone already */ }
          const again = net.createServer(onConnection);
          again.once('error', () => resolve(false));
          again.listen(where, () => { server = again; resolve(true); });
        });
      });
      s.listen(where, () => { server = s; resolve(true); });
    }).then((ok) => {
      if (ok && platform !== 'win32') { try { fs.chmodSync(where, 0o600); } catch { /* the folder is the user's own */ } }
      return ok;
    });
  }

  function onConnection(sock) {
    sockets.add(sock);
    let greeted = false;
    const helloTimer = setTimeout(() => { if (!greeted) sock.destroy(); }, HELLO_MS);
    sock.on('error', () => {});
    sock.on('close', () => { clearTimeout(helloTimer); sockets.delete(sock); });
    readLines(sock, (m) => {
      if (greeted) return;
      if (m.t !== 'hello' || !same(m.token, token)) { sock.destroy(); return; }
      greeted = true;
      clearTimeout(helloTimer);
      if (m.priority === 'desktop' && priority !== 'desktop' && serving) {
        send(sock, { t: 'stepping-down', who });
        void stepDown(String(m.who || 'the desktop app'), sock);
        return;
      }
      /* a link held open: when this member ends, the other side's link closes and it tries again */
      send(sock, { t: 'held', who });
    });
  }

  /* the desktop app asked: let go of what this process serves, give the endpoint back, then tell it */
  async function stepDown(by, asker) {
    serving = false;
    log(`this computer's member: ${by} takes over - standing by`);
    try { await onStandBy(by); } catch (e) { log(`standing by: ${e && e.message || e}`); }
    await closeServer(asker);
    send(asker, { t: 'released' });
    /*
     * the asker drops this link and then listens (a Windows pipe keeps its name while any of its connections is open);
     * this side only CONNECTS for a while (YIELD_TRIES) - it must not listen first and take the place back
     */
    asker.once('close', () => { if (!stopped) void attempt({ yielding: YIELD_TRIES }); });
  }

  /*
   * stops listening at once - the endpoint is free for the next member - and ends every link but `keep` (the asker,
   * told 'released' on it). server.close's own callback waits for every connection to end, the kept one included, so it
   * is not waited for.
   */
  function closeServer(keep = null) {
    for (const s of sockets) if (s !== keep) s.destroy();
    if (server) { server.close(); server = null; }
    return new Promise((resolve) => setImmediate(resolve));
  }

  function standBy() {
    return new Promise((resolve) => {
      const sock = net.connect(where);
      link = sock;
      let answered = false;
      let released = false;
      sock.on('error', () => {});
      sock.once('connect', () => send(sock, { t: 'hello', token, who, priority }));
      readLines(sock, (m) => {
        if (m.t === 'held') { answered = true; log(`this computer's member is ${m.who} - standing by`); }
        if (m.t === 'stepping-down') { answered = true; log(`${m.who} steps down for this one`); }
        /* the member let go: this link is dropped first, then the endpoint listened on (below) */
        if (m.t === 'released') { released = true; sock.destroy(); }
      });
      sock.once('close', async () => {
        if (link === sock) link = null;
        resolve(answered);
        if (stopped || serving) return;
        if (released) {
          if (await listen()) await becomeMember();
          else void attempt();
          return;
        }
        /* the member went (quit or died): try again */
        if (answered) void attempt();
      });
    });
  }

  async function becomeMember() {
    serving = true;
    log(`this computer's member: ${who}`);
    await onServe();
  }

  let retries = 0;
  let trying = false;
  /* yielding: tries left that only connect - after stepping down, the endpoint is the asker's to listen on */
  async function attempt({ yielding = 0 } = {}) {
    /* one try at a time, and none while serving or standing by on a link */
    if (stopped || serving || trying || link) return;
    if (!yielding) {
      trying = true;
      let listened = false;
      try { listened = await listen(); } finally { trying = false; }
      if (listened) { retries = 0; await becomeMember(); return; }
    }
    const answered = await standBy();
    /* neither listened nor answered (a member mid-way out): once more, after a moment - a failure's retry, not a poll */
    if (!answered && !stopped && !serving) {
      retries += 1;
      setTimeout(() => { void attempt({ yielding: Math.max(0, yielding - 1) }); }, Math.min(2000, 50 * retries));
    } else retries = 0;
  }

  return {
    start: () => attempt(),
    async stop() {
      stopped = true;
      serving = false;
      if (link) link.destroy();
      await closeServer();
    },
    get serving() { return serving; },
  };
}

module.exports = { createMember, endpoint, memberToken };
