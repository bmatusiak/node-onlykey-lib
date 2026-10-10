'use strict';

/**
 * edge/cli/control.js - how `onlykey-js edge` and the gpg shim reach the agent service
 * (onlykey-edge APP.md). One JSON line per request, one per
 * answer, on a local endpoint:
 *
 *   POSIX    ~/.onlykey-js/edge/control.sock  (directory 0700, socket 0600)
 *   Windows  \\.\pipe\okedge-control-<16 hex of the user's home>
 *
 * Every request carries `auth`, the secret in ~/.onlykey-js/edge/control.key
 * (written 0600 on POSIX; on Windows the file sits in the user's profile, which
 * only the user can read). That is what makes the endpoint owner-only on
 * Windows too, where Node cannot set a pipe's security descriptor: the pipe's
 * default security already keeps other users from writing to it, and a process
 * that cannot read the user's files cannot speak. Compared in constant time.
 *
 * Node only.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const IS_WINDOWS = process.platform === 'win32';

/*
 * The Edge home is ~/.onlykey-js/edge. A different one (a test's scratch home, a second
 * agent) is set only through setHome - by a test, or by the dev command set
 * (edge/cli/dev, --edge-home): a production package reads no environment variable for it
 * (CLI.md §5, 2026-10-06: the agent could set one itself).
 */
let homeOverride = null;
function setHome(dir) { homeOverride = dir ? path.resolve(dir) : null; }
function edgeHome(home = os.homedir()) {
  return homeOverride || path.join(home, '.onlykey-js', 'edge');
}

function controlPath({ home = os.homedir(), windows = IS_WINDOWS } = {}) {
  if (windows) {
    const tag = crypto.createHash('sha256').update(edgeHome(home)).digest('hex').slice(0, 16);
    return `\\\\.\\pipe\\okedge-control-${tag}`;
  }
  return path.join(edgeHome(home), 'control.sock');
}

/* the control secret: made once, owner-only */
function controlKey({ home = os.homedir(), create = false } = {}) {
  const dir = edgeHome(home);
  const file = path.join(dir, 'control.key');
  if (!fs.existsSync(file)) {
    if (!create) throw Object.assign(new Error('the agent service is not set up here (no control key) - start `onlykey-js edge agent`'), { code: 'EEDGE_NO_AGENT' });
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  }
  return fs.readFileSync(file, 'utf8').trim();
}

const same = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

/**
 * Serve the control endpoint. handlers: {[op]: async (request) => answer}.
 * A request without the right `auth` gets {ok: false, error: 'unauthorised'}.
 */
async function serveControl({ handlers, home = os.homedir(), windows = IS_WINDOWS, log = () => {}, onError = null, where: at = null, key: givenKey = null }) {
  /* where/key: a one-shot endpoint of its own (an exec's gpg endpoint) instead of the home's control endpoint */
  const key = givenKey || controlKey({ home, create: true });
  const where = at || controlPath({ home, windows });
  if (!windows) {
    fs.mkdirSync(path.dirname(where), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.dirname(where), 0o700);
    try { fs.unlinkSync(where); } catch { /* none */ }
  }
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('error', () => {});
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.length > 4 * 1024 * 1024) { sock.destroy(); return; }
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        (async () => {
          let req;
          try { req = JSON.parse(line); } catch { return { ok: false, error: 'not JSON' }; }
          if (!same(req.auth, key)) return { ok: false, error: 'unauthorised' };
          const h = handlers[req.op];
          if (!h) return { ok: false, error: `no such request: ${req.op}` };
          try {
            return { ok: true, ...(await h(req)) };
          } catch (e) {
            log(`control ${req.op}: ${e.message}`);
            if (onError) { try { await onError(e, req); } catch { /* the answer still goes back */ } }
            return { ok: false, error: e.message, code: e.code };
          }
        })().then((answer) => { if (!sock.destroyed) sock.write(JSON.stringify(answer) + '\n'); });
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(where, () => { server.removeListener('error', reject); resolve(); });
  });
  if (!windows) fs.chmodSync(where, 0o600);
  return {
    path: where,
    close: () => new Promise((resolve) => server.close(() => { if (!windows) { try { fs.unlinkSync(where); } catch { /* gone */ } } resolve(); })),
  };
}

/** One request to the agent service. -> its answer; throws on {ok: false} with the service's words. */
/*
 * BUG 2 (2026-10-05): with no live agent, okedge must say so AT ONCE. Two ways
 * there is none: nothing listens (the connect fails - always said at once), or
 * the agent DIES while handling the request (both of the day's crashes): the
 * socket closes with no answer, and with no handler for that, okedge printed
 * "Waiting for the phone" and sat out its 200 s while the phone showed nothing.
 * Now the close without an answer is an answer: the agent stopped.
 *
 * onSent: called once the agent has the request - "waiting for the phone" is
 * said only when something is actually waiting.
 */
function ask(op, fields = {}, { home = os.homedir(), windows = IS_WINDOWS, timeoutMs = 120000, onSent = null, where = null, key: givenKey = null } = {}) {
  let key = givenKey;
  if (!key) {
    try {
      key = controlKey({ home });
    } catch (e) {
      return Promise.reject(Object.assign(new Error('no edge agent is running here (it was never set up) - start `onlykey-js --ble --address <phone> edge agent`'), { code: 'EEDGE_NO_AGENT' }));
    }
  }
  return new Promise((resolve, reject) => {
    const sock = net.connect(where || controlPath({ home, windows }));
    let buf = '';
    let done = false;
    const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); fn(v); };
    const timer = setTimeout(() => { sock.destroy(); finish(reject, Object.assign(new Error(`the agent service did not answer "${op}" in ${timeoutMs / 1000} s`), { code: 'EEDGE_AGENT_TIMEOUT' })); }, timeoutMs);
    let connected = false;
    sock.once('error', (e) => {
      finish(reject, connected
        ? Object.assign(new Error(`the edge agent stopped while handling "${op}" (${e.code || e.message}) - see its log, then start it again`), { code: 'EEDGE_AGENT_GONE' })
        : Object.assign(new Error(`no edge agent is running (${e.code || e.message}) - start \`onlykey-js --ble --address <phone> edge agent\``), { code: 'EEDGE_NO_AGENT' }));
    });
    sock.on('connect', () => {
      connected = true;
      sock.write(JSON.stringify({ op, auth: key, ...fields }) + '\n');
      if (onSent) onSent();
    });
    sock.on('data', (c) => {
      buf += c.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      sock.destroy();
      const answer = JSON.parse(buf.slice(0, nl));
      if (answer.ok) finish(resolve, answer);
      else finish(reject, Object.assign(new Error(answer.error), { code: answer.code || 'EEDGE_AGENT' }));
    });
    sock.on('close', () => {
      finish(reject, Object.assign(new Error(`the edge agent stopped before answering "${op}" - it may have crashed; see its log, then start it again`), { code: 'EEDGE_AGENT_GONE' }));
    });
  });
}

module.exports = { edgeHome, setHome, controlPath, controlKey, serveControl, ask };
