'use strict';

/**
 * cli/edge-control.js - how `okedge` and the gpg shim reach the agent service
 * (onlykey-edge mcp-service.md §4.2a). One JSON line per request, one per
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

/* OKEDGE_HOME moves everything (a test's scratch home; a second agent) - the child processes of an exec inherit it */
function edgeHome(home = os.homedir()) {
  return process.env.OKEDGE_HOME ? path.resolve(process.env.OKEDGE_HOME) : path.join(home, '.onlykey-js', 'edge');
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
    if (!create) throw Object.assign(new Error('the agent service is not set up here (no control key) - start `onlykey-js edge-agent`'), { code: 'EEDGE_NO_AGENT' });
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
async function serveControl({ handlers, home = os.homedir(), windows = IS_WINDOWS, log = () => {} }) {
  const key = controlKey({ home, create: true });
  const where = controlPath({ home, windows });
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
function ask(op, fields = {}, { home = os.homedir(), windows = IS_WINDOWS, timeoutMs = 120000 } = {}) {
  const key = controlKey({ home });
  return new Promise((resolve, reject) => {
    const sock = net.connect(controlPath({ home, windows }));
    let buf = '';
    const timer = setTimeout(() => { sock.destroy(); reject(Object.assign(new Error(`the agent service did not answer "${op}" in ${timeoutMs / 1000} s`), { code: 'EEDGE_AGENT_TIMEOUT' })); }, timeoutMs);
    sock.once('error', (e) => {
      clearTimeout(timer);
      reject(Object.assign(new Error(`the agent service is not running (${e.code || e.message}) - start \`onlykey-js edge-agent\``), { code: 'EEDGE_NO_AGENT' }));
    });
    sock.on('connect', () => sock.write(JSON.stringify({ op, auth: key, ...fields }) + '\n'));
    sock.on('data', (c) => {
      buf += c.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      clearTimeout(timer);
      sock.destroy();
      const answer = JSON.parse(buf.slice(0, nl));
      if (answer.ok) resolve(answer);
      else reject(Object.assign(new Error(answer.error), { code: answer.code || 'EEDGE_AGENT' }));
    });
  });
}

module.exports = { edgeHome, controlPath, controlKey, serveControl, ask };
