'use strict';

/**
 * desktop/trust.js - how the CLI finds the ok-edge desktop app on THIS machine, and why it may talk
 * to it (ok-edge TODO B4b; Brad, 2026-10-23: "for ipc security app can write a file and the cli can
 * read it").
 *
 * The desktop app and the CLI share one home, ~/.onlykey-js (the bucket's root): the app's records
 * ARE the CLI's. While the app runs it writes `desktop.json` there:
 *
 *   { v: 1, socket, token, pid }
 *
 * - socket: where it listens - a named pipe on Windows, a unix socket in the home elsewhere.
 * - token:  32 random bytes, hex. A client's hello must carry it; the app refuses one that does not.
 *           The file is the user's own (owner-only permissions where the OS has them), so being able
 *           to read it IS the trust - the same user, on the same machine. No pairing.
 * - pid:    the app's process, so a file left by an app that crashed is seen as stale.
 *
 * The app removes the file when it quits (only if it is still its own - another instance may have
 * written a newer one).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const VERSION = 1;
const FILE = 'desktop.json';

/* the shared home (bucket/cli/home.js root(): ~/.onlykey-js); a test may pass its own */
function homeRoot(root) {
  return root || path.join(os.homedir(), '.onlykey-js');
}

function trustFile(root) {
  return path.join(homeRoot(root), FILE);
}

/*
 * The socket. A Windows named pipe is machine-wide, so its name carries a tag of this user and home
 * (two users, or a test home, never meet); a unix socket lives in the home itself.
 */
function socketPath(root, platform = process.platform) {
  const home = homeRoot(root);
  if (platform === 'win32') {
    let user = '';
    try { user = os.userInfo().username; } catch (_) { /* no user name: the home alone */ }
    const tag = crypto.createHash('sha256').update(`${user}\n${home}`).digest('hex').slice(0, 12);
    return `\\\\.\\pipe\\okedge-desktop-${tag}`;
  }
  return path.join(home, 'desktop.sock');
}

/** the app's side: a fresh token, the file written owner-only; returns what was written */
function writeTrust({ root, socket = socketPath(root), pid = process.pid } = {}) {
  const record = { v: VERSION, socket, token: crypto.randomBytes(32).toString('hex'), pid };
  const file = trustFile(root);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch (_) { /* Windows: the profile's own ACL */ }
  return record;
}

function readTrust(root) {
  try {
    const r = JSON.parse(fs.readFileSync(trustFile(root), 'utf8'));
    if (!r || r.v !== VERSION || typeof r.socket !== 'string' || typeof r.token !== 'string' || !/^[0-9a-f]{64}$/.test(r.token)) return null;
    return r;
  } catch (_) {
    return null;
  }
}

/* is that process still running? EPERM = it exists, owned by someone else */
function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e && e.code === 'EPERM'; }
}

/**
 * The app as the CLI sees it: the record when the file is there, its app is running and (off
 * Windows) its socket exists - else null. Synchronous and quick: plain `onlykey-js` asks this once
 * to choose between the desktop app and the USB key.
 */
function liveTrust(root, { platform = process.platform, isAlive = alive } = {}) {
  const r = readTrust(root);
  if (!r || !isAlive(r.pid)) return null;
  if (platform !== 'win32' && !fs.existsSync(r.socket)) return null;
  return r;
}

/** the app's side, at quit: the file goes only if it is still this app's */
function removeTrust(record, root) {
  const now = readTrust(root);
  if (now && record && now.token === record.token) {
    try { fs.unlinkSync(trustFile(root)); } catch (_) { /* already gone */ }
  }
}

/* the token compared in constant time */
function tokenMatches(record, offered) {
  if (!record || typeof offered !== 'string' || offered.length !== record.token.length) return false;
  return crypto.timingSafeEqual(Buffer.from(offered), Buffer.from(record.token));
}

module.exports = { VERSION, FILE, homeRoot, trustFile, socketPath, writeTrust, readTrust, liveTrust, removeTrust, tokenMatches, alive };
