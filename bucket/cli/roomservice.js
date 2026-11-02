'use strict';

/**
 * THIS COMPUTER IN ITS IDENTITY'S ROOM, HEADLESS (the structure track S5b; Brad, 2026-11-02: the CLI is the desktop app
 * without its window, "--service is its local MCP"). While `onlykey-js --service` is this computer's member
 * (desktop/member.js - the desktop app is, while it is open), it is a FULL device in the room, as the app is:
 *
 *   - the room sync is the lib's (bucket/src/roomsync.js), the same the app runs: it answers the trades other devices
 *     start, starts one with each device that comes online (the lower id starts), and follows the server's sealed copy;
 *   - its bucket is this computer's kept file (~/.onlykey-js/buckets/<net>/<id>.json, bucket/cli/home.js), held in
 *     memory while it serves; what it takes is merged into the file under the file's lock (newer wins - a write the
 *     desktop app or a command made meanwhile is never lost), and what other writers put in the file comes in through
 *     the folder's watch (bucket/cli/watch.js) - taken in between trades, then sent to the room;
 *   - one id and one look for the computer: home.js thisDevice()'s id, the desktop app's too; named "<computer> (<the
 *     key in use>)", kind 'desktop' - whichever of the two serves, the room sees the same device.
 *
 * THE JOIN IS THE APP'S (Brad, 2026-11-02: "like the app"): with `login`, the key signs this connection's challenge
 * (identity.proveLogin) - one key proof when it takes over; a server that asks a fresh proof (REQUIRE_LOGIN) is never
 * re-proven on a timer: a dropped connection waits until the person asks (`rejoin`, said through onNeedsKey). Without
 * `login` it joins with the kept certificate and a dropped connection is joined again after a growing wait (no key asked).
 * The room's close 4409 ("replaced": the newest join of this device id is the device - the desktop app joined) is never
 * joined again: onReplaced.
 *
 * KEY REQUESTS: the bucket key, once ever per computer (meFor - kept, its certificate checked on read); with `login`,
 * one sign per join the person asked for (the takeover's included). Trades and the sealed copy ask the key nothing.
 *
 *   createRoomService({okcrypto, net, url, login, keyKind, say, WebSocket, randomBytes, onNeedsKey, onReplaced})
 *     url()      -> the server (the key's site) or null
 *     login      -> (asked, me) => proof - the key signs this connection's challenge for the kept identity and bucket
 *                   key (me: the proof material); null: the kept certificate
 *   -> {start(), stop(), rejoin(), state}
 */

const path = require('path');
const bucketLib = require('../src/bucket');
const trade = require('../src/trade');
const { createRoomSync } = require('../src/roomsync');
const { connectRoom } = require('../src/room-client');
const { storeRules } = require('../src/store-rules');
const home = require('./home');
const { meFor } = require('./trade');
const { watchBuckets } = require('./watch');

const REJOIN_MS = 15000;
const REJOIN_MAX_MS = 300000;
const count = (o) => Object.values(o || {}).reduce((a, b) => a + Number(b), 0);

function createRoomService({
  okcrypto, net = 'live', url, login = null, keyKind = 'hard key', say = () => {}, WebSocket: WS = globalThis.WebSocket,
  randomBytes, onNeedsKey = () => {}, onReplaced = () => {}, device = home.thisDevice(), watch, debounceMs, proof = null,
}) {
  const rules = storeRules();
  let me = null;
  let file = null;
  let cur = null;
  let watcher = null;
  let room = null;
  let stopped = false;
  let retries = 0;
  let rejoinTimer = null;
  const state = { status: 'idle', host: null, why: null };
  const shown = { id: device.id, name: `${device.name} (${keyKind})`, kind: 'desktop' };

  /* what other writers put in the file, taken into the bucket in memory (the merge: newer wins) */
  function takeFile() {
    const m = bucketLib.merge(cur, home.read(file), { rules }).bucket;
    cur.stores = m.stores;
    cur.clock = m.clock;
  }

  /* what a trade or a round took, into the file under its lock - and the file's own news back */
  async function save() {
    home.update(file, (b) => {
      const m = bucketLib.merge(b, cur, { rules }).bucket;
      b.stores = m.stores;
      b.clock = m.clock;
    });
    takeFile();
    if (watcher) watcher.noteOwn();
  }

  const answer = trade.peerSide({ bucket: () => cur, me: () => me, randomBytes, rules });
  async function handleTrade(message, from, { allowed }) {
    if (!allowed()) return { ok: false, refusal: 'no' };
    const out = answer(message, from);
    if (message && message.type === trade.TYPES.GIVE && out && out.ok && count(out.taken)) await save();
    return out;
  }

  const sync = createRoomSync({
    open: () => (cur && me ? { bucket: cur, identity: me.id } : null),
    me: async () => me,
    save,
    handleTrade,
    rules,
    randomBytes,
    selfId: () => device.id,
    tell: { last: (w, line) => say(`sync: ${w}: ${line}`), items: (b) => Object.fromEntries(Object.keys(b.stores).map((s) => [s, Object.keys(b.stores[s] || {}).length])) },
  });

  function rejoinLater() {
    if (stopped) return;
    const wait = Math.min(REJOIN_MAX_MS, REJOIN_MS * 2 ** retries);
    retries += 1;
    state.status = 'waiting';
    say(`sync: joining again in ${Math.round(wait / 1000)} s`);
    rejoinTimer = setTimeout(() => { rejoinTimer = null; void join(); }, wait);
  }

  function needsKey(why) {
    state.status = 'needs-key';
    state.why = why;
    onNeedsKey(why);
  }

  async function join() {
    if (stopped || room) return;
    const where = await url();
    if (!where) { state.status = 'no-server'; say('sync: the key names no server (its site) - this computer syncs nothing through a room'); return; }
    const host = new URL(where).host;
    state.host = host;
    state.status = 'joining';
    let asked = false;
    try {
      const r = await connectRoom({
        url: where,
        device: shown,
        WebSocket: WS,
        randomBytes,
        /* with a login: no kept certificate in the join - the proof over this connection's challenge takes its place */
        me: login ? { ...me, certificate: new Uint8Array(0) } : me,
        login: login ? async (q) => { asked = true; say(`sync: proving the identity to ${host} - the key signs its challenge`); return login(q, me); } : null,
      });
      if (stopped) { r.close(); return; }
      room = r;
      retries = 0;
      state.status = 'joined';
      state.why = null;
      say(`sync: in this identity's room on ${host} as ${shown.name}${r.peers().length ? ` - ${r.peers().map((p) => p.name).join(', ')} online` : ''}`);
      sync.wire(r, {
        tag: `[room ${host}]`,
        peers: () => {},
        sealed: (s) => { if (s.status === 'error') say(`sync: the server's sealed copy - ${s.why}`); },
        newer: () => {},
      }, me);
      r.on('close', (e) => {
        if (room === r) room = null;
        if (stopped) return;
        if (e && e.code === 4409) {
          state.status = 'replaced';
          say(`sync: this computer joined ${host} from another place (the desktop app) - this one stands by`);
          onReplaced();
          return;
        }
        if (login) { needsKey(`the connection to ${host} closed - the login proof was that connection's`); return; }
        say(`sync: the connection to ${host} closed`);
        rejoinLater();
      });
    } catch (e) {
      const why = String((e && e.message) || e);
      say(`sync: not joined on ${host} - ${why}`);
      /* the key was asked (or a server that asks it refused): only the person asks it again */
      if (asked || login) { needsKey(`not joined on ${host} - ${why}`); return; }
      rejoinLater();
    }
  }

  return {
    state,
    async start() {
      /* proof: proof material already in hand (tests); otherwise the kept bucket key, made once through the key */
      me = proof || await meFor({ okcrypto, net, say });
      file = home.identityFile(me.id, net);
      if (!home.hasIdentityBucket(me.id, net)) home.keepIdentityBucket(me.id, net, bucketLib.create({ owner: me.id }));
      cur = home.read(file);
      watcher = watchBuckets({
        dir: path.dirname(file),
        say,
        ...(watch ? { watch } : {}),
        ...(debounceMs !== undefined ? { debounceMs } : {}),
        /* another writer changed the file: taken in between trades, then sent to the room */
        onChange: () => { void sync.inQueue(async () => takeFile()).then(() => sync.changed()); },
      });
      await join();
    },
    /* the person asked (the Try again): one more join - it asks the key again when it has to */
    rejoin() {
      if (stopped || room) return Promise.resolve();
      retries = 0;
      if (rejoinTimer) { clearTimeout(rejoinTimer); rejoinTimer = null; }
      return join();
    },
    async stop() {
      stopped = true;
      if (rejoinTimer) clearTimeout(rejoinTimer);
      if (watcher) watcher.stop();
      if (room) { const r = room; room = null; r.close(); }
      state.status = 'stopped';
    },
  };
}

module.exports = { createRoomService };
