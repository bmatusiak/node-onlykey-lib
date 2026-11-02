'use strict';

/**
 * A HOST'S BUCKET SYNC IN A JOINED ROOM (the structure track S5, 2026-11-02): one set of work for every room a host
 * joins - the user's server over its websocket, a computer's mcp-server over Bluetooth, later the CLI's `--service`:
 *
 *   - ANSWER the trades other devices start (the host's peer side - its handleTrade);
 *   - START one with each device that comes online, and with every device when this bucket changes - ONE STARTER PER
 *     PAIR: two devices that both start a trade run two at once, each mid-way when the other changes the bucket; a CLI
 *     starts its own (its sync is one-shot: it starts, never answers), and between two apps the lower id starts;
 *   - FOLLOW THE SERVER'S SEALED COPY (bucket/src/sealedcopy.js): at each join and each change here, the room's table of
 *     keyed ids and change tags against this bucket's, then only the rows that differ - the newer ones taken through the
 *     stores' own rules, this side's put sealed; with the heads row (each Edge log's newest link). A server that keeps
 *     none for this identity is said once. When the room says the copy got newer (another device's put), the stores it
 *     touches here are told and a round fetches them.
 *
 * One trade or round at a time, in the order asked (one change to the bucket at a time). It was the ok-edge app's alone
 * (serverRoom.ts wireRoom / tradeWith / sealedSync); here it is the lib's, the host gives what is its own:
 *
 *   createRoomSync({open, me, save, handleTrade, rules, randomBytes, selfId, answerMs, tell})
 *     open()        -> {bucket, identity} | null   the bucket open here
 *     me()          -> Promise<Me | null>          its proof material (bucket-identity)
 *     save()        -> Promise                     store the bucket after something was taken
 *     handleTrade(message, from, {allowed})        the peer side's answer
 *     rules, randomBytes, answerMs (a trade message's time to answer; 120 s)
 *     selfId()      -> this device's id in the room ('' before it has one)
 *     tell: {pulse(), checked(stores), traded(taken, items), last(withName, line), items(bucket)}   what the host shows
 *   -> {wire(room, hooks, joinedAs), changed(), rooms()}    joinedAs: the proof material the room was joined with
 *     hooks: {tag, peers(room), sealed(news), newer(stores, unknown)}   per room: '[room]' / '[room ble]' ...
 */

const trade = require('./trade');
const replicate = require('./replicate');
const sealedCopy = require('./sealedcopy');
const logblocks = require('../../edge/src/logblocks');

const count = (o) => Object.values(o || {}).reduce((a, b) => a + Number(b), 0);
const say = (line) => { if (typeof console !== 'undefined') console.log(line); };

function createRoomSync({ open, me, save, handleTrade, rules, randomBytes, selfId = () => '', answerMs = 120000, tell = {} }) {
  for (const [n, f] of Object.entries({ open, me, save, handleTrade, randomBytes })) {
    if (typeof f !== 'function') throw new TypeError(`room sync: ${n} is a function`);
  }
  const t = { pulse: () => {}, checked: () => {}, traded: () => {}, last: () => {}, items: () => ({}), ...tell };
  const wired = new Map();
  let chain = Promise.resolve();
  const sealedSaid = new Map();

  function queue(fn, onError) {
    chain = chain.then(fn).catch(onError);
    return chain;
  }

  /* joinedAs: the proof material the room was joined with - its trades are answered for that identity only */
  function wire(r, hooks, joinedAs) {
    wired.set(r, hooks);
    /* the room was joined with the key's proof, so it may trade while the bucket it joined for is open */
    r.serve(async (from, message) => {
      t.pulse();
      const out = await handleTrade(message, from, { allowed: () => open()?.identity === joinedAs.id });
      /* a check answered: the two states compared, and each store as it is here */
      if (message?.type === trade.TYPES.PROVE && out?.ok && out.state && message.state) {
        const b = open()?.bucket;
        const differs = replicate.differs(out.state, message.state);
        const stores = {};
        if (b) for (const [name, items] of Object.entries(t.items(b))) stores[name] = { items, same: !differs.includes(name) };
        t.checked(stores);
      }
      /* a trade another device started, answered here: it is this device's last trade too */
      if (message?.type === trade.TYPES.GIVE && out?.ok) {
        const b = open()?.bucket;
        t.traded(out.taken || {}, b ? t.items(b) : {});
        const who = r.peers().find((p) => p.id === from);
        t.last(who ? who.name : from, 'traded - answered its trade');
      }
      return out;
    });
    r.on('peer', (p) => {
      hooks.peers(r);
      say(`${hooks.tag} ${p.up ? `${p.up.name} (${p.up.kind}) came online` : `${p.down} left`}`);
      if (p.up) tradeSoon(p.up, r, hooks);
    });
    r.on('sealed-changed', (e) => {
      void (async () => {
        const o = open();
        const m = await me();
        if (!o || !m) return;
        const at = sealedCopy.locate(o.bucket, sealedCopy.keysOf(m.bucketKey), e.rows, { rules });
        if (!at.stores.length && !at.unknown) return;
        say(`${hooks.tag} the sealed copy changed on the server (${e.from ?? 'another device'}): newer there - ${[...at.stores, ...(at.unknown ? [`${at.unknown} new`] : [])].join(', ')}`);
        hooks.newer(at.stores, at.unknown);
        sealedSoon('the server copy changed', r, hooks);
      })().catch(() => { /* not this device's bucket now: the next round compares anyway */ });
    });
    r.on('close', () => { wired.delete(r); });
    /* joined: a trade with each device here now, and a round with the server's copy */
    for (const p of r.peers()) tradeSoon(p, r, hooks);
    sealedSoon('joined', r, hooks);
  }

  /* the bucket changed here: a trade with every device in every room joined now, and a round with each server's copy */
  function changed() {
    for (const [r, hooks] of wired) {
      for (const p of r.peers()) tradeSoon(p, r, hooks);
      sealedSoon('this bucket changed', r, hooks);
    }
  }

  function tradeSoon(peer, r, hooks) {
    const mine = selfId() || r.you || '';
    /* said, so a pair where neither starts shows: the other side's line says it starts */
    if (peer.kind === 'cli' || (mine && peer.id < mine)) { say(`${hooks.tag} ${peer.name}: it starts the trade (${peer.kind === 'cli' ? 'a CLI starts its own' : 'the lower id'})`); return; }
    queue(() => tradeWith(peer, r, hooks), (e) => {
      const line = `not traded: ${String(e?.message ?? e)}`;
      say(`${hooks.tag} ${peer.name}: ${line}`);
      t.last(peer.name, line);
    });
  }

  /* this device's side of a trade (trade.computerSide): proofs both ways, the states, then HAVE/GIVE rounds until they match */
  async function tradeWith(peer, r, hooks) {
    const o = open();
    const m = await me();
    if (!r || !wired.has(r) || !o || !m) {
      say(`${hooks.tag} ${peer.name}: no trade - ${!o ? 'no bucket open here' : !m ? 'no proof material for the open bucket' : 'that room is closed'}`);
      return;
    }
    const send = (msg) => { t.pulse(); return r.request(peer.id, msg, { timeoutMs: answerMs }); };
    const c = trade.computerSide({ bucket: o.bucket, me: m, randomBytes, rules });
    const done = (line) => {
      say(`${hooks.tag} ${peer.name}: ${line}`);
      t.last(peer.name, line);
    };
    const m2 = c.prove(await send(c.hello()));
    if (!m2) return done('refused - it did not prove this bucket identity, or does not trade');
    let step = c.compare(await send(m2));
    if (!step) return done('it did not say its state');
    if (step.same) return done('in sync');
    const taken = {};
    let gave = 0;
    let settled = false;
    for (;;) {
      const g = c.give(await send(step.message));
      if (!g) break;
      for (const [s, n] of Object.entries(g.taken || {})) taken[s] = (taken[s] || 0) + Number(n);
      const s = c.settle(await send(g.message));
      if (!s) break;
      gave += count(s.taken);
      if (s.same) { settled = true; break; }
      if (!s.message) break;
      step = s;
    }
    if (count(taken)) {
      await save();
      t.traded(taken, t.items(o.bucket));
    }
    done(`${settled ? 'traded' : 'not settled'} - took ${count(taken)}, gave ${gave}`);
  }

  function sealedSoon(why, r, hooks) {
    queue(() => sealedSync(why, r, hooks), (e) => {
      const msg = String(e?.message ?? e);
      say(`${hooks.tag} the sealed copy: not synced - ${msg}`);
      hooks.sealed({ status: 'error', at: Date.now(), why: msg });
    });
  }

  async function sealedSync(why, r, hooks) {
    const o = open();
    const m = await me();
    if (!r || !wired.has(r) || !o || !m) return;
    const store = r.sealedStore();
    if (!(await store.on())) {
      if (sealedSaid.get(hooks.tag) !== 'off') { sealedSaid.set(hooks.tag, 'off'); say(`${hooks.tag} the sealed copy: this server keeps none for this identity`); }
      hooks.sealed({ status: 'none', at: Date.now(), why: null, stores: {}, tier: null });
      return;
    }
    const entries = (name) => Object.fromEntries(Object.entries(o.bucket.stores[name] ?? {})
      .filter(([, x]) => x && !x.archived && x.v !== null).map(([k, x]) => [k, x.v]));
    const heads = { ...logblocks.newestSeqs(entries('edge-logs')), ...logblocks.newestSeqs(entries('edge-logs-test')) };
    hooks.sealed({ status: 'syncing' });
    t.pulse();
    const res = await sealedCopy.syncWith(o.bucket, sealedCopy.keysOf(m.bucketKey), store, { rules, randomBytes, heads });
    for (const x of res.refused) say(`${hooks.tag} the sealed copy: a row refused - ${x}`);
    if (count(res.taken)) {
      await save();
      t.traded(res.taken, t.items(o.bucket));
    }
    sealedSaid.set(hooks.tag, 'on');
    hooks.sealed({ status: 'synced', at: Date.now(), why: null, stores: res.stores ?? {}, tier: typeof store.tier === 'function' ? store.tier() : null });
    say(`${hooks.tag} the sealed copy (${why}): got ${res.got}, put ${res.put}${count(res.taken) ? ` - took ${JSON.stringify(res.taken)}` : ''}`);
  }

  return { wire, changed, rooms: () => wired };
}

module.exports = { createRoomSync };
