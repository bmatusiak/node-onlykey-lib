/**
 * THE USER'S SERVER (ok-edge plan M1): one Cloudflare Worker that hosts the web app and the rooms its devices meet in.
 * Brad, 2026-10-26: "lets host it on the MCP server" (one site: the key's rpId is this host, no cross-site, no address
 * to type); "the mcp service acts as 2 main things, the MCP service and websocket service ... they interwork together".
 *
 *   /ws/<identity id>  a websocket into that bucket identity's ROOM (a Durable Object, one per identity): the devices
 *                      of the identity online now. A device enters with its bucket key's proof over this host and a
 *                      fresh nonce (node-onlykey-lib bucket/src/room.js) - the key alone, no code, no account - and
 *                      then passes frames to the others by device id. The server never holds a bucket byte: frames
 *                      are passed as they come, and the trade over them is proved and sealed end to end (M2).
 *   /mcp               the MCP face (mcp.js): an AI agent builds a sign/decrypt plan for an identity; the plan shows
 *                      live in that identity's room, whose owner accepts the agent, approves and presses
 *   anything else      the web app (docs/, the static build), one page for every route.
 *
 * THE ROOM AND THE AGENTS. Per identity, the room keeps which agents its owner accepted or blocked (written only by the
 * identity's own joined devices - an agent can never accept itself) and a mirror of the plans that target it, so a
 * device that joins later sees them. The owner's devices hear {t:'mcp', ev, ...} and answer {t:'mcp-re', op, ...}.
 *
 * HIBERNATION: the room accepts its sockets through the Durable Object's hibernation API, so a quiet room is evicted
 * from memory and costs nothing while its devices stay connected; each socket's state lives in its attachment, not in
 * the object. Pings are answered by the runtime itself (an auto-response) without waking the room.
 */
import bucketLib from '../../bucket/src/index.js';
import bytes from '../../src/bytes.js';

const { room } = bucketLib;
export const ROOM_PATH = /^\/ws\/([0-9a-f]{32})$/;
const AGENT_STATES = ['accepted', 'blocked', 'removed'];
/* the largest frame passed on: a first sync of post-quantum keys is ~240 KB; room to spare, never unbounded */
const MAX_FRAME = 4 * 1024 * 1024;
/* a socket that has not joined by then is closed: an open connection with no proof holds nothing open for long */
const JOIN_WITHIN_MS = 30_000;
/* the sealed copy's bounds: rows a get or a put names, and one sealed unit (an Edge links block is ~25 KB) */
const SEALED_MAX_IDS = 2000;
const SEALED_MAX_BLOB = 1024 * 1024;

const send = (ws, msg) => {
  try { ws.send(JSON.stringify(msg)); } catch { /* the socket is closing; its close handler tells the room */ }
};

/*
 * THE CORE'S ROOM (mcp-server Rectify app, Brad 2026-11-01: "1 core api, a cloudflare service, and a localhost service";
 * "the core api will contain MCP and websocket api logic"): the identity's room as plain logic over ctx - its storage,
 * its sockets, its alarm. The Cloudflare service hands it a Durable Object's ctx; the localhost service a ctx of its own
 * - the same websocket API either way, so the desktop authenticates itself to its local MCP exactly as the web app to the
 * remote one (Brad, 2026-11-01: "so the desktop can re-use the core and websocket to host the mcp and authenticate
 * itself, like it was talking to the remote mcp").
 */
export class RoomCore {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  /*
   * one connection's socket (the websocket API): accept it, give it this connection's challenge, JOIN_WITHIN_MS to answer.
   * origin 'ble': a phone over Bluetooth (localhost/ble.js) - the same socket, kept in its attachment for the join's rule.
   */
  async accept(server, url, { origin = null } = {}) {
    const { nonce, message } = room.challenge((n) => crypto.getRandomValues(new Uint8Array(n)));
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ room: ROOM_PATH.exec(url.pathname)[1], host: url.host, nonce: bytes.toHex(nonce), device: null, since: Date.now(), origin });
    send(server, message);
    /* the join deadline comes first - an alarm set for a free sealed copy's drop is days away (alarm() sets it again) */
    const at = await this.ctx.storage.getAlarm();
    if (at === null || at > Date.now() + JOIN_WITHIN_MS) await this.ctx.storage.setAlarm(Date.now() + JOIN_WITHIN_MS);
  }

  /*
   * The devices that have joined: [socket, attachment], ONE per device - its newest socket. A replaced socket is still
   * listed by getWebSockets until its close completes, and changing its attachment once it closes does not hold, so the
   * room decides by device: the latest join of a device id is that device.
   */
  joined() {
    const newest = new Map();
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (!a || !a.device) continue;
      const have = newest.get(a.device.id);
      if (!have || a.joinedAt > have[1].joinedAt) newest.set(a.device.id, [ws, a]);
    }
    return [...newest.values()];
  }

  async webSocketMessage(ws, data) {
    if (typeof data !== 'string' || data.length > MAX_FRAME) return ws.close(1009, 'text frames up to 4 MiB');
    let msg;
    try { msg = JSON.parse(data); } catch { return ws.close(1007, 'not JSON'); }
    const me = ws.deserializeAttachment();

    /* an agent's socket (agentHello below): its key messages to the device it names, only while the owner accepts it */
    if (me.agent) return this.fromAgent(ws, me, msg);
    /* an agent introduces itself instead of joining - never over Bluetooth (what comes over the radio is a device) */
    if (!me.device && msg && msg.t === 'agent' && me.origin !== 'ble') return this.agentHello(ws, me, msg);

    if (!me.device) {
      /* one try: the join, checked against this connection's own challenge and this server's host */
      /* REQUIRE_LOGIN ('1'): only a login proof for THIS challenge enters - the key was present at this join */
      /* OPEN_JOIN ('1'): no proof at all - the desktop's own local MCP on 127.0.0.1 (lib room.js checkJoin open) */
      /*
       * A BLUETOOTH SOCKET ALWAYS PROVES THE LOGIN (Brad, 2026-11-01: "the app authorizes/approves ble over to the host
       * using the same mechanism"): the open join is for this computer's own 127.0.0.1 joins only - anything in radio
       * range enters with a login proof for this connection's challenge, whatever OPEN_JOIN says.
       */
      const ble = me.origin === 'ble';
      const check = room.checkJoin(me.room, msg, { nonce: bytes.fromHex(me.nonce), host: me.host },
        { requireLogin: ble || this.env.REQUIRE_LOGIN === '1', open: !ble && this.env.OPEN_JOIN === '1' });
      if (!check.ok) {
        send(ws, { t: 'refused' });
        return ws.close(4401, 'refused');
      }
      /* one socket per device: a device that reconnects replaces its old socket (joined() counts the newest only) */
      const old = this.joined().find(([, a]) => a.device.id === check.device.id);
      const peers = this.joined().filter(([, a]) => a.device.id !== check.device.id).map(([, a]) => a.device);
      ws.serializeAttachment({ ...me, device: check.device, nonce: null, joinedAt: Date.now() });
      if (old) {
        old[0].close(4409, 'replaced');
        return send(ws, { t: 'joined', you: check.device.id, peers });
      }
      send(ws, { t: 'joined', you: check.device.id, peers });
      for (const [other] of this.joined()) if (other !== ws) send(other, { t: 'peer', up: check.device });
      return;
    }

    switch (msg && msg.t) {
      case 'frame': {
        if (typeof msg.to !== 'string' || typeof msg.body !== 'string') return send(ws, { t: 'error', why: 'a frame is {to, body}' });
        const to = this.joined().find(([, a]) => a.device.id === msg.to);
        if (!to) return send(ws, { t: 'gone', to: msg.to });
        return send(to[0], { t: 'frame', from: me.device.id, body: msg.body });
      }
      case 'peers':
        return send(ws, { t: 'peers', peers: this.joined().filter(([s]) => s !== ws).map(([, a]) => a.device) });
      case 'key-re': {
        /* the key session's answer to an agent (the device holds the key): to that agent's sockets */
        if (typeof msg.to !== 'string' || !msg.m || typeof msg.m !== 'object') return send(ws, { t: 'error', why: 'a key-re is {to, m}' });
        const to = this.agents(msg.to);
        if (!to.length) return send(ws, { t: 'key-gone', from: msg.to });
        for (const [s] of to) send(s, { t: 'key', from: me.device.id, m: msg.m });
        return;
      }
      case 'mcp-re': {
        /* the reply carries the device's own id for it (re): the room's broadcasts reach the sender too, before it */
        const r = await this.fromOwner(me.room, msg, me.device.id);
        return send(ws, msg.re !== undefined ? { ...r, re: msg.re } : r);
      }
      case 'sealed': {
        /* a server with no SQLite (the desktop's local MCP - its bucket stays in its own file) keeps no sealed copy: off */
        if (!this.ctx.storage.sql) return send(ws, { t: 'sealed', re: msg.re, on: false });
        const r = this.sealedOp(me.room, msg);
        /* any operation by a device of the identity is a touch: a free copy's 7 days start again */
        await this.sealedTouch(me.room);
        send(ws, { t: 'sealed', re: msg.re, ...r });
        /*
         * A PUT THE COPY TOOK IS NEWS TO THE IDENTITY'S OTHER DEVICES (Brad, 2026-10-30: "if the app becomes stale and mcp
         * is newer, then it should reflect"): the ids and tags just written - keyed values the server cannot read - so each
         * finds which of its stores are now older than the server's and syncs. An event, so nobody polls.
         */
        if (msg.op === 'put' && r.ok && r.n) {
          const rows = {};
          for (const [id, x] of Object.entries(msg.rows)) rows[id] = x.tag;
          for (const [other] of this.joined()) if (other !== ws) send(other, { t: 'sealed-changed', from: me.device.id, rows });
        }
        return;
      }
      default:
        return send(ws, { t: 'error', why: `unknown message ${JSON.stringify(msg && msg.t)}` });
    }
  }

  /* ------------------------------------------------------------------ the sealed copy (bucket/src/sealedcopy.js) */

  /*
   * THE IDENTITY'S SEALED COPY, IN THIS ROOM'S SQLITE (Phase 3; Brad, 2026-10-29: "the server's sealed copy will have a
   * hash table for changes"; the room's own SQLite, one row per unit). Rows the server cannot read: a keyed id, a keyed
   * change tag, a sealed unit - written and read only by the identity's own joined devices (this is past the join).
   *
   * TWO TIERS, AND EVERY IDENTITY SYNCS (Brad, 2026-10-30: "1 free (temp 7 day) and the lifetime (ones i choose)"; "they
   * both sync, i should not have to enable a key to sync, you should have to enable a key to not get purged if it has
   * not been touched"):
   *   free      any identity: its copy is dropped once nothing of it has touched the copy (a table, get or put by any of
   *             its devices) for SEALED_FREE_MS - 7 days unless set (a test server sets it short)
   *   lifetime  the ids in LIFETIME_IDENTITIES (comma-separated; * for all - local dev): never dropped
   * The drop is the room's alarm (alarm below) - an inactivity timer, nothing polls.
   */
  sealedLifetime(identity) {
    const list = String(this.env.LIFETIME_IDENTITIES || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    return list.includes('*') || list.includes(String(identity).toLowerCase());
  }
  sealedFreeMs() {
    const ms = Number(this.env.SEALED_FREE_MS);
    return Number.isFinite(ms) && ms > 0 ? ms : 7 * 24 * 3600 * 1000;
  }
  sealedSql() {
    const sql = this.ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS sealed (id TEXT PRIMARY KEY, tag TEXT NOT NULL, blob TEXT NOT NULL, at INTEGER NOT NULL)');
    sql.exec('CREATE TABLE IF NOT EXISTS sealed_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
    return sql;
  }
  /* what the copy's tier is, and when a free copy is dropped if nothing touches it again (null: never) */
  sealedTier(identity, touched) {
    const lifetime = this.sealedLifetime(identity);
    return { tier: lifetime ? 'lifetime' : 'free', purgeAt: lifetime ? null : touched + this.sealedFreeMs() };
  }
  /* a touch: the 7 days start again, and the room's alarm is set for the earlier of that and any join deadline */
  async sealedTouch(identity) {
    const now = Date.now();
    const sql = this.sealedSql();
    sql.exec('INSERT INTO sealed_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', 'touched', String(now));
    sql.exec('INSERT INTO sealed_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', 'identity', String(identity));
    const { purgeAt } = this.sealedTier(identity, now);
    if (purgeAt === null) return;
    const at = await this.ctx.storage.getAlarm();
    if (at === null || at > purgeAt) await this.ctx.storage.setAlarm(purgeAt);
  }
  /* the alarm's half for the copy: a free copy nothing touched for its window is dropped; -> when to look again (or null) */
  sealedPurgeDue(now) {
    const sql = this.sealedSql();
    const meta = Object.fromEntries(sql.exec('SELECT k, v FROM sealed_meta').toArray().map((r) => [r.k, r.v]));
    if (!meta.identity || !meta.touched) return null;
    const { purgeAt } = this.sealedTier(meta.identity, Number(meta.touched));
    if (purgeAt === null) return null;
    if (now < purgeAt) return purgeAt;
    sql.exec('DELETE FROM sealed');
    sql.exec('DELETE FROM sealed_meta');
    return null;
  }
  sealedOp(identity, msg, touched = Date.now()) {
    const sql = this.sealedSql();
    const HEX = /^[0-9a-f]{32}$/;
    if (msg.op === 'table') {
      const rows = {};
      for (const r of sql.exec('SELECT id, tag FROM sealed').toArray()) rows[r.id] = r.tag;
      return { on: true, rows, ...this.sealedTier(identity, touched) };
    }
    if (msg.op === 'get') {
      const ids = Array.isArray(msg.ids) ? msg.ids.filter((id) => typeof id === 'string' && HEX.test(id)).slice(0, SEALED_MAX_IDS) : [];
      const rows = {};
      for (const id of ids) {
        const r = sql.exec('SELECT blob FROM sealed WHERE id = ?', id).toArray()[0];
        if (r) rows[id] = r.blob;
      }
      return { rows };
    }
    if (msg.op === 'put') {
      const entries = Object.entries(msg.rows && typeof msg.rows === 'object' ? msg.rows : {});
      if (entries.length > SEALED_MAX_IDS) return { ok: false, why: `at most ${SEALED_MAX_IDS} rows a put` };
      for (const [id, r] of entries) {
        if (!HEX.test(id) || !r || typeof r.tag !== 'string' || !HEX.test(r.tag) || typeof r.blob !== 'string' || r.blob.length > SEALED_MAX_BLOB) {
          return { ok: false, why: `row ${String(id).slice(0, 12)}: an id and a tag of 32 hex, a blob up to ${SEALED_MAX_BLOB} characters` };
        }
      }
      const now = Date.now();
      for (const [id, r] of entries) sql.exec('INSERT INTO sealed (id, tag, blob, at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET tag = excluded.tag, blob = excluded.blob, at = excluded.at', id, r.tag, r.blob, now);
      return { ok: true, n: entries.length };
    }
    return { ok: false, why: `no sealed ${JSON.stringify(msg.op)}` };
  }

  async webSocketClose(ws) {
    this.left(ws);
  }

  async webSocketError(ws) {
    this.left(ws);
  }

  /* a joined device left: the others hear it - unless this was a replaced socket and a newer one holds the device */
  left(ws) {
    const a = ws.deserializeAttachment();
    /* an agent left: the devices it talked to end its key session */
    if (a && a.agent) {
      if (!this.agents(a.agent.id).some(([s]) => s !== ws)) for (const [d] of this.joined()) send(d, { t: 'key-gone', from: a.agent.id });
      return;
    }
    if (!a || !a.device) return;
    /* its agents hear it too: a key session with it is over */
    for (const [s] of this.agents()) send(s, { t: 'peer', down: a.device.id });
    const others = this.joined().filter(([s]) => s !== ws);
    if (others.some(([, b]) => b.device.id === a.device.id)) return;
    for (const [other] of others) send(other, { t: 'peer', down: a.device.id });
  }

  /* ------------------------------------------------------------------ the agents and their plans (mcp.js) */

  /* to every joined device of this identity - the owner's web app, phone, desktop */
  tell(msg) { for (const [ws] of this.joined()) send(ws, { t: 'mcp', ...msg }); }

  /* ------------------------------------------------------------------ an agent on the identity's key (plan B4) */

  /*
   * THE CLI REACHES A DEVICE'S KEY THROUGH THE ROOM (ok-edge plan B4; Brad, 2026-11-01: "the app authorizes/approves ble
   * over to the host using the same mechanism ... re-use code we already have"): a computer's onlykey-js is an AGENT of
   * this identity - the same agent record the MCP keeps (agent:<id>, id = sha256 of its agent_key), accepted, blocked or
   * removed only by the owner's own devices (fromOwner). It opens a socket to the room and introduces itself
   * ({t:'agent', agent_key, name}) instead of joining; while accepted, its {t:'key', to, m} goes to the device it names -
   * the device runs the lib's key session (desktop/session.js) on its key and answers {t:'key-re', to, m}. A new agent is
   * entered as pending and the owner told, as a plan's agent is; nothing reaches a key until the owner accepts it.
   */
  agents(id = null) {
    const out = [];
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (a && a.agent && (id === null || a.agent.id === id)) out.push([ws, a]);
    }
    return out;
  }

  async agentHello(ws, me, msg) {
    const key = typeof msg.agent_key === 'string' ? msg.agent_key.toLowerCase() : '';
    const name = typeof msg.name === 'string' ? msg.name.slice(0, 60) : '';
    if (!/^[0-9a-f]{64}$/.test(key) || !name) {
      send(ws, { t: 'refused', why: 'an agent is {agent_key: 64 hex, name}' });
      return ws.close(4400, 'not an agent');
    }
    const id = bytes.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.fromHex(key))));
    let a = await this.agentOf(id);
    if (!a) {
      a = { id, name, state: 'pending', first: Date.now() };
      this.tell({ ev: 'agent', agent: a });
    }
    a = { ...a, name, last: Date.now() };
    await this.ctx.storage.put(`agent:${id}`, a);
    if (a.state === 'blocked') {
      send(ws, { t: 'agent', you: id, state: 'blocked' });
      return ws.close(4403, 'blocked');
    }
    ws.serializeAttachment({ ...me, agent: { id, name }, nonce: null });
    send(ws, { t: 'agent', you: id, state: a.state, devices: this.joined().map(([, d]) => d.device) });
  }

  async fromAgent(ws, me, msg) {
    switch (msg && msg.t) {
      case 'key': {
        /* the owner's word now, not at hello: a block takes effect at once */
        const a = await this.agentOf(me.agent.id);
        if (!a || a.state !== 'accepted') return send(ws, { t: 'key-refused', why: `the owner has not accepted this computer (${a ? a.state : 'removed'}) - they accept it in the app's Agents list` });
        if (typeof msg.to !== 'string' || !msg.m || typeof msg.m !== 'object') return send(ws, { t: 'error', why: 'a key is {to, m}' });
        const to = this.joined().find(([, d]) => d.device.id === msg.to);
        if (!to) return send(ws, { t: 'gone', to: msg.to });
        return send(to[0], { t: 'key', from: me.agent.id, name: me.agent.name, m: msg.m });
      }
      case 'devices': {
        const a = await this.agentOf(me.agent.id);
        return send(ws, { t: 'devices', state: a ? a.state : 'removed', devices: this.joined().map(([, d]) => d.device) });
      }
      default:
        return send(ws, { t: 'error', why: `an agent sends key or devices, not ${JSON.stringify(msg && msg.t)}` });
    }
  }
  async agentOf(id) { return this.ctx.storage.get(`agent:${id}`); }
  async plans() { return [...(await this.ctx.storage.list({ prefix: 'plan:' })).values()]; }

  /*
   * An agent's plan, shown (new or changed): the agent is entered as pending the first time it targets this identity,
   * so the owner sees who asks before anything can be submitted. A blocked agent's plans are not shown.
   */
  async show(plan) {
    let a = await this.agentOf(plan.agent.id);
    if (!a) {
      a = { id: plan.agent.id, name: plan.agent.name, state: 'pending', first: Date.now() };
      await this.ctx.storage.put(`agent:${a.id}`, a);
      this.tell({ ev: 'agent', agent: a });
    } else if (a.name !== plan.agent.name) {
      a = { ...a, name: plan.agent.name };
      await this.ctx.storage.put(`agent:${a.id}`, a);
    }
    a = { ...a, last: Date.now() };
    await this.ctx.storage.put(`agent:${a.id}`, a);
    if (a.state === 'blocked') return { agent_state: a.state, owner_online: this.joined().length > 0, shown: false };
    await this.ctx.storage.put(`plan:${plan.id}`, plan);
    this.tell({ ev: 'plan', plan });
    return { agent_state: a.state, owner_online: this.joined().length > 0, shown: true };
  }

  async withdraw(planId, why) {
    if (!(await this.ctx.storage.get(`plan:${planId}`))) return;
    await this.ctx.storage.delete(`plan:${planId}`);
    this.tell({ ev: 'plan-gone', plan: planId, why });
  }

  /* status, for the agent: its state here (unknown until it targets a plan here) and whether an owner is online */
  async agentStatus(me) {
    const a = await this.agentOf(me.id);
    return { agent_state: a ? a.state : 'unknown', owner_online: this.joined().length > 0 };
  }

  /* submit: only an accepted agent, only with an owner device online to approve it - the web app runs it from here */
  async submit(plan) {
    const a = await this.agentOf(plan.agent.id);
    if (!a || a.state !== 'accepted') {
      return { ok: false, why: `the owner has not accepted you yet (${a ? a.state : 'unknown'}): they see your plan in their web app and accept you there` };
    }
    if (!this.joined().length) return { ok: false, why: 'no owner device is online to approve it - try again when the owner has the web app open' };
    await this.ctx.storage.put(`plan:${plan.id}`, plan);
    this.tell({ ev: 'submit', plan });
    return { ok: true };
  }

  async fill(planId, item, data) {
    const plan = await this.ctx.storage.get(`plan:${planId}`);
    if (!plan || !['running', 'paused'].includes(plan.state)) return { ok: false, why: 'the plan is not running here' };
    if (!this.joined().length) return { ok: false, why: 'no owner device is online' };
    const it = plan.items.find((x) => x.item === item);
    if (it) Object.assign(it, data);
    await this.ctx.storage.put(`plan:${planId}`, plan);
    this.tell({ ev: 'fill', plan: planId, item, ...data });
    return { ok: true };
  }

  async finish(planId) {
    const plan = await this.ctx.storage.get(`plan:${planId}`);
    if (!plan) return { ok: false, why: 'the plan is not here' };
    if (!this.joined().length) return { ok: false, why: 'no owner device is online to end its budget' };
    this.tell({ ev: 'finish', plan: planId });
    return { ok: true };
  }

  /*
   * An owner device's answer ({t:'mcp-re', op}): the agents (list, accept, block, remove), or a plan's progress, which
   * goes on to the agent. Only a joined device gets here (webSocketMessage) - the identity's own key proved it.
   */
  async fromOwner(roomId, msg, deviceId = null) {
    if (msg.op === 'agents') return { t: 'mcp', ev: 'agents', agents: [...(await this.ctx.storage.list({ prefix: 'agent:' })).values()], plans: await this.plans() };
    if (msg.op === 'agent') {
      if (!AGENT_STATES.includes(msg.state)) return { t: 'error', why: `an agent is ${AGENT_STATES.join(' | ')}` };
      const a = await this.agentOf(String(msg.agent || ''));
      if (!a) return { t: 'error', why: 'no such agent here' };
      if (msg.state === 'removed') await this.ctx.storage.delete(`agent:${a.id}`);
      else await this.ctx.storage.put(`agent:${a.id}`, { ...a, state: msg.state });
      /* block and remove take effect at once: the agent's plans that are not running go from every device */
      if (msg.state !== 'accepted') {
        for (const p of await this.plans()) {
          if (p.agent.id === a.id && !['running', 'paused'].includes(p.state)) await this.withdraw(p.id, `agent ${msg.state}`);
        }
      }
      this.tell({ ev: 'agent', agent: { ...a, state: msg.state } });
      /* the agent's own sockets hear it; blocked or removed, they close - and the devices end its key session */
      for (const [s] of this.agents(a.id)) {
        send(s, { t: 'agent', you: a.id, state: msg.state });
        if (msg.state !== 'accepted') s.close(4403, msg.state);
      }
      if (msg.state !== 'accepted') for (const [d] of this.joined()) send(d, { t: 'key-gone', from: a.id });
      return { t: 'mcp', ev: 'ok', op: 'agent' };
    }
    /*
     * ONE DEVICE RUNS A PLAN (Step 4b): every device of the identity hears it submitted and shows its sheet; the first
     * whose owner taps Approve claims it, before the press - so two Approves never open two budgets. The others hear the
     * claim (the plan, with `by`) and withdraw their sheets; only the claiming device's updates are taken after.
     */
    if (msg.op === 'plan-claim') {
      const plan = await this.ctx.storage.get(`plan:${String(msg.plan || '')}`);
      if (!plan) return { t: 'error', why: 'no such plan here' };
      if (plan.by && plan.by !== deviceId) return { t: 'error', why: 'another of your devices runs it' };
      if (!plan.by && plan.state !== 'submitted') return { t: 'error', why: `the plan is ${plan.state}, not waiting for approval` };
      plan.by = deviceId;
      await this.ctx.storage.put(`plan:${plan.id}`, plan);
      this.tell({ ev: 'plan', plan });
      return { t: 'mcp', ev: 'ok', op: 'plan-claim' };
    }
    if (msg.op === 'plan') {
      const plan = await this.ctx.storage.get(`plan:${String(msg.plan || '')}`);
      if (!plan) return { t: 'error', why: 'no such plan here' };
      if (plan.by && plan.by !== deviceId) return { t: 'error', why: 'another of your devices runs it' };
      const r = await this.env.AGENTS.get(this.env.AGENTS.idFromName(plan.agent.id)).fromRoom(roomId, msg);
      if (!r.ok) return { t: 'error', why: r.why };
      if (msg.state) plan.state = msg.state;
      for (const x of Array.isArray(msg.results) ? msg.results : []) plan.results = { ...plan.results, [x.item]: x };
      await this.ctx.storage.put(`plan:${plan.id}`, plan);
      this.tell({ ev: 'plan', plan });
      return { t: 'mcp', ev: 'ok', op: 'plan' };
    }
    return { t: 'error', why: `unknown mcp-re op ${JSON.stringify(msg.op)}` };
  }

  /*
   * The room's one alarm, two jobs: close the sockets that never joined in time, and drop a free sealed copy nothing has
   * touched for its window. Set again for whichever comes first.
   */
  async alarm() {
    const now = Date.now();
    let waiting = false;
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (!a || a.device || a.agent) continue;
      if (now - a.since >= JOIN_WITHIN_MS) ws.close(4408, 'no join in time');
      else waiting = true;
    }
    const purge = this.sealedPurgeDue(now);
    const next = [waiting ? now + JOIN_WITHIN_MS : null, purge].filter((x) => x !== null);
    if (next.length) await this.ctx.storage.setAlarm(Math.min(...next));
  }
}
