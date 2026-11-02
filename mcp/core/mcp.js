/**
 * THE MCP FACE: EDGE CONTROL IN THE CLOUD (the MCP plan, Step 2; Brad, 2026-10-28: "no software to use besides the MCP
 * ... we tell the agent our identity pubkey and we point it at the MCP url, it should handle itself from there"; "the
 * MCP will be used like edge control, where the MCP assists the AI in building a sign/decrypt plan to send to the key;
 * the web app can see the plan built in real time before it's sent").
 *
 *   POST /mcp   Streamable HTTP, JSON responses (no event stream): initialize gives the session (Mcp-Session-Id), then
 *               tools/list and tools/call. One JSON-RPC message a request.
 *
 * WHO IS WHO. The agent says hello and gets an AGENT KEY the first time (32 random bytes, kept by the agent, sent in
 * every later hello); its ID is the key's SHA-256, and only that hash is kept here - a name is a label, not proof, so a
 * copycat without the key is a new agent. The owner's acceptance lives in the identity's room (index.js), per identity:
 * accepted by A means nothing at B.
 *
 * THE PLAN IS THE BUDGET, DRAFTED AHEAD AND HELD HERE (Brad, 2026-10-28: "the plan is held in the mcp and the agent
 * doesn't need to pass a full plan around multiple times"): one copy, in the agent's own Durable Object (AgentSession);
 * the agent sends the plan's id and one change a call. Every change is mirrored at once to the plan's TARGET identity's
 * room - to that owner's web app - and withdrawn from the old target's when it moves. Nothing reaches a key except
 * through plan_submit to the current target, whose owner approves it there (the web app runs it: one budget, one press).
 *
 * Trust: the server relays over TLS; nothing is sealed end to end (decided 2026-10-28: "sealing e2e will require a lot
 * of tooling"). What the server never does: hold a key, approve, or answer for the owner.
 */
import bucketLib from '../../bucket/src/index.js';
import bytes from '../../src/bytes.js';

const PROTOCOL = '2025-06-18';
const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];
const SESSION_ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
/* bounds: a plan is a page a person reads before one press, not a queue */
const MAX_ITEMS = 32;
const MAX_DATA = 64 * 1024;
const MAX_TEXT = 200;
const WAIT_MAX_S = 60;
const OPS = ['sign', 'decrypt'];
const KINDS = ['ssh', 'gpg'];

const hex = (u8) => bytes.toHex(u8);
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256Hex = async (h) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.fromHex(h))));
/* the room a target identity's devices meet in: its identity id, from the identity public key the agent was given */
const roomOf = (identityPublicKey) => bucketLib.bucketIdentity.identityIdOf(bytes.fromHex(identityPublicKey));

/* a refusal the agent reads: a tool result with isError, not a protocol error (the call itself was fine) */
class Refused extends Error {}
const need = (ok, why) => { if (!ok) throw new Refused(why); };
const text = (v, name, { max = MAX_TEXT, optional = false } = {}) => {
  if (optional && (v === undefined || v === null || v === '')) return null;
  need(typeof v === 'string' && v.trim().length > 0 && v.length <= max, `${name}: text, 1-${max} characters`);
  return v.trim();
};
const identityArg = (v) => {
  const h = typeof v === 'string' ? v.trim().toLowerCase() : '';
  need(HEX64.test(h), 'identity: the identity PUBLIC KEY, 64 hex characters (the owner gives it to you)');
  return h;
};

/* ------------------------------------------------------------------------------------------------ the tools */

const KEY_SCHEMA = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: KINDS, description: 'ssh or gpg: the agent-derived key Edge uses' },
    identity: { type: 'string', description: 'the key\'s label, e.g. "you@example.com" (gpg) or "ssh://user@host" (ssh)' },
  },
  required: ['kind', 'identity'],
};
const ITEM_PROPS = {
  plan_id: { type: 'string' },
  op: { type: 'string', enum: OPS },
  key: KEY_SCHEMA,
  reason: { type: 'string', description: 'why, in a few words - the owner reads it before approving' },
};

export const TOOLS = [
  { name: 'hello', description: 'Start here. Name yourself; the first time you get an agent_key - keep it and send it in every later hello, so the owners who accepted you know you again.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, agent_key: { type: 'string', description: '64 hex characters, from your first hello' } }, required: ['name'] } },
  { name: 'status', description: 'Your plans, and for an identity: whether its owner has accepted you, and whether the owner is online.',
    inputSchema: { type: 'object', properties: { identity: { type: 'string', description: 'an identity public key (64 hex)' } } } },
  { name: 'plan_new', description: 'A new plan for an identity (its public key, 64 hex). Its owner sees it in their web app at once, and every change after.',
    inputSchema: { type: 'object', properties: { identity: { type: 'string' }, title: { type: 'string' } }, required: ['identity', 'title'] } },
  { name: 'plan_target', description: 'Move a draft plan to another identity: withdrawn from the old owner\'s web app, shown in the new one\'s.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, identity: { type: 'string' } }, required: ['plan_id', 'identity'] } },
  { name: 'plan_add', description: 'Add one operation with its data (base64 when it is bytes, set encoding: "base64").',
    inputSchema: { type: 'object', properties: { ...ITEM_PROPS, data: { type: 'string' }, encoding: { type: 'string', enum: ['text', 'base64'] } }, required: ['plan_id', 'op', 'key', 'data', 'reason'] } },
  { name: 'plan_hold', description: 'Add a PLACEHOLDER: an operation whose data comes later (plan_fill, while the plan runs), counted in the budget - so work that depends on an earlier signature needs no second approval.',
    inputSchema: { type: 'object', properties: ITEM_PROPS, required: ['plan_id', 'op', 'key', 'reason'] } },
  { name: 'plan_remove', description: 'Remove one item from a draft plan.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, item: { type: 'integer' } }, required: ['plan_id', 'item'] } },
  { name: 'plan_show', description: 'The plan as it is now (read only).',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
  { name: 'plan_submit', description: 'Ask the owner to approve the plan: one budget sized to it, one press. Refused until the owner has accepted you, or while no owner device is online.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
  { name: 'plan_fill', description: 'While the plan runs: a placeholder\'s data. It runs inside the open budget, no new press.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, item: { type: 'integer' }, data: { type: 'string' }, encoding: { type: 'string', enum: ['text', 'base64'] } }, required: ['plan_id', 'item', 'data'] } },
  { name: 'plan_wait', description: 'Wait (up to 60 s) for the plan to move on: its state, each item\'s result (signature, plaintext or refusal), the placeholders still waiting, the receipts.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, seconds: { type: 'integer' } }, required: ['plan_id'] } },
  { name: 'plan_finish', description: 'End the plan\'s budget now: unfilled placeholders are dropped, receipts filed.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
];

const INSTRUCTIONS = 'OnlyKey Edge control. Your owner gives you this URL and their identity public key. '
  + 'Say hello (keep the agent_key you get the first time), build a plan for the identity (plan_new, plan_add, '
  + 'plan_hold for data that comes later), then plan_submit: the owner sees the plan live in their web app, accepts you '
  + 'once, approves the plan and presses their key once. plan_wait gives the results.';

/* ------------------------------------------------------------------------------------------------ the HTTP face */

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const rpcError = (id, code, message) => json({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });

/**
 * One POST to /mcp. A browser's request from another site is refused (the spec's DNS-rebinding guard); an agent sends
 * no Origin. Sessions: initialize makes one; every later request names it, and an unknown one is 404 (the client
 * starts again).
 */
export async function handleMcp(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return new Response('another site', { status: 403 });
  if (request.method === 'GET') return new Response('no event stream: POST JSON-RPC', { status: 405, headers: { Allow: 'POST, DELETE' } });
  const sid = request.headers.get('Mcp-Session-Id');
  if (request.method === 'DELETE') {
    if (sid && SESSION_ID.test(sid)) await env.MCP_SESSIONS.get(env.MCP_SESSIONS.idFromName(sid)).end();
    return new Response(null, { status: 204 });
  }
  if (request.method !== 'POST') return new Response('POST', { status: 405, headers: { Allow: 'POST, DELETE' } });
  let msg;
  try { msg = await request.json(); } catch { return rpcError(null, -32700, 'not JSON'); }
  if (Array.isArray(msg)) return rpcError(null, -32600, 'one message a request');
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(msg && msg.id, -32600, 'not a JSON-RPC request');
  const isNotification = msg.id === undefined;

  if (msg.method === 'initialize') {
    const asked = msg.params && msg.params.protocolVersion;
    const id = randomHex(16);
    await env.MCP_SESSIONS.get(env.MCP_SESSIONS.idFromName(id)).open();
    return json({ jsonrpc: '2.0', id: msg.id, result: {
      protocolVersion: SUPPORTED.includes(asked) ? asked : PROTOCOL,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'ok-edge', version: '0.1.0' },
      instructions: INSTRUCTIONS,
    } }, 200, { 'Mcp-Session-Id': id });
  }
  if (!sid || !SESSION_ID.test(sid)) return rpcError(msg.id, -32600, 'no session: initialize first (Mcp-Session-Id)');
  const session = env.MCP_SESSIONS.get(env.MCP_SESSIONS.idFromName(sid));
  if (isNotification) {
    /* notifications/initialized and the like: nothing to answer */
    if (!(await session.known())) return new Response('unknown session', { status: 404 });
    return new Response(null, { status: 202 });
  }
  const r = await session.call(msg.method, msg.params || {});
  if (r.unknownSession) return new Response('unknown session', { status: 404 });
  if (r.error) return rpcError(msg.id, r.error.code, r.error.message);
  return json({ jsonrpc: '2.0', id: msg.id, result: r.result });
}

/* ------------------------------------------------------------------------------------------------ one session */

/** One MCP session: which agent said hello on it. Everything the agent owns lives in its AgentSession. */
/*
 * THE CORE'S SESSION (mcp-server Rectify app, Brad 2026-11-01: "1 core api, a cloudflare service, and a localhost
 * service"): plain logic over ctx.storage - the Cloudflare service wraps it in a Durable Object, the localhost service
 * gives it storage of its own.
 */
export class McpSessionCore {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async open() { await this.ctx.storage.put('created', Date.now()); }
  async known() { return (await this.ctx.storage.get('created')) !== undefined; }
  async end() { await this.ctx.storage.deleteAll(); }

  async call(method, params) {
    if (!(await this.known())) return { unknownSession: true };
    try {
      if (method === 'ping') return { result: {} };
      if (method === 'tools/list') return { result: { tools: TOOLS } };
      if (method !== 'tools/call') return { error: { code: -32601, message: `no method ${method}` } };
      const { name, arguments: args = {} } = params;
      if (!TOOLS.some((t) => t.name === name)) return { error: { code: -32602, message: `no tool ${name}` } };
      const out = name === 'hello' ? await this.hello(args) : await this.forAgent(name, args);
      return { result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out } };
    } catch (e) {
      if (e instanceof Refused || (e && e.refused)) return { result: { content: [{ type: 'text', text: e.message }], isError: true } };
      return { error: { code: -32603, message: String((e && e.message) || e) } };
    }
  }

  async hello(args) {
    const name = text(args.name, 'name', { max: 60 });
    let key = args.agent_key;
    const first = key === undefined || key === null || key === '';
    if (first) key = randomHex(32);
    else need(typeof key === 'string' && HEX64.test(key.toLowerCase()), 'agent_key: the 64 hex characters your first hello gave you');
    const id = await sha256Hex(key.toLowerCase());
    await this.ctx.storage.put('agent', { id, name });
    await this.env.AGENTS.get(this.env.AGENTS.idFromName(id)).hello(id, name);
    return first
      ? { agent_id: id, agent_key: key, keep: 'this agent_key is shown once: keep it, and send it in every later hello' }
      : { agent_id: id };
  }

  async forAgent(name, args) {
    const agent = await this.ctx.storage.get('agent');
    need(agent, 'say hello first');
    const r = await this.env.AGENTS.get(this.env.AGENTS.idFromName(agent.id)).tool(name, args);
    if (r && r.refused) throw new Refused(r.refused);
    return r;
  }
}

/* ------------------------------------------------------------------------------------------------ one agent */

const ROOM_STUB = (env, roomId) => env.ROOMS.get(env.ROOMS.idFromName(roomId));

/**
 * One agent, by its ID: its name and its plans. The rooms it targets call back here with what their owners did
 * (fromRoom). plan_wait waits on this object's own memory: a change wakes the waiters at once.
 */
export class AgentSessionCore {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.waiters = [];
  }

  async hello(id, name) {
    const me = (await this.ctx.storage.get('me')) || { id, first: Date.now() };
    await this.ctx.storage.put('me', { ...me, name, last: Date.now() });
  }

  async me() { return this.ctx.storage.get('me'); }
  async plan(id) { return this.ctx.storage.get(`plan:${id}`); }
  /*
   * Every change bumps the plan's version. SEEN is the version the agent has been shown: its own changes are seen as it
   * makes them; the owner's (fromRoom) are not until plan_wait or plan_show returns them - so an answer that lands just
   * before a plan_wait starts is returned at once, not missed while the wait looks for a later one.
   */
  async save(p, { byAgent = true } = {}) {
    p.updated = Date.now();
    p.version = (p.version || 0) + 1;
    if (byAgent) p.seen = p.version;
    await this.ctx.storage.put(`plan:${p.id}`, p);
    for (const w of this.waiters.splice(0)) w();
  }
  async shownToAgent(p) {
    if (p.seen !== p.version) { p.seen = p.version; await this.ctx.storage.put(`plan:${p.id}`, p); }
    return this.view(p);
  }
  /* what the owner's web app is shown: everything but the agent's own bookkeeping */
  shown(p, me) { return { id: p.id, room: p.room, title: p.title, agent: { id: me.id, name: me.name }, state: p.state, items: p.items, results: p.results, receipts: p.receipts, why: p.why || null }; }
  async mirror(p) {
    const me = await this.me();
    return ROOM_STUB(this.env, p.room).show(this.shown(p, me));
  }

  /* each call: one change to one plan, or a read; a refusal comes back as {refused} (an RPC throw loses its class) */
  async tool(name, args) {
    try {
      return await this.run(name, args);
    } catch (e) {
      if (e instanceof Refused) return { refused: e.message };
      throw e;
    }
  }

  async run(name, args) {
    const me = await this.me();
    if (name === 'status') {
      const plans = (await this.ctx.storage.list({ prefix: 'plan:' })).values();
      const out = { agent_id: me.id, plans: [...plans].map((p) => ({ plan_id: p.id, title: p.title, identity: p.identity, state: p.state, items: p.items.length })) };
      if (args.identity !== undefined) {
        const identity = identityArg(args.identity);
        out.identity = { identity_public_key: identity, ...(await ROOM_STUB(this.env, roomOf(identity)).agentStatus(me)) };
      }
      return out;
    }
    if (name === 'plan_new') {
      const identity = identityArg(args.identity);
      const p = { id: randomHex(8), title: text(args.title, 'title'), identity, room: roomOf(identity), state: 'draft', items: [], results: {}, receipts: [], created: Date.now() };
      await this.save(p);
      const seen = await this.mirror(p);
      return { plan_id: p.id, identity, ...seen };
    }
    const p = await this.plan(String(args.plan_id || ''));
    need(p, `no plan ${args.plan_id} - plan_new makes one`);
    const draft = () => need(p.state === 'draft', `the plan is ${p.state}: only a draft changes`);
    const itemOf = (n) => {
      const it = p.items.find((x) => x.item === Number(n));
      need(it, `no item ${n} in the plan`);
      return it;
    };
    const opArgs = () => {
      need(OPS.includes(args.op), `op: ${OPS.join(' or ')}`);
      const k = args.key || {};
      need(KINDS.includes(k.kind), `key.kind: ${KINDS.join(' or ')}`);
      return { op: args.op, key: { kind: k.kind, identity: text(k.identity, 'key.identity') }, reason: text(args.reason, 'reason') };
    };
    const dataArg = () => {
      const enc = args.encoding || 'text';
      need(enc === 'text' || enc === 'base64', 'encoding: text or base64');
      need(typeof args.data === 'string' && args.data.length > 0 && args.data.length <= MAX_DATA, `data: 1 to ${MAX_DATA} characters`);
      if (enc === 'base64') need(/^[A-Za-z0-9+/]*={0,2}$/.test(args.data) && args.data.length % 4 === 0, 'data: not base64');
      return { data: args.data, encoding: enc };
    };
    const nextItem = () => p.items.reduce((m, x) => Math.max(m, x.item), 0) + 1;

    switch (name) {
      case 'plan_show':
        return this.shownToAgent(p);
      case 'plan_target': {
        draft();
        const identity = identityArg(args.identity);
        if (identity === p.identity) return this.view(p);
        const old = p.room;
        p.identity = identity;
        p.room = roomOf(identity);
        await this.save(p);
        await ROOM_STUB(this.env, old).withdraw(p.id, 'moved to another identity');
        return { ...this.view(p), ...(await this.mirror(p)) };
      }
      case 'plan_add':
      case 'plan_hold': {
        draft();
        need(p.items.length < MAX_ITEMS, `a plan holds up to ${MAX_ITEMS} items`);
        const it = { item: nextItem(), ...opArgs(), ...(name === 'plan_add' ? dataArg() : { data: null, held: true }) };
        p.items.push(it);
        await this.save(p);
        await this.mirror(p);
        return { item: it.item, ...this.view(p) };
      }
      case 'plan_remove': {
        draft();
        const it = itemOf(args.item);
        p.items = p.items.filter((x) => x !== it);
        await this.save(p);
        await this.mirror(p);
        return this.view(p);
      }
      case 'plan_submit': {
        draft();
        need(p.items.length > 0, 'an empty plan: add an item first');
        const r = await ROOM_STUB(this.env, p.room).submit(this.shown({ ...p, state: 'submitted' }, me));
        need(r.ok, r.why);
        p.state = 'submitted';
        await this.save(p);
        return this.view(p);
      }
      case 'plan_fill': {
        need(p.state === 'running' || p.state === 'paused', `the plan is ${p.state}: a placeholder is filled while it runs`);
        const it = itemOf(args.item);
        need(it.held && it.data === null, `item ${it.item} is not a placeholder waiting for its data`);
        Object.assign(it, dataArg());
        await this.save(p);
        const r = await ROOM_STUB(this.env, p.room).fill(p.id, it.item, { data: it.data, encoding: it.encoding });
        need(r.ok, r.why);
        return this.view(p);
      }
      case 'plan_finish': {
        need(['submitted', 'running', 'paused'].includes(p.state), `the plan is ${p.state}: nothing to finish`);
        const r = await ROOM_STUB(this.env, p.room).finish(p.id);
        need(r.ok, r.why);
        p.finishing = true;
        await this.save(p);
        return this.view(p);
      }
      case 'plan_wait': {
        /* anything the agent has not been shown returns at once; else the next change, or the time is up */
        const seconds = Math.max(0, Math.min(WAIT_MAX_S, Number(args.seconds) || 30));
        const end = Date.now() + seconds * 1000;
        for (;;) {
          const now = await this.plan(p.id);
          if (now.version !== now.seen || ['done', 'declined', 'failed', 'ended'].includes(now.state) || Date.now() >= end) return this.shownToAgent(now);
          await new Promise((resolve) => {
            const t = setTimeout(resolve, end - Date.now());
            this.waiters.push(() => { clearTimeout(t); resolve(); });
          });
        }
      }
      default:
        throw new Refused(`no tool ${name}`);
    }
  }

  /* what the agent reads: the plan, its results, and the placeholders still waiting for data */
  view(p) {
    return {
      plan_id: p.id, title: p.title, identity: p.identity, state: p.state, why: p.why || null,
      items: p.items.map(({ item, op, key, reason, held, data }) => ({ item, op, key, reason, ...(held ? { placeholder: true, filled: data !== null } : {}) })),
      results: p.results, waiting: p.items.filter((x) => x.held && x.data === null).map((x) => x.item), receipts: p.receipts,
    };
  }

  /**
   * What the owner did, from their room (index.js, an owner device's mcp-re): the plan's state - declined, running,
   * paused (waiting for a placeholder), done, failed, ended - with results by item and the receipts. The room has
   * checked the plan is its own and the device joined; here the plan must be this agent's and past its draft.
   */
  async fromRoom(roomId, u) {
    const p = await this.plan(String(u.plan || ''));
    if (!p || p.room !== roomId || p.state === 'draft') return { ok: false, why: 'not a submitted plan of that identity' };
    if (u.state) {
      const STATES = ['declined', 'running', 'paused', 'done', 'failed', 'ended'];
      if (!STATES.includes(u.state)) return { ok: false, why: `state: ${STATES.join(' | ')}` };
      p.state = u.state;
    }
    if (typeof u.why === 'string') p.why = u.why.slice(0, MAX_TEXT);
    for (const r of Array.isArray(u.results) ? u.results : []) {
      if (!p.items.some((x) => x.item === r.item)) continue;
      const kept = {};
      for (const k of ['signature', 'plaintext', 'refusal', 'encoding']) if (typeof r[k] === 'string') kept[k] = r[k].slice(0, MAX_DATA);
      p.results[r.item] = kept;
    }
    if (Array.isArray(u.receipts)) p.receipts = u.receipts.slice(0, 256).map((x) => (typeof x === 'object' && x ? { seq: Number(x.seq), code: String(x.code || '').slice(0, 40) } : null)).filter(Boolean);
    await this.save(p, { byAgent: false });    return { ok: true };
  }
}
