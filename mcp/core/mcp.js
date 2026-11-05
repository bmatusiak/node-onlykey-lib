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
 * FINGERPRINTS FIRST, DATA AFTER (Brad, 2026-11-04: "all ready, hashed, fingerprinted before sending; on budget approval,
 * then the data passes to the desktop app ... at the end of the budget, the results are sent back"): plan_new names
 * every item with the SHA-256 of its data and no data; the owner approves the count and the fingerprints; once the
 * budget is open (plan_wait: running) plan_data sends the data, which the device checks against the fingerprints before
 * the key signs any of it; the results come back together when the budget ends.
 *
 * UNDER THE AGENT'S OWN CARD (edge/src/agents.js): every plan names one, made for this agent with card_new - the owner
 * approves it once and the key certifies it at a press; its keys bound every budget the agent asks.
 *
 * Trust: the server relays over TLS; nothing is sealed end to end (decided 2026-10-28: "sealing e2e will require a lot
 * of tooling"). What the server never does: hold a key, approve, or answer for the owner.
 */
import bucketLib from '../../bucket/src/index.js';
import bytes from '../../src/bytes.js';
import x509 from '../../src/crypto/x509.js';

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
const KINDS = ['ssh', 'gpg', 'rsa'];
/* the RSA keys a card names, each by its X.509 certificate (card_new certs) */
const MAX_CERTS = 4;
const LABEL = /^[ -~]{1,64}$/;
const STATES = ['declined', 'running', 'done', 'failed', 'ended'];

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

/* one item of plan_new: what it signs with, why, and the fingerprint of the data it will be sent */
const itemArgs = (it, n) => {
  need(it && typeof it === 'object', `item ${n}: {op, key, reason, fingerprint}`);
  need(OPS.includes(it.op), `item ${n}: op ${OPS.join(' or ')}`);
  const k = it.key || {};
  need(KINDS.includes(k.kind), `item ${n}: key.kind ${KINDS.join(', ')}`);
  let key;
  if (k.kind === 'rsa') {
    /* named by its certificate's SHA-256 - one the card holds; the owner's device knows which slot that is */
    const cert = typeof k.cert === 'string' ? k.cert.trim().toLowerCase() : '';
    need(HEX64.test(cert), `item ${n}: an rsa key is named by key.cert - the SHA-256 (64 hex) of a certificate your card holds`);
    key = { kind: 'rsa', cert };
  } else key = { kind: k.kind, identity: text(k.identity, `item ${n}: key.identity`) };
  const fingerprint = typeof it.fingerprint === 'string' ? it.fingerprint.trim().toLowerCase() : '';
  need(HEX64.test(fingerprint), `item ${n}: fingerprint - the SHA-256 of its data, 64 hex`);
  return { op: it.op, key, reason: text(it.reason, `item ${n}: reason`), fingerprint };
};
/* one item's data in plan_data: text, or base64 for bytes */
const dataArg = (d) => {
  const enc = d.encoding || 'text';
  need(enc === 'text' || enc === 'base64', 'encoding: text or base64');
  need(typeof d.data === 'string' && d.data.length > 0 && d.data.length <= MAX_DATA, `data: 1 to ${MAX_DATA} characters`);
  if (enc === 'base64') need(/^[A-Za-z0-9+/]*={0,2}$/.test(d.data) && d.data.length % 4 === 0, 'data: not base64');
  return { data: d.data, encoding: enc };
};
const bytesOf = (one) => (one.encoding === 'base64' ? bytes.fromBase64(one.data) : new TextEncoder().encode(one.data));

/* ------------------------------------------------------------------------------------------------ the tools */

const KEY_SCHEMA = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: KINDS, description: 'ssh or gpg: an agent-derived key Edge uses; rsa: a key stored on the OnlyKey' },
    identity: { type: 'string', description: 'ssh / gpg: the key\'s label, e.g. "you@example.com" (gpg) or "ssh://user@host" (ssh)' },
    cert: { type: 'string', description: 'rsa: the SHA-256 (64 hex) of the key\'s X.509 certificate - one your card holds (card_new certs)' },
  },
  required: ['kind'],
};
const ITEM_SCHEMA = {
  type: 'object',
  properties: {
    op: { type: 'string', enum: OPS },
    key: KEY_SCHEMA,
    reason: { type: 'string', description: 'why, in a few words - the owner reads it before approving' },
    fingerprint: { type: 'string', description: 'SHA-256 of the exact bytes this item will sign (64 hex) - its data comes after the approval (plan_data)' },
  },
  required: ['op', 'key', 'reason', 'fingerprint'],
};

export const TOOLS = [
  { name: 'hello', description: 'Start here. Name yourself; the first time you get an agent_key - keep it and send it in every later hello, so the owners who accepted you know you again.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, agent_key: { type: 'string', description: '64 hex characters, from your first hello' } }, required: ['name'] } },
  { name: 'status', description: 'Your plans, and for an identity: whether its owner has accepted you, and whether the owner is online.',
    inputSchema: { type: 'object', properties: { identity: { type: 'string', description: 'an identity public key (64 hex)' } } } },
  { name: 'card_new', description: 'Ask the owner for your agent card: the keys your plans may use, under a label of your choosing. The owner approves it once and their key certifies it at a press; plan_wait on the plan_id it gives says when. Every plan names it.',
    inputSchema: { type: 'object', properties: {
      identity: { type: 'string' }, label: { type: 'string', description: 'the card\'s label, 1-64 printable characters, fixed for good' },
      certs: { type: 'array', items: { type: 'string' }, description: 'RSA keys on the OnlyKey, each named by its X.509 certificate (PEM): the owner\'s device finds the key it certifies - you never name a slot' },
      ssh: { type: 'string', description: 'an ssh identity to derive, ssh://user@host' },
      days: { type: 'integer', description: 'how long it lasts, in days (0 = until revoked)' },
      reason: { type: 'string', description: 'why you need it - the owner reads it' },
    }, required: ['identity', 'label', 'reason'] } },
  { name: 'plan_new', description: 'A new plan for an identity (its public key, 64 hex), under your card: every item with the SHA-256 of its data - no data yet. Its owner sees it in their web app at once, and every change after.',
    inputSchema: { type: 'object', properties: { identity: { type: 'string' }, title: { type: 'string' }, card: { type: 'string', description: 'your card\'s label (card_new)' }, items: { type: 'array', items: ITEM_SCHEMA } }, required: ['identity', 'title', 'card', 'items'] } },
  { name: 'plan_target', description: 'Move a draft plan to another identity: withdrawn from the old owner\'s web app, shown in the new one\'s.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, identity: { type: 'string' } }, required: ['plan_id', 'identity'] } },
  { name: 'plan_remove', description: 'Remove one item from a draft plan.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, item: { type: 'integer' } }, required: ['plan_id', 'item'] } },
  { name: 'plan_show', description: 'The plan as it is now (read only).',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
  { name: 'plan_submit', description: 'Ask the owner to approve the plan - the item count and their fingerprints: one budget sized to it, one press. Refused until the owner has accepted you, or while no owner device is online.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
  { name: 'plan_data', description: 'Once the plan runs (its budget is open): the items\' data (base64 when it is bytes, encoding: "base64"). Each must match its fingerprint, or nothing is signed.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, items: { type: 'array', items: { type: 'object', properties: { item: { type: 'integer' }, data: { type: 'string' }, encoding: { type: 'string', enum: ['text', 'base64'] } }, required: ['item', 'data'] } } }, required: ['plan_id', 'items'] } },
  { name: 'plan_wait', description: 'Wait (up to 60 s) for the plan to move on: its state, the items whose data it still waits for, and at its end every item\'s result (signature or refusal) and the receipts.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' }, seconds: { type: 'integer' } }, required: ['plan_id'] } },
  { name: 'plan_finish', description: 'End the plan\'s budget now: if its data has not all come, nothing is signed.',
    inputSchema: { type: 'object', properties: { plan_id: { type: 'string' } }, required: ['plan_id'] } },
];

const INSTRUCTIONS = 'OnlyKey Edge control. Your owner gives you this URL and their identity public key. '
  + 'Say hello (keep the agent_key you get the first time); once, ask for your card (card_new) and plan_wait for its '
  + 'approval. Then build a plan under it: plan_new with every item\'s SHA-256 fingerprint and no data, plan_submit - the '
  + 'owner sees it live in their web app, accepts you once, approves the plan and presses their key once. When '
  + 'plan_wait says running, send the data (plan_data); plan_wait gives every result when the budget ends.';

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
  /* a plan's items go out with their fingerprints and never their data: the data goes to the device that runs it (plan_data) */
  shown(p, me) {
    return {
      id: p.id, kind: p.kind || 'plan', room: p.room, title: p.title, agent: { id: me.id, name: me.name }, state: p.state,
      ...(p.card ? { card: p.card } : {}), ...(p.ask ? { ask: p.ask } : {}),
      items: p.items.map(({ item, op, key, reason, fingerprint }) => ({ item, op, key, reason, fingerprint })),
      results: p.results, receipts: p.receipts, why: p.why || null,
    };
  }
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
    if (name === 'card_new') {
      /*
       * THE AGENT'S CARD, ASKED (agents.js answer): a plan of kind 'card', submitted at once - the owner's device shows the
       * card sheet (its label, keys and who asks), the person approves, the key certifies it at a press, and the device
       * binds it to this agent's id. plan_wait on it says done, declined or failed.
       */
      const identity = identityArg(args.identity);
      const label = text(args.label, 'label', { max: 64 });
      need(LABEL.test(label), 'label: 1-64 printable characters');
      /*
       * THE KEYS BY THEIR CERTIFICATES (Brad, 2026-11-04: "we upload the pubcert as the label to select RSA3"): the agent
       * never names a slot. It sends the certificate it holds; the owner's device finds the slot whose public key it is,
       * shows the certificate on the card sheet, and keeps it in the owner's Key Chain. Read here, so what is not an RSA
       * certificate is refused before it reaches anyone.
       */
      const certs = args.certs === undefined ? [] : args.certs;
      need(Array.isArray(certs) && certs.length <= MAX_CERTS, `certs: up to ${MAX_CERTS} PEM certificates`);
      const read = certs.map((pem, i) => {
        need(typeof pem === 'string' && pem.length <= 8192, `certs[${i}]: a PEM certificate`);
        try { return { pem: pem.trim(), sha256: x509.read(pem).sha256 }; } catch (e) { throw new Refused(`certs[${i}]: ${e.message}`); }
      });
      const ssh = args.ssh === undefined ? null : text(args.ssh, 'ssh');
      need(ssh === null || /^ssh:\/\/\S+$/.test(ssh), 'ssh: ssh://user@host');
      need(read.length || ssh, 'a card names at least one key: certs or ssh');
      const days = args.days === undefined ? 0 : Number(args.days);
      need(Number.isInteger(days) && days >= 0 && days <= 3650, 'days: 0 (until revoked) to 3650');
      const ask = { label, certs: read.filter((c, i) => read.findIndex((x) => x.sha256 === c.sha256) === i),...(ssh ? { ssh } : {}), days, reason: text(args.reason, 'reason') };
      const p = { id: randomHex(8), kind: 'card', title: `agent card "${label}"`, identity, room: roomOf(identity), state: 'draft', ask, items: [], results: {}, receipts: [], created: Date.now() };
      await this.save(p);
      await this.mirror(p);
      /*
       * submitted at once when it can be; while the owner has not accepted this agent (it is shown to them now, pending)
       * it stays a draft and says why - plan_submit sends it once they have, as a plan's
       */
      const r = await ROOM_STUB(this.env, p.room).submit(this.shown({ ...p, state: 'submitted' }, me));
      if (r.ok) p.state = 'submitted';
      else p.why = r.why;
      await this.save(p);
      return this.view(p);
    }
    if (name === 'plan_new') {
      const identity = identityArg(args.identity);
      const card = text(args.card, 'card', { max: 64 });
      need(Array.isArray(args.items) && args.items.length > 0 && args.items.length <= MAX_ITEMS, `items: 1 to ${MAX_ITEMS}, each {op, key, reason, fingerprint}`);
      const items = args.items.map((it, n) => ({ item: n + 1, ...itemArgs(it, n + 1) }));
      const p = { id: randomHex(8), title: text(args.title, 'title'), identity, room: roomOf(identity), card, state: 'draft', items, results: {}, receipts: [], created: Date.now() };
      await this.save(p);
      const seen = await this.mirror(p);
      return { ...this.view(p), ...seen };
    }
    const p = await this.plan(String(args.plan_id || ''));
    need(p, `no plan ${args.plan_id} - plan_new makes one`);
    const draft = () => need(p.state === 'draft', `the plan is ${p.state}: only a draft changes`);
    const itemOf = (n) => {
      const it = p.items.find((x) => x.item === Number(n));
      need(it, `no item ${n} in the plan`);
      return it;
    };
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
        need(p.kind === 'card' || p.items.length > 0, 'an empty plan: add an item first');
        /* a reason a draft kept (card_new before the owner accepted) is not the submitted plan's */
        const r = await ROOM_STUB(this.env, p.room).submit(this.shown({ ...p, state: 'submitted', why: null }, me));
        need(r.ok, r.why);
        p.state = 'submitted';
        p.why = null;
        await this.save(p);
        return this.view(p);
      }
      case 'plan_data': {
        need(p.kind !== 'card', 'a card ask takes no data');
        need(p.state === 'running', `the plan is ${p.state}: its data is sent once it runs (its budget is open - plan_wait)`);
        need(Array.isArray(args.items) && args.items.length > 0, 'items: [{item, data, encoding}]');
        /* checked here first (a wrong one is refused at once, nothing sent); the device checks again before the key signs */
        const sent = [];
        for (const d of args.items) {
          const it = itemOf(d && d.item);
          need(!it.sent, `item ${it.item}'s data was sent already`);
          const one = dataArg(d);
          need(await sha256Hex(bytes.toHex(bytesOf(one))) === it.fingerprint, `item ${it.item}'s data does not match its fingerprint ${it.fingerprint.slice(0, 16)} - not sent`);
          sent.push([it, one]);
        }
        for (const [it, one] of sent) {
          const r = await ROOM_STUB(this.env, p.room).data(p.id, it.item, one);
          need(r.ok, r.why);
          it.sent = true;
        }
        await this.save(p);
        return this.view(p);
      }
      case 'plan_finish': {
        need(['submitted', 'running'].includes(p.state), `the plan is ${p.state}: nothing to finish`);
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

  /* what the agent reads: the plan, the items whose data the running plan still waits for, and at its end the results */
  view(p) {
    return {
      plan_id: p.id, kind: p.kind || 'plan', title: p.title, identity: p.identity, state: p.state, why: p.why || null,
      ...(p.card ? { card: p.card } : {}), ...(p.ask ? { ask: p.ask } : {}),
      items: p.items.map(({ item, op, key, reason, fingerprint, sent }) => ({ item, op, key, reason, fingerprint, sent: !!sent })),
      results: p.results, waiting: p.state === 'running' ? p.items.filter((x) => !x.sent).map((x) => x.item) : [], receipts: p.receipts,
    };
  }

  /**
   * What the owner did, from their room (index.js, an owner device's mcp-re): the plan's state - declined, running (its
   * budget open: the data may come), done, failed, ended - with results by item and the receipts. The room has checked
   * the plan is its own and the device joined; here the plan must be this agent's and past its draft.
   */
  async fromRoom(roomId, u) {
    const p = await this.plan(String(u.plan || ''));
    if (!p || p.room !== roomId || p.state === 'draft') return { ok: false, why: 'not a submitted plan of that identity' };
    if (u.state) {
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
