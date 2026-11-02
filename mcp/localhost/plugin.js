/*
 * THE LOCALHOST SERVICE (a Rectify plugin - the mcp-server's runtime in plain Node; Brad, 2026-11-01: "localhost running
 * local without the cloudflare overhead"; "so the desktop can re-use the core and websocket to host the mcp and
 * authenticate itself, like it was talking to the remote mcp"; "local only, only need plain, no cert needed").
 *
 * The core's logic on http:// and ws:// at 127.0.0.1 - the same routes as the Worker:
 *   /mcp       the MCP face, for agents on this machine
 *   /ws/<id>   an identity's room: the same challenge and join (the login proof required - REQUIRE_LOGIN '1'), frames,
 *              peers, the agents' room side
 *   /          the web app's files when `assets` names them (the Worker's ASSETS: docs/, a single-page app), else a
 *              plain page naming the server
 * What Cloudflare gives a Durable Object, given here: storage per room / session / agent (in memory), its sockets with
 * their attachments, its alarm as a timer - and, with `sealed`, each room's SQLite (node:sqlite, in memory) for the
 * sealed copy. Without it the room keeps none and says so ({on: false}): the desktop's bucket stays in its own file.
 *
 * THE WEB APP ON IT (Brad, 2026-11-01: "test webapp with local mcp + websocket embedded, localhost plugin will host the
 * webapp files"): a page reaches a key over FIDO2 only from a secure origin on the key's site, so `tls` serves it as
 * https with the box's dev certificate, under the site's name mapped to this machine - the deployed path, one process.
 *
 * THE PHONE ON IT (Brad, 2026-11-01: "bucket-data-storage-container ~ android <-> remote-mcp ~ ..."): a phone trusts no
 * dev certificate and reaches this machine only through `adb reverse` to a port of its own 127.0.0.1 - so `plain` is a
 * second listener, plain http on this host, with the same routes and the same rooms (one process, one sealed copy).
 *
 * THE PHONE OVER BLUETOOTH (ok-edge plan B2; Brad, 2026-11-01: "the mcp server should make communication with ble
 * transparent"): with `ble`, ble.js holds a Bluetooth link to the phone and hands each socket the phone opens to the
 * room here, as an upgrade is - the same attach(), origin 'ble' (the room then asks it for the login proof).
 *
 *   mcpLocalhost.start({host = '127.0.0.1', port = 0, env = {}, assets = null, tls = null, sealed = false, plain = null, ble = null})
 *     assets: a directory to serve;  tls: {key, cert} (PEM);  sealed: true for the sealed copy (needs node:sqlite)
 *     plain: a port for a second, plain http listener beside the tls one
 *     ble: {addresses?, host?, log?, createLink?} - ble.js startBle's options
 *     -> {url, port, plainUrl, ble: {host, phones()} | null, close()}
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import pathOf from 'node:path';
import { startBle } from './ble.js';

/*
 * `ws` - AN OPTIONAL PEER of node-onlykey-lib, as node-hid is (the web app and the phone never need a websocket SERVER):
 * loaded when a server starts, from the host that runs it (ok-edge's desktop app and tools have it). ws 7 names the class
 * Server, ws 8 WebSocketServer - and neither has ESM named exports.
 */
async function webSocketServer() {
  let WS;
  try { WS = (await import('ws')).default; } catch {
    throw Object.assign(new Error('the local MCP needs "ws" (an optional peer of node-onlykey-lib, as node-hid is) - install it beside node-onlykey-lib'), { code: 'ENOWS' });
  }
  return WS.WebSocketServer || WS.Server;
}

const clone = (v) => (v === undefined ? undefined : structuredClone(v));

/*
 * A DURABLE OBJECT'S SQL, AS THE CORE USES IT: exec(query, ...bindings) -> a cursor with toArray(). One in-memory
 * database per room (node:sqlite's DatabaseSync, Node 22.5+) - gone with the process, as the copy is only a carrier: the
 * devices keep their buckets.
 */
function memorySql(DatabaseSync) {
  const db = new DatabaseSync(':memory:');
  return {
    exec(query, ...bindings) {
      const st = db.prepare(query);
      const rows = /^\s*SELECT\b/i.test(query) ? st.all(...bindings) : (st.run(...bindings), []);
      return { toArray: () => rows.map((r) => ({ ...r })) };
    },
    close: () => db.close(),
  };
}

/* what Cloudflare's ctx.storage gives the core: key-value, and one alarm (fire is set by the namespace) */
function memoryStorage(DatabaseSync) {
  const kv = new Map();
  let alarmAt = null;
  let timer = null;
  const sql = DatabaseSync ? memorySql(DatabaseSync) : null;
  const storage = {
    fire: null,
    sql: sql || undefined,
    async get(k) { return clone(kv.get(k)); },
    async put(k, v) { kv.set(k, clone(v)); },
    async delete(k) { return kv.delete(k); },
    async deleteAll() { kv.clear(); },
    async list({ prefix = '' } = {}) { return new Map([...kv].filter(([k]) => k.startsWith(prefix)).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [k, clone(v)])); },
    async getAlarm() { return alarmAt; },
    async setAlarm(at) {
      alarmAt = at;
      clearTimeout(timer);
      timer = setTimeout(() => { alarmAt = null; if (storage.fire) storage.fire(); }, Math.max(0, at - Date.now()));
      if (timer.unref) timer.unref();
    },
    stop() { clearTimeout(timer); if (sql) sql.close(); },
  };
  return storage;
}

/* a namespace of instances by name, as env.ROOMS / AGENTS / MCP_SESSIONS - each with a ctx of its own */
function namespace(Core, env, all, DatabaseSync = null) {
  const made = new Map();
  return {
    idFromName: (name) => String(name),
    get(id) {
      if (!made.has(id)) {
        const storage = memoryStorage(DatabaseSync);
        const sockets = new Set();
        const ctx = { storage, sockets, acceptWebSocket: (ws) => sockets.add(ws), getWebSockets: () => [...sockets] };
        const core = new Core(ctx, env);
        if (typeof core.alarm === 'function') storage.fire = () => core.alarm().catch(() => undefined);
        made.set(id, core);
        all.push(storage);
      }
      return made.get(id);
    },
    /* the instances made so far, [id, core] */
    made: () => [...made.entries()],
  };
}

/* a Node socket as the core handles a Durable Object's: its attachment kept on it */
function attachable(ws) {
  let att = null;
  ws.serializeAttachment = (v) => { att = clone(v); };
  ws.deserializeAttachment = () => clone(att);
  return ws;
}

/* a Node request as a fetch Request (the MCP face takes one), its answer written back */
async function asRequest(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = chunks.length ? Buffer.concat(chunks) : null;
  return new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? null : body });
}
/* a file of the web app, or its index.html for any other path (a single-page app, as the Worker's not_found_handling) */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml', '.ttf': 'font/ttf', '.woff2': 'font/woff2', '.map': 'application/json', '.wasm': 'application/wasm', '.webmanifest': 'application/manifest+json' };
function serveAsset(dir, urlPath, res) {
  const root = pathOf.resolve(dir);
  let f = pathOf.join(root, decodeURIComponent(urlPath));
  if (f !== root && !f.startsWith(root + pathOf.sep)) { res.writeHead(403); return res.end(); }
  if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = pathOf.join(root, 'index.html');
  /* no-store: a --dev export names its bundle the same every build, so a cached copy would not be the new one */
  res.writeHead(200, { 'content-type': TYPES[pathOf.extname(f)] || 'application/octet-stream', 'cache-control': 'no-store' });
  fs.createReadStream(f).pipe(res);
}

async function writeResponse(res, response) {
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}

export default function setup(imports, register) {
  const { mcpCore } = imports;
  register(null, {
    mcpLocalhost: {
      async start({ host = '127.0.0.1', port = 0, env: settings = {}, assets = null, tls = null, sealed = false, plain = null, ble = null } = {}) {
        const storages = [];
        const env = { REQUIRE_LOGIN: '1', LIFETIME_IDENTITIES: '*', ...settings };
        /* node:sqlite only when asked: Electron's Node may not have it, and the desktop keeps no sealed copy */
        const DatabaseSync = sealed ? (await import('node:sqlite')).DatabaseSync : null;
        env.ROOMS = namespace(mcpCore.RoomCore, env, storages, DatabaseSync);
        env.AGENTS = namespace(mcpCore.AgentSessionCore, env, storages);
        env.MCP_SESSIONS = namespace(mcpCore.McpSessionCore, env, storages);
        const WebSocketServer = await webSocketServer();
        const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 + 1024 });
        /* the Bluetooth link (ble.js), once started below */
        let bt = null;
        const handler = async (req, res) => {
          try {
            const path = new URL(req.url, 'http://x').pathname;
            if (path === '/mcp') return writeResponse(res, await mcpCore.handleMcp(await asRequest(req), env));
            if (mcpCore.ROOM_PATH.test(path)) { res.writeHead(426); return res.end('a websocket only'); }
            if (path === '/ble' && bt) return bleRooms(req, res);
            if (assets) return serveAsset(assets, path, res);
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            return res.end('<!doctype html><title>ok-edge</title><p>The local MCP: /mcp for agents, /ws/&lt;identity&gt; for this computer\'s app.</p>');
          } catch (e) {
            res.writeHead(500);
            res.end(String(e && e.message || e));
          }
        };
        const server = tls ? https.createServer({ key: tls.key, cert: tls.cert }, handler) : http.createServer(handler);
        /* a socket into its room - a websocket's, or a phone's over Bluetooth (ble.js): the same room either way */
        const attach = (raw, roomId, url, origin = null) => {
          if (!mcpCore.ROOM_PATH.test(`/ws/${roomId}`)) return false;
          const ws = attachable(raw);
          const room = env.ROOMS.get(roomId);
          ws.on('message', (data, isBinary) => {
            const text = isBinary ? null : data.toString('utf8');
            /* pings answered here, as Cloudflare's auto-response does - the room is not asked */
            if (text === '{"t":"ping"}') { ws.send('{"t":"pong"}'); return; }
            room.webSocketMessage(ws, isBinary ? data : text).catch(() => undefined);
          });
          const gone = () => { room.webSocketClose(ws).catch(() => undefined).finally(() => room.ctx.sockets.delete(ws)); };
          ws.on('close', gone);
          ws.on('error', gone);
          room.accept(ws, url, { origin }).catch(() => ws.close(1011, 'not accepted'));
          return true;
        };
        const onUpgrade = (req, socket, head) => {
          const url = new URL(req.url, `http://${req.headers.host}`);
          const m = mcpCore.ROOM_PATH.exec(url.pathname);
          if (!m) { socket.destroy(); return; }
          wss.handleUpgrade(req, socket, head, (raw) => attach(raw, m[1], url));
        };
        server.on('upgrade', onUpgrade);
        const second = plain && tls ? http.createServer(handler) : null;
        if (second) second.on('upgrade', onUpgrade);
        const listen = (s, p) => new Promise((resolve, reject) => {
          s.once('error', reject);
          s.listen(p, host, () => resolve(s.address().port));
        });
        const p = await listen(server, port);
        const p2 = second ? await listen(second, plain) : null;
        /*
         * WHICH ROOM THE PHONE IS IN (ok-edge plan B4): this computer's onlykey-js --ble asks, to reach the phone's key as
         * an agent of that room (bucket room-agent.js). Answered only to this computer itself - the room's id and the
         * phone's device record, what the room tells any agent of it anyway; the agent still waits for the owner to accept it.
         */
        const bleRooms = (req, res) => {
          const from = req.socket.remoteAddress || '';
          if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(from)) { res.writeHead(403); return res.end('this computer only'); }
          const phones = [];
          for (const [room, core] of env.ROOMS.made()) {
            for (const [, a] of core.joined()) if (a.origin === 'ble') phones.push({ room, device: a.device });
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ host: bt.host, phones }));
        };
        bt = ble ? startBle({ ...ble, attach: (raw, roomId, url) => attach(raw, roomId, url, 'ble') }) : null;
        return {
          url: `${tls ? 'https' : 'http'}://${host}:${p}`,
          port: p,
          plainUrl: second ? `http://${host}:${p2}` : null,
          ble: bt ? { host: bt.host, phones: bt.phones } : null,
          close: async () => {
            if (bt) await bt.stop();
            await new Promise((done) => {
              for (const s of storages) s.stop();
              for (const c of wss.clients) c.terminate();
              if (second) second.close();
              server.close(() => done());
            });
          },
        };
      },
    },
  });
}
setup.consumes = ['mcpCore'];
setup.provides = ['mcpLocalhost'];
