/*
 * THE MCP SERVER'S CORE (a Rectify plugin; Brad, 2026-11-01: "break it down into a rectify app: 1 core api, a cloudflare
 * service, and a localhost service"; "the core api will contain MCP and websocket api logic"; "I'm just trying to prevent
 * unnecessary logic, and reuse logic already there").
 *
 * The logic, with no runtime of its own:
 *   mcpCore.handleMcp(request, env)   the MCP face (JSON-RPC over HTTP) - core/mcp.js
 *   mcpCore.RoomCore                  an identity's room: the websocket API (join, frames, peers, the sealed copy, the
 *                                     agents' room side) - core/room.js
 *   mcpCore.McpSessionCore, AgentSessionCore   an MCP session and an agent - core/mcp.js
 *   mcpCore.ROOM_PATH                 /ws/<identity id>
 * Each takes a ctx (storage, sockets, alarm) and env (the namespaces ROOMS / AGENTS / MCP_SESSIONS, settings) from the
 * service that runs it: mcp-cloudflare (Durable Objects) or mcp-localhost (Node, the desktop's local MCP).
 */
import { handleMcp, McpSessionCore, AgentSessionCore } from './mcp.js';
import { RoomCore, ROOM_PATH } from './room.js';

export default function setup(imports, register) {
  register(null, { mcpCore: { handleMcp, RoomCore, McpSessionCore, AgentSessionCore, ROOM_PATH } });
}
setup.consumes = [];
setup.provides = ['mcpCore'];
