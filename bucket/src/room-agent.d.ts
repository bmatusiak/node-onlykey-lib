/**
 * bucket/src/room-agent.js - A COMPUTER AS AN AGENT OF AN IDENTITY'S ROOM, reaching a device's key through it (ok-edge
 * plan B4; Brad, 2026-11-01: "the phone asks over ble to talk to the mcp-server like it was connected to it over
 * websockets"; "the app authorizes/approves ble over to the host using the same mechanism").
 *
 * The room is the one on a local mcp-server (the box's headless server, later the desktop or `onlykey-js --service`),
 * where a phone joined over Bluetooth. The agent does not join - it holds no login proof - it introduces itself with its
 * agent key ({t:'agent', agent_key, name}); the room keeps it pending until the identity's owner accepts it in the app's
 * Agents list, and passes its key-session messages only while accepted (ok-edge mcp-server core room.js).
 *
 *   const a = await connectAgent({url, room, agentKey, name, WebSocket})  -> {you, state, devices}
 *   a.keyChannel(deviceId)   the channel cli/transport-desktop.js takes ({channel}): desktop/protocol.js messages to the
 *                            device's key session (desktop/session.js) and back
 *
 * The agent key is a secret of this computer's user (the CLI keeps it owner-only beside its home); its sha256 is the
 * agent id the owner sees. Over the network it is a bearer secret - fine on 127.0.0.1, sealed by TLS beyond.
 */
/**
 * @param {{url: string, room: string, agentKey: string, name: string, WebSocket: any, timeoutMs?: number}} o
 * @returns {Promise<object>} the agent connection
 */
export function connectAgent({ url, room, agentKey, name, WebSocket: WS, timeoutMs }: {
    url: string;
    room: string;
    agentKey: string;
    name: string;
    WebSocket: any;
    timeoutMs?: number;
}): Promise<object>;
