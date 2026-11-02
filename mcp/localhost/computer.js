/**
 * THIS COMPUTER'S LOCAL MCP (Brad, 2026-11-01: "the desktop app should be running a local mcp"; 2026-10-30: "--service =
 * the local MCP"; S5c, 2026-11-02): hosted by the computer's MEMBER (desktop/member.js) - the desktop app while it is
 * open, `onlykey-js --service` when it is not - so an agent on this computer always finds it at the same address, and
 * the two never hold it at once (a member that steps down closes it first).
 *
 * The mcp-server Rectify app (core + localhost) on http:// and ws:// at 127.0.0.1:8650 - never another interface. The
 * same routes and logic as the hosted one: /mcp for agents on this machine, /ws/<identity> where this computer's member
 * joins to hear their plans and answer them. It keeps no sealed copy - the bucket stays in its file.
 *
 *   startComputerMcp({log}) -> {url, close()}    also says where it runs: ~/.onlykey-js/local-mcp-computer.json
 */
import Rectify from '@bmatusiak/rectify';
import core from '../core/plugin.js';
import localhost from './plugin.js';
import trust from '../../desktop/trust.js';

/*
 * ONE ADDRESS, ALWAYS (Brad, 2026-11-02: "80 = http web, 65 = OK" - OK on a phone keypad; "8650 - web is surrounded
 * around ok", as 8065 is Mattermost's default): an agent's MCP config names a URL - Claude Code's
 * `claude mcp add --transport http okedge http://127.0.0.1:8650/mcp` - so the port cannot be a new one each start. Taken
 * by another program, it does not start and says so (no other port: an agent would not find it).
 */
export const PORT = 8650;

export async function startComputerMcp({ log = () => {} } = {}) {
  const app = Rectify.build([core, localhost]);
  await app.start();
  /*
   * NO AUTH HERE (Brad, 2026-11-01: "the local mcp has no auth, but it still will communicate with the desktop app for
   * the planner and budget calls"): the login proves the key to the user's server, or the member checks it itself; this
   * room only carries this computer's agents to its member - any well-formed join for the identity enters (OPEN_JOIN).
   */
  let server;
  try {
    server = await app.services.mcpLocalhost.start({ host: '127.0.0.1', port: PORT, env: { REQUIRE_LOGIN: '0', OPEN_JOIN: '1' } });
  } catch (e) {
    if (e && e.code === 'EADDRINUSE') throw Object.assign(new Error(`127.0.0.1:${PORT} is taken by another program`), { code: 'EADDRINUSE' });
    throw e;
  }
  /* where it runs, for the agents and the CLI on this computer */
  try { trust.writeLocalMcp({ url: server.url, what: 'computer' }); } catch (e) { log(`its record was not written: ${(e && e.message) || e}`); }
  return {
    url: server.url,
    async close() {
      try { trust.removeLocalMcp({ what: 'computer' }); } catch { /* none */ }
      await server.close().catch(() => undefined);
    },
  };
}
