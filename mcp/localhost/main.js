/*
 * THE LOCAL MCP, ON ITS OWN (the mcp-server Rectify app in Node - mcp-core + mcp-localhost): for the server tests and a
 * machine without the desktop app. The desktop app composes the same two plugins in Electron's main process.
 *   node node_modules/node-onlykey-lib/mcp/localhost/main.js [--port 8790] [--host 127.0.0.1] [--var KEY=VALUE ...]
 *     [--assets docs] [--tls-key k.pem --tls-cert c.pem] [--sealed] [--plain-port 8787]
 *     [--ble [--ble-address <phone> ...] [--ble-host <name>]]
 *   e.g. --var REQUIRE_LOGIN=0 for the server tests' kept-certificate joins; the web app on the box (as the key's site,
 *   the dev certificate, the sealed copy): --assets docs --tls-key .../apps.crp.to.key --tls-cert .../apps.crp.to.crt --sealed
 *
 * --ble (ok-edge plan B2, the headless server on the box): the phone's sockets over Bluetooth too (ble.js) - the phone by
 * address or Bluetooth name (repeat for more), else the one bonded phone with the OnlyKey service. Linux needs
 * dbus-next (an optional peer of the lib: NODE_PATH to where it is installed works), Windows the noble fork. The radio
 * is checked first: Bluetooth 5.0 or newer (node-onlykey-lib cli/bt-radio.js - a 4.0 radio could not hold the bond).
 * Its lines are "[ble] ...", one per change of state.
 */
import fs from 'node:fs';
import Rectify from '@bmatusiak/rectify';
import radio from '../../cli/bt-radio.js';
import core from '../core/plugin.js';
import localhost from './plugin.js';

const args = process.argv.slice(2);
const at = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const all = (name) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []));
const env = {};
for (let i = 0; i < args.length; i++) if (args[i] === '--var') { const [k, ...v] = String(args[i + 1] || '').split('='); env[k] = v.join('='); }

let ble = null;
if (args.includes('--ble')) {
  const r = await radio.checkRadio();
  if (!r.ok) { console.error(`[ble] ${r.message}`); process.exit(1); }
  ble = { addresses: all('--ble-address'), log: (line) => console.log(`[ble] ${line}`) };
  if (at('--ble-host')) ble.host = at('--ble-host');
}

const app = Rectify.build([core, localhost]);
await app.start();
const tls = at('--tls-key') ? { key: fs.readFileSync(at('--tls-key')), cert: fs.readFileSync(at('--tls-cert')) } : null;
const s = await app.services.mcpLocalhost.start({
  host: at('--host') || '127.0.0.1', port: Number(at('--port') || 8790), env, assets: at('--assets') || null, tls, sealed: args.includes('--sealed'),
  plain: at('--plain-port') ? Number(at('--plain-port')) : null, ble,
});
console.log(`local MCP ready on ${s.url}${s.plainUrl ? ` and ${s.plainUrl}` : ''}${s.ble ? `, and over Bluetooth as ${s.ble.host}` : ''}`);
/*
 * WITH BLUETOOTH, IT SAYS WHERE IT RUNS (~/.onlykey-js/local-mcp-ble.json): onlykey-js --ble on this machine finds it at
 * whatever port it took. Only this kind writes it - the box's stand-in (no --ble) is the web app's server, not this one.
 */
const trust = s.ble ? (await import('../../desktop/trust.js')).default : null;
if (trust) trust.writeLocalMcp({ url: s.plainUrl || s.url, what: 'ble' });
/* Ctrl+C / a stop: the Bluetooth links closed first, so the phone advertises again at once */
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (trust) trust.removeLocalMcp({ what: 'ble' }); s.close().finally(() => process.exit(sig === 'SIGINT' ? 130 : 143)); });
