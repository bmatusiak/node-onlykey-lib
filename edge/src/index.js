'use strict';

/**
 * OnlyKey Edge: the chain library every host shares (ok-rn's Edge tab, the
 * MCP server, the watcher). Pure, Hermes-clean, no device access - the key's
 * Edge messages come later as a lib plugin, once the firmware plugin exists.
 * Spec: APP.md-L3, L6; numbers in ./codes.
 */
module.exports = {
  codes: require('./codes'),
  chain: require('./chain'),
  grants: require('./grants'),
  receipts: require('./receipts'),
  copy: require('./copy'),
  /* B7: what a use was and whether it stands out - the phone's Live view and onlykey-js edge watch */
  /* B7 stage 2: the agent's signed words about a use (reason, receipt message, a refused TX start) */
  note: require('./note'),
  /* L7 (2026-10-03): the budget request message, the app's side, the agent's side */
  request: require('./request'),
  approve: require('./approve'),
  client: require('./client'),
  /* step 2: EDGE_REQUEST over the Bluetooth vendor channel (OKEDGE_REQUEST 0xF7, kept by the phone for the app) */
  wire: require('./wire'),
  /* onlykey-js edge sync: the phone's log into a computer's copy, and other devices' logs offered to the phone, held there until approved (BLOCKS.md) */
  sync: require('./sync'),
  devices: require('./devices'),
  /* a pure Bluetooth link test: the phone echoes, testing mode only (onlykey-js edge ping) */
  ping: require('./ping'),
  block: require('./block'),
};
