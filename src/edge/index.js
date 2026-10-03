'use strict';

/**
 * OnlyKey Edge: the chain library every host shares (ok-rn's Edge tab, the
 * MCP server, the watcher). Pure, Hermes-clean, no device access - the key's
 * Edge messages come later as a lib plugin, once the firmware plugin exists.
 * Spec: onlykey-edge/build/okrn-edge-tab.md L1-L3, L6; numbers in ./codes.
 */
module.exports = {
  codes: require('./codes'),
  chain: require('./chain'),
  grants: require('./grants'),
  tickets: require('./tickets'),
  copy: require('./copy'),
  /* L7 (2026-10-03): the budget request message, the app's side, the agent's side */
  request: require('./request'),
  approve: require('./approve'),
  client: require('./client'),
};
