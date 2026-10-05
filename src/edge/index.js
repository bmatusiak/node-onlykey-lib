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
  /* B7: what a use was and whether it stands out - the phone's Live view and okedge watch */
  live: require('./live'),
  /* B7 stage 2: the agent's signed words about a use (reason, ticket message, a refused ARM) */
  note: require('./note'),
  /* L7 (2026-10-03): the budget request message, the app's side, the agent's side */
  request: require('./request'),
  approve: require('./approve'),
  client: require('./client'),
  /* step 2: EDGE_REQUEST over the Bluetooth vendor channel (OKEDGE_REQUEST 0xF7, kept by the phone for the app) */
  wire: require('./wire'),
  /* okedge sync phase 2 (2026-10-05): a place that keeps copies fills the phone's copy; the `sync` link */
  sync: require('./sync'),
};
