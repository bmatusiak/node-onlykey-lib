'use strict';

/**
 * THE STORE RULES, ONE TABLE (the structure track S2, 2026-11-02): which merge each store of a bucket takes - read by
 * every merge and trade, on every host. There were three tables: the app's (ok-edge bucketRules.ts), the CLI's trades
 * (bucket/cli/trade.js) and the CLI's `bucket merge` (bucket/cli/plugin.js), and they differed - the last knew only Key
 * Chain and the old Edge copies, so a file merge took the Guest Book, Passwords, CryptoBox and the Edge logs as plain
 * newer-wins, where the room's trades used their own rules.
 *
 * A feature's rule is made from the feature's own module (rules.js), required softly: the bucket stands without any
 * feature folder (scripts/check-without.js), and a store without its rule takes the generic newer-wins. Pure - no
 * Node built-ins - so the app's bundles take it as the CLI does.
 *
 * -> {[store]: rule}; the testnet's stores (`-test`) take the same rule as their live twin.
 */
const rules = require('./rules');

function storeRules() {
  const out = {};
  const both = (name, rule) => { out[name] = rule; out[`${name}-test`] = rule; };
  try { both('keychain', rules.keychain(require('../../keychain/src/list'))); } catch { /* no Key Chain here */ }
  both('guestbook', rules.guestbook());
  both('passwords', rules.passwords());
  both('cryptobox', rules.cryptobox());
  /* each device's Edge log, as blocks (edge/src/logblocks.js): links the union, a fork reported, never repaired */
  try { both('edge-logs', rules.edgeLogs(require('../../edge/src/logblocks'))); } catch { /* no Edge here */ }
  /* the Edge copies of before the identity bucket (edge/cli/copy.js adoptAll reads them): their own merge while any is left */
  try {
    const copies = rules.edgeCopies(require('../../edge/src/copyfile'));
    out['edge.copies'] = copies;
    out['edge-test.copies'] = copies;
  } catch { /* no Edge here */ }
  return out;
}

module.exports = { storeRules };
