'use strict';

/**
 * THE OLD SINGLE-PASSWORD VAULT, BROUGHT IN (PASSWORD-MANAGER-SPEC.md "Data model"): each old
 * record was sealed under its own `vault:<serviceId>` key, so the caller opens each one with the
 * key (okcrypto.deviceVault.load - one derive per site, as before) and this re-seals what it got
 * as a `login` entry under the manager key. The old store is left as it is.
 *
 * Only records made on firmware with the hardened derive open (3.0.5+): an older firmware
 * derived another key. A record that does not open is counted, never guessed at.
 */

/**
 * -> {imported, failed: [{serviceId, reason}]}
 * legacy:   the old vault_store (list()) - its serviceId is the site name the person typed
 * openOne:  async (serviceId) => the password text (the caller's device derive)
 * manager:  an open manager (openManager)
 */
async function importLegacy({ legacy, openOne, manager }) {
  const failed = [];
  let imported = 0;
  for (const rec of await legacy.list()) {
    let password;
    try {
      password = await openOne(rec.serviceId);
    } catch (e) {
      failed.push({ serviceId: rec.serviceId, reason: String((e && e.message) || e) });
      continue;
    }
    if (typeof password !== 'string') {
      failed.push({ serviceId: rec.serviceId, reason: 'did not open' });
      continue;
    }
    await manager.put({ kind: 'login', title: rec.serviceId, password, notes: 'Imported from the old vault' });
    imported += 1;
  }
  return { imported, failed };
}

module.exports = { importLegacy };
