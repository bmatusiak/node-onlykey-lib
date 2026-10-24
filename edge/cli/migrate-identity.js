'use strict';

/**
 * edge/cli/migrate-identity.js - the records from before identities, copied into a key's identity home
 * (ok-edge B3.0; Brad, 2026-10-24: "one identity, one store").
 *
 * Before B3.0 a net's Edge home held ONE set of stores for every key: edge.identity ('record'),
 * edge.copies, edge.budgets (by budget id alone - which collides across devices), edge.pointers. A key
 * now files under <net home>/<identity id>, which starts empty. This copies into it ONLY what is
 * provably that key's:
 *   - the agent identity record: when its certificate's signing key is the one THIS key derives for its
 *     gpg user ID (the same test the agent runs before it signs - agent.js);
 *   - the chain copy of THIS key's device (copies are filed by device id);
 *   - budgets: an old `okedge.budget.<id>` record when its genesis is the genesis of an opening of that
 *     id in this device's copy - re-filed `okedge.budget.<device id>.<id>` (edge/src/client.js);
 *   - the budget pointer of this device.
 * Nothing is moved and nothing old is changed: the net's stores stay as they were. It runs once per
 * identity home (a 'migrated' mark in its identity store); a dry run reports what it would copy and
 * writes nothing.
 */

const bucketHome = require('../../bucket/cli/home');

const MARK = 'migrated';

/**
 * @param {object} o
 * @param {string} o.netHome the net's Edge home (control.edgeHome())
 * @param {string} o.idHome the key's identity home (<netHome>/<identity id>)
 * @param {string} o.deviceIdHex this key's device id, hex (32)
 * @param {(gpgUid: string) => Promise<string>} o.signPublicOf the hex public key this key derives for a gpg user ID
 * @param {boolean} [o.dryRun]
 * @param {() => number} [o.now]
 * @returns {Promise<{done: boolean, already?: boolean, identity: boolean, copy: boolean, budgets: number[], pointers: number, skipped: string[]}>}
 */
async function migrateToIdentity({ netHome, idHome, deviceIdHex, signPublicOf, dryRun = false, now = Date.now }) {
  const kv = (home, name) => bucketHome.kv(bucketHome.edgeAt(home, name));
  const idStore = kv(idHome, 'identity');
  const report = { done: false, identity: false, copy: false, budgets: [], pointers: 0, skipped: [] };
  if (idStore.getItem(MARK)) return { ...report, done: true, already: true };

  /* the agent identity record - this key's only if its certificate is this key's own derive */
  const oldRecord = kv(netHome, 'identity').getItem('record');
  if (oldRecord && !idStore.getItem('record')) {
    let rec = null;
    try { rec = JSON.parse(oldRecord); } catch (_) { report.skipped.push('identity record: not JSON'); }
    if (rec && rec.gpgUid && rec.cert && typeof rec.cert.signPublic === 'string') {
      const mine = (await signPublicOf(rec.gpgUid)).toLowerCase() === rec.cert.signPublic.toLowerCase();
      if (mine) { report.identity = true; if (!dryRun) idStore.setItem('record', oldRecord); }
      else report.skipped.push(`identity record (${rec.cert.fingerprint || rec.gpgUid}): another key's certificate`);
    }
  }

  /* this device's chain copy */
  const short = deviceIdHex.slice(0, 16);
  const oldCopy = kv(netHome, 'copies').getItem(short);
  const idCopies = kv(idHome, 'copies');
  let copy = null;
  if (oldCopy) {
    try { copy = JSON.parse(oldCopy); } catch (_) { report.skipped.push(`copy ${short}: not JSON`); }
    if (copy && !idCopies.getItem(short)) { report.copy = true; if (!dryRun) idCopies.setItem(short, oldCopy); }
  }

  /* budgets: provably this device's by the genesis of its opening in this device's copy */
  const genesisOf = new Map(((copy && copy.openings) || []).map((o) => [o.grantId, String(o.genesis || '').toLowerCase()]));
  const oldBudgets = kv(netHome, 'budgets');
  const idBudgets = kv(idHome, 'budgets');
  for (const k of oldBudgets.keys()) {
    const m = /^okedge\.budget\.(\d+)$/.exec(k);
    if (!m) continue;
    const grantId = Number(m[1]);
    let rec = null;
    try {
      const v = JSON.parse(oldBudgets.getItem(k));
      rec = typeof v === 'string' ? JSON.parse(v) : v;
    } catch (_) { report.skipped.push(`budget ${grantId}: not JSON`); continue; }
    const g = genesisOf.get(grantId);
    if (!g || !rec || String(rec.genesis || '').toLowerCase() !== g) continue; /* not provably this device's */
    const to = `okedge.budget.${deviceIdHex}.${grantId}`;
    if (idBudgets.getItem(to)) continue;
    report.budgets.push(grantId);
    if (!dryRun) idBudgets.setItem(to, JSON.stringify(JSON.stringify({ ...rec, deviceId: deviceIdHex })));
  }

  /* this device's budget pointer */
  const pointerKey = `okedge.pointer.budget.${deviceIdHex}`;
  const oldPointer = kv(netHome, 'pointers').getItem(pointerKey);
  const idPointers = kv(idHome, 'pointers');
  if (oldPointer && !idPointers.getItem(pointerKey)) { report.pointers = 1; if (!dryRun) idPointers.setItem(pointerKey, oldPointer); }

  if (!dryRun) idStore.setItem(MARK, JSON.stringify({ at: now(), from: netHome, ...report }));
  report.done = !dryRun;
  return report;
}

/*
 * Must this identity home be migrated before a command uses it? Yes while it is not marked and the
 * net's stores from before identities hold anything - then a command would start empty beside records
 * that may be this key's, and it stops instead (no second path: register.js says to run edge migrate).
 */
function needsMigration(netHome, idHome) {
  const kv = (home, name) => bucketHome.kv(bucketHome.edgeAt(home, name));
  if (kv(idHome, 'identity').getItem(MARK)) return false;
  return ['identity', 'copies', 'budgets', 'pointers'].some((name) => kv(netHome, name).keys().length > 0);
}

module.exports = { migrateToIdentity, needsMigration, MARK };
