'use strict';

/**
 * edge/cli/nametag.js - "my device name": the nametag of one device of an identity (Brad, 2026-10-24:
 * "i should be able to set the nametag for key1 and change it too, and the desktop app i should be able
 * to set it in the edge manage popup"). One function for every host - the CLI's `edge name`, the desktop
 * app's Edge Management.
 *
 * Set: the key CERTIFIES the nametag at a press (edge.statement -> edge.certify; Brad, 2026-10-30: "change
 * nametag to certify") - one link on the chain, then its owner key and ML-DSA-65 twin sign the device id, its
 * checkpoint keys, that link's seq and the nametag's hash (grants.certifyDigest). It is checked here with the owner keys it names (grants.verifyStatement), and the owner key
 * must be THIS identity's (its id is the identity home's) - then it is kept in the identity's `devices`
 * store, by device id. Another device of the identity checks the same statement with its own owner keys:
 * that is how a phone or a hard key of yours is recognised, under its name, when logs are offered.
 */

const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { grants } = require('../src');
const { identityIdOf } = require('../src/identity-id');
const { toHex } = require('../../src/bytes');

const { fromHex } = require('../../src/bytes');

/*
 * WHERE A NAMETAG LIVES (2026-10-30): the device's copy in the identity bucket (edge-logs <dev>.statement) and the
 * bucket's edge-names history - the same records the app reads and writes (copy.keepNametag). Not a store of this
 * computer's own: a name set here shows on the phone and the desktop app, and theirs show here.
 */

/** the name of one device of this identity: its copy's statement, or null */
function getName(home, deviceIdHex) {
  const copy = require('./copy');
  const st = copy.load(home, fromHex(deviceIdHex)).statement;
  if (!st) return null;
  const at = copy.nametagHistory().filter((r) => r.deviceId === deviceIdHex.toLowerCase() && r.statement.nametag === st.nametag).map((r) => r.at)[0];
  return { nametag: st.nametag, seq: st.seq ?? null, at: at || null };
}

/** every device of this identity with a nametag in the bucket: [{deviceId, nametag, at}], the newest name each */
function listNames(home) {
  const copy = require('./copy');
  const newest = new Map();
  for (const r of copy.nametagHistory()) {
    const was = newest.get(r.deviceId);
    if (!was || (r.statement.seq ?? -1) > (was.statement.seq ?? -1) || ((r.statement.seq ?? -1) === (was.statement.seq ?? -1) && r.at > was.at)) newest.set(r.deviceId, r);
  }
  return [...newest.values()].map((r) => ({ deviceId: r.deviceId, nametag: r.statement.nametag, at: r.at }));
}

/**
 * Name this device: the key CERTIFIES the nametag at a press (onPress: say so), it is checked, it is kept with the copy.
 * @param {{edge: object, home: string, nametag: string, onPress?: () => void, now?: () => number}} o
 * @returns {Promise<{deviceId: string, nametag: string, at: number}>}
 */
async function setName({ edge, home, nametag, onPress, now = Date.now }) {
  grants.nametagHash(nametag); /* throws for an empty or too long one, before the key is asked */
  const st = await edge.statement(String(nametag).trim(), { onPress });
  if (!grants.verifyStatement(st, st.ownerKey, st.ownerKeyPq)) throw new Error('edge: the key\'s certification does not verify with the owner keys it names - nothing kept');
  if (identityIdOf(st.ownerKeyPq) !== path.basename(home)) throw new Error('edge: the key\'s owner key is not this identity\'s - nothing kept');
  const at = now();
  require('./copy').keepNametag(home, st.deviceId, st, { now: () => at });
  const deviceId = toHex(st.deviceId);
  /* named: its log can now be offered to the identity's other devices */
  const log = await offerOwnLog({ edge, home }).catch((e) => ({ kept: false, why: e.message }));
  return { deviceId, nametag: st.nametag, at, log };
}

/* the statement on one device's copy, as copy.keepLog checks it */
function statementOf(home, deviceIdHex) {
  return require('./copy').load(home, fromHex(deviceIdHex)).statement || null;
}

/**
 * A HARD KEY'S LOG, READY TO OFFER to the other devices of its identity (Brad, 2026-10-24: "each team
 * knows the budget history if using the same key identity"). A phone's log is kept to offer by the pull
 * of edge sync (agent.js: its statement + its checkpoint -> copy.keepLog); a hard key has no phone to
 * pull, so this computer does the same with the SAME function, from the key's own statement (its name,
 * setName) and its checkpoint now. keepLog's checks decide - the statement names this device, the chain
 * verifies, every use is complete - and say why not.
 * @returns {Promise<{kept: boolean, why?: string}>}
 */
async function offerOwnLog({ edge, home }) {
  const copy = require('./copy');
  const { publicKey, deviceId } = await edge.publicKey();
  const statement = statementOf(home, toHex(deviceId));
  if (!statement) return { kept: false, why: 'this device has no name yet (onlykey-js edge name)' };
  const c = copy.load(home, deviceId);
  const checkpoint = await edge.checkpoint();
  return copy.keepLog(home, { deviceId, publicKey, publicKeyPq: c.publicKeyPq || (await edge.publicKeyPq('checkpoint')), records: c.links, checkpoint, statement });
}

module.exports = { getName, listNames, setName, offerOwnLog };
