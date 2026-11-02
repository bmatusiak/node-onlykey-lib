'use strict';

/**
 * THE SHARED FILE'S SIDE - the four calls bucket/src/storage.js sharedFileStorage needs, over the CLI's folder
 * (~/.onlykey-js/buckets/<net>/<id>.json, home.js). The desktop's main process answers its page's IPC with these (ok-edge
 * electron/desktop/hosting.js: okedge:bucketHas / Keep / Read / MergeIn), and the CLI uses them as they are - one code
 * for the file both share, so the two never drop each other's change: every write is a locked read-modify-write, the
 * merge with the store rules, newer wins.
 *
 *   fileSide(home = require('./home')) -> {has, read, keep, mergeIn}
 */
const bucketLib = require('../src/bucket');
const { storeRules } = require('../src/store-rules');

function fileSide(home = require('./home')) {
  return {
    has: (identity, net) => home.hasIdentityBucket(identity, net),
    read: (identity, net) => (home.hasIdentityBucket(identity, net) ? bucketLib.serialize(home.read(home.identityFile(identity, net))) : null),
    /* a new bucket, opened (the identity check opened it with the key; the file keeps it opened, as the CLI does) */
    keep: (identity, net, text) => home.keepIdentityBucket(identity, net, bucketLib.open(text, { allowUnsealed: true }).bucket),
    /* -> the records taken in, per store */
    mergeIn: (identity, net, text) => {
      const rules = storeRules();
      const report = home.update(home.identityFile(identity, net), (b) => {
        const { bucket, report: r } = bucketLib.merge(b, bucketLib.parse(text), { rules });
        b.stores = bucket.stores;
        b.clock = bucket.clock;
        return r;
      });
      return report.taken;
    },
  };
}

module.exports = { fileSide };
