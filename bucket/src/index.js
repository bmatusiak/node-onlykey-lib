'use strict';

/**
 * The bucket (PROPOSAL-one-gui.md): one portable, key-sealed file for everything a front end keeps.
 * Its own plugin: core never requires this folder.
 */
module.exports = { ...require('./bucket'), rules: require('./rules'), replicate: require('./replicate'), bucketIdentity: require('./bucket-identity'), trade: require('./trade'), room: require('./room'), roomClient: require('./room-client') };
