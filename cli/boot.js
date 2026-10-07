'use strict';

/**
 * THE CLI'S BOOT (step 3a): the only file that knows what the CLI is made of, as the
 * Rectify example's boot is. It lists core and whichever feature plugins are here,
 * hands them to Rectify, and Rectify loads them in the order their consumes/provides
 * need - and refuses to build, naming it, when a plugin consumes what nothing
 * provides (Edge without Key Chain).
 *
 * A feature plugin's folder can be left out of a build (CLI.md §6): its plugin is
 * then simply not listed. Only "that folder is not there" counts as absent - a
 * broken require inside a plugin still throws.
 */
const Rectify = require('@bmatusiak/rectify');

function optional(spec, folder) {
  try {
    return require(spec);
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND' && new RegExp(`[\\\\/]${folder}[\\\\/]cli[\\\\/]plugin`).test(e.message)) return null;
    throw e;
  }
}

/** the plugins this build has: core, then each feature plugin whose folder is here */
function listPlugins() {
  return [
    require('./core'),
    optional('../keychain/cli/plugin', 'keychain'),
    optional('../edge/cli/plugin', 'edge'),
  ].filter(Boolean);
}

/** build and start the given plugins with the core's command table -> the started app */
function boot(plugins, { COMMANDS, helpers }) {
  const list = [...plugins];
  list.config = { cli: { COMMANDS, helpers } };
  return new Promise((resolve, reject) => {
    let app;
    try {
      app = Rectify.build(list, (err, started) => (err ? reject(err) : resolve(started)));
    } catch (e) {
      reject(e);
      return;
    }
    app.start();
  });
}

module.exports = { boot, listPlugins };
