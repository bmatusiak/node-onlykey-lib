'use strict';

/**
 * THE CLI'S CORE PLUGIN (step 3a; Brad, 2026-10-07: "rectify i love it, its my go to").
 *
 * The command table stays one table, in cli/index.js (Brad: the core commands in one
 * core plugin for now). This plugin owns it and provides `cli`, the service the
 * feature plugins extend while they set up - as the Rectify example's `server` is
 * extended with `route()`:
 *   command(name, spec)       a command of its own (Key Chain: `keychain`; Edge: `edge`)
 *   option(name, opts, hook)  options added to an existing command (Key Chain: `gpg --slot`)
 *   aroundStart(fn)           wraps the device start of every command (Key Chain records keys)
 *   stack.add(plugin)         a device-stack plugin for cli/desktop.js (Edge, step 3b)
 *   helpers                   the shared CLI pieces: errors, rows, withDevice, ...
 * Core knows no feature: it never requires keychain/ or edge/.
 */
function setup(imports, register, config) {
  const { COMMANDS, helpers } = config.cli;
  const around = [];
  const stackPlugins = [];
  const cli = {
    helpers,
    commands: COMMANDS,
    command(name, spec) {
      if (Object.prototype.hasOwnProperty.call(COMMANDS, name)) throw new Error(`cli: a command "${name}" is already there`);
      COMMANDS[name] = spec;
    },
    /*
     * hook(io, opts, rest) runs before the command when one of its options is given;
     * a value it returns other than undefined is the command's result instead.
     */
    option(name, options, hook) {
      const cmd = COMMANDS[name];
      if (!cmd) throw new Error(`cli: no command "${name}" to add ${Object.keys(options).map((o) => `--${o}`).join(', ')} to`);
      cmd.options = { ...(cmd.options || {}), ...options };
      if (hook) (cmd.optionHooks = cmd.optionHooks || []).push({ names: Object.keys(options), hook });
    },
    aroundStart(fn) {
      around.push(fn);
    },
    stack: {
      add(plugin) { stackPlugins.push(plugin); },
      list() { return [...stackPlugins]; },
    },
    /* main() hands each command's start through every plugin's wrapper */
    wrapStart(start, ctx) {
      return around.reduce((s, fn) => fn(s, ctx), start);
    },
  };
  register(null, { cli });
}

setup.consumes = [];
setup.provides = ['cli'];

module.exports = setup;
