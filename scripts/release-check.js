#!/usr/bin/env node
'use strict';

/**
 * scripts/release-check.js - the published package holds no test or dev command,
 * option or switch, and only the one CLI (onlykey-edge CLI.md §1, §5, §7; decided
 * 2026-10-06). Packs the library as `npm publish` would, unpacks it in a temp
 * folder and checks the package itself - never the working tree:
 *
 *   1. one bin: onlykey-js (no okedge, no onlykey-edge-gpg);
 *   2. nothing of cli/dev or edge/cli/dev ships, nor cli/okedge.js;
 *   3. no shipped code reads a dev switch (OKEDGE_HOME, OKEDGE_TIMES,
 *      OKEDGE_IDLE_MS, ONLYKEY_JS_DEBUG) - the agent could set those itself;
 *   4. the packed CLI, with every dev switch set, refuses `edge ping` as an unknown
 *      command and lists no removed command (okedge, edge-agent, pairing).
 *
 * It never connects to a key or a phone. Exit 0 = pass, 1 = a finding (each named).
 */
const { execFileSync, execSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DEV_ENV = ['OKEDGE_HOME', 'OKEDGE_TIMES', 'OKEDGE_IDLE_MS', 'ONLYKEY_JS_DEBUG'];

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

/* code lines only: a dev switch named in a comment is fine, read in code is not */
function codeOnly(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').map((l) => l.replace(/(^|[^:'"`])\/\/.*$/, '$1')).join('\n');
}

function main() {
  const findings = [];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'onlykey-release-check-'));
  try {
    const packed = JSON.parse(execSync(`npm pack --json --pack-destination "${tmp}"`, { cwd: ROOT, encoding: 'utf8' }));
    /* relative names, run inside the folder: GNU tar reads "C:" in a path as a remote host */
    execFileSync('tar', ['-xzf', packed[0].filename], { cwd: tmp });
    const pkg = path.join(tmp, 'package');
    const files = walk(pkg).map((f) => path.relative(pkg, f).split(path.sep).join('/'));

    /* 1. one CLI */
    const pj = JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8'));
    const bins = Object.keys(pj.bin || {});
    if (bins.length !== 1 || bins[0] !== 'onlykey-js') findings.push(`bins are ${JSON.stringify(bins)} - only onlykey-js may be installed`);

    /* 2. no dev files, no okedge */
    for (const f of files) {
      if (/^(cli|edge\/cli)\/dev\//.test(f)) findings.push(`dev file in the package: ${f}`);
      if (f === 'cli/okedge.js') findings.push('cli/okedge.js is in the package');
    }

    /* 3. no shipped code reads a dev switch */
    for (const f of files.filter((x) => x.endsWith('.js'))) {
      const code = codeOnly(fs.readFileSync(path.join(pkg, f), 'utf8'));
      for (const name of DEV_ENV) {
        if (new RegExp(`process\\.env\\.${name}\\b|process\\.env\\[['"]${name}['"]\\]`).test(code)) findings.push(`${f} reads ${name}`);
      }
    }

    /* 4. the packed CLI, every dev switch set: edge ping is unknown, no removed command is listed */
    const env = { ...process.env, NODE_PATH: path.join(ROOT, 'node_modules'), OKEDGE_HOME: path.join(tmp, 'home'), OKEDGE_TIMES: '1', OKEDGE_IDLE_MS: '5', ONLYKEY_JS_DEBUG: '1' };
    const cli = path.join(pkg, 'cli', 'index.js');
    const ping = spawnSync(process.execPath, [cli, 'edge', 'ping'], { env, encoding: 'utf8', timeout: 30000 });
    const pingSaid = `${ping.stdout}${ping.stderr}`;
    if (ping.status === 0 || !/unknown edge command "ping"/.test(pingSaid)) findings.push(`the packed CLI did not refuse "edge ping" as unknown (exit ${ping.status}): ${pingSaid.trim().split('\n')[0]}`);
    const help = spawnSync(process.execPath, [cli, 'help'], { env, encoding: 'utf8', timeout: 30000 });
    for (const gone of ['okedge', 'edge-agent', 'pairing']) {
      if (new RegExp(`(^|\\s)${gone}(\\s|$)`, 'm').test(help.stdout)) findings.push(`"onlykey-js help" lists the removed "${gone}"`);
    }
    if (help.status !== 0) findings.push(`"onlykey-js help" failed in the packed package (exit ${help.status}): ${String(help.stderr).trim().split('\n')[0]}`);

    if (findings.length) {
      for (const f of findings) process.stderr.write(`release-check: FAIL ${f}\n`);
      return 1;
    }
    process.stdout.write(`release-check: ok - ${files.length} files, one bin (onlykey-js), no dev command, option or switch reachable\n`);
    return 0;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

if (require.main === module) process.exitCode = main();
module.exports = { main, codeOnly };
