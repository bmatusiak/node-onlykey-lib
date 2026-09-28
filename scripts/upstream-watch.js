#!/usr/bin/env node
/*
 * upstream-watch.js - what have the maintainers changed in THEIR copies of
 * the protocol since this library last caught up?
 *
 *   node scripts/upstream-watch.js              summary + the newest commits per watch
 *   node scripts/upstream-watch.js --all        every commit, not just the newest few
 *   node scripts/upstream-watch.js --json       machine-readable, for tooling
 *   node scripts/upstream-watch.js web-app      only the named watch(es)
 *
 * WHY THIS EXISTS. This library is meant to be the ONE implementation of the
 * OnlyKey protocol and crypto that every GUI runs - the phone app, the test
 * kit, the emulator, and in time the web app and the desktop app. But the
 * maintainers keep building inside their own apps: a new field in the desktop
 * app's OnlyKeyComm.js, a new gate in the firmware's ok_extension.cpp, a
 * derivation change in lib-agent. Every one of those widens the gap this
 * library has to close, and none of them announce themselves. A gap nobody
 * can see is a gap nobody closes - so this makes it a list.
 *
 * upstream/watch.json names, per repo and branch, the paths that carry
 * protocol or crypto and the date this library had caught up to (`since`).
 * This asks GitHub for every commit on those paths after that date. Each one
 * is a work item: port it (with vectors taken from THEIR implementation, the
 * way the kit's outputs were frozen), record a capability change, or decide
 * it needs nothing - then move `since` forward in the same commit that
 * closes it, so the manifest always says how far the library has looked.
 *
 * Read-only: it only reads GitHub through the `gh` CLI, which must be
 * installed and logged in (several of the watched repos are private).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const MANIFEST = path.join(__dirname, '..', 'upstream', 'watch.json');
const NEWEST = 5;   // commits shown per watch without --all

function gh(args) {
  try {
    return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('the `gh` CLI is not installed or not on PATH - https://cli.github.com, then `gh auth login`');
    }
    const [first] = String(err.stderr || err.message).trim().split('\n');
    throw new Error(first);
  }
}

/** Every commit on `branch` touching `p` since the date, newest first. */
function commitsFor(repo, branch, p, since) {
  const q = `repos/${repo}/commits?sha=${encodeURIComponent(branch)}` +
    `&path=${encodeURIComponent(p)}&since=${since}T00:00:00Z&per_page=100`;
  const out = gh(['api', '--paginate', q, '--jq',
    '.[] | [.sha, .commit.committer.date, .commit.author.name, (.commit.message | split("\\n")[0])] | @tsv']);
  return out.split('\n').filter(Boolean).map((line) => {
    const [sha, date, author, subject] = line.split('\t');
    return { sha, date, author, subject };
  });
}

function check(watch) {
  const seen = new Map();
  const errors = [];
  for (const p of watch.paths) {
    try {
      for (const c of commitsFor(watch.repo, watch.branch, p, watch.since)) {
        const had = seen.get(c.sha);
        if (had) had.paths.push(p); else seen.set(c.sha, { ...c, paths: [p] });
      }
    } catch (err) {
      errors.push(`${p}: ${err.message}`);
    }
  }
  const commits = [...seen.values()].sort((a, b) => b.date.localeCompare(a.date));
  return { name: watch.name, repo: watch.repo, branch: watch.branch, since: watch.since, commits, errors };
}

function main() {
  const argv = process.argv.slice(2);
  const all = argv.includes('--all');
  const json = argv.includes('--json');
  const names = argv.filter((a) => !a.startsWith('--'));

  const { watches } = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const unknown = names.filter((n) => !watches.some((w) => w.name === n));
  if (unknown.length) {
    throw new Error(`no watch named ${unknown.join(', ')}; known: ${watches.map((w) => w.name).join(', ')}`);
  }
  const results = watches.filter((w) => !names.length || names.includes(w.name)).map(check);

  if (json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) {
      console.log(`\n${r.name}  ${r.repo}@${r.branch}  since ${r.since}: ${r.commits.length} commit(s)`);
      for (const c of all ? r.commits : r.commits.slice(0, NEWEST)) {
        console.log(`  ${c.sha.slice(0, 7)} ${c.date.slice(0, 10)} ${c.author}: ${c.subject.slice(0, 72)}`);
      }
      if (!all && r.commits.length > NEWEST) console.log(`  ... ${r.commits.length - NEWEST} more (--all)`);
      for (const e of r.errors) console.log(`  ERROR ${e}`);
    }
    const total = results.reduce((n, r) => n + r.commits.length, 0);
    console.log(`\nupstream-watch: ${total} commit(s) across ${results.length} watch(es) not yet caught up`);
  }
  if (results.some((r) => r.errors.length)) process.exitCode = 1;
}

try {
  main();
} catch (err) {
  console.error(`upstream-watch: ${err.message}`);
  process.exitCode = 2;
}
