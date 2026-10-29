'use strict';

/**
 * edge/cli/edge-control.js - `onlykey-js edge control`: keep track of what is sent to Edge to sign,
 * preview it, and ship it in ONE budget (Brad, 2026-10-23: the workspace's edge skill, "so this
 * skill comes with the cli", its info "with its other home files").
 *
 *   onlykey-js [--ble [--address <phone>]] [--gui-prompt] edge [--test-mode] control note <repo>[:<base>[:<branch>]] ...
 *   onlykey-js … edge … control preview          everything pending: commits to sign, pushes, the request
 *   onlykey-js … edge … control ship [<repo>...] [--plan] [--reason "..."] [--head <h>]
 *   onlykey-js … edge … control status
 *   onlykey-js … edge … control settings         where its files are, and what they say
 *
 * WHICH KEY: the global flags, as every other command - no flag is a hard key on USB (this computer
 * is the host: a y/N here, then the press), --ble the phone. The skill used to carry its own
 * "phone" / "usb" settings for that; one way of saying it is enough.
 *
 * WHERE ITS STATE LIVES: the net's Edge home (control.edgeHome(): ~/.onlykey-js/edge, or edge-test
 * with --test-mode), beside the agent's files - `control-batch.json` (the repos noted) and
 * `control-settings.json` (ttl; hooks.ready / hooks.watch, run from that folder). So the testnet's
 * batch and the live one never mix.
 *
 * HOW IT SHIPS - unchanged from the skill, which shipped the 3.1.0 release work through A13, Pixel
 * and key 1 budgets: every commit after <base> (default @{u}) that is not signed is re-signed, one
 * signature per `edge exec` during a rebase that stops at each; each repo's branch (default the
 * current one) is pushed; every exec's receipt is filed (retried when a Bluetooth link drops); the
 * budget is ended. Each step is this same CLI run as a child, with the same flags: the budget,
 * exec and receipt commands stay the one implementation, and a child that fails stops the batch at
 * that step with the `--head` to go on. It stops at the first thing it does not expect.
 *
 * It never force-pushes, deletes a branch or tag, or rewrites a commit that is already pushed
 * (only commits after the base). The person holding the key or phone approves every budget; hooks
 * exist for test rigs, not to take that away.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync, spawn } = require('child_process');

const CLI = path.join(__dirname, '..', '..', 'cli', 'index.js');
const BATCH_FILE = 'control-batch.json';
const SETTINGS_FILE = 'control-settings.json';

const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (_) { return d; } };

/* a stop: printed by run(), exit 1 */
class Stop extends Error {}

/* what a child was, for the timeline: `edge exec`, `git rebase` - the command's verb past its options, nothing more */
function ranWhat(file, a) {
  const verb = (from) => { let i = from; while (i < a.length && /^-/.test(a[i])) i += /^-[Cc]$/.test(a[i]) ? 2 : 1; return a[i]; };
  return file === process.execPath ? `edge ${verb(a.indexOf('edge') + 1)}` : `${path.basename(file)} ${verb(0)}`;
}

const USAGE = [
  'onlykey-js [--ble [--address <phone>]] [--gui-prompt] edge [--test-mode] control note <repo>[:<base>[:<branch>]] ...',
  'onlykey-js … edge … control preview',
  'onlykey-js … edge … control ship [<repo>...] [--plan] [--reason "..."] [--head <h>]',
  'onlykey-js … edge … control status | settings',
];

/**
 * @param {object} o
 * @param {{out: Function, err: Function}} o.io
 * @param {object} o.opts the global options (ble, address, path)
 * @param {string[]} o.argv after `control`
 * @param {string} o.net 'live' | 'test'
 * @param {string} o.home this net's Edge home
 * @returns {Promise<number>} the exit code
 */
async function run({ io, opts, argv, net, home, dev = null }) {
  const say = (s) => io.out(s);
  /* the ship's timeline (edge/cli/dev/times.js): every child it runs, and their steps - the dev set only */
  const TIMES = dev && dev.times ? dev.times : null;
  const args = argv.slice();
  const cmd = args.shift();
  const opt = (name) => { const i = args.indexOf(name); if (i < 0) return null; const v = args[i + 1]; args.splice(i, 2); return v; };
  const flag = (name) => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };
  const REASON = opt('--reason');
  const PLAN = flag('--plan');
  let HEAD = opt('--head');

  const batchFile = path.join(home, BATCH_FILE);
  const settingsFile = path.join(home, SETTINGS_FILE);
  const CFG = readJson(settingsFile, {});
  const HOOKS = CFG.hooks || {};
  const TTL = String(CFG.ttl || 30);
  const USB = !opts.ble;
  /* the key on USB, hosted by the ok-edge desktop app when it runs (cli deviceOpts: --desktop, or plain with a live app) */
  const VIA_APP = USB && (opts.desktop || (!opts.path && Boolean(require('../../desktop/trust').liveTrust())));
  /* --gui-prompt: the budget's y/N in a desktop dialog, so whoever runs this (an agent's shell) never answers it */
  const GUI = Boolean(opts['gui-prompt']);
  const keyArgs = [...(opts.ble ? ['--ble', ...(opts.address ? ['--address', opts.address] : [])] : (opts.path ? ['--path', opts.path] : [])), ...(GUI ? ['--gui-prompt'] : [])];
  const netArgs = net === 'test' ? ['--test-mode'] : [];
  const where = USB ? 'the key on USB' : `the phone${opts.address ? ` (${opts.address})` : ''}`;

  const runP = (file, a, o = {}) => {
    const t = Date.now();
    const r = spawnSync(file, a, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...o });
    /* on the timeline by what ran (edge exec, git rebase), never its arguments: an intent names what is signed */
    if (TIMES) TIMES.took(`run ${ranWhat(file, a)}`, Date.now() - t, { failed: r.status !== 0 });
    return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
  };
  const git = (repo, ...a) => runP('git', ['-C', repo, ...a]);
  /* this CLI, run as a child with the same key and net: no shell, so reasons and intents need no quoting */
  const cli = (a, timeout = 180000, extra = {}) => runP(process.execPath, [CLI, ...keyArgs, 'edge', ...netArgs, ...a], { timeout, ...extra });
  /* hooks run from the Edge home, so the settings may name scripts beside them */
  const hook = (name) => HOOKS[name] && runP(HOOKS[name], [], { shell: true, cwd: home, timeout: 300000 });
  let watcher = null;
  const watch = () => { watcher = spawn(HOOKS.watch, [], { shell: true, cwd: home, stdio: 'ignore', detached: process.platform !== 'win32' }); };
  /* the hook's whole process tree: a shell, and whatever it started */
  const unwatch = () => {
    if (!watcher) return;
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(watcher.pid), '/T', '/F'], { stdio: 'ignore' });
    else try { process.kill(-watcher.pid); } catch (_) { /* gone */ }
    watcher = null;
  };
  /* --gui-prompt: one progress window for the run (cli/gui-prompt guiProgress), opened with the budget */
  let PROGRESS = null;
  let signedCount = 0;
  let pushCount = 0;
  const stop = (why) => {
    say(`STOP: ${why}`);
    if (HEAD) say(`  the budget is open - go on with the same ship command plus: --head ${HEAD}`);
    if (PROGRESS) PROGRESS.finish(`STOP: ${why}${HEAD ? ` - the budget is open (head ${HEAD.slice(0, 12)})` : ''}`);
    unwatch();
    throw new Stop(why);
  };
  const readBatch = () => readJson(batchFile, []);
  const writeBatch = (b) => { fs.mkdirSync(home, { recursive: true }); fs.writeFileSync(batchFile, `${JSON.stringify(b, null, 2)}\n`); };

  /* ---------------------------------------------------------------- repos */
  /* the branch being worked on - mid-rebase HEAD is detached, so the rebase's own record says which */
  function currentBranch(repo) {
    const during = path.join(repo, '.git', 'rebase-merge', 'head-name');
    if (fs.existsSync(during)) return fs.readFileSync(during, 'utf8').trim().replace(/^refs\/heads\//, '');
    return git(repo, 'branch', '--show-current').out.trim();
  }
  /*
   * <path>[:<base>[:<branch>[+<also>...]]] - a drive letter's colon (C:\ or C:/) is not a separator. Each +<also> is
   * a remote branch moved to the same head in the same push (Brad, 2026-10-26: Cloudflare deploys ok-edge from a
   * "cloudflare" branch): `ok-edge::main+cloudflare` pushes main and sets cloudflare to it - one push, one spend.
   */
  function parseSpec(spec) {
    const [repo, base, branchSpec] = spec.split(/:(?![\\/])/);
    const [branch, ...also] = (branchSpec || '').split('+');
    const abs = path.resolve(repo);
    if (!fs.existsSync(path.join(abs, '.git'))) stop(`${repo} is not a git repository`);
    for (const b of also) if (!/^[\w./-]+$/.test(b)) stop(`${repo}: "${b}" is not a branch name`);
    const r = { spec: abs + (base ? `:${base}` : '') + (branchSpec ? `:${branchSpec}` : ''), repo: abs, name: path.basename(abs), base: base || '@{u}', branch: branch || currentBranch(abs), also };
    /*
     * A FIRST PUSH NAMES ITS BASE "root" (2026-10-28, bmatusiak/onlykey-js: a new repository has no upstream, so
     * `@{u}..HEAD` failed and the plan counted the error line as one commit - the first commit would have gone up
     * unsigned). `root` = every commit from the first; any other base must resolve, or the plan stops saying so
     * rather than guessing what to sign.
     */
    if (r.base !== 'root' && git(abs, 'rev-parse', '--verify', '-q', `${r.base}^{commit}`).code !== 0) {
      stop(`${r.name}: base ${r.base} does not resolve${r.base === '@{u}' ? ' (no upstream yet)' : ''} - for a first push into an empty repository name the base root: ${repo}:root:${r.branch}`);
    }
    return r;
  }
  /* the commits a ship takes: those after the base, or every one for a first push */
  const range = (r) => (r.base === 'root' ? 'HEAD' : `${r.base}..HEAD`);
  const rebasing = (r) => fs.existsSync(path.join(r.repo, '.git', 'rebase-merge'));
  function finishRebase(r) {
    for (let i = 0; i < 500 && rebasing(r); i++) git(r.repo, '-c', 'commit.gpgsign=false', 'rebase', '--continue');
    if (rebasing(r)) stop(`${r.name}: a rebase is in progress and will not finish`);
  }
  /* commits after base, oldest first (G/U/E = signed; E = by a key whose public half is not on this machine) */
  const commits = (r) => git(r.repo, 'log', '--reverse', '--format=%H%x09%G?%x09%s', range(r)).out.trim().split('\n').filter(Boolean)
    .map((l) => { const [hash, g, subject] = l.split('\t'); return { hash, signed: /^[GUE]$/.test(g), subject }; });
  const unsigned = (r) => commits(r).filter((c) => !c.signed);

  /* ---------------------------------------------------------------- the request */
  let REPOS = [];
  const totals = () => ({ gpg: REPOS.reduce((n, r) => n + unsigned(r).length, 0), ssh: REPOS.filter((r) => commits(r).length).length });
  const reasonText = (gpg) => REASON || (gpg
    ? `sign ${gpg} commit(s) and push: ${REPOS.map((r) => `${r.name} (${unsigned(r).length})`).join(', ')}`
    : `push: ${REPOS.map((r) => r.name).join(', ')}`);
  function sheet({ gpg, ssh }) {
    say(VIA_APP ? '>>> In the ok-edge desktop app\'s window, a budget request for the key on USB:'
      : USB && GUI ? '>>> In a window on this desktop, a budget request for the key on USB:'
        : USB ? '>>> On this terminal, a budget request for the key on USB:' : `>>> On ${where}, a budget request:`);
    say(`>>>   reason: "${reasonText(gpg)}"`);
    say(`>>>   ${gpg} signature(s), ${ssh} push(es), valid ${TTL} min${net === 'test' ? ' - TESTNET' : ''}`);
    say(`>>>   ${HOOKS.watch ? 'answered by the watch hook'
      : VIA_APP ? 'Approve it in the window, then PRESS the key within 20 s (it pulses); nothing else is asked until the batch is done'
      : USB && GUI ? 'answer Yes in the window, then PRESS the key within 20 s (it pulses); nothing else is asked until the batch is done'
      : USB ? 'answer y, then PRESS the key within 20 s of "PRESS the key now" (it pulses); nothing else is asked until the batch is done'
        : 'APPROVE it and PRESS the key; nothing else is asked until the batch is done'}`);
  }

  /* ---------------------------------------------------------------- the budget */
  function ready() {
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = cli(['status']);
      if (r.code === 0) return;
      if (attempt || !HOOKS.ready) stop(`${where} does not answer: ${r.out.trim().split('\n').pop()}`);
      say(`${where}: running the ready hook`);
      hook('ready');
    }
  }
  /*
   * On USB the budget is a y/N on THIS terminal (local-host.js), so that child shares the terminal:
   * stdin and its prompt (stderr) are the person's, and only stdout is read for the head. Through
   * a pipe the question was never seen and the empty pipe answered No.
   */
  function openBudget(t) {
    sheet(t);
    const r = cli(['budget', '--reason', reasonText(t.gpg), '--gpg', String(t.gpg), '--ssh', String(t.ssh), '--ttl', TTL],
      HOOKS.watch ? 180000 : 600000, USB && !GUI ? { stdio: ['inherit', 'pipe', 'inherit'] } : {});
    HEAD = (r.out.match(/head = ([0-9a-f]{64})/) || [])[1];
    if (!HEAD) stop(`no budget: ${r.out.trim().split('\n').pop() || 'refused (see above)'}`);
    say(`budget open, head ${HEAD.slice(0, 12)}`);
  }
  /* one exec under the budget and its receipt; HEAD moves on */
  /*
   * A FAILED EXEC STILL MOVES THE CHAIN (2026-10-26: a signature timed out on its press, "note #885: FAILED"): the key
   * numbered it, so its receipt is filed too - "FAILED: <intent>" - and HEAD follows the head that receipt prints.
   * Stopping without it left HEAD at the budget's opening head, and the resume line it printed was refused ("--head is
   * not the budget's head").
   */
  const fileReceipt = (seq, msg) => {
    for (let t = 1; t <= 3; t++) {
      const h = (cli(['receipt', seq, '--msg', msg]).out.match(/head = ([0-9a-f]{64})/) || [])[1];
      if (h) { HEAD = h; return true; }
      say(`  receipt #${seq}: no answer (try ${t}), again`);
    }
    return false;
  };
  /*
   * CANCEL IN THE PROGRESS WINDOW STOPS THE WORK (Brad, 2026-10-26): checked before each use of the budget - nothing more
   * goes to the key, the commits already signed stay on their branch (shipRepo keeps them on a Stop), and the budget is
   * ended here, as every budget is (nothing is left open to resume).
   */
  const cancelIfAsked = () => {
    if (!PROGRESS || !PROGRESS.cancelled()) return;
    say(`CANCELLED in the progress window - ${signedCount} signed, ${pushCount} pushed`);
    if (HEAD) {
      const ended = cli(['end']).out.trim().split('\n').pop();
      say(/not live|was ended/.test(ended) ? 'budget closed' : ended);
      HEAD = null;
    }
    unwatch();
    PROGRESS.finish(`STOP: cancelled - ${signedCount} signed, ${pushCount} pushed; the budget is ended`);
    PROGRESS = null; /* nothing later writes over the cancel line */
    throw new Stop('cancelled in the progress window');
  };
  /*
   * ONE PROCESS A USE (Brad, 2026-10-29: "fit it in the same process so we dont need to do things twice"): the exec files
   * its own receipt (--receipt) before it lets the key go, and HEAD follows the head it prints. Only a receipt it left
   * owed goes to its own `edge receipt` (fileReceipt, with its tries) - as every receipt did before.
   */
  function spend(intent, ...command) {
    cancelIfAsked();
    const r = cli(['exec', '--head', HEAD, '--intent', intent, '--receipt', intent, '--', ...command]);
    const filed = /receipt filed for #\d+/.test(r.out) && !/receipt owed for #/.test(r.out) && r.out.match(/head = ([0-9a-f]{64})/g);
    if (filed) { HEAD = filed.pop().slice(7); return r.out; }
    const seq = (r.out.match(/receipt owed for #(\d+)/) || [])[1];
    if (!seq) {
      const failed = (r.out.match(/note #(\d+): FAILED/) || [])[1];
      if (failed) fileReceipt(failed, `FAILED: ${intent}`.slice(0, 200));
      stop(`${intent}: ${r.out.trim().split('\n').slice(-2).join(' | ')}`);
    }
    if (fileReceipt(seq, intent)) return r.out;
    return stop(`receipt #${seq} would not file`);
  }
  function shipRepo(r) {
    const todo = unsigned(r);
    const ahead = commits(r).length;
    say(`== ${r.name} (${r.branch}): ${ahead} to push, ${todo.length} to sign`);
    if (todo.length) {
      /*
       * RE-SIGNED IN A WORKTREE OF ITS OWN (2026-10-24): the rebase ran in the repo itself, so its files
       * went back to older commits while it stopped at each one - and when the repo is node-onlykey-lib,
       * that is the very CLI shipping it: at the first stop the running code was from before identity
       * homes, and the exec could not find the budget the ship had just opened ("no work budget").
       * Now the rebase runs in a temporary detached worktree; the repo's own files never change. Signing
       * changes no file, so the tree is checked equal and the branch is moved to the signed commits
       * (reset --soft: the working files stay as they are).
       */
      const os = require('os');
      const wt = fs.mkdtempSync(path.join(os.tmpdir(), `okedge-ship-${r.name}-`));
      fs.rmSync(wt, { recursive: true, force: true });
      const added = git(r.repo, 'worktree', 'add', '--detach', wt, 'HEAD');
      if (added.code !== 0) stop(`${r.name}: could not make a worktree to sign in: ${added.out.trim().split('\n').pop()}`);
      const wtRebasing = () => fs.existsSync(git(wt, 'rev-parse', '--git-path', 'rebase-merge').out.trim().replace(/^(?![A-Za-z]:|\/)/, `${wt}/`));
      try {
        /* GIT_EDITOR=true: no step may wait on an editor nobody sees (a scratch run of this flow hung on one) */
        const noEditor = { env: { ...process.env, GIT_EDITOR: 'true', GIT_SEQUENCE_EDITOR: 'sed -i s/^pick/edit/' } };
        /* the first commit of a repository has no parent to rebase onto: --root takes it too */
        const onto = git(wt, 'rev-parse', '--verify', '-q', `${todo[0].hash}^`).code === 0 ? `${todo[0].hash}^` : '--root';
        runP('git', ['-C', wt, '-c', 'commit.gpgsign=false', 'rebase', '-q', '-i', onto], noEditor);
        if (!wtRebasing()) stop(`${r.name}: the rebase did not stop at ${todo[0].hash.slice(0, 7)}`);
        /* the signed commits go on the branch - all of them, or as many as were signed before a stop */
        const keep = () => {
          const signed = git(wt, 'rev-parse', 'HEAD').out.trim();
          if (git(r.repo, 'rev-parse', 'HEAD^{tree}').out.trim() !== git(wt, 'rev-parse', `${signed}^{tree}`).out.trim()) {
            stop(`${r.name}: the signed commits do not carry the same files - the branch was not moved (signed head ${signed.slice(0, 12)})`);
          }
          const moved = git(r.repo, 'reset', '-q', '--soft', signed);
          if (moved.code !== 0) stop(`${r.name}: could not move ${r.branch} to the signed commits: ${moved.out.trim()}`);
        };
        try {
          while (wtRebasing()) {
            const subject = git(wt, 'log', '-1', '--format=%h %s').out.trim().slice(0, 60);
            spend(`sign: ${r.name} ${subject}`, 'git', '-C', wt, 'commit', '--amend', '--no-edit', '-S');
            say(`  signed ${subject}`);
            signedCount += 1;
            if (PROGRESS) PROGRESS.step(`signed ${signedCount} - ${r.name}: ${subject}`);
            runP('git', ['-C', wt, '-c', 'commit.gpgsign=false', 'rebase', '--continue'], noEditor);
          }
        } catch (e) {
          /*
           * A STOP MID-REPO KEEPS WHAT WAS SIGNED (2026-10-26: four ok-edge signatures - four of the budget's uses - went
           * with the worktree when the fifth timed out). The rest of the commits are replayed as they are, unsigned, the
           * files are checked equal, and the branch moves: the next ship signs only what is left.
           */
          if (e instanceof Stop) {
            for (let n = 0; wtRebasing() && n < 500; n++) runP('git', ['-C', wt, '-c', 'commit.gpgsign=false', 'rebase', '--continue'], noEditor);
            if (!wtRebasing()) { try { keep(); say(`  ${r.name}: the commits signed so far are kept on ${r.branch}`); } catch (_) { /* the stop below says why */ } }
          }
          throw e;
        }
        keep();
      } finally {
        git(r.repo, 'worktree', 'remove', '--force', wt);
      }
      if (unsigned(r).length) stop(`${r.name}: commits still unsigned`);
    }
    if (!ahead) return;
    const named = [r.branch, ...r.also].join(' + ');
    /* a first push also sets the upstream, so the next ship's default base (@{u}) is there */
    const out = spend(`push: ${r.name} ${named}`, 'git', '-C', r.repo, 'push', ...(r.base === 'root' ? ['-u'] : []), 'origin', r.branch, ...r.also.map((b) => `${r.branch}:${b}`));
    for (const line of out.match(/\S+(?:\.\.\.?\S+)?\s+\S+ -> \S+/g) || ['pushed']) say(`  ${line}`);
    pushCount += 1;
    if (PROGRESS) PROGRESS.step(`pushed ${r.name} (${named})`);
  }

  /* ---------------------------------------------------------------- commands */
  try {
    if (cmd === 'note' && args.length) {
      const b = readBatch();
      for (const spec of args) { const s = parseSpec(spec).spec; if (!b.includes(s)) b.push(s); }
      writeBatch(b);
      say(`batch${net === 'test' ? ' (testnet)' : ''}: ${b.join(', ')}`);
      return 0;
    }
    if (cmd === 'preview') {
      REPOS = readBatch().map(parseSpec);
      if (!REPOS.length) say(`batch${net === 'test' ? ' (testnet)' : ''}: empty`);
      for (const r of REPOS) {
        say(`== ${r.name} (${r.branch})`);
        for (const c of commits(r)) say(`   ${c.signed ? 'signed ' : 'TO SIGN'} ${c.hash.slice(0, 7)} ${c.subject.slice(0, 80)}`);
      }
      const t = totals();
      if (t.gpg + t.ssh) sheet(t);
      return 0;
    }
    if (cmd === 'status') {
      const r = cli(['status']);
      say(r.out.trim());
      return r.code === 0 ? 0 : 1;
    }
    if (cmd === 'settings') {
      say(`batch:    ${batchFile}`);
      say(`settings: ${settingsFile}${fs.existsSync(settingsFile) ? '' : ' (none: ttl 30, no hooks)'}`);
      say(JSON.stringify({ ttl: Number(TTL), hooks: HOOKS }, null, 2));
      return 0;
    }
    if (cmd === 'ship') {
      const fromBatch = !args.length;
      REPOS = (fromBatch ? readBatch() : args).map(parseSpec);
      if (!REPOS.length) stop(`nothing to ship: name repos, or note them first (${USAGE[0].replace(/ \.\.\.$/, '')})`);
      REPOS.forEach(finishRebase);
      /*
       * A DIRTY TREE STOPS HERE, BEFORE THE BUDGET (2026-10-24): git will not rebase over changes to
       * tracked files - `npm test` had regenerated two .d.ts files - so the budget opened, the
       * person approved and pressed, and the first re-sign stopped ("the rebase did not stop"),
       * leaving an open budget to resume. Checked first now; untracked files do not block a rebase.
       */
      for (const r of REPOS) {
        if (!unsigned(r).length) continue;
        const dirty = git(r.repo, 'status', '--porcelain', '--untracked-files=no').out.trim();
        if (dirty) stop(`${r.name}: uncommitted changes to tracked files - commit or stash them first (nothing was asked of the key):\n${dirty.split('\n').slice(0, 5).map((l) => `    ${l}`).join('\n')}`);
      }
      const t = totals();
      say(`plan: ${t.gpg} signature(s), ${t.ssh} push(es)`);
      if (PLAN) return 0;
      if (t.gpg + t.ssh === 0) { say('nothing to do'); return 0; }
      /* the timeline of this ship, printed at its end - DONE or STOP (Brad, 2026-10-29: where a commit's 14.5 s go) */
      const timeline = TIMES ? TIMES.begin(home) : null;
      try {
        return await shipIt(t, fromBatch);
      } finally {
        if (timeline) { try { for (const l of TIMES.summary(timeline)) say(l); } catch (e) { say(`times: no summary (${e.message})`); } }
      }
    }
    for (const l of USAGE) io.err(l);
    return 2;
  } catch (e) {
    if (e instanceof Stop) return 1;
    unwatch();
    throw e;
  }

  /* the ship itself, once its plan is counted: the window, the budget, each repo, the end */
  async function shipIt(t, fromBatch) {
    {
      /*
       * THE WINDOW OPENS BEFORE ANY WORK (Brad, 2026-10-26: "it should start the progress window before it start work,
       * and automatically close when the job is done"): opened after the approval and press it came up when the ship was
       * all but over. It says each wait - the key, the approval, the press - then each signature and push.
       */
      if (GUI) {
        PROGRESS = require('../../cli/gui-prompt').guiProgress({ title: `OnlyKey - ship${net === 'test' ? ' (testnet)' : ''}`, total: t.gpg + t.ssh });
        PROGRESS.note(`${t.gpg} signature(s), ${t.ssh} push(es): ${REPOS.map((r) => r.name).join(', ')} - checking the key`);
      }
      ready();
      if (HOOKS.watch) watch();
      if (!HEAD) {
        cancelIfAsked();
        if (PROGRESS) PROGRESS.note('approve the budget in its window, then PRESS the key');
        openBudget(t);
      }
      if (PROGRESS) PROGRESS.note('budget open - signing');
      for (const r of REPOS) shipRepo(r);
      const ended = cli(['end']).out.trim().split('\n').pop();
      say(/not live|was ended/.test(ended) ? 'budget closed (every use spent)' : ended);
      unwatch();
      if (fromBatch) writeBatch([]);
      say('DONE');
      if (PROGRESS) PROGRESS.finish(`done: ${signedCount} signed, ${pushCount} pushed - budget closed`);
      return 0;
    }
  }
}

/* ------------------------------------------------------------------ --claude-setup */

const SKILL_MARK = '<!-- written by onlykey-js edge --claude-setup -->';

/*
 * The command a skill should run: `onlykey-js` when this CLI is the installed one, else this very
 * script under node - a checkout run as `node …/cli/index.js` has no onlykey-js on PATH (the
 * workspace this was first made in), and a skill that names a missing command does nothing.
 */
function cliCommand() {
  const script = process.argv[1] ? path.resolve(process.argv[1]) : '';
  if (script && path.resolve(script) === path.resolve(CLI)) return `node "${CLI.replace(/\\/g, '/')}"`;
  return 'onlykey-js';
}

function skillText(cmdline) {
  const c = cmdline;
  return `---
name: edge-control
description: Sign and push commits through an OnlyKey Edge budget - note repos as commits land, preview the batch, then ship it in one budget (re-sign every unsigned commit, push, file receipts, end) with one command. Use whenever commits must be signed or pushed through Edge, instead of working out the budget/exec/receipt/end steps by hand.
---
${SKILL_MARK}

# edge control

\`onlykey-js edge control\` keeps the batch of repos whose commits need an Edge signature, shows what is pending, and ships it in ONE budget: the person approves once (on the phone, or y + a press on a hard key) and every signature and push after that is paid by the budget, each with a receipt.

Which key is chosen by the CLI's own flags; add \`--test-mode\` after \`edge\` for the testnet:

| Key | Command prefix |
|---|---|
| a hard key on USB (y/N here, then the press - it pulses) | \`${c} edge control\` |
| a hard key on USB, the y/N in a desktop dialog (an agent's shell runs it, the person answers) | \`${c} --gui-prompt edge control\` |
| a phone (ok-edge mobile) over Bluetooth | \`${c} --ble --address "<phone>" edge control\` |

\`\`\`
${c} edge control note <repo>          # after each commit that will need signing (once per repo)
${c} edge control preview              # each commit TO SIGN or signed, the totals, the request
${c} edge control ship                 # ship the batch in one budget; the batch is emptied when DONE
${c} edge control ship <repo>... --plan  # or name repos directly; --plan only counts
${c} edge control status               # the budget status
${c} edge control settings             # where the batch and settings live (the Edge home)
\`\`\`

A repo is a path, optionally \`<path>:<base>:<branch>\` (defaults: the upstream \`@{u}\`, the current branch); \`<branch>+<other>\` also moves the remote branch \`<other>\` to the same head in the same push (\`ok-edge::main+cloudflare\`). A first push into an empty repository names the base \`root\` (\`onlykey-js:root:main\`): every commit is signed, and the push sets the upstream. Commits land unsigned (\`git -c commit.gpgsign=false commit …\`) and \`ship\` signs them.

## ship, step by step
1. Counts the work: signatures = commits after the base that are not signed; pushes = repos with commits ahead.
2. Checks the key answers (\`edge status\`); if not, runs the \`ready\` hook once.
3. Prints the budget request - reason, counts, minutes - BEFORE asking. Relay it to the person: they approve and press.
4. Opens one budget, re-signs each unsigned commit (one \`edge exec\` each, during a rebase that stops at each), pushes each repo, files every receipt, ends the budget.
5. Stops at the first thing it does not expect: \`STOP: <why>\` and, if the budget is open, the \`--head <h>\` to go on with the same command.

## Settings
In the net's Edge home (\`~/.onlykey-js/edge\`, or \`edge-test\` with \`--test-mode\`): \`control-settings.json\` - \`ttl\` (budget minutes, default 30), \`hooks.ready\` (run when the key does not answer), \`hooks.watch\` (run in the background while shipping, for a TEST rig that answers the request itself - never on a key whose owner should approve).

## Rules
- It never force-pushes, never deletes branches or tags, never rewrites commits that are already pushed.
- The person holding the key approves every budget; a live budget is never answered for them.
`;
}

/**
 * Write the skill into a workspace: <cwd>/.claude/skills/edge-control/SKILL.md. A file this did not
 * write is left alone unless --force.
 */
function claudeSetup({ io, cwd = process.cwd(), force = false, cmdline = cliCommand() }) {
  const dir = path.join(cwd, '.claude', 'skills', 'edge-control');
  const file = path.join(dir, 'SKILL.md');
  if (fs.existsSync(file) && !force && !fs.readFileSync(file, 'utf8').includes(SKILL_MARK)) {
    io.err(`edge: ${file} exists and was not written by onlykey-js - left alone (--force replaces it)`);
    return 1;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, skillText(cmdline));
  io.out(`skill written: ${file}`);
  io.out(`  it runs: ${cmdline} edge control …`);
  return 0;
}

module.exports = { run, claudeSetup, skillText, BATCH_FILE, SETTINGS_FILE, USAGE };
