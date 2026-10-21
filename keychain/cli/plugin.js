'use strict';

/**
 * KEY CHAIN, THE CLI PLUGIN (step 3a; Brad, 2026-10-07: "keychain should turn into
 * a plugin too ... edge consumes that").
 *
 * It brings the `keychain …` command, the recording of every derived public key a
 * device command makes into this computer's list (cli.aroundStart), and `gpg
 * --slot` - a certificate imported into Key Chain (pgp-import; Brad: "all into Key
 * Chain"). Core never requires this folder: built without it, `keychain` and `gpg
 * --slot` are unknown, and Edge, which consumes `keychain`, refuses to build.
 *
 * An emitter, as every feature plugin is (Brad, 2026-10-07). Its events are the
 * ones code needs ("we will find out"): 'recorded' - a device command's derived
 * keys reached this computer's list.
 */
const { EventEmitter } = require('events');

function setup(imports, register) {
  const { cli } = imports;
  const { CliError, NAME, row, usage, withDevice, requireUnlocked, deviceWrite, promptSecret, parseExpires, own } = cli.helpers;
  const deviceKeys = require('../../src/device/keys');
  const events = new EventEmitter();

  /*
   * KEY CHAIN - generate, list, derive and export keys (owner, 2026-10-01).
   * The same lib calls ok-rn's Key Chain tab makes, so the kit can drive them
   * on the emulator. The rules are Key Chain's:
   *
   *   - made ON the OnlyKey where the firmware can (gen <type> --slot): the
   *     private key never exists anywhere else. Config mode, then a restart
   *     before its public key can be read (the key drops OKGETPUBKEY there).
   *   - made on THIS machine (gen <type> --host) only for what the device
   *     cannot make (RSA, a PGP key) or a key meant to be used elsewhere: in
   *     memory, stored (--slot) and/or exported encrypted (--export-pem /
   *     --export-pgp, passphrase asked twice, the backup passphrase's rule),
   *     then wiped. One of the two is required - a key made and dropped is
   *     nothing.
   *   - a slot that already has a label is refused without --yes: it holds
   *     something, and generating over it destroys it. (In config mode an
   *     UNLABELLED key cannot be seen - the device answers no public-key read
   *     there - so list the slots first.)
   */
  const KEYCHAIN_DEVICE_TYPES = {
    ed25519: { ecc: 1, use: 'signature' },
    p256: { ecc: 2, use: 'signature' },
    secp256k1: { ecc: 3, use: 'signature' },
    x25519: { ecc: 4, use: 'decryption' },
    mlkem768: { pq: 5 },
    xwing: { pq: 6 },
  };
  const KEYCHAIN_SLOTS = [1, 2, 3, 4, ...Array.from({ length: 16 }, (_, i) => 101 + i)];

  function keychainSlot(text) {
    const m = /^(?:(rsa|ecc)\s*)?(\d+)$/i.exec(String(text || '').trim());
    if (!m) throw usage(`"${text}" is not a key slot - RSA1-4 or ECC1-16 (or 1-4, 101-116)`);
    let n = Number(m[2]);
    if (m[1] && m[1].toLowerCase() === 'ecc') n += 100;
    if (!KEYCHAIN_SLOTS.includes(n)) throw usage(`"${text}" is not a key slot - RSA1-4 or ECC1-16`);
    return n;
  }
  const slotName = (n) => (n <= 4 ? `RSA${n}` : `ECC${n - 100}`);

  /*
   * One label can hold several keys: gpg init records the ed25519 signing key
   * and the x25519 encryption key under one uid, gpg and ssh derive v1 by
   * default while the Edge agent derives v2 for the same name, and ssh -e adds
   * a P-256 key. Taking the first entry in the file certified or exported
   * whichever key happened to be written first. So every lookup by name goes
   * through here: --type and --v1/--v2 narrow it, and more than one key left is
   * refused with each candidate listed, never guessed.
   */
  const versionOf = (e) => (e.code === 232 ? 2 : e.code === 132 ? 1 : null);
  /*
   * An entry is filed as its scheme and bare name (gpg + "Name <email>"), as the
   * phone does; the name a person types and reads is the full one,
   * gpg://Name <email> or ssh://user@host - derive.identityName, the one place
   * that builds it. A slot or an imported key has no scheme: its label is its name.
   */
  const fullName = (e) => String(require('../src').derive.identityName(e) || e.label || e.name || '');
  /* the fingerprint as `keychain list` prints it, spaces or not: what tells two keys under one name apart */
  const flat = (s) => String(s || '').replace(/\s+/g, '').toLowerCase();
  const named = (e, q) => e.label === q || e.id === q || fullName(e) === q
    || (flat(q).length >= 16 && (flat(e.fingerprint) === flat(q) || flat(e.pgpFingerprint) === flat(q)));
  function narrow(entries, opts) {
    if (opts.v1 && opts.v2) throw usage('--v1 and --v2 name different keys; give one');
    return entries.filter((e) => (!opts.type || e.type === opts.type)
      && (!opts.v1 || versionOf(e) === 1) && (!opts.v2 || versionOf(e) === 2));
  }
  function onlyOne(found, name, file) {
    if (found.length <= 1) return found[0];
    const lines = found.map((e) => `  ${e.type.padEnd(9)} ${versionOf(e) ? `v${versionOf(e)}` : '  '}  ${e.fingerprint || ''}  ${(e.tools || []).join(', ')}`);
    throw new CliError([`${found.length} keys in ${file} match "${name}" - say which with --type <type> and/or --v1 / --v2, or give its fingerprint (as listed below):`, ...lines].join('\n'));
  }

  function printArtifacts(io, a) {
    if (a.ssh) io.out(`ssh     ${a.ssh}`);
    if (a.age) io.out(`age     ${a.age}`);
    io.out(`hex     ${a.hex}`);
  }



  const KEYCHAIN = {
    mirrors: '(new)',
    usage: 'list [--json] | show <label> [--type T] [--v1|--v2] [--json] | import <file> | export <label|fingerprint> --pgp|--ssh|--age [--type T] [--v1|--v2] [-o file] | cert <gpg-label> [--expires 1y] [--revoke [--reason N]] [--v1|--v2] | slots | pub <slot> | derive <label|ssh|gpg> <type> <label> [--v2] | gen <type> (--slot <slot> --label <name> | --host [--slot <slot> --label <name>] ...)',
    writes: true,
    summary: 'Key Chain: the derived keys this machine has used (list, show), the key slots, derive/generate keys',
    options: {
      host: { type: 'boolean' },
      slot: { type: 'string' },
      label: { type: 'string' },
      bits: { type: 'string' },
      'export-pem': { type: 'string' },
      'export-pgp': { type: 'string' },
      'user-id': { type: 'string' },
      v1: { type: 'boolean' },
      'test-mode': { type: 'boolean' },
      v2: { type: 'boolean' },
      type: { type: 'string' },
      json: { type: 'boolean' },
      pgp: { type: 'boolean' },
      ssh: { type: 'boolean' },
      age: { type: 'boolean' },
      output: { type: 'string', short: 'o' },
      expires: { type: 'string' },
      revoke: { type: 'boolean' },
      reason: { type: 'string' },
    },
    async run(io, opts, args) {
      const keychain = require('../src');
      const [sub, ...rest] = args;
      /* --test-mode: the testnet's list (keychain-test.json), the one edge --test-mode records into */
      { const rec = require('./record'); rec.setFile(opts['test-mode'] ? rec.testFile() : null); }

      /*
       * list / show: the host's Key Chain list (~/.onlykey-js/keychain.json) -
       * every derived public key a command on this machine made, read-only and
       * with no device. --json for agents and scripts. Public data only.
       */
      if (sub === 'list' || sub === 'show') {
        const rec = require('./record');
        const entries = rec.load();
        if (sub === 'show' && (rest.length !== 1)) throw usage('keychain show takes one label (as `keychain list` prints it)');
        const pick = sub === 'show' ? narrow(entries.filter((e) => named(e, rest[0])), opts) : entries;
        if (sub === 'show' && !pick.length) throw new CliError(`no derived key "${rest[0]}" in ${rec.keychainFile()}`);
        if (sub === 'show') onlyOne(pick, rest[0], rec.keychainFile());
        const shape = (e) => ({
          name: fullName(e), label: e.label, scheme: e.scheme, type: e.type, code: e.code, publicKey: Buffer.from(e.publicKey).toString('hex'),
          fingerprint: e.fingerprint || keychain.list.fingerprint(e.publicKey), firstSeen: e.firstSeen, lastSeen: e.lastSeen, tools: e.tools || [],
          ...(sub === 'show' ? { artifacts: e.artifacts || {} } : {}),
        });
        if (opts.json) {
          io.out(JSON.stringify(sub === 'show' ? shape(pick[0]) : pick.map(shape), null, 2));
          return 0;
        }
        if (!pick.length) {
          io.out(`no derived keys recorded yet (${rec.keychainFile()})`);
          return 0;
        }
        if (sub === 'show') {
          const e = shape(pick[0]);
          for (const [k, v] of Object.entries({ name: e.name, type: e.type, code: e.code, fingerprint: e.fingerprint, 'first seen': e.firstSeen, 'last seen': e.lastSeen, 'derived by': e.tools.join(', ') })) io.out(row(k, String(v ?? '')));
          printArtifacts(io, pick[0].artifacts || {});
          return 0;
        }
        for (const e of pick.map(shape)) io.out(`${e.name.padEnd(44)} ${e.type.padEnd(8)} ${e.fingerprint}  ${e.tools.join(', ')}`.trimEnd());
        return 0;
      }

      /*
       * export: what the host list saved for a key - its armored PGP certificate,
       * its authorized_keys line or its age recipient. No device, no press,
       * public only (spec session, 2026-10-03). A derived key has nothing private
       * to export; host-made keys keep their own encrypted-copy flow (gen --host).
       */
      if (sub === 'export') {
        const rec = require('./record');
        const want = ['pgp', 'ssh', 'age'].filter((k) => opts[k]);
        if (rest.length !== 1 || want.length !== 1) throw usage('keychain export takes one label or fingerprint and one of --pgp, --ssh, --age');
        const key = rest[0].replace(/\s+/g, '').toLowerCase();
        const found = narrow(rec.load().filter((x) => named(x, rest[0])
          || String(x.fingerprint || '').replace(/\s+/g, '') === key || String(x.pgpFingerprint || '').toLowerCase() === key), opts);
        if (!found.length) throw new CliError(`no key "${rest[0]}" in ${rec.keychainFile()} - keychain list shows what is there`);
        const formOf = (x) => (want[0] === 'pgp' ? x.pgp : (x.artifacts || {})[want[0]]);
        /* only keys that have the asked form compete: the x25519 key beside a gpg uid has no certificate of its own */
        const e = onlyOne(found.some(formOf) ? found.filter(formOf) : found, rest[0], rec.keychainFile());
        const text = formOf(e);
        if (!text) {
          throw new CliError(want[0] === 'pgp'
            ? `no certificate saved for ${fullName(e)} - make one: ${NAME} keychain cert "${fullName(e)}"`
            : `${fullName(e)} (${e.type}) has no ${want[0]} form`);
        }
        if (opts.output) {
          await io.writeFile(opts.output, text.endsWith('\n') ? text : `${text}\n`);
          io.out(`wrote ${opts.output}`);
        } else {
          io.out(text.replace(/\n$/, ''));
        }
        return 0;
      }

      /*
       * cert: build (or renew) the PGP certificate of a derived gpg identity, or
       * --revoke it. Each self-signature is a PHYSICAL PRESS on the key - never an
       * Edge budget, even under a live one that covers the label (src/keychain/
       * cert.js never ARMs). The certificate is saved into the host list, where
       * `keychain export --pgp` finds it.
       */
      if (sub === 'cert') {
        if (rest.length !== 1) throw usage('keychain cert takes one gpg label: gpg://Name <email>');
        const rec = require('./record');
        const uid = keychain.cert.uidOf(rest[0]);
        const label = `gpg://${uid}`; /* the full name, for the device and the messages; the list files the bare uid */
        const saved = onlyOne(narrow(rec.load().filter((x) => named(x, label) && x.type === 'ed25519'), opts), label, rec.keychainFile());
        const version = opts.v2 ? 2 : opts.v1 ? 1 : saved ? versionOf(saved) || 1 : 1;
        const expires = opts.expires !== undefined ? parseExpires(opts.expires) : (saved && saved.certExpires) || 0;
        const record = io.keychainRecord || rec.record;
        return withDevice(io, opts, async ({ okcrypto, identity, transport }) => {
          requireUnlocked(identity, 'keychain cert');
          const onPress = () => io.err('keychain: confirm on the OnlyKey (a press)');
          const openpgp = require('../../src/crypto/pgp');
          if (opts.revoke) {
            if (!saved || !saved.certCreated) throw new CliError(`no certificate saved for ${label} - there is nothing to revoke yet`);
            const r = await keychain.cert.makeRevocation(okcrypto, openpgp, { label, version, created: saved.certCreated, reason: Number(opts.reason) || 0, onPress });
            record({ scheme: 'gpg', label: uid, type: 'ed25519', publicKey: saved.publicKey, code: version === 2 ? 232 : 132, revocation: r.armored, tool: `${NAME} keychain cert` });
            io.out(row('revoked', r.fingerprint));
            if (opts.output) { await io.writeFile(opts.output, r.armored); io.out(`wrote ${opts.output}`); } else io.out(r.armored.replace(/\n$/, ''));
            return 0;
          }
          /* a renewal keeps the creation time, so the fingerprint stays */
          const c = await keychain.cert.makeCertificate(okcrypto, openpgp, { label, version, created: saved && saved.certCreated, expires, onPress });
          record({
            scheme: 'gpg', label: uid, type: 'ed25519', publicKey: c.signPublic, code: version === 2 ? 232 : 132,
            pgp: c.armored, pgpFingerprint: c.fingerprint, certCreated: c.created, certExpires: c.expires, tool: `${NAME} keychain cert`,
          });
          io.out(row('fingerprint', c.fingerprint));
          io.out(row('expires', c.expires ? new Date((c.created + c.expires) * 1000).toISOString().slice(0, 10) : 'never'));
          io.out(`saved - ${NAME} keychain export "${label}" --pgp`);
          return 0;
        });
      }

      /*
       * import: merge another Key Chain file (the phone's export) into this
       * machine's list - one entry per key: a phone's hash:… entry and this list's
       * named entry for the same public key become one, under the name. Public
       * data only (list.parse refuses anything private); "yours" never comes in.
       */
      if (sub === 'import') {
        if (rest.length !== 1) throw usage('keychain import takes one Key Chain file (the phone export)');
        const rec = require('./record');
        const incoming = keychain.list.parse(await io.readFile(rest[0]));
        const r = keychain.list.merge(rec.load(), incoming);
        rec.save(r.entries);
        io.out(`imported ${rest[0]}: ${r.added} added, ${r.paired} paired with a named entry, ${r.kept} already here`);
        return 0;
      }

      if (sub === 'slots') {
        return withDevice(io, opts, async ({ device, identity }) => {
          requireUnlocked(identity, 'keychain slots');
          const labels = new Map();
          try {
            const { keys } = await device.readKeyLabels();
            for (const k of keys) labels.set(k.slot, k.label || '');
          } catch (_) { /* names are a nicety; the probe is the answer */ }
          for (const slot of KEYCHAIN_SLOTS) {
            const label = labels.get(slot) || '';
            const tag = keychain.tag.parseTag(label);
            const p = await device.probeKeySlot(slot, { hint: tag && tag.hint });
            const what = p.kind === 'rsa' ? `rsa ${p.bits}` : p.wiped ? 'wiped' : p.kind;
            const fp = p.publicKey ? keychain.list.fingerprint(p.publicKey) : '';
            io.out(`${slotName(slot).padEnd(6)} ${what.padEnd(10)} ${label.padEnd(16)} ${fp}`.trimEnd());
          }
          return 0;
        });
      }

      if (sub === 'pub') {
        if (rest.length !== 1) throw usage('keychain pub takes one slot');
        const slot = keychainSlot(rest[0]);
        return withDevice(io, opts, async ({ device, identity }) => {
          requireUnlocked(identity, 'keychain pub');
          const p = await device.probeKeySlot(slot);
          if (!p.publicKey) throw new CliError(`${slotName(slot)} is ${p.kind}; there is no public key to show`);
          io.out(`${slotName(slot)} ${p.kind === 'rsa' ? `rsa ${p.bits}` : p.kind}`);
          printArtifacts(io, keychain.artifacts.forKey({ type: p.kind, publicKey: p.publicKey }));
          return 0;
        });
      }

      if (sub === 'derive') {
        const [scheme, type, label, ...extra] = rest;
        if (!scheme || !type || !label || extra.length) throw usage('keychain derive takes a scheme (label, ssh or gpg), a type and a label');
        return withDevice(io, opts, async ({ okcrypto, identity }) => {
          requireUnlocked(identity, 'keychain derive');
          let entry;
          try {
            entry = await keychain.derive.derivePublic(okcrypto, { scheme, type, label, version: opts.v2 ? 2 : 1 });
          } catch (err) {
            if (/derives|scheme|needs a label/.test(err.message)) throw usage(err.message);
            throw err;
          }
          io.out(`derived ${scheme} ${type} "${label}"`);
          printArtifacts(io, entry.artifacts);
          return 0;
        });
      }

      if (sub === 'gen') {
        const [type, ...extra] = rest;
        if (!type || extra.length) throw usage('keychain gen takes one key type');
        return opts.host ? keychainGenHost(io, opts, type, keychain) : keychainGenDevice(io, opts, type);
      }

      throw usage('keychain takes list, show, import, export, cert, slots, pub, derive or gen');
    },
  };

  /*
   * The overwrite guard reads the slot's LABEL - in config mode, where writes
   * happen, the device cannot be asked what a slot holds (probeKeySlot works
   * out of config mode only). A key written with no label is invisible to the
   * next gen or load, which then destroys it without --yes. So a key this
   * command writes into a slot always carries a name.
   */
  function needLabel(opts) {
    if (opts.label === undefined || opts.label === '') {
      throw usage('a key written into a slot needs --label (up to 16 characters): the name is what makes the next gen or load into that slot ask for --yes');
    }
    return opts.label;
  }

  async function keychainGenDevice(io, opts, type) {
    const spec = KEYCHAIN_DEVICE_TYPES[type];
    if (!spec) {
      throw usage(`the OnlyKey generates ${Object.keys(KEYCHAIN_DEVICE_TYPES).join(', ')}; for "${type}" use --host`);
    }
    if (!opts.slot) throw usage('keychain gen on the OnlyKey needs --slot (ECC1-16)');
    const slot = keychainSlot(opts.slot);
    if (slot < 101) throw usage('the OnlyKey generates into ECC1-16 only; RSA is made with --host');
    const label = needLabel(opts);
    return withDevice(io, opts, async ({ device, identity }) => {
      requireUnlocked(identity, 'keychain gen');
      const { keys } = await device.readKeyLabels();
      const existing = (keys.find((k) => k.slot === slot) || {}).label;
      if (existing && !opts.yes) {
        throw new CliError(`${slotName(slot)} is named "${existing}" - it holds a key, and generating destroys it. Run again with --yes to replace it.`);
      }
      if (spec.ecc) {
        const r = await deviceWrite(() => device.generateEccKey(slot, spec.ecc, { [spec.use]: true, label }));
        io.out(r.response || `Generated ${type} in ${slotName(slot)}`);
        io.out(`Restart the key (leaving config mode), then: onlykey-js keychain pub ${slotName(slot)}`);
      } else {
        const key = await deviceWrite(() => device.generateKey(slot, spec.pq, { label }));
        const a = require('../src').artifacts.forKey({ type, publicKey: key });
        io.out(`Generated ${type} in ${slotName(slot)}`);
        printArtifacts(io, a);
      }
      return 0;
    });
  }

  async function keychainGenHost(io, opts, type, keychain) {
    const store = opts.slot !== undefined;
    const pem = opts['export-pem'];
    const pgpFile = opts['export-pgp'];
    if (!store && !pem && !pgpFile) {
      throw usage('a key made here must be stored (--slot) or exported (--export-pem / --export-pgp) - otherwise it is made and lost');
    }
    if (store && type !== 'pgp') needLabel(opts);
    /*
     * A PGP key's two slots carry one tag, pgp:<name> (keychain/src/tag.js) -
     * the kind and the name, as a Key Chain entry has them, in the 16 bytes the
     * device keeps. Checked here, before the key is made.
     */
    let pgpTag = null;
    if (store && type === 'pgp') {
      const given = needLabel(opts);
      const t = keychain.tag.parseTag(given);
      try {
        pgpTag = t && t.kind === 'pgp' ? given : keychain.tag.formatTag('pgp', given);
      } catch (err) {
        throw usage(err.message);
      }
    }

    if (type === 'pgp') {
      if (pem) throw usage('a PGP key exports with --export-pgp; --export-pem is for a single key');
      if (store && opts.slot !== 'auto') throw usage('a PGP key is stored with --slot auto (decryption in 1, signing in 2, as loadkey does)');
      const userId = opts['user-id'];
      if (!userId) throw usage('a PGP key needs --user-id "Name <email>"');
      const m = /^(.*?)\s*<([^>]+)>\s*$/.exec(userId);
      const uid = m ? { name: m[1], email: m[2] } : { name: userId };
      const bits = opts.bits === undefined ? null : Number(opts.bits);
      if (bits !== null && !keychain.generate.RSA_BITS.includes(bits)) {
        throw usage(`RSA is ${keychain.generate.RSA_BITS.join(', ')} bits`);
      }
      const openpgp = require('../../src/crypto/pgp');
      const { privateKey } = await openpgp.generateKey({
        ...(bits ? { type: 'rsa', rsaBits: bits } : { type: 'ecc', curve: 'curve25519' }),
        userIDs: [uid], format: 'object',
      });
      if (pgpFile) {
        const passphrase = await promptSecret(io, 'Passphrase for the copy: ', 'passphrase');
        const again = await promptSecret(io, 'Again: ', 'passphrase');
        const armored = await keychain.export.encryptedPgp(privateKey, passphrase, { confirm: again, openpgp })
          .catch((err) => { throw usage(`${err.message} Nothing was written.`); });
        await io.writeFile(pgpFile, armored);
        io.out(`Encrypted copy written to ${pgpFile}`);
      }
      if (store) {
        await withDevice(io, opts, async ({ device, identity }) => {
          requireUnlocked(identity, 'keychain gen');
          /* the slots loadPgpKey's own plan will write, checked as every other slot write is */
          const planned = deviceKeys.assignPgpSlots(deviceKeys.fromPgpKey(privateKey)).map(({ slot, key }) => {
            const p = deviceKeys.prepareKey(key, { slot, autoAssign: true }); /* role slot 1/2 -> ECC1/ECC2 for an ECC key */
            p.key.fill(0);
            return p.slot;
          });
          const { keys } = await device.readKeyLabels();
          const named = keys.filter((k) => planned.includes(k.slot) && k.label);
          if (named.length && !opts.yes) {
            throw new CliError(`${named.map((k) => `${slotName(k.slot)} is named "${k.label}"`).join(', ')} - loading the PGP key destroys ${named.length > 1 ? 'them' : 'it'}. Run again with --yes to replace.`);
          }
          const loaded = await deviceWrite(() => device.loadPgpKey(privateKey, {}));
          for (const s of planned) await deviceWrite(() => device.setKeyLabel(s, pgpTag));
          io.out(`Loaded: ${loaded.map((l) => `${l.role} in slot ${l.slot}`).join(', ')} - named ${pgpTag}`);
        });
      }
      io.out(privateKey.toPublic().armor().trimEnd());
      return 0;
    }

    let key;
    try {
      key = await keychain.generate.hostKey(type, { bits: opts.bits === undefined ? 2048 : Number(opts.bits) });
    } catch (err) {
      throw usage(err.message);
    }
    try {
      if (pgpFile) throw usage('--export-pgp is for a PGP key (keychain gen pgp --host); a single key exports with --export-pem');
      if (pem) {
        const passphrase = await promptSecret(io, 'Passphrase for the copy: ', 'passphrase');
        const again = await promptSecret(io, 'Again: ', 'passphrase');
        const pemKey = type === 'rsa' ? { type, p: key.p, q: key.q, e: key.e } : { type, secret: key.secret };
        const text = await keychain.export.encryptedPem(pemKey, passphrase, { confirm: again })
          .catch((err) => { throw usage(`${err.message} Nothing was written.`); });
        await io.writeFile(pem, text);
        io.out(`Encrypted copy written to ${pem}`);
      }
      if (store) {
        const slot = keychainSlot(opts.slot);
        if ((slot <= 4) !== (type === 'rsa')) throw usage(type === 'rsa' ? 'an RSA key goes in RSA1-4' : 'an ECC key goes in ECC1-16');
        const use = type === 'x25519' ? { decryption: true } : { signature: true };
        const prepared = deviceKeys.prepareKey(key.material, { slot, ...use });
        await withDevice(io, opts, async ({ device, identity }) => {
          requireUnlocked(identity, 'keychain gen');
          const { keys } = await device.readKeyLabels();
          const existing = (keys.find((k) => k.slot === slot) || {}).label;
          if (existing && !opts.yes) {
            throw new CliError(`${slotName(slot)} is named "${existing}" - it holds a key, and loading over it destroys it. Run again with --yes to replace it.`);
          }
          const r = await deviceWrite(() => device.loadKey(slot, { type: prepared.type, key: prepared.key },
            { label: opts.label }));
          prepared.key.fill(0);
          if (r.response) io.out(r.response);
        });
      }
      io.out(`${type}${type === 'rsa' ? ` ${key.bits}` : ''} public key:`);
      printArtifacts(io, keychain.artifacts.forKey({ type, publicKey: key.publicKey }));
      return 0;
    } finally {
      keychain.generate.wipe(key);
    }
  }

  cli.command('keychain', KEYCHAIN);

  /*
   * EVERY DEVICE COMMAND RECORDS what it derives into this computer's list (it was a
   * wrapper in main()). A test that brings its own start records nothing unless it
   * gives io.keychainRecord too.
   */
  cli.aroundStart((start, { name, io, full }) => {
    const rec = require('./record');
    const recordFn = io.keychainRecord !== undefined ? io.keychainRecord : (io.start ? null : rec.record);
    if (!recordFn) { full.keychainRecord = recordFn; return start; }
    /* whatever records through this run tells the listeners (the commands use full.keychainRecord too) */
    const told = (...a) => { const r = recordFn(...a); events.emit('recorded', a[0]); return r; };
    full.keychainRecord = told;
    return rec.recordingStart(start, { tool: `${NAME} ${name}`, err: full.err, recordFn: told });
  });

  /*
   * GPG IN SLOT MODE (Brad, 2026-10-07: pgp-import into the Key Chain plugin, and gpg's
   * slot mode with it). A key pair stored in slots keeps the certificate it already has:
   * `gpg init --skey ECC<n> --dkey ECC<n> --import-pub <its .asc>`. It is used only if it
   * is genuine and its keys are the ones the slots report - the checks the phone's
   * Import PGP key runs. Without Key Chain there is no --import-pub and no slot mode.
   */
  cli.option('gpg', { 'import-pub': { type: 'string' } });
  cli.commands.gpg.slotCertificate = async ({ opts, givenUserId, skey, dkey, dev }) => {
    const pgpImport = require('../src/pgp-import');
    const openpgpLib = require('../../src/vendor/openpgp/openpgp.js');
    let armored;
    try {
      armored = require('fs').readFileSync(opts['import-pub'], 'utf8');
    } catch (err) {
      throw new CliError(`cannot read ${opts['import-pub']} (${err.code || err.message})`);
    }
    let info;
    try {
      info = await pgpImport.inspect(openpgpLib, armored);
    } catch (err) {
      throw new CliError(`${opts['import-pub']}: ${err.message}`);
    }
    if (givenUserId && givenUserId !== info.userId) {
      throw new CliError(`the certificate's user id is "${info.userId}", not "${givenUserId}" - leave the user id out to use the certificate's`);
    }
    let probes;
    try {
      probes = await dev.use(async (okcrypto, services) => [
        await services.device.probeKeySlot(skey.slot),
        await services.device.probeKeySlot(dkey.slot),
      ]);
    } finally {
      await dev.release();
    }
    const match = pgpImport.matchSlots(info, probes);
    if (match.signSlot !== skey.slot) {
      throw new CliError(`${skey.name} does not hold the certificate's signing key (it reads ${probes[0].kind}) - wrong slot, or another OnlyKey`);
    }
    if (info.encryption && match.ecdhSlot !== dkey.slot) {
      throw new CliError(`${dkey.name} does not hold the certificate's decrypt key (it reads ${probes[1].kind}) - wrong slot, or another OnlyKey`);
    }
    return {
      userId: info.userId,
      cert: { armored: info.key.armor(), fingerprint: info.fingerprint },
      createdAt: Math.floor(info.key.getCreationTime().getTime() / 1000),
    };
  };

  register(null, { keychain: events });
}

setup.consumes = ['cli'];
setup.provides = ['keychain'];

module.exports = setup;
