# Changelog

Consumers pin this library by **commit hash**, never by a branch or a floating
tag:

    "node-onlykey-lib": "github:bmatusiak/node-onlykey-lib#<full commit hash>"

A GUI, the emulator and the test kit then all run exactly the same library
until someone moves the pin on purpose. Why that matters was measured, not
assumed: on 2026-09-27 the emulator's version matrix built v3.0.4 on a Raspberry
Pi whose checkout of this library was a few commits behind the one on the other
two hosts, and the Pi read the same firmware's capabilities differently in 11
flags. Nothing had failed - two copies of "the library" simply disagreed.

The version in package.json names the release being worked on; the tag names
the commit that release ended at.

## 0.4.0 - in progress

- **The Key Chain sync converges** (the A13, 2026-10-05: every sync moved the same entries and asked for a press): `list.merge` now JOINS the fields of an entry both sides hold (`joined`) instead of keeping one side's copy - it was dropping the computer's PGP certificate, which the next agent start put back; the sync compares and digests a canonical text (keys sorted) without `lastSeen`, which moves by itself on every derive. Proven on the A13: one sync took the certificate fields, the next found the lists matching - no sheet, no press.
- **okedge sync merges the Key Chain lists** (P2a done, 2026-10-05): the place sends its whole public list in signed parts (`EDGE_SYNC_KEYCHAIN`), `EDGE_SYNC_COMMIT` brings up ONE sheet for links and list, and after the press the place `EDGE_SYNC_TAKE`s back the merged list - kept only if none of its entries is missing (`sync.checkTaken`), every entry re-parsed (nothing private, no "yours"). The sync link's last field is `sync.keychainDigest` (the list in id order); a sync that moved only the list names no seq range (0xFFFFFFFF, CHOSEN). Proven on the Pixel: 1 entry in, 8 back, both lists identical (a second sync moved nothing). The agent sends `~/.onlykey-js/keychain.json` and saves the merged list.
- **A stale Windows GATT cache**: when the quick (cached) discovery never answers, the one retry asks the phone for its whole table (uncached).
- **The Bluetooth reconnect really reconnects** (2026-10-05; reproduced on the Pixel, proven on the A13 after a force stop): the reconnect's Part T hello was queued behind the very write that was reconnecting - nothing left the PC, and it read as the phone's silence (only a fresh process got in); the hello now skips the queue during connect(). A reconnect waits for the old link to close. A request whose FIRST fragment the old link refused (a phone app restart) is sent once more after the reconnect - the phone held none of it; a request refused partway is never re-sent. Reply clocks (the Edge plugin's and the shared transport's request) start once the write has gone out.
- **okedge sync, phase 2: this PC's copy fills the phone's** (spec, 2026-10-05). `src/edge/sync.js`: signed `EDGE_SYNC_HAVE` / `EDGE_SYNC_LINKS` (batches of 40), `merge` (a disagreeing link is a fork - reported, nothing taken), `syncFields` / `syncSubject` = SHA256("OKEDGE-SYNC-v1" ‖ SHA256(peer) ‖ first ‖ last ‖ the copy head after the merge ‖ SHA256(Key Chain list) or zeros), pinned by a test vector the soft key's firmware also passes. `edge.sync` sends the three parts (wire 0x39, op 20 - the KEY computes the subject and checks the peer is on its list), `approve.approveSync`, `client.syncToPhone`; `okedge sync` offers its verified copy to the phone after phase 1. Status `sync-order` (0x17).
- **The Bluetooth link survives a failure** (2026-10-05, the A13): a write the phone refuses fails only its own request, the link is dropped and the next request reconnects (reported through `onLink`); a reconnect whose Part T hello meets silence CLOSES the link it opened (it was left open: the phone showed "connected" and stopped advertising); the Edge plugin no longer leaves a refused write unhandled (it ended the edge-agent); an Edge request's answer clock starts once the write has gone out.
- **okedge says when no agent is there**: "no edge-agent is running" at once, and "the edge-agent stopped" when it dies mid-request (both of the day's hangs); "Waiting for the phone" only once the agent has the request.
- **Known peers - okedge sync phase 2, P2a** (firmware.md R20; Brad, 2026-10-05): the places a sync may send copies to are the KEY's list, added and removed only with a press, each a link (`peer-add` / `peer-remove`, subject SHA256(X ‖ Y)). Device: `edge.peerAdd` (two requests on the wire - X staged, then Y and the press), `edge.peerRemove`, `edge.peers` (no press); status words `peers-full`, `peer-known`, `bad-key`, `no-such-peer`; `grants.peerSubject`. The phone's side: `EDGE_PEER_ADD` (`request.buildPeerAdd` / `verifyPeerAdd`, signed by the peer's own P-256 key) and `approve.approvePeerAdd` (sheet, Yes, press, the link checked); `client.peerAdd`. CLI: this PC's copy store gets its own key (`<edge home>/peer.key`, never the agent's); `okedge peer add | list`. Peers and siblings are not in the backup.
- **A LOSS sets aside links the copy still holds** (2026-10-04): `verifyCopy` checks from after the last LOSS range, not only after the gaps a LOSS covers. Budgets the Pixel opened between the two R3 builds (opening count 0, spends scoped) fail the exact rule; the spec's fix is a LOSS over their links (a press), and the copy is then checked after them. New refusal `busy`: another request is on the phone.
- **edge-agent records its certificate in the Key Chain list** (step 3): `keychain export "gpg://…" --pgp` prints the agent's certificate for GitHub.
- **R3, exact** (spec session, 2026-10-03): the grant-create link carries its budget's scope count in byte 46. `verifyCopy`: the opening says N → every spend names 1..N; it says 0 → every spend is 0 (an older budget); an opening not in the copy (a LOSS range) → all or none. An opening whose count is not its scopes' count fails. Proven on the emulator: kit 38 21/0/1 (the R26 replay with 47-byte REPLAY, the agent service).
- **R3: the scope that paid, in byte 46** (spec session, 2026-10-03; firmware.md R3). A budget-spending link names which of its budget's scopes paid (1-based); 0 on every other link and on links written before. `chain.decodeLink` gives `scope`; "reserved zero" is now bytes 47-63; `encodeLink` takes `scope`. `verifyCopy` checks it: in range, covering the link's op and slot, each scope within its cap, a budget's spends all scoped or none (an older chain), no scope on a link that is not a spend, bytes 47-63 zero. REPLAY sends 47 bytes. The fake Edge key writes it (matching the label, as R11a); the external vectors (onlykey-edge `vectors/`) carry it.
- **The spec session's answers (2026-10-03, night).**
  - `keychain cert` under R16 (no firmware exemption): refuses to start while the key owes anything, and tickets its own presses right after (code OK, "cert self-signature <fingerprint>") - `cert.guardOwed` / `cert.ticketOwnPresses`.
  - One entry per key: `list.merge` pairs a phone's `hash:…` entry with a named one holding the same public key (`findTwin` / `combine`: the name, the hash kept as `labelHash`, first seen earliest, last seen latest, tools, transport and rpId joined); `record()` pairs the same way; new `onlykey-js keychain import <file>` merges the phone's export into this machine's list.
  - The agent after the soft key's idle restart: a budget gone without a grant-end link makes it ask the phone ONCE to continue (the old lifetime; your Yes and press) and refuse that exec with the new head (EEDGE_CONTINUED) - no retry loop. A budget ended on purpose stays ended. `client.continue` reuses the saved lifetime when none is given.
- **`okedge watch [--once]`** (mcp-service.md: "the same live feed in a terminal"; okrn-edge-tab.md B7). Read-only: one line per use (self-press or pressed, the budget and which use, the exec's reason in quotes), its ticket under it (code name and message, one plain line - the agent's text is never interpreted), and alarms highlighted: an alarm ticket (bit 7 or an unknown code), a press under a live budget (R16), an ARM that did not match its request, a refused exec, a budget no longer live, a LOSS or a wipe, links lost from the key's ring. The agent service gains a read-only `feed` control request; approve, hold and waive stay on the phone.
- **`keychain export` and `keychain cert`** (spec session, 2026-10-03). `export <label|fingerprint> --pgp|--ssh|--age [-o file]` prints or writes what the host list saved: the armored certificate, the authorized_keys line, the age recipient - no device, no press, public only. `cert <gpg-label> [--expires 1y]` builds (or renews, keeping the fingerprint) the certificate of a derived gpg identity and saves it into the list; `--revoke [--reason N]` makes a revocation certificate (new `pgp-cert.buildRevocation`). Every self-signature is a PHYSICAL PRESS, never an Edge budget, even under a live budget covering that label (`src/keychain/cert.js` never ARMs; tested on the fake Edge key). The CLI now parses each command with its own options, so one option name can mean different things to two commands (`edge-agent --ssh ssh://…`, `keychain export --ssh`).
- **firmware-plugins `stateless` / `slotPlugins()`**: a plugin that keeps no state of its own (`stateless: true` in its manifest - ok-rn's key_chain, which only reports derives) no longer names the storage slot, so adding it does not move a soft key to an empty slot (that reads as "set up this key").
- **The host's Key Chain list** (spec session, 2026-10-03: Brad's idea). Every derived public key a CLI command makes - `agent`, `gpg-agent`, `edge-agent`, `keychain derive` (agent and label schemes) - is recorded into `~/.onlykey-js/keychain.json` (`ONLYKEY_KEYCHAIN` moves it; owner-only), in the phone's own export format so the existing import merges it: label, type, code, public key, fingerprint, first/last seen, which tool. `onlykey-js keychain list | show <label>` read it with no device, `--json` for agents; the old `keychain list` (the key's slots) is now `keychain slots`. Recording never fails a command. "Yours" (the own-identities mark behind the phone's red warning) is the phone's alone: `list.createEntry` drops it from every entry, so a CLI or agent write cannot set or clear it and an imported file cannot bring it.
- **The agent sees what the KEY owes** (spec session, 2026-10-03; found on the Pixel in step 2). Under R16 a pressed sign with the agent's key owes a ticket while a budget covers it, and R18 then stops every budget - but the agent only tracked its own paid uses, so `okedge status` said nothing was owed while the phone said two. Now `status` names each seq the key owes (replayed from its ring with `tickets.keyDebts`; anything older is counted), says which are the budget's own uses and which pressed signs, and reports uses spent from the budget's steps; `exec` refuses up front with EEDGE_KEY_OWED naming them. The fake Edge key models R16's covered case (it only marked ARMed presses). And a key whose version was not read (locked, just restarted) no longer reads as "no agent derivation v2".
- **edge-agent `--expires 1y|<n>d|never`** (Brad, 2026-10-03: one year for the real key). The agent's PGP certificate carries that lifetime; a changed lifetime makes a new certificate (two presses), the same one reuses the saved certificate. And edge-agent waits 180 s for the phone (was 150): ok-rn now gives the person 2 minutes to say Yes, then the key's 25 s press.
- **The Edge agent service (Phase 2, build step 1)** (onlykey-edge mcp-service.md §4.2 / §4.2a, decided 2026-10-03; PROPOSAL-edge-agent.md). `onlykey-js [--ble …] edge-agent` holds ONE link to the phone, the agent's OWN derived ssh + PGP keys (D2; ed25519, agent derivation v2; the PGP certificate made once, two presses, kept in agent.json), the work budget, and three endpoints: the shared ssh-agent (never paid - always a press), the control endpoint (`okedge`, the gpg shim; owner-only, every request carries the 0600 control.key secret), and **one endpoint per `okedge exec`** - a fresh owner-only SSH_AUTH_SOCK and a one-time gpg-shim token, closed with the command (cap 10 min). The budget pays once per exec, only for a sign on its endpoint; for ssh only when session-bind@openssh.com is VERIFIED to a pinned host (GitHub's three fingerprints by default) and the request is for that session. `okedge` (bin): budget | continue | exec | ticket | status | end - exec refuses up front on a ticket owed, a budget held or gone, or a stale --head, runs the command with git's gpg.program / signing key / the agent as committer, prints the link it caused, exits with the command's code. `onlykey-edge-gpg` (bin): git's gpg.program - `pgp-cert.signDetached`, no Gpg4win. The L7 client now ARMs over the key's head read just before each use (another link in between - a person's press, another agent - had left the budget unable to pay). Proven: lib tests on the fake key incl. a real `git commit -S`; the ok-rn plugin kit test on the real Edge firmware (emulator): a signed commit and an ssh sign paid and ticketed, the shared endpoint a press, skipped ticket / stale head / Hold refused.

- **Rapid agent calls after an unanswered press** (Brad, 2026-10-03: "it must be a 5 sec wipe"). When nobody presses, the key gives up at 20 s but keeps CRYPTO_AUTH set until its 5-second wipe runs (3.1.0 okcore.cpp:5620, :5651, :5606); meanwhile every OKSIGN/OKDECRYPT is answered "Error device locked" by a key that is unlocked (okcore.cpp:472). Measured on the Pixel soft key: a sign 2.4 s after a timed-out one got exactly that. okcrypto now waits the wipe out (5.5 s) once and sends again - keyed on the answer, so it works across processes (each agent run is a new one); a key still saying it after the wait gets that answer. `onBusy` tells the caller (the CLI agent prints it). Tests: the fake firmware's `cryptoBusy`.

- **Edge L7 step 2: the Bluetooth channel, continue, agents registered with a press** (onlykey-edge mcp-service.md 4.7a, firmware.md R15c). `edge.wire`: EDGE_REQUEST travels as its own vendor message, OKEDGE_REQUEST 0xF7 (OKEDGE is 0xF8, the config plugin 0xF9/0xFA), cut into 64-byte reports; the phone's bridge keeps it for the app, the key never sees it; `createWireChannel(transport)` is the computer's side. `continue: <budget>` is signed with the request; only an ENDED budget is continued - `client.continue()` ends the old one first (a revoke, no press), the app refuses a live one with the new refusal `still_live`, and the sheet is told what live budgets already cover the request (`view().covered`). Registration (`EDGE_REGISTER`, signed by the key it names): the person's Yes, then a PHYSICAL press - the Edge plugin's new sub-op **AGENT_ADD 0x15** {agent key 32} links op 15 (`agent-add`), grant_id 0, subject SHA256("OKEDGE-AGENT-v1" || key); `approve.approveRegister`, `edge.agentAdd`, `grants.agentSubject`, `request.fingerprint` (what the phone and the computer both print). `approve.agentInCopy(rows, key)` (R15c): an agent counts only with its pressed agent-add link in the app's VERIFIED copy - one in storage without it is refused unread. A press the key gave up on ("Timeout occured while waiting for confirmation") is now an ETIMEDOUT for every Edge press; it used to be parsed as an answer. CLI: `onlykey-js --ble edge register | request | continue | use | ticket | end` (the agent's own key in ~/.onlykey-js/edge/). The app makes every hash from the text and the names; a test proves hashes carried by a request are never used.

- **Edge L7: Edge from an app** (`edge.request`, `edge.approve`, `edge.client`; onlykey-edge okrn-edge-tab.md L7 + mcp-service.md 4.7a). One `EDGE_REQUEST` message for every channel: agent key, nonce, reason text, scopes with identity names, caps, lifetime, an Ed25519 signature over an unambiguous body. `approve.approveRequest` is the app's side (what ok-rn runs, minus the screen): drops unregistered, tampered or replayed requests; checks caps (at most 300, D4) and lifetime (1 min to 24 h, CHOSEN); asks the person through a plug-in `ask(view)` - the view flags the person's own identities for the red warning; verifies its copy (R27); makes the labels and the reason hash itself; grants on the key; answers with the budget or a typed refusal (declined, timeout, copy_unverified, ticket_owed, restoring, invalid). `client.createEdgeClient({edge, channel, signer, store})` is the agent's side: `request()` checks the opening against the key itself (EEDGE_OPENING when the answer is not what was asked), `budget.use(bytes, op)` ARMs over the head and those bytes, fails fast on a refused ARM (EEDGE_ARM) and checks the link it caused, `ticket()`, `pending()`, `end()`, and `resume()` from a store. The fake Edge key moved to test/helpers and decides signs like the firmware.

- **Edge R11a: budgets on derived identities are scoped by label.** The agent sign codes 201-203 / 221-223 are shared by every derived identity, so a scope on them must name one: `{op, slot, cap, identity: "ssh://agent@host" | "gpg://user id"}` (or `label`, the 32 bytes). `grants.identityLabel(name)` hashes the name exactly as the agents do; `grantSubject` ends with the derived scopes' full labels; `edge.grant()` stages each with `GRANT_LABEL` (sub-op 0x11, no press) before `GRANT_CREATE`. A derived scope without an identity is refused before anything is sent (the key refuses it too, EDGE:03). Stored slots are unchanged - there the slot is the key, and their grant subject is the same bytes as before.

- **gpg with keys stored in slots** (owner, 2026-10-03: sign git commits with the PGP pair made in Key Chain). `onlykey-js gpg init --skey ECC2 --dkey ECC1 --import-pub <key.asc>` imports the slots' EXISTING certificate - re-signing would change the published fingerprint - after `keychain.pgpImport` checks it is genuine and its keys are the ones ECC2/ECC1 report; the user id comes from the certificate. `gpg-agent --skey ECC<n> --dkey ECC<n>` signs with the slot (OKSIGN) and does the X25519 exchange with the other (OKDECRYPT); every signature is still verified against the keyring before gpg gets it. The ssh agent keeps the derived key only. Tests: the fake key signs/exchanges with stored keys (`slotKeys`).

- **One lane per key: one conversation with the key at a time, across every plugin** (`src/transport/lane.js`). The vendor interface has no request ids, so two conversations in flight swap answers - measured on the phones (2026-10-03): a background Edge sync and a test's grant; Key Chain's slot reads and a sync (slots read "unknown", ECC1 as ed25519), and a PGP signing that locked the production firmware. Edge's own queue (89850fd) did not make the device plugin wait for Edge. Now the transport owns the lane: `transport.request()` waits its turn, `transport.exclusive(fn)` holds it for a whole conversation (listener, write, answer, a press), `transport.requestNow()` is the raw request inside one. The device plugin's conversations (PIN, public-key reads, key generation, chunked key loads, slot wipes, restore and its verdict), okcrypto's sign/decrypt, config's read/write and every Edge request run in it. Taken at request level, never around code that makes several requests - key generation's label write uses the raw request, or it would wait for itself. An idle lane starts at once (no extra tick before a conversation subscribes); a transport without `exclusive` (older contract, test fakes) gets a lane kept for it (`inLane`). Tests: test/lane.test.js.

- **restore() reads the device's verdict without a passphrase too.** Measured on the Pixel (2026-10-03): the no-passphrase path returned when the last packet was out, so ok-rn reported three restores as done while the firmware had answered "Error incorrect backup key set" and written nothing. Now an "Error ..." throws; "Successfully loaded backup" returns `verdict: 'loaded'`; silence still returns, as `verdict: 'unknown'`. Test: a wrong backup key is refused, not "done" (fails before the fix).

- **Key Chain: import a PGP public key back** (`keychain.pgpImport`, owner 2026-10-03). A device backup restores the private keys, but the certificate lives in the App's list - so a restored phone needs the `.asc` too, and re-signing would make a DIFFERENT PGP key (the fingerprint covers the creation time). Nothing lands until three checks pass: `inspect` (the self-signatures and subkey binding verify; private key blocks refused), `matchSlots` (the keys equal what the slots report - the key computes those from its private keys), `proveSlots` (the signing slot signs a fresh challenge that verifies with the certificate's key; the decrypt slot's X25519 exchange with a throwaway key equals the host's - a press each). `entryFor` links the slots only when proven; otherwise it is someone's key to encrypt to.

- **Edge: one request at a time** (`plugins/edge`). OKEDGE replies are binary with no marker, and each request took the next vendor reports as its own, so two callers on one stack swapped answers. Measured on the Pixel (2026-10-03): ok-rn's background copy ran a PICKUP while an e2e test waited for its GRANT_CREATE, and the grant read link bytes ("3618 uses, opened at #4229928469"). Every request now waits for the one before it - a pressed one (grant, resume, waive, replayDone, loss) for its whole wait. Test: a grant, a pickup and a HEAD at once each get their own answer (it failed before the fix).

- **Edge R16 changed (spec session, 2026-10-02): which uses owe a ticket is decided by ARM and slot, by the key, at decision time.** ARMed (an arm waited at the prime, token matched or not) → owes; not ARMed but a live budget - held or not, used up or not - covers the op and slot → owes; neither → owes nothing (a direct press the person saw). The key writes it into the link: `FLAG.OWES_TICKET` 0x10 (bit 4) and `FLAG.ARMED` 0x20 (bit 5). `tickets.keyDebts` counts only approved uses with bit 4; `pairTickets` reports an approved use without it as `no-ticket-owed`. Vectors regenerated (onlykey-edge `vectors/make_vectors.py`: the self-presses carry both bits). A chain written before this firmware has no bit 4, so its pressed uses read as owing nothing.

- **OKGETCONFIG - the soft key's settings as INI** (owner, 2026-10-02; `PROPOSAL-softkey-config-plugin.md`). The firmware writes settings and reads none back; ok-rn's soft-key `config` plugin prints them as INI with this library's preference names. `node-onlykey-lib/config` (`parse`, `plan` - pure) and `plugins/config` (`config.read()` / `readText()`: whole reports to the NUL; `EREFUSED` on a refusal, `EUNSUPPORTED` on silence - every hard key, which never has it). CLI: `onlykey-js config [export [file] | import <file> [--one-way]]`. Import is the firmware's OKSETCONFIG (owner: config mode only, DEBUG soft-key builds only): `config.write()` sends the file in 58-byte chunks, the key hands each value to its own setting write, then the CLI reads back and reports each value as taken or not. Never `[input]`; `[advanced]` only with `--one-way`. The ssh agent reads the key's mode and prints only what applies ("press any button" or the code); a key without OKGETCONFIG keeps the old wording.
- **Edge chain library: `node-onlykey-lib/edge` (Edge step E1).** Pure, no
  device access, Hermes-clean (vendored @noble only; the test runs it with
  Buffer, TextEncoder/Decoder and crypto removed). Spec:
  onlykey-edge/build/okrn-edge-tab.md L1-L3, L6.
  - `chain`: the 64-byte link (encode/decode), `genesis`, `weld`, and
    `verify(links, {deviceId, expectHead, anchors, lastSeen, ringFrom, ...})`,
    which returns `{ok, verifiedThrough, gaps, failure?: {seq, reason}}`.
    Reasons: `hash-mismatch`, `seq-gap`, `seq-reorder`, `head-mismatch`,
    `rollback`, `device-mismatch`. Trust spreads forward from genesis or a
    checkpoint, and backward from the key's head through the heads a mirror
    stores. Anything it cannot reach is a gap, never "verified".
  - `grants`: budget self-press checks (`H^i(v_i) == G`, plus an HMAC over the
    subject); reasons `wrong-budget`, `wrong-step`, `mac-mismatch`,
    `past-cap`; `checkSpends` also catches a replayed or skipped step.
  - `tickets`: pairs each sign/decrypt with its ticket (ticketed, alarm,
    missing, or no ticket owed). A message from sync is shown only when it
    hashes to the ticket link. Bit 7 or an unknown code means alarm.
  - **Each budget is its own provable chain, opened by a signed press** (owner,
    2026-10-02; the `bmatusiak/provable` construction). The firmware keeps ONE
    signature, the checkpoint over `(seq, head)` (`chain.checkpointDigest`,
    `verifyCheckpoint`, P-256 with the Edge key).
    - A budget's grant-create link commits to `G` in its subject
      (`grants.grantSubject`), and the press is answered with a checkpoint over
      that link, so `G` is signed through the chain.
    - `grants.verifyBudgetOpening` checks that proof on its own. Failure
      reasons: `uses-mismatch`, `not-a-grant-create`, `subject-mismatch`,
      `weld-mismatch`, `bad-signature`.
    - Every reveal then hashes back to `G`.
    - `chain.deviceIdOf` derives the device id from the Edge public key, as the
      key does.
    - Node's own ECDSA agrees in both directions.
    - Budgets have at most 255 uses (owner).
  - **Plugin backups** (`cli/firmware-plugins`, the owner's rule: plugins back up
    their important bits, and older firmware is never affected). A plugin whose
    manifest says `backup: true` gets an entry in one section the loader writes
    LAST in the device backup:
    - layout: `0xFB | name length . name . data length (u16) . data` per plugin,
      at most 512 bytes for all plugins together;
    - it sits inside the backup's encryption and digest;
    - older firmware stops its restore at `0xFB` with everything before it
      applied, and reports success - measured on v3.0.4 and base 3.1.0
      (node-onlykey-emulator `test/restore-plugin-backup.js`).
  - **`node-onlykey-lib/plugins/edge`: the device calls (L4/L5).** A Rectify
    plugin over the transport, providing `edge`: `head`, `publicKey` (and the
    device id), `pickup`, `checkpoint`, `grant` (waits for the physical press;
    `onPress` for the UI), `revoke`, `ticket`, `probe`.
    - The firmware's `EDGE:xx` replies become an `EdgeError` with a name
      (`codes.STATUS` holds the words; the firmware sends only the code).
    - Every wait is bounded. `probe()` returns `'edge'`, `'no-pin'` or
      `'none'`, and silence never hangs.
    - It is removable: nothing else depends on it, and a host decides whether to
      probe (only Edge soft-key builds know 0xF8).
  - **The spec change (onlykey-edge c7c30dd): every approved use owes a
    ticket, nothing automatic while one is owed.**
    - Every approved use - pressed or self-pressed - owes a ticket (R16). The
      key keeps the latest 4 owed; `pairTickets` shows those as `waiting` and
      older ones as `missing`. A deny does not clear a debt.
    - WAIVE (R18): one press clears every owed ticket. It is linked as a
      ticket `0x8F` with the press flag, grant id = the oldest waived, subject
      `tickets.waiveSubject(seqs, overflow)` =
      SHA256("OKEDGE-WAIVE-v1" || seqs u32 LE || overflow byte). Uses it lists
      read `waived`; with overflow, the older ones read `waived-unlisted`. An
      agent's own `0x8F` ticket (no press flag) still pays one use and is an
      alarm.
    - New calls: `arm(head)` before each self-press (R13a), `hold(id)` /
      `resume(id, { onPress })` (R15a; resume needs a press), `waive({ onPress
      })`. `ticket()` now returns `{ seq, head }` - the head the next `arm()`
      passes. `head()` adds `held`, `owed` and `overflow`.
    - Codes: sub-ops GRANT_HOLD 0x13, GRANT_RESUME 0x14, WAIVE 0x21, ARM 0x22;
      link ops grant-hold 13 / grant-resume 14 (appended last in `OP`); status
      0B stale-head, 0C ticket-owed, 0D nothing-to-arm.
  - **A budget is up to 1024 uses again** (R11; Brad, 2026-10-02: 255 is too few once the VM and the Pi are in the loop). `grants.MAX_USES` 1024; caps stay u16 per scope.
  - **The key's own links are not a loss** (spec okrn-edge-tab.md 4.3): `verifyCopy(copy, { ..., held })` trusts the links PICKUP gave from the key's ring this session (byte-equal to the copy's), so a gap - and the range offered to accept as lost - is only what is really missing (`copy.missingGaps`). A held grant-create whose predecessor is gone is checked by its subject and the checkpoint over the key's head. `edge.grants.check` fetches the ring itself.
  - **What counts as verified** (firmware.md R27, tab spec B2; found on the Pixel, 2026-10-02: a key restart left the copy #30-#36 and #48, and the banner offered #0-#47 as lost). `copy.assess(copy, key, {ringFrom, lastSeen})` is the one answer the tab's banner and `verifyCopy` (Approve) both read: anchors are the genesis, the key's live HEAD and every checkpoint (the key's latest, each budget opening's, `copy.checkpoints`) whose signature verifies under `key.publicKey` - the key's, never one the copy carries; without a public key only genesis and HEAD anchor. The gap is only what no anchor reaches. **Security fix:** a LOSS link now counts only when it is itself verified and later than the gap it covers - before, a LOSS inserted inside an unverified range covered its own gap, so an edited copy passed the check (test first: it returned ok).
  - **The link after a LOSS** (firmware.md R24, Brad 2026-10-02; the Pixel: #37-#47 accepted while the key held #48, which a restore later made unprovable). A LOSS {A..B} written while the key held #B+1 carries the first 28 bytes of SHA-256(link B+1) after `to`; `copy.lossesIn` returns it as `next`, and a VERIFIED LOSS keeps the copy's #B+1 when its bytes hash to it - never on the copy's word. Without it #B+1 stays in the missing range (#A..#B+1). Verified LOSS links later than a gap now cover it together, so an overlapping or adjoining pair (#37-#47, then #37-#48) settles it cleanly.
  - **LOSS {from, to} and gaps under R27** (onlykey-edge R24, the red banner, 2026-10-02). `edge.loss({ from, to, onPress })`: a pressed loss link (grant_id = from, subject = to); `bad-range` (0x12, CHOSEN) past the head. `copy.verifyCopy` now accepts a gap only when a LOSS link in the copy covers it (`copy.uncoveredGaps`, `copy.lossesIn`), looks heads up by seq (a copy need not start at genesis), and replays the debts from after the last covered gap.
  - **R26 fix: replay commits only vouched history** (onlykey-edge firmware.md R26, 2026-10-02). Replay is tentative on the key until `edge.replayDone({ seq, tag, newestSeq })` presents the key's own vouch tag for exactly the replayed head; otherwise `EdgeError` `not-vouched` (0x11) and the LOSS covers everything since the backup. `edge.vouch()` (05) gives `{seq, head, tag}` for the current head (refused while restoring, like CHECKPOINT); `ticket()` and `waive()` now return the tag too. A host keeps the newest tag with its copy.
  - **ARM bound to the request (R13a), budget expiry (R15b), the GRANT_CREATE
    layout** - onlykey-edge `892ece8`, `badfd16`.
    - `grants.armToken({ head, subject })` = SHA256("OKEDGE-ARM-v1" || head ||
      subject); `grants.requestSubject(bytes)` = SHA-256 of exactly the bytes
      the firmware primes. `edge.arm(head, subject)` sends the token, not the
      head. Proven against the firmware's own `pend.subject` on the emulator
      (kit 38: RSA sign, ECC sign, RSA decrypt, a multi-packet sign).
    - `grantSubject` / `verifyBudgetOpening` take `lifetime` (u16 minutes, 0 =
      the key's 12 h): the subject ends `|| G || lifetime`. The copy check reads
      it from each opening.
    - `edge.grant({ ttlMinutes })`: GRANT_CREATE is `[49]` flags, `[50..51]`
      lifetime, `[52..57]` the first 6 bytes of the verified head (the spec's
      layout; it was 8 bytes, CHOSEN).
    - Vectors: the grant subject with a lifetime, and an ARM token
      (onlykey-edge `35d99f9`).

  - **Restore, then replay (R26) and no budget from a copy that doesn't verify
    (R27)** - onlykey-edge `0dda6ac`.
    - `copy.verifyCopy(copy, key)` (new `src/edge/copy.js`): a host's copy must
      verify from genesis up to the key's live HEAD - every weld, the latest
      checkpoint, each budget's opening and `G`, every self-press reveal, and
      the debts HEAD reports. The first failure is the answer: `restoring`,
      `chain`, `gap`, `checkpoint`, `budget-opening-missing`,
      `budget-opening`, `reveal-missing`, `reveal`, `debts`.
    - `edge.grants.create` / `edge.grants.resume` run it first and fail closed
      (`EDGE_COPY_UNVERIFIED`, with the verdict; nothing reaches the key);
      `edge.grants.check` gives the verdict alone, for a UI. The raw
      `grant` / `resume` now require `verifiedHead`.
    - `edge.replay(link)`, `edge.replayDone({ newestSeq, onPress })`; `head()`
      adds `restoring`. Statuses 0E restoring, 0F replay-mismatch, 10
      replay-closed.
    - CHOSEN, pending the spec: GRANT_CREATE carries the first 8 bytes of the
      verified head and REPLAY the link's first 46 bytes plus the first 8 of the
      head the copy stored after it, so the key can check the weld (a vendor report has
      58 argument bytes; bytes 46-63 of a link are reserved zeros).
    - Fixed: `pairTickets` counted "the newest 4 unpaid" as waiting. The key's
      list does not refill once a use falls off, so after a 5th use and one
      ticket the key reports 3 owed + overflow while the lib said 4 waiting.
      New `tickets.keyDebts` replays the key's own list over the chain.
  - `codes`: every number the spec left open, marked CHOSEN in one place.
  - Vectors: `test/vectors/edge-v1.json` is made by
    onlykey-edge/vectors/make_vectors.py (stdlib Python, written from the spec
    text alone). The device calls (L4) and the `capabilities().edge` probe (L5)
    wait for the Edge firmware plugin (E3).

- **PBKDF2 natively where the platform can, with progress where it cannot.**
  New `src/crypto/pbkdf2.js`: `pbkdf2Sha256(password, salt, iterations, dkLen,
  { onProgress })` uses WebCrypto's PBKDF2 (Node, browsers, or the shim when
  the host lent a native one) and otherwise runs the RFC 8018 loop itself,
  reporting 0..1 and yielding between steps so a UI can draw a bar. The
  WebCrypto shim implements PBKDF2 and takes a host hook, `install({ pbkdf2 })`
  (ok-rn lends Android's); `okShim.nativePbkdf2` says which. Key Chain's
  `encryptedPem` uses it and takes `onProgress` - 600000 rounds were a long,
  silent wait under Hermes. Every path is held to Node's `pbkdf2Sync`.

- **Key Chain L7: `onlykey-js keychain`.** `list` (every key slot: what it
  holds, its label, a fingerprint), `pub <slot>` (SSH line / age recipient /
  hex), `derive <label|ssh|gpg> <type> <label> [--v2]`, `gen <type> --slot`
  (made ON the OnlyKey: ed25519, p256, secp256k1, x25519, mlkem768, xwing) and
  `gen <type> --host` (made here: the ECC types, rsa `--bits`, or `pgp
  --user-id`; stored with `--slot` and/or exported encrypted with
  `--export-pem` / `--export-pgp`, passphrase asked twice, written 0600 and
  never over an existing file; one of the two required). A slot that already
  has a label needs `--yes`. `withDevice` now hands commands `okcrypto` too.
  Fixed on the way: `derivePublic`'s SSH identity is `{ ssh: { user, host } }`
  (the agent's shape), not the bare string.

- **Key Chain L5 + L6: derived public keys and the public-only list.**
  `keychain.derive.derivePublic(okcrypto, { scheme, label, type })` - a public
  key the device derives from a label (`label`: P-256, secp256k1, X25519 and
  the X-Wing age identity; `ssh` / `gpg`: the agent identities, Ed25519 or
  P-256, v1 or v2), returned as a Key Chain entry; nothing private is kept, the
  device re-derives it. `keychain.artifacts.forKey` gives every shareable form
  in one place (hex, base64, SSH line for Ed25519 / P-256 / RSA, age recipient
  for X25519 / X-Wing). `keychain.list`: entries for slots, derived keys and
  external public keys with stable ids, a JSON file format
  (`onlykey-keychain` v1) with `serialize` / `parse` / `merge`, and a refusal of
  anything private - private-key field names, PEM, armored private blocks, age
  secret keys - on create and on every parse.

- **Key Chain L3: keys made on the host.** `keychain.generate.hostKey(type,
  { bits })` makes Ed25519, X25519, P-256, secp256k1 (noble) or RSA 2048 /
  3072 / 4096 (WebCrypto) in memory and returns the public key plus the
  `material` `device.loadKey` takes; `wipe()` zeroes it after. The WebCrypto
  shim takes a host RSA generator - `install({ rsaGenerate })`, `async (bits,
  e) => ({ p, q })` - completes the key from the primes (new
  `src/crypto/rsa.js`, shared with the PKCS#8 writer), refuses a modulus of the
  wrong size, and serves the JWK openpgp's RSA generation reads: so under
  Hermes (ok-rn: Android's generator) PGP RSA keys can be made at all. Without
  the hook RSA generation is refused as before.

- **Key Chain L4: encrypted private copies, both formats.** `keychain.export`:
  `encryptedPgp(privateKey, passphrase, { confirm, openpgp })` - an armored
  OpenPGP private key under OpenPGP's own passphrase protection (gpg and the
  OnlyKey apps' "load a key" read it back) - and `encryptedPem(key, passphrase,
  { confirm })` from the new `src/crypto/pkcs8.js`: EncryptedPrivateKeyInfo,
  PBES2 with PBKDF2-HMAC-SHA256 (600000 rounds by default, 16-byte salt) and
  AES-256-CBC, around PKCS#8 for RSA (from p and q alone, the CRT values
  computed), Ed25519 / X25519 (RFC 8410) and P-256 / secp256k1 (RFC 5915).
  Hermes-clean (a small DER encoder, @noble, BigInt). Both use the backup
  passphrase's rule (25+ characters, asked twice). Post-quantum keys leave as
  PGP only. OpenSSL (Node's crypto) opens every PEM in the tests; the RSA one
  signs. `openpgp.d.ts` now declares `encryptKey`.

- **Key Chain L1: naming and probing key slots.** New `./keychain` export with
  `tag` - the record of what a slot is, kept in the key's own 16-byte label as
  `<kind>:<name>` (`pgp`, `ssh`, `age`, `xwg`, `mlk`, `pqc`, `sig`, `enc`);
  a label that is not a tag is left alone. `device.probeKeySlot(slot, { hint })`
  works out what a slot holds from its public key, since no command returns the
  stored type: empty, composite, RSA (bits), P-256 / secp256k1 (which curve the
  point is on), Ed25519 / X25519 (asked again with the Curve25519 conversion),
  ML-KEM-768 / X-Wing (19 reports; told apart by the bytes the firmware leaves
  in its reply buffer, okcore.cpp:2568-2573, or by the tag's hint). Silence is
  reported as locked or config mode, never as empty. `device.setKeyLabel(slot,
  label)` names or blanks a slot without touching the key; `generateEccKey` and
  `generateKey` take `{ label }` and write it after the key. One label writer
  for loadKey, the generators and setKeyLabel. The fake firmware models the
  reply buffer (a short last piece keeps the previous piece's tail within one
  reply; cleared after every reply, okcore.cpp:2640-2646, checked on the
  emulator), the conversion, the composite refusal and the config-mode drop.

- **Key Chain L2: public artifacts in `src/`, Hermes-clean** (no Node crypto,
  no Buffer). `crypto.pgpCert.buildCertificate(openpgp, opts)` is the GPG
  certificate builder moved out of `cli/gpg-key.js` - byte-identical output
  (vectors frozen from the CLI before the move), the device still signs through
  the openpgp `signer` hook, and new optional `expires` (Key Expiration Time
  subpacket, absent by default), `userIds` (several; the first is marked
  primary) and a `created` that defaults to 0 and takes a Date. `crypto.ssh`
  is the authorized_keys line builder from `cli/ssh-wire.js` (Ed25519, P-256,
  unchanged lines) plus `rsaPublicKeyLine(modulus)` (`ssh-rsa`, e = 65537,
  checked against ssh-keygen). `crypto.pqc.encodeX25519Recipient` gives the
  classic age `age1...` recipient (checked against age-keygen's published
  pair). `cli/gpg-key.js` and `cli/ssh-wire.js` now import these: one copy.

- **`onlykey-js setbackuppassphrase [--latin-passphrase]`** (N-1 escape hatch,
  owner's decision 2026-10-01). Sets the backup key from a passphrase asked for
  twice (never argv), UTF-8 by default. `--latin-passphrase` hashes the bytes
  0.3.0 hashed - each UTF-16 code unit's low byte, the new encoding
  `'truncated-legacy'` - so a backup made with lib <= 0.3.0 and a character
  above U+00FF ("€" became 0xAC; "pašsword" collided with "paasword") can still
  be restored: set the key with the CLI in config mode, then restore with the
  passphrase left blank. Within Latin-1 it equals `'latin-1-legacy'`, so classic
  App backups open with it too. CLI-only on purpose: no GUI offers it and
  restore's automatic choice never tries it.

- **The backup passphrase is hashed as UTF-8; the Latin-1 form is legacy and
  never truncated** (N-1, owner's decision 2026-09-30). **Changed output:**
  `keys.backupKeyFromPassphrase(passphrase)` and `device.setBackupPassphrase()`
  now hash the UTF-8 bytes. Up to 0.3.0 they hashed Latin-1 like the classic
  desktop App (OpenPGP.js `str_to_Uint8Array`), while python-onlykey (f4ecaf2+)
  and trustcrypto's rewrite hash UTF-8 - and the device, which only ever
  receives the 32-byte hash in slot 131, cannot tell them apart. So a backup
  made by one could not be restored by the other whenever the passphrase had a
  character in U+0080..U+00FF ("pässword": Latin-1 sha256 `fe699eee...`, UTF-8
  `3478267b...`). UTF-8 is what the rest of the ecosystem settled on and what
  every typeable character has. **A pure-ASCII passphrase gives the same key as
  before.** The legacy bytes stay available explicitly:
  `backupKeyFromPassphrase(p, { encoding: 'latin-1-legacy' })`,
  `setBackupPassphrase(p, { encoding: 'latin-1-legacy' })`,
  `keys.passphraseBytes(p, encoding)`; `keys.backupPassphraseCandidates(p)`
  lists the keys a passphrase could have made (two only when the forms differ).
  **Fixed:** the old Latin-1 path kept `& 0xff` of each UTF-16 unit, so
  "pašsword" (U+0161) hashed as "paasword" - different passphrases, one key,
  silently. A Latin-1 form is now produced only for a string entirely within
  U+0000..U+00FF and refused otherwise.

- **`device.restore(text, { passphrase })` sets the backup key itself and falls
  back to the classic App's Latin-1 key automatically** (N-1). Returns
  `passphraseEncoding: 'utf-8' | 'latin-1-legacy'`, `tried`, and the device's
  `response`. **The fallback is decided on the host, not by a second restore**,
  because the firmware does not allow a second restore: RESTORE answers a wrong
  key with "Error incorrect backup key set" and `CPU_RESTART()`s (okcore.cpp
  :6630-6636 at 3.1.0); a retry then needs the PIN and config mode entered on
  the device again (the first-use window closes at that reboot), and with
  backup-key mode locked slot 131 cannot be replaced at all. Everything the
  device decrypts with derives from the 32-byte key the host computed (Ed25519
  pub, `crypto_box_beforenm`, `sha256(s || pub || iv)`, AES-GCM with no tag
  check) and its only test is the first plaintext byte `>= 0xFD`, so
  `device/backupkey.js` (`predictRestore`, `chooseBackupKey`) runs that test for
  UTF-8 and - only when the forms differ - Latin-1, sets the one key that
  passes, restores once, and awaits "Successfully loaded backup" or the
  device's "Error ..." (thrown with `deviceText`). A wrong passphrase sends
  NOTHING. Where both forms pass the one-byte test (~3/256 for a Latin-range
  passphrase) it refuses to guess - the device would write the wrong one's
  garbage into the slots - and the caller names it: `{ passphraseEncoding }`.
  A file whose trailer is not Ed25519 (101) was made with an RSA/PGP backup key
  and is refused for a passphrase. `restore(text)` without a passphrase is
  unchanged.

## 0.3.0 - `eeaea46eeff55454bc1370034d7790253f560f8d` (tag `v0.3.0`)

- **`device.generateEccKey(slot, keyType, { signature, decryption, backup })`**
  (G-1). On-device ECC keygen, types 1-4 in ECC1-16, was CLI-only: `genkey`
  sent its own all-FF trigger through loadKey, so a GUI had to copy the
  trigger, the Curve25519 gate and the send-once rule. The plugin now owns
  them: python-onlykey's 32-byte FF trigger, sent ONCE (`ackRetries: 0`; a
  resent trigger generates again), the "Successfully set ECC Key" answer
  returned as `response`, and Curve25519 refused unless the firmware is KNOWN
  to be 3.0.5+ (`curve25519Keygen`; the version is asked when missing) - v3.0.4
  would flash the trigger itself as every device's key and report success. No
  public key is read back: generation runs in config mode, which drops
  OKGETPUBKEY (okcore.cpp:335), so the caller reads it after the restart. The
  CLI's `genkey x/n/s/c` calls it.

- **wipeSlot returns every reply; loadKey returns the device's reply; both
  refusals carry `deviceText`** (G-3). **Breaking for wipeSlot:** it resolves
  `{ slot, response, responses }` instead of a bare string - `response` is the
  string it used to return. wipe_slot() answers once per field (ten on v2.1.2 -
  3.1.0, eleven on 2.1.0-2.1.1); wipeSlot resolved on the first and left the
  rest on the bus. It now collects until the device is quiet (`quietMs`, 500),
  python-onlykey e6d261c's rule. `loadKey` adds `response` ("Successfully set
  ECC Key"), which went only to a `keyAck` progress event. Both throw
  `okmsg.deviceError`. The CLI's `loadKeyAck` workaround is gone and `wipeslot`
  prints all ten lines, as python does. Note: for slots 1-24 the firmware wipes
  the WHOLE slot whatever `field` byte is sent. Consumer to update on re-pin:
  the App port's `OnlyKeyComm.js` wipeSlot callback (`text` -> `r.response`).

- **The preference table is public, and setPreference checks the row this
  firmware has** (G-4). PREFERENCES and its 3.0.5 enum overlay moved out of the
  device plugin's setup() into `src/device/preferences.js`, exported as
  `node-onlykey-lib/device/preferences` and `device.preferences`, with pure
  `preferenceRow(name, capabilities)` / `preferenceRows(capabilities)` - a GUI
  reads the rows for any firmware without composing a stack.
  `device.preferences()` is now `preferenceRows(session.capabilities)`, and
  `setPreference` validates against `preferenceRow(name, session.capabilities)`
  instead of the static max: on 3.0.5+ `derivedChallengeMode` 8 (the old bit 3)
  and `storedChallengeMode` 2 are refused before the wire, where they used to
  go out for the firmware to refuse; v3.0.4 keeps the bitmask and bit 3.
  Unknown capabilities keep the legacy row, as before.

- **The host refuses low-order X25519 points and all-zero shared secrets**
  (G-12). New `src/crypto/x25519guard.js` (also `crypto.x25519guard`):
  `isLowOrderU`, `assertPeerNotLowOrder`, `assertNonZeroSecret`, throwing
  `code: 'LOW_ORDER_POINT'`, over the seven low-order encodings (RFC 7748
  decoding; noble's `lowOrderU` plus p and p+1, libsodium's list). Wired where
  the vendored noble check does not reach: `okconnect.transitKey` (tweetnacl's
  `box.before` is unchecked and turns every low-order device key into ONE fixed
  shared key), the 25519 peer key framed for a derive (`peerKeyWire`),
  every secret `okconnect.sharedSecretFrom` reads out of a reply, and
  `okcrypto.agent.ecdh` (the X25519 peer before sending, the result after).
  Firmware 8d28305 refuses the zero secret on the device; v3.0.4 does not, and
  the library serves both.

- **X-Wing asks the firmware version first, or refuses; it never guesses the
  old shape** (G-6, G-9). okcrypto read "capabilities unknown" (never
  connected, or connected while LOCKED - status INITIALIZED, no version) as the
  pre-3.0.5 world: a 3.1.0 key's 1216-byte recipient was sliced into a 64-byte
  "pair" and a decapsulation took the split path, with no error. Now
  `deviceAge.identity` / `decrypt` and every X-Wing derive learn the version
  first - `connectTunnel()` with a supplied ctap, `session.connect()` (set_time,
  no prompt) on the vendor interface - and refuse with
  `code: 'XWING_VERSION_UNKNOWN'` if the device still does not say. The split
  shape stays only for a version KNOWN below 3.0.5. The learned version also
  makes the `xwingDerive` gate fire on an unconnected session, so a v3.0.4
  release key is refused by name. `okconnect.publicKeyWidth` / `publicKeyFrom` /
  `sharedSecretFrom` no longer default X-Wing to 64 bytes: `xwingCustody` must be
  a boolean (`code: 'XWING_SHAPE_REQUIRED'`).

- **A device refusal before the caller awaits no longer ends the process**
  (2152942). okcrypto's deviceOperation and device.js's two key operations arm
  their `answer` before sending and await it later (after confirm(), a write, a
  bus-quiet wait); a refusal in between - the 20 s confirmation window closing
  while confirm() still runs, or a reply beating the write over BLE - was an
  unhandled rejection, and Node exits on those. apk-signer's signing helper died
  that way mid-signature during the 0.0.5 release. Each `answer` is now handled
  from birth; the await still throws the device's words.

- **An unanswered confirmation is a refusal, not the answer** (90ec3b6).
  `deviceOperation` took only `/^Error/` as a refusal, so the firmware's 20 s
  timeout - "Timeout occured while waiting for confirmation on OnlyKey", with no
  "Error" in front, the same words in every signed release - came back as the
  RESULT: a derived X-Wing decap took its first 32 bytes as the secret and age
  failed "invalid tag", blaming the file for a button nobody pressed. Those words
  are now a refusal (`okmsg.errorKind`), with a test.
- **User Input Modes as firmware 3.1.0 and the desktop App define them**
  (17efcb6). Fields 21 (SSH/GPG derived keys), 22 (stored keys) and 30 (web and
  agent derived keys) carry the section "User Input Modes" on every firmware
  line, so every GUI groups them alike; the choices use the desktop App's words
  ("Challenge Code (enter 3 digits)", "Button Press (tap any button)", and for 30
  "None (no confirmation)"), the first-use default (press) is stated, field 26 is
  "HMAC User Input Mode" with its choices, field 31 "Webcrypt Access".

- **v3.1.0 pin follows the release again: libraries 16d8863 -> 8d28305.**
  Re-squashed on 2026-09-30; the tree change is one file, `onlykey/okcrypto.cpp`:
  X25519 private keys are now clamped (RFC 7748) when DERIVED and when
  GENERATED on the device; an all-zero X25519 shared secret is refused; a
  derived decap confirmed by a button press answers on the interface it was
  asked on. **Compatibility:** a derived X25519 identity - an agent key of
  type X25519, a GPG `cv25519` subkey made by `onlykey-js gpg init` or
  `onlykey-gpg`, a website-derived X25519 key - has a different public key on
  this firmware than on 16d8863 and earlier. P-256, secp256k1 and Ed25519
  identities, and X-Wing/age, are unchanged. OnlyKey-Firmware stays 9fceea1.

- **v3.1.0 pin follows the re-squashed release: libraries eb25290 -> 16d8863.**
  trustcrypto/libraries PR #33 (`release-3.1.0`) was re-squashed on 2026-09-29;
  the only change is the stale-staged-reply fix in `fido2/device.cpp` and
  `fido2/ok_extension.cpp` (a fully delivered FIDO2 reply is no longer served
  again from the start to a new request, and a duplicate poll no longer re-arms
  the wipe timer). OnlyKey-Firmware stays 9fceea1. okcrypto's stale-timer
  settle (`settleStaleTimers`, up to 6 s) is unchanged: it already runs only on
  firmware without the `staleFadeGuard` capability (v3.0.4 and older), so a
  3.1.0 key never waits. Verified on 16d8863 + the CTAPHID fix: kit 01-protocol
  144/0/6 on Windows, VM and Pi; the web app's X-Wing age round trip passes
  (03-gui 30/0/1); Pixel e2e 104/0/34.
- **`scripts/upstream-watch.js` watches the release PR branches by HEAD**, not
  only by new commits: a re-squash (force-push) is reported as "head moved".

- **`onlykey-js --ble [--address <phone>]`: every device command over Bluetooth
  LE, to a phone running ok-rn.** `cli/transport-ble.js` is a byte pipe for
  `plugins/transport/ble` (CTAP-over-BLE framing of 64-byte vendor reports,
  one write per report at the phone's MTU of 517, 20-byte fragments below it;
  replies that beat their write's acknowledgement are held until after its
  echo). Windows goes through WinRT with `@stoprocent/noble` 2.8.0; Linux
  talks to BlueZ's GATT API over D-Bus with `dbus-next` (vendor
  characteristics found by UUID wherever BlueZ put them, cached GATT not
  trusted, `PreferredBearer = le` and `Connect()` inside an LE discovery
  session, never `Device1.Disconnect()`). Both are optional peers, loaded
  lazily, like `node-hid`. `agent`, `gpg init` (its run-agent script) and
  `gpg-agent --daemon` carry the option through. Firmware update is refused
  by the pipe. Proven live 2026-09-29 against a Pixel 6a from a Windows PC
  and a Raspberry Pi 4: status, fwversion, getlabels, capabilities and the
  agent's ssh key read the same on both.
- **`onlykey-js gpg init` and `onlykey-js gpg-agent`: the GPG half of lib-agent,
  dependency-less.** `gpg init "<user id>"` makes the certificate for the
  keys derived from `gpg://<user id>` (ed25519 + cv25519, or `-e nist256p1`),
  its two self-signatures made by the device through the vendored openpgp
  fork's `signer` hook, and writes lib-agent's GnuPG home; `gpg-agent` is
  the Assuan agent gpg.conf starts (`--daemon` backgrounds it and exits, as gpg
  waits for; lib-agent's command set; gpg's socket
  path from gpgconf; Windows' port-and-nonce socket file). Key packets,
  fingerprints and keygrips equal python's own encoder's for the same device
  keys, and keygrips equal what gpg prints. Differs from lib-agent toward
  gpg-agent's answers: unknown commands get ERR (lib-agent's silence hangs
  gpg), KEYINFO for a key it does not hold is "No secret key", ECDH values
  carry the 0x40/0x04 prefix, and a key dated 0 gets self-signatures dated 1
  (GnuPG otherwise shows the owner's own signatures as `[uncertain]`). The
  armor carries the CRC line (GnuPG 2.4.4 rejects openpgp.js v6's default
  armor without it). Proven live on the VM (GnuPG 2.4.4, the private kit
  emulator): init twice gives the same fingerprint; `gpg --clearsign` then
  `--verify` is "Good signature ... [ultimate]"; `gpg --encrypt` then
  `--decrypt` through the agent gives the plaintext back - both curves.
- **`onlykey-js agent`: the SSH half of lib-agent, dependency-less.** Prints
  the derived key line for `[user@]host` (byte for byte python
  `onlykey-agent`'s line, comment included), or serves an ssh-agent over it:
  `-f`, `-- command`, `-s`, `-c`; ed25519 by default, `-e nist256p1`;
  derivation v1 by default, `--skey derived-v2` (refused on firmware without
  it). POSIX serves a 0600 socket in a private 0700 directory; Windows a
  private named pipe for Windows OpenSSH. Every signature is verified against
  the listed key before ssh gets it; ECDSA signatures carry canonical mpints
  (lib-agent always prefixes 0x00 - OpenSSH tolerates it, RFC 4251 does not).
  Node built-ins only (`cli/ssh-wire.js`, `cli/ssh-agent.js`). Proven live on
  the VM against the real firmware (a private kit emulator): `ssh-add -L`,
  and an `ssh localhost` login with each key type. `main()` now takes
  per-command options and refuses one given to a command that does not take it.
- **versions: v3.0.5 dropped from the table.** It was never released or signed,
  and 3.1.0 supersedes it. v3.1.0 - the proposed release, pinned to its PR heads
  (libraries eb25290, OnlyKey-Firmware 9fceea1) - is treated like the signed
  release. `list()` no longer offers v3.0.5 and `pinsFor('v3.0.5')` refuses it
  by name. The firmware-version gates in `src/device/version.js` are unchanged:
  a key running a 3.0.5 build is still read correctly.
- **onlykey-js step 2: python's write commands.** `setslot` (every python
  field, python's slot names), `wipeslot`, the fifteen settings commands,
  `settime`, `genkey`, `setkey`, `loadkey` (armored PGP) and `wipekey`, each
  over the device plugin. What the key says is printed on stdout as python
  prints it, and a refusal also exits 1; secrets are prompted for
  (`cli/prompt.js`); the one-way settings need `--yes`. Still no firmware
  update, backup or restore. See cli/README.md for each command's
  differences from python's, most of them python bugs not copied.

- **`capabilities().curve25519Keygen`** - false below 3.0.5, where
  okcrypto_generate_random_key has no type-4 branch and a Curve25519
  "generation" flashes the all-FF trigger itself as the key. `genkey c`
  refuses there.

- **The desktop App's six lib gaps, closed from the firmware.** OnlyKey-App's
  port onto the library (its docs/LIB-PORT.md) kept raw frames for these; each
  was read against release 3.1.0 and fixed there. `device.wipeYubiAuth()` -
  the global Yubico OTP wipe, which the firmware performs WITHOUT replying
  (okcore.cpp wipe_slot has no hidprint for slot 0 field 10), so it listens
  only for a refusal. `setPreference('secProfileMode')` no longer spends three
  10 s timeouts: the firmware stores it silently on first use and refuses it
  later with "Second Profile Mode may only be changed on first use", which has
  no "Error" and now classifies as `refused`. `device.restartByRestore()` -
  the App's no-file restore named: one all-zero OKRESTORE, which RESTORE
  turns into CPU_RESTART, the restart a release build has (only in config
  mode or on first use). `pinStep` ends on any device refusal, not just the
  two PIN sentences; `committed` no longer waits the full timeout on a release
  build, whose console line is DEBUG-only; and `duoPin` skips the status
  broadcast that can arrive before the answer - by timing, since a locked DUO
  reads its PIN only in its broadcast tick and a wrong PIN's only "no" is the
  next INITIALIZED-D. These three silent operations return
  `confirmed: false` and are never retried.

- **"UNLOCKED BOOTLOADERv1" is the bootloader.** `version.parseStatus` and
  `okmsg.parseState` tested UNLOCKED first, so a key waiting for firmware
  parsed as an unlocked key with version " BOOTLOADERv1". Both desktops test
  BOOTLOADER first and read version "v1"; so does the library now.

- **Key import: secp256k1, and 33-byte scalars.** secp256k1 keys map to key
  type 3 (KEYTYPE_P256K1, which the firmware generates, signs and does ECDH
  with) from SSH (`secp256k1` / `k256`) and OpenPGP (OID 1.3.132.0.10); they
  were refused as unknown curves. A 33-byte ECC scalar with a zero sign byte -
  an SSH mpint whose top bit is set - is stripped to 32 instead of thrown.
  Vectors from the App rewrite's keyMaterial tests.

- **age docs match device custody.** `crypto/age_pqc` and `crypto/age_file`
  described the old split-custody X-Wing; from 3.0.5 the device returns the
  finished recipient and secret. `mlkemKeypairFromSeed`, `buildRecipient`,
  `splitDecapsulate` and `ctXOf` serve only the old design and are marked
  deprecated - still exported, since consumers pin by hash.

- **`onlykey-js` - a command line in the library, the start of replacing
  python-onlykey's `onlykey-cli`.** A `bin` with no protocol code of its own:
  each command is a few lines over the device plugin, on the stack
  `node-onlykey-lib/cli/desktop`'s `startDesktop()` composes (host, usb
  transport, session, device, okcrypto - the transport opened, which no plugin
  does). Read-only first: `help`, `version`, `fwversion`, `status`,
  `capabilities`, `getlabels`, `getkeylabels`, with python's names and output
  layout; `capabilities` is derived from the version, since no signed release
  sends the report python asks for. Named `onlykey-js` so it cannot shadow
  `onlykey-cli` while both are installed. The key is reached by
  `cli/transport-hid.js`, a pipe for transport/usb over node-hid: vendor
  interface by usage page 0xffab, the 0x00 report ID hidapi takes on every
  write, clear refusals for no key, two keys (`--path`) and no node-hid.
  `node-hid` is an OPTIONAL PEER (not installed with the library - the web app
  and ok-rn never download a native module; `npm install node-hid` where the
  CLI is used), required lazily under `cli/` only. Keys found by USB id
  1d50:60fc or 16c0:0486, the vendor interface by usage page. No firmware update path.
  Tested over the fake firmware and a fake node-hid; see `cli/README.md`.

- **Classic PGP keys on the device, in a browser too.** `crypto.classic
  .registerClassicHooks(openpgp, ok, { signSlot, decryptSlot })` routes an RSA or
  Ed25519/cv25519 key's private operations to device slots through the PGP fork's
  hardware hooks, as composite_pgp does for composite keys. `okcrypto.sign/decrypt`
  now run over the WebAuthn tunnel when a ctap is supplied, and a tunnelled
  operation no longer needs `expectBytes`: an RSA decrypt's plaintext length is
  collected by the firmware's short-chunk rule. Tests round-trip real openpgp
  messages against a fake device doing real RSA / Ed25519 / X25519.

- **Agent derivation: `okcrypto.agent` - SSH and GPG keys derived on the device.**
  What onlykey-agent / onlykey-gpg drive, now in the library:
  `agent.publicKey(identity, {keyType, version})`, `agent.sign(identity, message)`,
  `agent.ecdh(identity, peerPublicKey)`. `identity` is a 32-byte hash or
  `{ssh: {user, host}}` / `{gpg: userId}`, hashed as lib-agent does (non-ASCII
  refused: lib-agent transliterates it). v1 (132, 201-204; every release from
  2.1.0; the default) and v2 (232, 221-224; HKDF "onlykey/agent/v2"; 3.0.5 on)
  are different keys. New capabilities `agentDerivation`, `agentDerivationV2`;
  `src/protocol/agent.js` is the spec, read at release 3.1.0. The fake firmware
  carries a K132 and the real derivation, so the tests verify signatures and ECDH
  against the key the library reads.

- **`node-onlykey-lib/bundler-aliases` - the exports map for webpack 4.**
  The web app's bundler predates package "exports", so every subpath that is
  not a real path failed to resolve. `aliases()` generates one alias per
  export. Measured in a webpack 4.47 spike: with it, babel over the library
  and `node: { crypto: "empty" }`, the whole stack (host, tunnel transport,
  session, device, okcrypto, webauthn ctap, crypto, the PGP fork) bundles with
  no warnings and composes at runtime.

- **`device.generateKey` asks for no button challenge - the firmware dropped it.**
  libraries 97f0149 (2026-09-22) removed the PQC keygen gate; the bench key
  (b412e78), 3.0.5 and release 3.1.0 all generate on the one OKSETPRIV, and no
  signed release has PQC keygen. The lib still computed digits, emitted
  `challenge` and called `confirm` - so a caller pressing on the user's behalf
  typed slot contents on an unlocked key. Now no digits, no event; `confirm`,
  `duo`, `formula` are accepted and ignored. Also fixed the race that exposed:
  the collector marked the request sent only after `await write`, so a device
  answering inside the write (the emulator) lost the key's first reports.

- **One copy of every third-party library, vendored here.** `@noble/hashes`,
  `@noble/curves`, `@noble/ciphers` 2.4.0, `@noble/post-quantum` 0.7.1 and
  `tweetnacl` 1.0.3 are no longer npm dependencies. They are their npm tarballs,
  unmodified, under `src/vendor/node_modules/`, recorded by integrity and tree
  hash in `src/vendor/VENDORED.json`, and reached through
  `node-onlykey-lib/vendor/@noble/<pkg>/<module>.js` and
  `node-onlykey-lib/vendor/tweetnacl`. `scripts/vendor.js` re-vendors
  (`--check` verifies offline); `test/vendor.test.js` fails on an edited copy,
  on a second copy through npm, on code that bypasses the shims, and on a
  tarball that stops shipping them. Consumers drop their own @noble and use
  these subpaths - one place to audit, one place to swap. See
  `src/vendor/VENDORED.md`.
- **A browser can drive the tunnel: `node-onlykey-lib/transport/webauthn`.**
  `createWebAuthnCtap({ credentials, rpId?, timeoutMs? })` is the object
  `protocol/tunnel.js` already drives - `getAssertion(params) -> Map{2, 3}` -
  run by `navigator.credentials.get()` instead of CTAPHID, which is the only
  way a web page can reach the key. `credentials` is injected, never read from
  a global. The browser hashes its own clientData, so the tunnel's
  clientDataHash is replaced by a fresh random challenge. Browser failures
  come back as a `WebAuthnError` with a `code` (`NOT_ALLOWED`, `TIMEOUT`,
  `ABORTED`, `SECURITY`, `RPID_MISMATCH`, ...). A new package test also pins
  that nothing under `src/` requires a Node built-in.
- **okcrypto's tunnel ctap is injectable:
  `plugins.config = { okcrypto: { ctap } }`.** When supplied, the derives, the
  vault and the X-Wing pair run over it as given - no `CtapHid`, no CTAPHID
  INIT - which is how a browser hands in `createWebAuthnCtap()`. Omitted, which
  is every host today, the plugin builds and inits its own `CtapHid` exactly as
  before. A supplied object without `getAssertion` fails the composition.
- **A browser composes with no vendor interface:
  `node-onlykey-lib/plugins/transport/tunnel`.** A placeholder transport that
  satisfies the contract so session, device and okcrypto compose unchanged;
  every vendor write/request refuses with `code: 'NO_VENDOR_INTERFACE'`
  instead of timing out. Existing hosts keep composing embedded/usb/ble.
- **`okcrypto.connectTunnel()` - the key exchange and the firmware version over
  the tunnel.** A plain OKCONNECT (opt1 = 0, opt3 = 0), whose reply carries the
  status in the clear; it is fed to `session.observeStatus()`, so
  `capabilities()` (transitV2 and the rest) is known in a browser too. Refused
  without a supplied ctap. One WebAuthn ceremony.
- **Composite sign/decrypt over a supplied ctap.** `composite_sign`,
  `composite_decrypt` and the derived X-Wing decapsulation run as tunnelled
  OKSIGN/OKDECRYPT when a ctap is supplied: every keyhandle (and every OKPING)
  sealed under the tunnel's transit session - transit v2 frames from 3.0.5,
  the v1 box on 3.0.4 - with a counter that persists across operations and
  resets at each key exchange (a derive re-keys, and its reply becomes the
  session). Chunks are 171 bytes sealed (v2) or 228 (v1), whole 57-byte
  packets but the last, never a length the encoder would pad. opt2 marks the
  final chunk and opt3 never wraps inside an operation. Results are collected
  by OKPING and, from 3.0.5, opened as v2 frames (+20 bytes, libraries
  a29b063). The three-button challenge and `confirm({ digits, isAnswered })`
  are the vendor path's. The reply to each request chunk is CHECKED: a
  transit-authentication failure, a stale staged reply or a dropped duplicate
  fails at once with `code: 'REQUEST_NOT_ACCEPTED'`, and a device refusal
  ("stored key use over FIDO2 not enabled") comes back as its own sentence.
  Before the first chunk the operation waits out the firmware's 5-second
  staged-reply wipe (`settle` event), because a reply still staged is served
  again to the request and hides whether it was accepted. Cost per operation,
  in ceremonies (browser prompts): one connect per session, one per request
  keyhandle (Ed25519/X25519 1, ML-KEM 7 on v3.0.5 / 5 on v3.0.4), one per
  1-second poll while the user enters the challenge, and one per 512-byte
  result chunk (ML-DSA-65: 7). Vendor-HID behaviour is unchanged.
- `protocol/chunk`: `planKeyhandleChunks`, `reservePacketRun`, `PACKET_DATA`,
  and `sendChunked({ sizes, onReply })`; `protocol/ctap`: `dataRegionLength`.
- okcrypto's vendor `deviceOperation` now takes its listener and timer down
  when the write itself fails, instead of leaving an unhandled rejection
  `timeoutMs` later.

## 0.2.0 - `4b74b3e93b314cd0808b04bc7733695f0f008601` (tag `v0.2.0`)

Released 2026-09-27, after ok-rn ran this code through the full Pixel 6a
version matrix: every release equal to or better than its baseline (working
tree 104 passed / 0 failed, v3.0.4 84/0, v0.2-beta.8 still parked at 60/4).

- **The release table lives here now: `node-onlykey-lib/versions`.**
  `list()`, `pinsFor(version)` (the pinned `libraries` / `OnlyKey-Firmware`
  commits and the signed image; `null` for the named-but-not-cut working
  tree; a half-pinned row throws), `compatibilityOf(version)`,
  `signedStatus()`, `expectedCompatibility()`. The table used to be copied
  into ok-rn and node-onlykey-emulator (only the emulator's had the
  compatibility rows); consumers read this one. Each consumer keeps its own
  per-release stage scripts - those are build-system patches, not data.
  `scripts/versions-compat.js --write` regenerates the compatibility rows,
  and a test fails when they drift from `capabilities()`.
- `crypto.pqc` exports `bech32Encode`, `bech32Decode`, `RECIPIENT_HRP`,
  `IDENTITY_HRP` and `DERIVED_MARKER` - the encoding under the recipient and
  identity strings, which onlykey-testing's age-pqc.js carried its own copies
  of. Checked identical to the kit's (20/20); one frozen vector from it.
- `CtapHid` takes an `AbortSignal` (`new CtapHid(t, { signal })`, or
  `opts.signal` per call): an aborted wait rejects at once with an
  `AbortError` whose `cause` is the signal's reason, and an already-aborted
  one sends nothing. And `resendCutRequest` (default `true`) switches off the
  one resend of a multi-packet request refused as INVALID_COMMAND, for a
  client that must see the firmware's own answer. Both for onlykey-testing,
  whose runner stops stuck exchanges and whose test 32 is about exactly that
  refusal; GUI behaviour is unchanged.
- CTAP status names: the rest of the firmware's `ctap_errors.h` -
  `CTAP2_ERR_ACTION_TIMEOUT` (0x3A), `CTAP1_ERR_OTHER` (0x7F) and OnlyKey's
  vendor codes 0xF6 `DATA_READY`, 0xF7 `DATA_WIPE`, 0xF8/0xF9
  `OKSIGN`/`OKDECRYPT_ERR_USER_ACTION_PENDING`. The table stopped at 0x39;
  onlykey-testing's named 0x3A. Its 0x3E `UP_REQUIRED` is not added - a
  CTAP 2.1 code this firmware neither defines nor sends.
- **Transit v2, host -> device.** `session/transit` gains `session(key)`,
  `seal(session, data)` (advancing the session's counter) and
  `open(keyOrSession, frame)`, with `CTR_LEN`, `TAG_LEN`, `OVERHEAD`,
  `DIR_FROM_DEVICE`, `DIR_TO_DEVICE` and `transitIv`. The library had only the
  device -> host half (`crypto/okconnect`'s `openTransitV2`); onlykey-testing
  had both, run against the device, and they are ported from it. One
  implementation now: `openTransitV2` and `TRANSIT_V2_OVERHEAD` are the
  transit module's `open` and `OVERHEAD` under their old names. @noble's gcm,
  not Node's crypto, so it runs in every GUI. Frozen vectors from the kit's
  transit v2 (9eb1de6): 6 successive seals, 4 device frames the kit's own
  `open()` accepted.
- New exports-map subpaths: `./device/press`, `./device/version`,
  `./vendor/openpgp` - so consumers stop loading files by path.
- The cbor, ctaphid and transit cross-checks no longer load
  `../onlykey-testing` at test time. The kit's outputs are FROZEN in
  `test/vectors/kit-reference.json` by `scripts/freeze-kit-vectors.js`
  (onlykey-testing@adac782, the last commit whose transit still has `box()`),
  on inputs shared through `test/vectors/cases.js`. The kit is moving onto
  this library, which would make a live comparison circular - and it had
  already broken: the kit replaced `box()` with transit v2's seal/open.
  `npm test`: 861/861.
- `@bmatusiak/rectify` is pinned by commit hash
  (`a0d9f0e6e537053122273b1f763ac87ae461361c`), the commit the lockfile
  already resolved - it no longer floats with rectify's default branch.

Known at the tag: `npm test` is 861 of 862. The one failure is the transit
cross-check against onlykey-testing's own `lib/device/transit.js`, which no
longer exports `box` - the kit moved, the library did not. The same test
fails on 0.1.0 unmodified. It is the circularity the kit's move onto this
library has to deal with first (freeze the kit's originals as vectors).

## 0.1.0 - `f734c5e7654314df53691bafa13220a1ac38f91c` (tag `v0.1.0`)

The first pinned release: the library as every consumer ran it on 2026-09-27
(ok-rn; the emulator on Windows, Linux x64 and the Pi). Everything before this
point was untagged development.

Two changes in it that reach every GUI, recorded here afterwards (2026-09-30):

- **An unwritten field 31 allows stored keys** (0c9e092). `webcryptPolicy`
  records what a never-written Webcrypt Access field does (stored keys allowed,
  as on v3.0.4) as `unwritten`, so a form starts there rather than at 0 - saving
  an untouched form no longer turns web PGP off.
- **Backup capture times out on silence** (c96c11a). `captureBackup`'s timeout
  restarts on every keystroke, so a slow backup that is still typing is not cut
  off.
