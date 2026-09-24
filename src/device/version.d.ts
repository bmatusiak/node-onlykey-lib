/**
 * Split a status line into what it actually tells you.
 *
 * The version is taken by SPLITTING on the state word, not by slicing at a
 * fixed index - `msg.split("UNLOCKED").pop()` (OnlyKeyComm.js:1335).
 * python-onlykey reads `okversion[19]`, a fixed offset that breaks the moment a
 * version string is a different length, and version strings have already been
 * three different lengths.
 *
 * @param {string|Uint8Array} status the device's reply, as text or as bytes
 */
export function parseStatus(status: string | Uint8Array): {
    raw: string;
    state: string;
    /** Everything after the state word, model letter included - what the desktop displays. */
    version: null;
    /** The same string, named for the 12-byte field the OKCONNECT reply carries it in. */
    versionField: null;
    release: null;
    model: string;
    /** A DUO reports whether a PIN is set. Nothing else does, hence null. */
    pinSet: null;
    build: string;
    /** Whether firmware can be updated from a host over USB. */
    fwUpdateOverUsb: boolean;
};
export function capabilities(status: any, { unreleased }?: {}): {
    gestures: {
        /** The device TYPES the whole backup file at the keyboard. */
        backup: {
            button: number;
            lo: number;
            hi: number | null;
            ticks: number;
        };
        /** The slot labels, typed as text. */
        slotLabels: {
            button: number;
            lo: number;
            hi: null;
            ticks: number;
        };
        /** The key labels too - a strictly longer hold on the same button. */
        keyLabels: {
            button: number;
            lo: number;
            hi: null;
            ticks: number;
        };
    };
    /**
     * The OKCONNECT reply layout.
     *
     * 'legacy': public key at [21..53], version at [8..20], body NOT encrypted.
     * 'modern': public key at [0..32], body AES-GCM under the transit key.
     *
     * onlykey-api.js:167-197. The reference switches on an exact string match
     * against the version field, so this does too.
     *
     * The legacy branch is UNVERIFIED - no pin in ok-versions.json is beta-8c,
     * so the matrix cannot reach it. See the note above capabilities().
     */
    okconnectLayout: string;
    /**
     * Which formula turns the payload hash into three button numbers.
     *
     *   'modern'  byte % 6 + 1                firmware okcore.cpp:7583-7585
     *   'duo'     byte % 3 + 1                firmware okcore.cpp:7578-7581
     *   'legacy'  byte < 6 ? 1 : byte % 5 + 1 onlykey-pgp.js:441-449
     *
     * The DUO branch exists in the firmware and in NO host client. We show
     * challenge digits on screen, so getting it wrong puts 4, 5 and 6 in front
     * of someone holding a device with three buttons.
     *
     * The legacy branch is UNVERIFIED for the same reason as okconnectLayout:
     * beta-8c has no pin. The DUO branch IS measured - a DUO is a staging
     * gate, not a fixture.
     *
     * ## THE DUO BRANCH IS NOT PRESENT IN EVERY RELEASE
     *
     * It is a FIRMWARE branch, so a DUO gets mod 3 only on firmware that has
     * it - and three signed releases do not. Read at the pins in
     * ok-versions.json:
     *
     *   v2.1.0 .. v3.0.1   `if (onlykeyhw==OK_HW_DUO) { % 3 } else { % 6 }`
     *   v3.0.2 (5d7ce7a)   the `if` is GONE; `% 6` unconditionally
     *   v3.0.3 (a133bea)   same
     *   v3.0.4 (c8804e3)   same - the NEWEST SIGNED RELEASE
     *   master  (3.0.5)    restored, okcore.cpp:7913-7920
     *
     * Not an artefact of reading the wrong function: v3.0.1's okcore.cpp has
     * 27 `OK_HW_DUO` references and v3.0.2's has 26, and the missing one is
     * this branch.
     *
     * So a DUO on v3.0.2, v3.0.3 or v3.0.4 computes digits in 1..6 while
     * holding three buttons, and 4, 5 and 6 cannot be pressed. That is the
     * FIRMWARE's own defect and not something a host can repair - but a host
     * must at least PREDICT the same digits it will be asked for, so this
     * returns 'modern' there. Returning 'duo' would make the host wrong as
     * well, and two wrongs would show as "Error incorrect challenge was
     * entered" with nothing to say which side produced it.
     *
     * Kept as a window rather than `below 3.0.5`, because the branch existed
     * before it and exists after it; what is unusual is the gap.
     */
    challengeFormula: string;
    /**
     * Multiplier on poll and inter-chunk delays.
     *
     * The Original hardware is slower and the web app waits four times as long
     * for it - onlykey-pgp.js:133-135 and 236-239, both keyed on
     * `OKversion == 'Original'`.
     *
     * UNVERIFIED, and unreachable by the matrix in a way the other two are not:
     * Original is a discontinued MODEL rather than a release, so no version
     * selects it and no build option produces one. Only a physical Original
     * key would settle this. See the note above capabilities().
     */
    pollDelayMultiplier: number;
    /** Firmware update from a host over USB - see supportsFwUpdate(). */
    firmwareUpdateOverUsb: any;
    /**
     * EVERY post-quantum path, and no released firmware has any of it.
     *
     * Measured across every pin in ok-versions.json, reading the sources at
     * those commits with `git show` rather than trusting a changelog:
     *
     *   okpqc.cpp            composite ML-DSA signing - ABSENT at v2.1.0,
     *                        v2.1.1, v3.0.0, v3.0.1, v3.0.2. The file does
     *                        not exist at any of them.
     *   KEYTYPE_MLKEM768 5   absent from okcore.h at all five
     *   KEYTYPE_XWING    6   absent from okcore.h at all five
     *   XWING / MLKEM        zero occurrences in okcrypto.cpp at all five
     *
     * So the three features that look separate in a UI - composite PGP keys,
     * X-Wing age identities derived over CTAP, and ML-KEM or X-Wing keys held
     * in a slot - are ONE capability as far as any shipped key is concerned:
     * a person holding a production OnlyKey has none of them, whatever their
     * firmware version, up to and including the newest release.
     *
     * They exist only in the firmware working tree, the line that builds
     * v3.0.4-testc, which is what the bench key runs. That is the same
     * position the web app's two post-quantum pages are in: present in its
     * working tree, registered in plugins-devel.js, absent from a production
     * build. The app and the firmware are ahead of the same release together.
     *
     * NO RELEASE HAS IT, AND THAT IS NOW MEASURED RATHER THAN ASSUMED.
     *
     * This used to be `atLeast(release, [3, 0, 3])`, with a comment calling
     * the threshold a guess about the future and saying to raise it once
     * there was a release to measure. There are two now, v3.0.3 and v3.0.4,
     * and neither has any of it - they ran the X-Wing and age tests instead of
     * skipping them and failed on a key type that does not exist.
     *
     * So the question is not "which version" but "release or development
     * line", and the BUILD KEYWORD answers it: a release is -prod, the
     * development tree is -test. The version number cannot, because the
     * development tree still declares 3.0.4 - the macro has not been bumped
     * since 2022 - so released v3.0.4 and the bench key share a number.
     *
     * The keyword only became usable when the matrix started building
     * releases as they ship. While every pinned release was forced to DEBUG
     * so it could be provisioned, a released v3.0.4 reported v3.0.4-testc,
     * character for character what the bench key reports.
     *
     * `atLeast(3.0.4)` as well as the keyword, so that a developer building
     * v3.0.2 with DEBUG on is not told it has post-quantum support. And
     * nothing is assumed forward: a future 3.0.5-prod reads false until
     * somebody measures it, because guessing one release ahead is precisely
     * what went wrong here.
     *
     * ok-rn/FINDING-capability-guesses-about-the-next-release-were-wrong.md
     */
    postQuantum: boolean;
    /**
     * Whether this firmware answers the FIRST-PARTY origin this library sends.
     *
     * `ok_extension.cpp:137` wraps the whole OnlyKey extension - OKCONNECT,
     * every derive, the tunnel - in `if (webcryptcheck(_appid, client_handle))`,
     * and `webcryptcheck` (fido2/device.cpp:83) answers with THREE values, not
     * two:
     *
     *   2  the request's rpId matches `stored_apprpid`, or its appid hash
     *      matches a stored one. Full extension.
     *   1  any other origin, but only for the `0xFFFFFFFF` OKCONNECT bootstrap
     *      and only when bit 2 of `derived_key_challenge_mode` is set. This is
     *      THIRD-PARTY MODE, and it is a feature: the site sends its own
     *      hostname, okcrypto_hkdf() folds that into the derivation, and the
     *      site gets keys nobody else can ask for. Present in every release
     *      from v2.1.0 on.
     *   0  refused, and the device answers nothing at all.
     *
     * This flag is about the 2, because that is what the app needs. Third-
     * party mode depends on an EEPROM byte written by setting 21 in config
     * mode, which is a device setting rather than anything a version can
     * answer for.
     *
     * MEASURED ACROSS NINE PINS: `stored_apprpid` is byte-identical
     * "apps.crp.to" from v0.2-beta.8 (2019) through HEAD. `onlyagent.app` is
     * an ADDITION at HEAD - libraries@a5b731f (2026-07-08) - matched by appid
     * hash, and has never shipped in a release. `localhost` exists only as the
     * comment "//Todo add localhost support".
     *
     * So this is not a version boundary. The library used to send
     * `onlyagent.app`, which dropped every release to 0; it now sends the
     * origin they all know, and this is a comparison rather than a threshold.
     * Left as a capability rather than deleted because it is the thing that
     * broke: if RP_ID moves again, this goes false and the suites that need
     * the vendor path skip by name instead of failing thirty tests later with
     * CTAP2_ERR_EXTENSION_NOT_SUPPORTED.
     *
     * A DEBUG build would accept anything - webcryptcheck returns 2, "trust
     * all origins for debug firmware", before comparing - and that is deliber-
     * ately NOT used here. Reading true because the console build waves every
     * origin through is how thirteen green sweeps hid this for a month.
     * See ok-rn/FINDING-the-vendor-path-is-origin-gated.md.
     *
     * A HOST THAT OVERRIDES THE ORIGIN is not visible from here - a caller can
     * pass `plugins.config = { okcrypto: { rpIds: [...] } }`, which is how a
     * third-party site would ask under its own hostname. This answers for the
     * library's own default, which is what every caller that does not override
     * gets.
     */
    vendorOrigin: boolean;
    /**
     * HMAC-SHA1 slot keys, which the Keys tab offers as a key type.
     *
     * `KEYTYPE_HMACSHA1 9` is in okcore.h at v3.0.0, v3.0.1 and v3.0.2 and
     * NOT at v2.1.0 or v2.1.1. v2.1.2 is unmeasured - its libraries commit
     * (12eb5b0) is not in the local checkout, so the probe skips it - which
     * only matters for a key running exactly that release, and the flag errs
     * towards not offering.
     */
    hmacSha1: boolean;
    /**
     * Whether a serial console is there to talk to.
     *
     *   true   a DEBUG build ('-test'), so SEREMU exists and prints prompts
     *   false  a production build ('-prod'), so it does not
     *   null   firmware older than the keyword
     *
     * null is UNKNOWN, not false. The console may well be there, and treating
     * unknown as absent would disable PIN provisioning on every old device -
     * exactly the population this work exists to support.
     *
     * onlykey.h:96-100. This decides whether the library may wait on console
     * prompts or must drive provisioning over the vendor interface instead.
     */
    debugConsole: boolean | null;
    /**
     * How many slots and profiles the device has.
     *
     * A DUO is 24 slots across 4 profiles, a Classic 12 across 2. Using the
     * Classic count against a DUO stops enumeration at 12 of 24 with no error,
     * which is the shape of failure this whole file exists to remove.
     */
    slots: number;
    profiles: number;
    /**
     * What the touch-free derive needs from this firmware.
     *
     *   'always'      it just works. No preference, nothing to turn on.
     *   'preference'  needs derived_key_challenge_mode bit 3 set.
     *   'broken'      the check exists and reads a stale cache, so the device
     *                 refuses it whatever the preference says.
     *
     * MEASURED, and the split is exactly one release wide:
     *
     *   v2.1.0 - v3.0.1   NO GATE AT ALL. ok_extension.cpp sets
     *                     additional_data[0] for the REQ_PRESS variants and
     *                     carries straight on; there is no preference check
     *                     anywhere (`git show a27ffa6:fido2/ok_extension.cpp`).
     *   v3.0.2            the check was ADDED, against `derived_key_challenge_mode`
     *                     - a RAM cache of an EEPROM byte that the raw-HID
     *                     pipeline zeroes on every done_process_packets(). By
     *                     the time the FIDO2 path reads it, it is always zero.
     *                     So the device answers CTAP2_ERR_EXTENSION_NOT_SUPPORTED
     *                     to a preference it is holding.
     *   after v3.0.2      the same check, reloading the byte from EEPROM first,
     *                     so the preference works as intended.
     *
     * Why a host needs to know: the press flag is an INPUT to the derivation,
     * not a permission check in front of it, so retrying with a touch derives a
     * DIFFERENT key (FINDING-the-press-flag-changes-the-derived-key.md). There
     * is no fallback. A caller that cannot do a touch-free derive cannot open
     * the vault at all, and the honest thing is to say why rather than to offer
     * a button that seals blobs nothing else can read.
     *
     * 'broken' is what the vault should refuse on, naming the firmware rather
     * than the preference - telling someone to enable a setting that cannot
     * take effect is worse than telling them nothing.
     */
    touchFreeDerive: string;
    /**
     * Whether the REQ_PRESS derive opcodes (3 and 4) exist on this firmware.
     *
     * They were DERIVE_PUBLIC_KEY_REQ_PRESS and DERIVE_SHARED_SECRET_REQ_PRESS,
     * and v3.0.5 removed them. The numbers are deliberately left burned
     * upstream rather than reused - ok_extension.cpp refuses anything above
     * DERIVE_SHAREDSEC outright - with the stated reason that "an old client
     * still sending them must fail loudly, not be silently reinterpreted".
     * That is what a host gets for ignoring this: every derive answered with
     * CTAP2_ERR_EXTENSION_NOT_SUPPORTED.
     *
     * WHY THEY WENT, because it decides what a client should do instead. The
     * suffix had stopped meaning what it said: presence is now implied by the
     * request, so the only thing REQ_PRESS still selected was a SECOND KEY
     * DOMAIN, through `additional_data[0] = 1` in the HKDF salt. Two keys per
     * label, chosen by an opcode named after touches.
     *
     * So the right client behaviour on v3.0.5+ is not to refuse, and not to
     * ask for a press some other way - it is to send the plain opcode and let
     * the firmware decide presence. derive() does exactly that.
     *
     * CONSEQUENCE WORTH KNOWING: on v3.0.5 `additional_data[0]` is always 0,
     * so anything sealed against the REQ_PRESS domain on older firmware
     * derives a different key here and will not open. That is upstream's
     * decision and not something a host can paper over - the old domain is
     * unreachable, because the opcode that selected it is refused.
     */
    deriveReqPress: boolean;
    /**
     * Whether this firmware speaks FIDO2 transit v2 (counter IV + GCM tag).
     *
     * v1 used AES-GCM as a stream cipher - fixed all-zero IV, a counter never
     * incremented, tag discarded. v2 gives every message its own IV and
     * verifies the tag. See openTransitV2() in src/crypto/okconnect.js.
     *
     * THE FIRMWARE STATES THIS CONTRACT ITSELF, which is why this is a version
     * comparison and not a measurement of behaviour. onlykey.h, beside the
     * version macros:
     *
     *   "3.0.5 is the FIRMWARE VERSION GATE for FIDO2 transit v2 (counter IV +
     *    GCM tag; see okcrypto.cpp). The host reads this string out of the
     *    plain OKCONNECT response - which is not encrypted - and picks its
     *    framing from it, so anything below 3.0.5 keeps the legacy scheme and
     *    anything at or above it speaks v2."
     *
     * So the threshold is published rather than inferred, and guessing forward
     * - the mistake this file is built to avoid - is not a risk here: a future
     * 4.x speaks v2 because the firmware says everything at or above 3.0.5
     * does, not because we are extrapolating from a release we measured.
     *
     * NOT DETECTABLE FROM THE WIRE. A v1 body and a v2 frame are both just
     * bytes; reading one as the other yields plausible noise, not an error.
     * That is what made this break look like "the device did not answer"
     * rather than like a decryption failure.
     *
     * THE BUILD DOES NOT AFFECT THIS, which is the property that matters for
     * production. okcrypto_transit_seal()/open() are wrapped in
     * `#ifdef STD_VERSION`, not `#ifdef DEBUG`, so a -prod and a -test build of
     * the same version frame identically. Proving it on a debug build proves it
     * for the shipped one.
     *
     * THE IN TRVL EDITION IS RETIRED, so the obvious caveat does not apply.
     * That `#ifdef STD_VERSION` would matter if a non-standard build existed -
     * it compiles both functions down to `return len`, no counter, no tag, no
     * encryption - but OnlyKey-Firmware@4a93dab retired the International
     * Travel Edition and resolved STD_VERSION, so from 3.0.5 there is no
     * edition to be on the wrong side of.
     *
     * It would be undetectable if there were: the status string carries the
     * model but NOT the edition. Upstream's own client (onlykey.extra.js,
     * TRANSIT_V2_MIN) gates on version alone for the same reason, so this
     * matches it rather than inventing a second definition of the contract.
     *
     * Older pinned releases still HAVE the edition, which is why nothing else
     * in this file drops its edition handling - but they are all below 3.0.5
     * and therefore speak v1 regardless.
     */
    transitV2: boolean;
    /**
     * Whether a captured backup carries a DIGEST to check it against.
     *
     * The backup file is armoured base64 the device TYPES at the keyboard, and
     * from v2.1.2 its last line is `--<base64>`: a rolling SHA-256 over the
     * data lines, each hash taken over the previous digest concatenated with
     * the next line's bytes. Chained rather than a hash of the whole file, so a
     * reordering is caught as well as a modification.
     *
     * BEFORE v2.1.2 THERE IS NO SUCH LINE AND NO INTEGRITY CHECK AT ALL.
     * libraries@v2.1.1-prod's okcore.cpp base64-encodes each block and stops -
     * the symbol `backuphash` does not occur in the file. The chain arrives in
     * the v2.1.1..v2.1.2 diff as an addition, alongside the `sha256_init` /
     * `sha256_update` / `sha256_final` calls that build it.
     *
     * So `parsers.verifyBackup()` on an older backup finds no digest line and
     * reports `{ok: false, reason: 'no digest line found'}` - which is the
     * truth about the FILE and not a fault in the capture. A caller that
     * asserts `verified` unconditionally calls three healthy firmware versions
     * broken: measured, v2.1.1, v2.1.0 and v0.2-beta.8 each failed
     * 8b-backup's capture test on all three of their runs, identically.
     *
     * What a caller should do below this line is assert the backup PARSES.
     * There is nothing else to check, which is itself worth knowing: a backup
     * taken from one of those versions cannot be verified, only restored.
     */
    backupDigest: boolean;
    /**
     * Whether the device holds BOTH halves of a derived X-Wing key.
     *
     * It used to answer a public-key request with
     * `[pk_X(32) | mlkem_seed(32)]` and a decapsulation with `ss_X`, leaving
     * the host to expand the ML-KEM half from the seed and combine - which
     * meant A PUBLIC-KEY REQUEST RETURNED PRIVATE MATERIAL. From 3.0.5 the
     * device does the whole thing:
     *
     *   OKGETPUBKEY  ->  [pk_M(1184) | pk_X(32)]      the real recipient, 1216
     *   OKDECRYPT    ->  ss(32)                       the X-Wing secret, bare
     *
     * A version comparison rather than a measurement because the two shapes
     * are indistinguishable by inspection: the reply is 1216 bytes either way,
     * and taking the last 64 of it yields something that looks exactly like the
     * old pair. That is not a hypothetical - it is what this library did, and
     * the test asserting "64 bytes and the halves differ" passed throughout.
     *
     * X-Wing is development-line only (see `xwingDerive`), so the 64-byte shape
     * exists only on a pre-3.0.5 development build. No release has either.
     */
    xwingDeviceCustody: boolean;
    /**
     * Whether fields 21, 22 and 30 are a 0/1/2 ENUM rather than a BITFIELD.
     *
     * The same byte, read two different ways, and nothing on the wire says
     * which - so it has to be decided from the version like everything else
     * here.
     *
     * Before 3.0.5, field 21 is a bitmask: bit 0 raises a three-button
     * challenge on raw-HID derives, and BIT 3 (value 8) is what lets a FIDO2
     * derive happen without a touch. From 3.0.5 the same field is an enum -
     * 0 challenge, 1 press, 2 none - and `set_slot()` REFUSES anything above
     * USER_INPUT_NONE with "Error invalid user input mode".
     *
     * So a host that writes 8 to a 3.0.5 key is refused, and a host that
     * writes 1 to an older key has asked for bit 0, which is a different
     * setting on a different code path. Neither failure names the version.
     *
     * Value 8 is not a hypothetical: writing it is what made five derives
     * answer OPERATION_DENIED for a whole debugging session, because the
     * touch-free setup silently never took (ok-rn@5230231).
     *
     * `2` is NOT universally available even at 3.0.5 - builds without
     * OK_ALLOW_NO_PRESS refuse it with "unsupported user input mode", and a
     * stale 2 in EEPROM fails closed to the challenge code. Field 30 permits
     * it; a caller offering it on 21 or 22 is offering an error.
     */
    userInputModeEnum: boolean;
    /**
     * Whether the DEVICE VAULT is offered on this firmware.
     *
     * NOT A LIMIT OF THE FIRMWARE, and that is why this comment is long. A
     * v3.0.4 key derives perfectly well - measured against a production build
     * of the last signed release, "a vault blob sealed on this device opens
     * again" - and slot 128 is the same slot number in both lines. Read as a
     * capability question alone, the honest answer for v3.0.4 would be yes.
     *
     * It is a PRODUCT decision, taken on 2026-09-23, and the reasoning is
     * about data rather than about what the silicon can do.
     *
     * 3.0.5 changed how a derived key is built (libraries@40464ca: the rpId
     * left okcrypto_hkdf()'s salt for a fixed info string), so anything sealed
     * on older firmware stops opening after an upgrade - silently, with the
     * blobs still present. The seed survives; the construction does not. And
     * the obvious recovery, restoring a backup onto the new firmware, does NOT
     * work, because a backup preserves the input rather than the expansion.
     *
     * No shipped release ever offered the vault: ok-rn is unreleased, and
     * whether the web app's July 2026 version reached anyone is unknown. So
     * the hazard is still hypothetical, and the cheapest way to keep it that
     * way is to never let data be created where an upgrade would strand it.
     * Offering it on v3.0.4 buys a feature nobody has asked for and creates a
     * migration nobody needs.
     *
     * A GUI decides what to do with this - ok-rn fades the section and says
     * which firmware it needs. Nothing here refuses the derive itself, because
     * the derive is genuinely available and a caller that means it (a test, a
     * recovery tool reading old data on purpose) must still be able to.
     */
    deviceVault: boolean;
    /**
     * Whether the X-Wing hybrid key type exists at all.
     *
     * THE DEVELOPMENT LINE, NOT A VERSION THRESHOLD - the third capability to
     * make this mistake, and the last one written before the rule was
     * understood. It read `patch > 2`, meaning v3.0.3 and later, which was a
     * guess one release ahead of anything anyone had run.
     *
     * MEASURED BY DIFF, not by grep. `KEYTYPE_XWING`, `mlkem`, `okpqc` and
     * every ML-KEM/ML-DSA source appear at HEAD and at NO pinned release:
     *
     *   v3.0.2  5d7ce7a   nothing
     *   v3.0.3  a133bea   nothing
     *   v3.0.4  c8804e3   nothing
     *   HEAD              okpqc.cpp/.h, utility/src/ (ML-KEM),
     *                     utility/mldsa_src/ (ML-DSA) - 50+ files
     *
     * And the releases it claimed to separate are barely distinguishable:
     * v3.0.2 -> v3.0.3 is 29 lines of libraries and 27 of firmware,
     * v3.0.3 -> v3.0.4 is sixteen lines - a Yubico OTP public-id length fix
     * and the patch number. There is no release boundary here to sit on.
     *
     * The cost of the old rule, measured in one production sweep: v3.0.4 and
     * v3.0.3 each reported two failures - "payload is 16 bytes; a keytype-5
     * public key is 64" - on firmware doing exactly what it should, while
     * v3.0.2 passed by skipping the same two tests. Identical builds, opposite
     * verdicts, from a boundary that does not exist.
     * ok-rn/FINDING-capability-guesses-about-the-next-release-were-wrong.md
     *
     * Defaults to FALSE for a version we cannot read, which is the opposite of
     * touchFreeDerive's default and deliberately so: that one is a feature old
     * firmware HAS, and this is one it does not. Guessing "present" would offer
     * a screen that produces an identity the device cannot use.
     */
    xwingDerive: boolean;
    /**
     * How the device asks for a touch, and therefore how a host must press.
     *
     *   'keepalive'  the request returns CTAP2_ERR_PROCESSING while it waits,
     *                the host keeps polling, and a press answered from inside
     *                the keepalive completes it. No time limit worth naming.
     *   'blocking'   ctap_user_presence_test(5000) BLOCKS for five seconds and
     *                then denies. There is no keepalive to answer, so a host
     *                that only presses when asked never presses at all.
     *
     * MEASURED at each pin by whether ok_extension.cpp mentions
     * CTAP2_ERR_PROCESSING: present through the whole 3.0 line, absent in the
     * 2.1 line. The split is the generation boundary.
     *
     * Why a host cannot ignore this: on 'blocking' firmware the press has to be
     * sent on a TIMER shortly after the request, not in response to anything.
     * Waiting to be asked produces CTAP2_ERR_OPERATION_DENIED five seconds
     * later, which reads as a refusal rather than as nobody having touched it.
     * Measured on a v2.1.0 soft key: every press-required shared-secret derive
     * failed this way while the touch-free derives beside them passed.
     */
    presenceTest: string;
    /**
     * The gesture that reaches config mode: which button, and for how long.
     *
     * OnlyKey.ino:914, verbatim:
     *
     *     (onlykeyhw==OK_HW_DUO && duration >= 180 && button_selected=='1')
     *     || (onlykeyhw!=OK_HW_DUO && duration >= 72 && button_selected=='6')
     *
     * `duration` is MAIN-LOOP ITERATIONS, not milliseconds - roughly 36ms each,
     * so the DUO's 180 is about six and a half seconds and the classic's 72 is
     * under three. The desktop app tells a DUO owner to hold for "10+ seconds"
     * and a classic owner for "5+", which are safe overshoots of these rather
     * than the numbers themselves.
     *
     * A host that uses the classic gesture on a DUO holds a button that does
     * something else entirely and then waits for a lock that never comes -
     * measured, as "the device never locked after three attempts".
     *
     * `ticks` is the FLOOR. Going further is not safer: past the same band a
     * hold stops being config mode and becomes another gesture, which is why
     * callers ask for this rather than picking a number that felt generous.
     *
     * Read off `gestures` rather than restated, so the two cannot disagree.
     * A caller that wants the whole band, or any other gesture, wants that.
     */
    configModeGesture: {
        button: any;
        ticks: any;
    };
    /**
     * Whether this firmware knows what a DUO is at all.
     *
     * MEASURED, from the pinned sources rather than from a changelog. The
     * constant that names the model appears on exactly one side of the 3.0
     * boundary, and its predecessor on the other:
     *
     *     v2.1.0  OK_GO       OK_HW_DUO absent
     *     v2.1.1  OK_GO       OK_HW_DUO absent
     *     v3.0.0  OK_HW_DUO   OK_GO absent
     *     v3.0.1  OK_HW_DUO   OK_GO absent
     *     v3.0.2  OK_HW_DUO   OK_GO absent
     *
     * They never coexist: the 3.0 line replaced OK_GO outright rather than
     * adding beside it. `//#define DEFINED_HWID OK_HW_DUO` - the firmware's own
     * commented-out override, which is how ok-rn stages a DUO - appears on the
     * same three releases and no earlier one.
     *
     * FALSE FOR UNKNOWN, the opposite of touchFreeDerive's default and for the
     * same reason xwingDerive is: this is a feature old firmware does NOT have.
     * Guessing "present" would offer 24 slots on a key that has 12 and put four
     * profiles in front of someone whose device has two.
     *
     * Note this is about the FIRMWARE, not the device in hand. A 3.0 build
     * running on classic hardware answers true here and 'classic' for its
     * model; the model is what decides how many buttons to draw.
     */
    duoSupported: boolean;
    /**
     * Whether the debug console can PRESS BUTTONS, not just print.
     *
     * MEASURED, and it settles a contradiction. `device.unlock()` defaults to
     * writing PIN digits to SEREMU, and a comment in ok-rn's test helpers said
     * that was a debug-build feature. Two readings of the firmware failed to
     * find anything consuming console input, and a probe on the running key
     * found that it plainly does. Both were right, for different firmware:
     *
     *   working tree   okcore.cpp:2689 reads Serial and queues presses
     *   v3.0.2 and older   NO Serial.read anywhere in okcore.cpp at all
     *
     * So on every RELEASED firmware the console is write-only, and unlock()'s
     * default path cannot work. On newer firmware it is a full control channel
     * - taps, holds by tier, explicit tick counts, restart and factory reset -
     * which is what makes a developer key drivable by a test suite.
     *
     * ## THIS IS NOT "CAN THE HOST PRESS A BUTTON"
     *
     * Pressing is a property of the HOST, not of the firmware, and this answers
     * only whether the CONSOLE accepts press commands - which is the question
     * for a real key reached over a wire.
     *
     * An emulated key presses in ANY build, including production, and does not
     * need the console at all: the host fakes the capacitive reading itself, so
     * the press arrives at `touch_sense_loop()`'s `touchread1..6` comparisons
     * (okcore.cpp:2574) exactly as a finger would. Those sit outside every
     * `#ifdef DEBUG` in that function - the first one is the console parser,
     * further down - so the gate this capability turns on is simply not in that
     * path. Reading `consolePress === false` as "this device cannot be pressed"
     * would disable a soft key that presses perfectly well.
     *
     * TWO CONDITIONS, and both are needed. The parser sits inside `#ifdef
     * DEBUG` (okcore.cpp:2360), so a production build of newer firmware has it
     * compiled out - which is `debugConsole` being false. And it postdates
     * every pinned release.
     *
     * The boundary is only known to be SOMEWHERE ABOVE v3.0.2: it is absent
     * from every pin in ok-versions.json and present in the working tree at
     * v3.0.4. No pin sits between them, so this is the tightest honest answer
     * rather than a measured edge.
     */
    consolePress: boolean;
    /** Three buttons on a DUO, six otherwise - see protocol/challenge.js. */
    buttons: number;
};
/**
 * Numbers out of a version string, for ordering.
 *
 * Two shapes have shipped and both have to parse:
 *
 *   v3.0.4-test   major.minor.patch with a build keyword
 *   v0.2-beta.8   major.minor with a prerelease that has its own number
 */
export function parseRelease(version: any): {
    major: number;
    minor: number;
    patch: number | null;
    prerelease: string | null;
} | null;
/**
 * Drop the model letter HW_MODEL appended, if one is there.
 *
 * Only a letter that MEANS something is dropped, so `v0.2-beta.3` keeps its 3
 * and reports an unknown model - which is right, since firmware that old
 * appended nothing.
 *
 * A version whose own last character happened to be n, p, c or o would lose it.
 * That is not a flaw here: the firmware appends unconditionally, so such a
 * version is genuinely ambiguous on the wire, and both reference clients read
 * the last character exactly this way.
 */
export function stripModelSuffix(version: any): any;
/**
 * Whether firmware can be updated over USB. Transcribed from
 * OnlyKeyComm.js:1360:
 *
 *   if (version && (version[9] != "." || version[10] > 6))
 *
 * Kept as the same character test rather than rewritten as a version
 * comparison, because the character test is what has been proven against the
 * old devices. What it reaches for is "newer than v0.2-beta.6": in that string
 * index 9 is the dot of `beta.6` and index 10 is that 6, so a string without a
 * dot there is a different shape and therefore newer.
 *
 * It compares a CHARACTER against a number, so `version[10] > 6` is '7' > 6,
 * which JavaScript coerces and which happens to work - and which would stop
 * working at a two-digit number. Transcribed, not corrected: correcting it
 * would be improving a protocol we have no way to test against.
 */
export function supportsFwUpdate(version: any): boolean;
/**
 * Is this release at or past `[major, minor, patch]`?
 *
 * Only for the version-gated capability flags below, which is why it is
 * deliberately strict rather than clever: a version that does not parse, or a
 * device that has not said what it is, returns false. Every caller is asking
 * "may I offer this feature", and the safe answer when nothing is known is no
 * - a feature offered to firmware that lacks it fails at the device with a
 * silence or a refusal the user has to interpret.
 *
 * A prerelease of the SAME numbers counts as at least that version. The only
 * prereleases this firmware produces are build keywords - `-test`, `-prod` -
 * on an otherwise complete number, not the semver sense of "not there yet".
 */
export function atLeast(release: any, [major, minor, patch]: [any, any, any]): boolean;
export namespace MODEL {
    let CLASSIC: string;
    let DUO: string;
    let ORIGINAL: string;
    let UNKNOWN: string;
}
export namespace BUILD {
    export let DEBUG: string;
    export let PRODUCTION: string;
    let UNKNOWN_1: string;
    export { UNKNOWN_1 as UNKNOWN };
}
export namespace MODEL_SUFFIX {
    import c = MODEL.CLASSIC;
    export { c };
    import p = MODEL.DUO;
    export { p };
    import n = MODEL.DUO;
    export { n };
    import o = MODEL.ORIGINAL;
    export { o };
}
/**
 * The one version whose OKCONNECT reply is laid out differently.
 *
 * onlykey-api.js:167 compares the 12-byte version field against this EXACT
 * string, model letter included, and switches the whole reply layout on it. It
 * is a string comparison in the reference and it stays one here: the condition
 * is not "older than 8c", it is "is 8c".
 */
export const BREAKING_BETA_8C: "v0.2-beta.8c";
/**
 * The version the desktop app assumes when a device says UNINITIALIZED with no
 * version after it (OnlyKeyComm.js:1343-1348). Such firmware predates the
 * version being in the string at all. The app also disables its in-app firmware
 * update on this path and tells the user to upgrade.
 */
export const PRE_VERSION_FIRMWARE: "v0.2-beta.6";
