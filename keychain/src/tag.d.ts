/**
 * Key Chain's record of what a key slot is, kept IN THE KEY'S OWN LABEL.
 *
 * ## Why the label (owner, 2026-10-01)
 *
 * The device never says what a slot holds - no command returns the stored
 * type byte - and a record kept on one phone or PC is lost the moment the key
 * is used somewhere else. The key label travels with the key: it is in the
 * device's backup, every app reads it (OKGETLABELS), and it costs nothing.
 * probeKeySlot() works the TYPE out from the public key; the tag adds what the
 * public key cannot say - what the key is FOR, and its name.
 *
 * ## The shape: "<kind>:<name>", 16 bytes at most
 *
 * A key label is sixteen bytes (EElen_label, okeeprom.h:94), shown as-is by
 * the desktop App and the CLI, so the tag is readable rather than packed:
 * "pgp:alice", "ssh:laptop", "xwg:backups". Three letters and a colon leave
 * twelve characters for the name. The kinds:
 *
 *   pgp  a PGP key (the type says which half: a signing type is the primary,
 *        X25519 the encryption subkey)
 *   ssh  an SSH key
 *   age  a classic age identity (X25519)
 *   xwg  an X-Wing key (post-quantum age)        } these two also settle what
 *   mlk  an ML-KEM-768 key                        } probeKeySlot cannot always
 *   pqc  the composite post-quantum PGP key (RSA slots)
 *   sig  a signing key with no other format
 *   enc  an encryption key with no other format
 *
 * A label that is not a tag is someone's own name for a key loaded elsewhere;
 * Key Chain shows it as it is and never rewrites it.
 *
 * Plain ASCII only: a key label is written as TEXT (slotConfig), and a byte
 * the desktop App would show as garbage is not a name.
 */
export const LABEL_MAX: 16;
export const KINDS: Readonly<{
    pgp: "PGP key";
    ssh: "SSH key";
    age: "age identity (X25519)";
    xwg: "X-Wing key";
    mlk: "ML-KEM-768 key";
    pqc: "composite post-quantum PGP key";
    sig: "signing key";
    enc: "encryption key";
}>;
/** What a kind tells probeKeySlot about a slot it cannot settle alone. */
export const PROBE_HINT: Readonly<{
    xwg: "xwing";
    mlk: "mlkem768";
}>;
/**
 * Build a tag. Throws, saying why, rather than truncating: a cut-off name is a
 * different name.
 * @param {string} kind one of KINDS
 * @param {string} name printable ASCII, no colon, no leading/trailing space
 * @returns {string}
 */
export function formatTag(kind: string, name: string): string;
/**
 * Read a label as a tag.
 * @param {string|null|undefined} label
 * @returns {{kind: string, name: string, hint: string|null}|null} null when it is not a tag
 */
export function parseTag(label: string | null | undefined): {
    kind: string;
    name: string;
    hint: string | null;
} | null;
