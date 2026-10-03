/**
 * Check 1: read the armored PUBLIC key and verify its self-signatures.
 * -> {key, userId, fingerprint, primary: {type, bytes}, encryption: {type, bytes} | null}
 * Throws on a private key block, an unreadable file or a self-signature that
 * does not verify.
 */
export function inspect(openpgp: any, armored: any): Promise<{
    key: any;
    userId: any;
    fingerprint: any;
    primary: {
        type: string;
        role: string;
        bytes: any;
    };
    encryption: {
        type: string;
        role: string;
        bytes: any;
    } | null;
}>;
/**
 * Check 2: which of this OnlyKey's slots hold the certificate's keys.
 * probes: [{slot, kind, publicKey}] as device.probeKeySlot / Key Chain's
 * readSlots return them. -> {signSlot, ecdhSlot} (null where none matches)
 */
export function matchSlots(info: any, probes: any): {
    signSlot: any;
    ecdhSlot: any;
};
/**
 * Check 3: the slots' private keys work now and are the certificate's.
 * hooks.sign(slot, digest32) -> 64-byte signature (okcrypto.sign);
 * hooks.ecdh(slot, peerPublic) -> 32-byte shared secret (okcrypto.ecdh).
 * Each asks the key, so each is a press. -> {sign: true|null, ecdh: true|null};
 * throws naming the check that failed.
 */
export function proveSlots(info: any, match: any, hooks: any): Promise<{
    sign: null;
    ecdh: null;
}>;
/**
 * The Key Chain list entry (list.createEntry input), shaped like the one Key
 * Chain makes for a PGP pair made in the key: kind 'external', the slots it
 * is linked to (decrypt first, as the maker writes them), the certificate.
 * Slots only when PROVEN; otherwise someone's key to encrypt to.
 */
export function entryFor(info: any, match: any, proven: any): {
    type: any;
    publicKey: any;
    pgp: any;
    slots?: any[] | undefined;
    kind: string;
    name: any;
};
export function keyOf(packet: any): {
    type: string;
    role: string;
    bytes: any;
} | null;
