export namespace TYPES {
    let HELLO: string;
    let PROVE: string;
    let GIVE: string;
}
/**
 * The computer's side of one trade, round by round.
 * @param {{bucket: object, me: object, randomBytes: (n: number) => Uint8Array, rules?: object}} o
 *   bucket: this computer's open bucket (changed in place by take); me: its bucket identity, bucket key, certificate
 * @returns {{hello(): object, prove(answer: object): object|null, give(answer: object): object|null, finish(answer: object): {taken: object}|null}}
 */
export function computerSide({ bucket, me, randomBytes, rules }: {
    bucket: object;
    me: object;
    randomBytes: (n: number) => Uint8Array;
    rules?: object;
}): {
    hello(): object;
    prove(answer: object): object | null;
    give(answer: object): object | null;
    finish(answer: object): {
        taken: object;
    } | null;
};
/**
 * The peer's side (the phone, a remote): answers each round, holding a trade per computer between rounds.
 * @param {{bucket: () => object|null, me: () => object|null, randomBytes: (n: number) => Uint8Array, rules?: object, seen?: Set<string>}} o
 *   bucket / me: the open bucket and this device's bucket identity, bucket key and certificate - null while the bucket
 *   is not open (then every round is refused, the same way); seen: nonces already answered (no replay)
 * @returns {(message: object, from: string) => object|null} null for a message that is not a trade
 */
export function peerSide({ bucket, me, randomBytes, rules, seen }: {
    bucket: () => object | null;
    me: () => object | null;
    randomBytes: (n: number) => Uint8Array;
    rules?: object;
    seen?: Set<string>;
}): (message: object, from: string) => object | null;
/**
 * A device's proof of its bucket identity over the other side's nonce.
 * @param {{identityPublicKey: Uint8Array, bucketKey: {secretKey: Uint8Array, publicKey: Uint8Array}, certificate: Uint8Array, id: string}} me
 */
export function prove(me: {
    identityPublicKey: Uint8Array;
    bucketKey: {
        secretKey: Uint8Array;
        publicKey: Uint8Array;
    };
    certificate: Uint8Array;
    id: string;
}, nonce: any, side: any): {
    identityPublicKey: string;
    bucketPublicKey: string;
    certificate: string;
    signature: string;
};
export function checks(proof: any, nonce: any, side: any, id: any): boolean;
