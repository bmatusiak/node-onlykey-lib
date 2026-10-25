export namespace TYPES {
    let HELLO: string;
    let PROVE: string;
    let HAVE: string;
    let GIVE: string;
}
/**
 * The computer's side of one trade, step by step. Each step takes the peer's answer to the last message and returns
 * the next message (or what the trade came to); null means the trade stops there (no proof, no answer, a refusal).
 * @param {{bucket: object, me: object, randomBytes: (n: number) => Uint8Array, rules?: object}} o
 *   bucket: this computer's open bucket (changed in place by take); me: its bucket identity, bucket key, certificate
 */
export function computerSide({ bucket, me, randomBytes, rules }: {
    bucket: object;
    me: object;
    randomBytes: (n: number) => Uint8Array;
    rules?: object;
}): {
    hello: () => {
        type: string;
        v: number;
        nonce: string;
        identity: any;
    };
    prove(answer: any): {
        type: string;
        v: number;
        identity: any;
        proof: {
            identityPublicKey: string;
            bucketPublicKey: string;
            certificate: string;
            signature: string;
        };
        state: {
            hash: string;
            at: string | null;
            stores: {
                [x: string]: string;
            };
        };
    } | null;
    compare(answer: any): {
        same: boolean;
        differs?: undefined;
        message?: undefined;
    } | {
        same: boolean;
        differs: string[];
        message: {
            type: string;
            v: number;
            identity: any;
            have: {
                [x: string]: {
                    [x: string]: {
                        at: string;
                        h: string;
                    };
                };
            };
        };
    } | null;
    give(answer: any): {
        message: {
            type: string;
            v: number;
            identity: any;
            give: {
                [x: string]: {
                    [x: string]: {
                        v: string | null;
                        at: string;
                        archived?: true;
                        part?: true;
                    };
                };
            };
        };
        taken: {
            [x: string]: number;
        };
        mine: any;
        theirs: any;
    } | null;
    settle(answer: any): {
        same: boolean;
        taken: any;
        differs?: undefined;
        message?: undefined;
    } | {
        same: boolean;
        taken: any;
        differs: string[];
        message: {
            type: string;
            v: number;
            identity: any;
            have: {
                [x: string]: {
                    [x: string]: {
                        at: string;
                        h: string;
                    };
                };
            };
        };
    } | {
        same: boolean;
        taken: any;
        differs: string[];
        message?: undefined;
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
