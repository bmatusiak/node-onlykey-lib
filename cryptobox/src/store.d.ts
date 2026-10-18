export type BoxMessage = {
    id: string;
    contact: string;
    dir: "out" | "in";
    armored: string;
    kind: "encrypted" | "signed";
    signed: boolean;
    at: string;
};
export const KEY: "cryptobox:v1";
export const VERSION: 1;
export const ARMORED_MAX: number;
export const MESSAGES_MAX: 5000;
/**
 * What an armored block is, for the store: 'encrypted', 'signed', or a thrown reason. One block
 * only - two messages pasted together are two messages, imported one at a time.
 * @param {string} armored
 * @returns {'encrypted'|'signed'}
 */
export function kindOf(armored: string): "encrypted" | "signed";
/** @typedef {{id: string, contact: string, dir: 'out'|'in', armored: string, kind: 'encrypted'|'signed', signed: boolean, at: string}} BoxMessage */
export function shapeMessage(m: any): {
    id: string;
    contact: string;
    dir: any;
    armored: string;
    kind: "signed" | "encrypted";
    signed: boolean;
    at: string;
};
/**
 * The Cryptobox over a key-value storage.
 * @param {{storage: {getItem(k: string): Promise<string|null>, setItem(k: string, v: string): Promise<void>}, randomBytes: (n: number) => Uint8Array, now?: () => Date, key?: string}} deps - key: the storage key (a host keeps a test list apart under another)
 */
export function createCryptobox({ storage, randomBytes, now, key }: {
    storage: {
        getItem(k: string): Promise<string | null>;
        setItem(k: string, v: string): Promise<void>;
    };
    randomBytes: (n: number) => Uint8Array;
    now?: () => Date;
    key?: string;
}): {
    KEY: string;
    load: () => Promise<{
        messages: BoxMessage[];
        recovered: boolean;
        reason?: string;
    }>;
    save: (messages: any) => Promise<any>;
    add: (m: {
        contact: string;
        dir: "out" | "in";
        armored: string;
        signed?: boolean;
    }) => Promise<BoxMessage>;
    remove: (id: any) => Promise<any>;
    removeThread: (contact: any) => Promise<any>;
    moveThread: (from: any, to: any) => Promise<any>;
};
/**
 * The threads, newest first: who, how many, the last message.
 * @param {BoxMessage[]} messages
 * @returns {{contact: string, count: number, last: BoxMessage}[]}
 */
export function threads(messages: BoxMessage[]): {
    contact: string;
    count: number;
    last: BoxMessage;
}[];
