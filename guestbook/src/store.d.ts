export type SourceLink = {
    kind: string;
    handle: string;
    lastChecked?: string;
    lastResult?: string;
};
export const KEY: "guestbook:v1";
export const VERSION: 1;
export const SOURCE_KINDS: string[];
export const HISTORY_MAX: 20;
/**
 * The Guest Book over a key-value storage.
 * @param {{storage: {getItem(k: string): Promise<string|null>, setItem(k: string, v: string): Promise<void>}, randomBytes: (n: number) => Uint8Array, now?: () => Date, key?: string}} deps - key: the storage key (a host keeps a test list apart under another)
 */
export function createGuestBook({ storage, randomBytes, now, key }: {
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
        contacts: any;
        recovered: boolean;
        reason?: undefined;
    } | {
        contacts: never[];
        recovered: boolean;
        reason: string;
    }>;
    save: (contacts: any) => Promise<any>;
    newContact: ({ name, found, source }: {
        name: any;
        found: any;
        source: any;
    }) => {
        id: string;
        name: string;
        keys: any;
        history: any;
    };
    addKeys: (contact: any, found: any, source: any) => {
        id: string;
        name: string;
        keys: any;
        history: any;
    };
    setVerified: (contact: any, keyId: any, verified: any) => {
        id: string;
        name: string;
        keys: any;
        history: any;
    };
    rename: (contact: any, name: any, note: any) => {
        id: string;
        name: string;
        keys: any;
        history: any;
    };
    removeKey: (contact: any, keyId: any) => {
        id: string;
        name: string;
        keys: any;
        history: any;
    };
};
export function shapeContact(c: any): {
    id: string;
    name: string;
    keys: any;
    history: any;
};
