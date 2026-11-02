/**
 * @param {{kv: {getItem: (k: string) => any, setItem: (k: string, v: string) => any, removeItem?: (k: string) => any, getAllKeys?: () => any}, prefix: () => string}} o
 * @returns {{key: (deviceId: Uint8Array | string) => string, load: (deviceId: Uint8Array | string) => Promise<any>,
 *   read: (deviceId: Uint8Array | string) => Promise<any>, save: (copy: any) => Promise<{written: boolean, outside: boolean}>,
 *   forget: (deviceId: Uint8Array | string) => Promise<void>, drop: (deviceId: Uint8Array | string) => void,
 *   ends: (deviceId: Uint8Array | string) => Promise<{seq: number, head: Uint8Array} | null>, ids: () => Promise<string[]>,
 *   take: (deviceId: Uint8Array | string, added: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array | null}>, now?: number) => Promise<{written: boolean, outside: boolean, added: number}>,
 *   empty: (deviceId: Uint8Array | string) => any}}
 */
export function createHistory({ kv, prefix }: {
    kv: {
        getItem: (k: string) => any;
        setItem: (k: string, v: string) => any;
        removeItem?: (k: string) => any;
        getAllKeys?: () => any;
    };
    prefix: () => string;
}): {
    key: (deviceId: Uint8Array | string) => string;
    load: (deviceId: Uint8Array | string) => Promise<any>;
    read: (deviceId: Uint8Array | string) => Promise<any>;
    save: (copy: any) => Promise<{
        written: boolean;
        outside: boolean;
    }>;
    forget: (deviceId: Uint8Array | string) => Promise<void>;
    drop: (deviceId: Uint8Array | string) => void;
    ends: (deviceId: Uint8Array | string) => Promise<{
        seq: number;
        head: Uint8Array;
    } | null>;
    ids: () => Promise<string[]>;
    take: (deviceId: Uint8Array | string, added: Array<{
        link: Uint8Array;
        head: Uint8Array;
        reveal?: Uint8Array | null;
    }>, now?: number) => Promise<{
        written: boolean;
        outside: boolean;
        added: number;
    }>;
    empty: (deviceId: Uint8Array | string) => any;
};
