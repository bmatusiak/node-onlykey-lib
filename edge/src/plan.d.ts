/**
 * Run one submitted plan.
 * @param {object} o
 * @param {any} o.plan        the plan as the room told it ({id, title, agent, card, items: [{item, op, key, reason, fingerprint}], ...})
 * @param {any} o.client      createEdgeClient({edge, channel: <this device's Edge host>})
 * @param {any} o.signers     planSigners(...)
 * @param {(u: any) => Promise<void>} o.update  the plan's progress back to its room: {state?, results?, receipts?, why?}
 * @param {(l: (e: any) => void) => () => void} o.subscribe  this plan's data / finish events
 * @param {number} [o.ttlMinutes]
 * @param {(line: string) => void} [o.log]
 * -> the end state: 'done' | 'ended' | 'declined' | 'failed'
 */
export function runPlan({ plan, client, signers, update, subscribe, ttlMinutes, log }: {
    plan: any;
    client: any;
    signers: any;
    update: (u: any) => Promise<void>;
    subscribe: (l: (e: any) => void) => () => void;
    ttlMinutes?: number | undefined;
    log?: ((line: string) => void) | undefined;
}): Promise<string>;
export function planSigners({ okcrypto, openpgp, identity }: {
    okcrypto: any;
    openpgp?: null | undefined;
    identity?: (() => Promise<null>) | undefined;
}): {
    ssh(key: any, data: any, pay: any): Promise<{
        signature: string;
        encoding: string;
    }>;
    gpg(key: any, data: any, pay: any): Promise<{
        signature: {
            armored: string;
            fingerprint: string;
            created: number;
        };
        encoding: string;
    }>;
    rsa(key: any, data: any, pay: any): Promise<{
        signature: string;
        encoding: string;
    }>;
};
export function scopesOf(runnable: any): any[];
export function sortItems(plan: any): {
    runnable: {
        it: any;
        key: {
            kind: any;
            name: string;
            slot: number;
            bits: number;
            derive?: undefined;
            uid?: undefined;
        } | {
            kind: any;
            name: string;
            derive: {
                ssh: {
                    user: string | undefined;
                    host: string;
                };
            };
            slot?: undefined;
            bits?: undefined;
            uid?: undefined;
        } | {
            kind: any;
            name: string;
            uid: string;
            derive: {
                gpg: string;
            };
            slot?: undefined;
            bits?: undefined;
        };
    }[];
    refused: {
        item: any;
        refusal: any;
    }[];
};
export function keyOf(key: any): {
    kind: any;
    name: string;
    slot: number;
    bits: number;
    derive?: undefined;
    uid?: undefined;
} | {
    kind: any;
    name: string;
    derive: {
        ssh: {
            user: string | undefined;
            host: string;
        };
    };
    slot?: undefined;
    bits?: undefined;
    uid?: undefined;
} | {
    kind: any;
    name: string;
    uid: string;
    derive: {
        gpg: string;
    };
    slot?: undefined;
    bits?: undefined;
};
export function reasonOf(plan: any, runnable: any): string;
export function fingerprintOf(bytes: any): string;
export const PLAN_LIFETIME_MINUTES: 15;
export const SIGN_CODE: 221;
export namespace AGENT_DERIVE {
    let keyType: number;
    let version: number;
}
export const RSA_SLOTS: number[];
