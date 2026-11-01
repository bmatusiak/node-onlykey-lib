/**
 * @param {Array<{deviceId: string|Uint8Array, links: Array<{link: Uint8Array, head?: Uint8Array}>}>} chains newest data
 *   each host holds, any order
 * @returns {{
 *   chains: Array<{deviceId: string, start: 'original'|'fork'|'partial', forkSeq: number|null, point: string|null, parent: string|null}>,
 *   points: Array<{point: string, seq: number, parent: string|null, forks: string[], flag: boolean}>
 * }}
 *   start: 'original' - the chain from its genesis (seq 0); 'fork' - it begins with a CONTINUE (a restored backup);
 *   'partial' - this host holds it only from a later link, so where it began is not known here.
 *   points: the backup points forks continue from, one per subject; flag: more than one fork of the same point.
 */
export function forkTree(chains: Array<{
    deviceId: string | Uint8Array;
    links: Array<{
        link: Uint8Array;
        head?: Uint8Array;
    }>;
}>): {
    chains: Array<{
        deviceId: string;
        start: "original" | "fork" | "partial";
        forkSeq: number | null;
        point: string | null;
        parent: string | null;
    }>;
    points: Array<{
        point: string;
        seq: number;
        parent: string | null;
        forks: string[];
        flag: boolean;
    }>;
};
