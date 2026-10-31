export function forkTree(chains: Array<{
    deviceId: string | Uint8Array;
    links: Array<Uint8Array | {
        link: Uint8Array;
        head?: Uint8Array;
    }>;
}>): {
    chains: Array<{
        deviceId: string;
        start: 'original' | 'fork' | 'partial';
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
