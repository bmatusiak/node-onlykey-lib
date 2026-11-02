export function storeRules(): {
    'edge.copies': (into?: {}, from?: {}) => {
        store: {};
        taken: number;
        conflicts: {
            key: string;
            reason: any;
            into: any;
            from: any;
            apply(): never;
        }[];
    };
    'edge-test.copies': (into?: {}, from?: {}) => {
        store: {};
        taken: number;
        conflicts: {
            key: string;
            reason: any;
            into: any;
            from: any;
            apply(): never;
        }[];
    };
};
