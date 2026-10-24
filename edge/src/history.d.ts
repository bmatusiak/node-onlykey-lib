export function budgetHistory(copy: any): {
    budgets: any[];
    presses: {
        seq: any;
        op: string;
        slot: any;
        intent: any;
        receipt: any;
    }[];
    losses: {
        seq: number;
        from: number;
        to: number;
    }[];
};
export const END_HOW: {
    1: string;
    2: string;
    3: string;
};
