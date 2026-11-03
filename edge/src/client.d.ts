/**
 * @param {object} opts
 * @param {any} opts.edge  the lib's Edge plugin, on the key the uses run on
 * @param {{send: (msg: any) => Promise<any>} | null} [opts.channel]  to the phone that approves; null where this app
 *   IS the phone (the web app): no request to send, no notes
 * @param {{get: (key: string) => Promise<string | null>, set: (key: string, value: string) => Promise<void>} | null} [opts.store]
 *   where budgets are kept between processes (resume)
 * @param {number} [opts.noteTimeoutMs]
 */
export function createEdgeClient({ edge, channel, store, noteTimeoutMs }: {
    edge: any;
    channel?: {
        send: (msg: any) => Promise<any>;
    } | null | undefined;
    store?: {
        get: (key: string) => Promise<string | null>;
        set: (key: string, value: string) => Promise<void>;
    } | null | undefined;
    noteTimeoutMs?: number | undefined;
}): {
    ping({ size, timeoutMs }?: {
        size?: number | undefined;
        timeoutMs?: number | undefined;
    }): Promise<{
        exact: boolean;
        ms: number;
        bytes: number;
        wire: number;
        why: string;
        parts?: undefined;
    } | {
        exact: boolean;
        why: string | undefined;
        ms: number;
        bytes: number;
        wire: number;
        parts: {
            queue: number | null;
            pcWrite: number | null;
            phoneIn: number | null;
            phoneHold: number | null;
            phoneTotal: number | null;
            pcIn: number | null;
        };
    }>;
    /** File an owed receipt with no budget (after it ended): the key checks only that the seq is owed. -> {seq, head} */
    receiptOwed: (seq: any, { code, message }: {
        code?: string | undefined;
        message: any;
    }) => Promise<any>;
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, receipt_owed, still_live, invalid, busy),
     * EEDGE_NO_ANSWER (dropped: not paired, replayed) or EEDGE_OPENING
     * (the answer is not a budget the key opened as asked).
     */
    request({ reason, scopes, ttlMinutes, card }: {
        reason: any;
        scopes: any;
        ttlMinutes: any;
        card?: null | undefined;
    }): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
        /**
         * The head this budget holds (hex): what the agent's next use TX starts over,
         * and what `onlykey-js edge exec --head` must name - proof the agent saw its own
         * last receipt's reply (APP.md).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         * @param {Uint8Array} bytes  what the key will sign - the TX start names exactly these
         * @param {(bytes: Uint8Array) => Promise<any>} op
         * @param {{reason?: string, intent?: string | null}} [opts]  the agent's words for the use (R13b)
         */
        use(bytes: Uint8Array, op: (bytes: Uint8Array) => Promise<any>, { reason, intent }?: {
            reason?: string;
            intent?: string | null;
        }): Promise<{
            result: any;
            purpose: string | undefined;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the receipt for a use; the new head is kept for the next use(). */
        receipt(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /**
         * Revoke what is left - only once every use is receipted (R16: the client
         * receipts first, then ends). Ending with a receipt owed left budget 351's
         * card waiting on a receipt after its end (Brad, 2026-10-06).
         */
        end(): Promise<void>;
    }>;
    /**
     * "Continues <budget>": the same scopes, new uses (caps: one per scope, in
     * the budget's order; the old caps when left out) and a new lifetime.
     * Opens with a press like a new budget; the agent checks the opening the
     * same way. Needs the store the budget was saved to.
     */
    continue(grantId: any, { ttlMinutes, caps, reason }: {
        ttlMinutes: any;
        caps?: null | undefined;
        reason?: null | undefined;
    }): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
        /**
         * The head this budget holds (hex): what the agent's next use TX starts over,
         * and what `onlykey-js edge exec --head` must name - proof the agent saw its own
         * last receipt's reply (APP.md).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         * @param {Uint8Array} bytes  what the key will sign - the TX start names exactly these
         * @param {(bytes: Uint8Array) => Promise<any>} op
         * @param {{reason?: string, intent?: string | null}} [opts]  the agent's words for the use (R13b)
         */
        use(bytes: Uint8Array, op: (bytes: Uint8Array) => Promise<any>, { reason, intent }?: {
            reason?: string;
            intent?: string | null;
        }): Promise<{
            result: any;
            purpose: string | undefined;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the receipt for a use; the new head is kept for the next use(). */
        receipt(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /**
         * Revoke what is left - only once every use is receipted (R16: the client
         * receipts first, then ends). Ending with a receipt owed left budget 351's
         * card waiting on a receipt after its end (Brad, 2026-10-06).
         */
        end(): Promise<void>;
    }>;
    /**
     * Pick up a budget another process asked for (with the same store). The
     * key's HEAD must still list it; the head to TX start over is read from the key.
     */
    resume(grantId: any): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
        /**
         * The head this budget holds (hex): what the agent's next use TX starts over,
         * and what `onlykey-js edge exec --head` must name - proof the agent saw its own
         * last receipt's reply (APP.md).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         * @param {Uint8Array} bytes  what the key will sign - the TX start names exactly these
         * @param {(bytes: Uint8Array) => Promise<any>} op
         * @param {{reason?: string, intent?: string | null}} [opts]  the agent's words for the use (R13b)
         */
        use(bytes: Uint8Array, op: (bytes: Uint8Array) => Promise<any>, { reason, intent }?: {
            reason?: string;
            intent?: string | null;
        }): Promise<{
            result: any;
            purpose: string | undefined;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the receipt for a use; the new head is kept for the next use(). */
        receipt(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /**
         * Revoke what is left - only once every use is receipted (R16: the client
         * receipts first, then ends). Ending with a receipt owed left budget 351's
         * card waiting on a receipt after its end (Brad, 2026-10-06).
         */
        end(): Promise<void>;
    }>;
};
