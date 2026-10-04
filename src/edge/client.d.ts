export function createEdgeClient({ edge, channel, signer, store, noteTimeoutMs }: {
    edge: any;
    channel: any;
    signer: any;
    store?: null | undefined;
    noteTimeoutMs?: number | undefined;
}): {
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, ticket_owed, restoring, invalid),
     * EEDGE_NO_ANSWER (dropped: not registered, replayed) or EEDGE_OPENING
     * (the answer is not a budget the key opened as asked).
     */
    request({ reason, scopes, ttlMinutes }: {
        reason: any;
        scopes: any;
        ttlMinutes: any;
    }): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
        /**
         * The head this budget holds (hex): what the agent's next use ARMs over,
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last ticket's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their ticket (seqs) */
        pending(): any[];
        /**
         * One use: ARM over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason }?: {}): Promise<{
            result: any;
            purpose: any;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the ticket for a use; the new head is kept for the next use(). */
        ticket(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /** Revoke what is left. */
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
         * The head this budget holds (hex): what the agent's next use ARMs over,
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last ticket's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their ticket (seqs) */
        pending(): any[];
        /**
         * One use: ARM over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason }?: {}): Promise<{
            result: any;
            purpose: any;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the ticket for a use; the new head is kept for the next use(). */
        ticket(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /** Revoke what is left. */
        end(): Promise<void>;
    }>;
    /**
     * Register this agent's key with the app, under `name` - once, with a
     * press on the phone. -> {already} ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    register(name: any): Promise<{
        already: boolean;
    }>;
    /**
     * Pick up a budget another process asked for (with the same store). The
     * key's HEAD must still list it; the head to ARM over is read from the key.
     */
    resume(grantId: any): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
        /**
         * The head this budget holds (hex): what the agent's next use ARMs over,
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last ticket's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their ticket (seqs) */
        pending(): any[];
        /**
         * One use: ARM over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason }?: {}): Promise<{
            result: any;
            purpose: any;
            link: {
                seq: number;
                paid: boolean;
                paidBy: number | null;
                step: number | null;
                reveal: any;
            };
        }>;
        /** File the ticket for a use; the new head is kept for the next use(). */
        ticket(link: any, { code, message }: {
            code?: string | undefined;
            message: any;
        }): Promise<any>;
        /** Revoke what is left. */
        end(): Promise<void>;
    }>;
};
