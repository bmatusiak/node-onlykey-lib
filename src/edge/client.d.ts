export function createEdgeClient({ edge, channel, signer, store }: {
    edge: any;
    channel: any;
    signer: any;
    store?: null | undefined;
}): {
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, ticket_owed, restoring, invalid) or
     * EEDGE_OPENING (the answer is not a budget the key opened as asked).
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
     * Pick up a budget another process asked for (with the same store). The
     * key's HEAD must still list it; the head to ARM over is read from the key.
     */
    resume(grantId: any): Promise<{
        grantId: any;
        uses: any;
        reason: any;
        scopes: any;
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
