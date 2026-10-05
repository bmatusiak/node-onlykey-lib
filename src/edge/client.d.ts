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
        end: () => Promise<void>;
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
        end: () => Promise<void>;
    }>;
    /**
     * Register this agent's key with the app, under `name` - once, with a
     * press on the phone. -> {already} ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    register(name: any): Promise<{
        already: boolean;
    }>;
    /**
     * R20: ask the phone to add a place that keeps copies (this PC's copy
     * store) as a known peer of the key - the person's Yes, then a press.
     * peerSigner: request.peerSignerFromSecret(the place's own P-256 secret),
     * not this agent's key. -> {already, seq?, index}; rejects EEDGE_REFUSED or
     * EEDGE_NO_ANSWER.
     */
    peerAdd(peerSigner: any, name: any): Promise<{
        already: boolean;
        seq: any;
        index: any;
    }>;
    /**
     * R29 (P2b): ask the phone whose key is `deviceId` to pair it with the
     * key `key` (X || Y; its id is derived) - the code on its sheet, Yes, a
     * press. peerSigner: this place's own key (on that key's list). The caller
     * asks the OTHER phone the same, the other way round.
     * -> {already, seq?, index?}; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    siblingAdd(peerSigner: any, { deviceId, key, name }: {
        deviceId: any;
        key: any;
        name: any;
    }): Promise<{
        already: boolean;
        seq: any;
        index: any;
    }>;
    /**
     * okedge sync phase 2: bring the PHONE's copy of chain `deviceId` up to
     * date from `records` (this place's verified copy, [{link, head, reveal}])
     * and merge `keychain` (this place's public Key Chain list, entries) with
     * the phone's. Asks what the phone holds, sends only the links it lacks and
     * the whole list, in signed parts; COMMIT brings up ONE sheet on the phone;
     * after its Yes and press, TAKEs the merged list back. peerSigner: this
     * place's own key (on the key's list).
     * -> {sent, seq (the sync link, or null when nothing moved), count, keychainIn,
     *     keychainOut, keychain (the merged list, or null)}
     * rejects EEDGE_REFUSED (declined, timeout, a fork - with the phone's words) or EEDGE_NO_ANSWER.
     */
    syncToPhone(peerSigner: any, { deviceId, records, name, keychain }: {
        deviceId: any;
        records: any;
        name: any;
        keychain?: null | undefined;
    }): Promise<{
        sent: any;
        seq: any;
        count: any;
        keychainIn: any;
        keychainOut: any;
        keychain: any;
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
        end: () => Promise<void>;
    }>;
};
