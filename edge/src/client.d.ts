export function createEdgeClient({ edge, channel, store, noteTimeoutMs }: {
    edge: any;
    channel: any;
    store?: null | undefined;
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
     * declined, timeout, copy_unverified, receipt_owed, restoring, invalid),
     * EEDGE_NO_ANSWER (dropped: not paired, replayed) or EEDGE_OPENING
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
         * The head this budget holds (hex): what the agent's next use TX starts over,
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last receipt's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason, intent }?: {
            intent?: any;
        }): Promise<{
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
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last receipt's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason, intent }?: {
            intent?: any;
        }): Promise<{
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
     * The phone's own name (its Bluetooth / Android device name) as it says it
     * - asked with a HAVE. A label,
     * never trusted: the person can rename it on each phone. -> string | null
     */
    phoneName(peerSigner: any, { deviceId, name }: {
        deviceId: any;
        name?: string | undefined;
    }): Promise<any>;
    /**
     * R30 (P2c): the phone's own copy of its chain, every record it holds -
     * GIVE, BATCH at a time. peerSigner: this computer's own sync key (copy.peerSigner).
     * -> [{link, head, reveal}] ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    copyFromPhone(peerSigner: any, { deviceId }: {
        deviceId: any;
    }): Promise<{
        link: Uint8Array<ArrayBuffer>;
        head: Uint8Array<ArrayBuffer>;
        reveal: Uint8Array<ArrayBuffer> | null;
    }[]>;
    /**
     * BLOCKS (BLOCKS.md §3, Brad 2026-10-07): the key's seals (the checkpoints that
     * close each block), as the phone keeps them - and the phone's own latest owner
     * statement (its nametag; 2026-10-08), so this computer can offer that phone's log to
     * your other devices. A phone that has no nametag yet gives none. A GIVE asked past the end: no links, just its last-batch fields.
     * Nothing is trusted here - each seal is checked against the key's own public
     * key when the blocks are built (block.verifyBlock).
     * -> {seals: [{seq, head, signature}], statement: {deviceId, publicKey, seq, nametag, signature} | null}
     */
    sealsFromPhone(peerSigner: any, { deviceId }: {
        deviceId: any;
    }): Promise<{
        seals: any;
        statement: {
            deviceId: Uint8Array<ArrayBuffer>;
            publicKey: Uint8Array<ArrayBuffer>;
            seq: any;
            nametag: string;
            signature: Uint8Array<ArrayBuffer>;
        } | null;
        openings: any;
        notes: {
            reasons: {};
            messages: {};
            seen: {};
        };
    }>;
    /**
     * OFFER ANOTHER DEVICE'S LOG (Brad, 2026-10-08: "if it has the private ecc key to sign
     * the block, then i want the log"): bring the phone whose key is `deviceId` the chain
     * `chain` (`records` up to that device's signed `checkpoint`) with its owner
     * `statement` - HAVE (what the phone holds of it), the LINKS it lacks, then OFFER. The
     * phone HOLDS it; the person approves the merge later from the Edge tab's banner.
     * -> {sent, held (true when the phone kept it), count}; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    offerToPhone(peerSigner: any, { deviceId, chain, records, checkpoint, statement, openings, notes, name }: {
        deviceId: any;
        chain: any;
        records: any;
        checkpoint: any;
        statement: any;
        openings?: never[] | undefined;
        notes?: null | undefined;
        name: any;
    }): Promise<{
        sent: any;
        held: boolean;
        count: any;
    }>;
    /**
     * okedge sync phase 2: bring the PHONE's copy of chain `deviceId` up to
     * date from `records` (this place's verified copy, [{link, head, reveal}])
     * and merge `keychain` (this place's public Key Chain list, entries) with
     * the phone's. Asks what the phone holds, sends only the links it lacks and
     * the whole list, in signed parts; COMMIT; TAKEs the merged list back. A Key Chain list that
     * would change the phone's is HELD there too (keychainHeld) - "Own links direct, Key Chain held". The links themselves are HELD on the phone until
     * the person approves them from the Edge tab's banner (Brad, 2026-10-08) - no key
     * press, no sync link. peerSigner: this computer's own sync key (copy.peerSigner).
     * -> {sent, seq (always null since 2026-10-08), count, keychainIn,
     *     keychainOut, keychainHeld, keychain (the merged list, or null)}
     * rejects EEDGE_REFUSED (declined, timeout, a fork - with the phone's words) or EEDGE_NO_ANSWER.
     */
    syncToPhone(peerSigner: any, { deviceId, records, name, keychain }: {
        deviceId: any;
        records: any;
        name: any;
        keychain?: null | undefined;
    }): Promise<{
        sent: number;
        seq: null;
        count: number;
        keychainIn: number;
        keychainOut: number;
        keychain: null;
        keychainHeld?: undefined;
    } | {
        sent: any;
        seq: any;
        count: any;
        keychainIn: any;
        keychainOut: any;
        keychainHeld: boolean;
        keychain: any;
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
         * and what `okedge exec --head` must name - proof the agent saw its own
         * last receipt's reply (mcp-service.md §4.2a).
         */
        head(): string;
        /** the uses still waiting for their receipt (seqs) */
        pending(): any[];
        /**
         * One use: TX start over the head this budget holds and SHA-256(bytes), run
         * op(bytes), and return the link it caused.
         * -> {result, link: {seq, paid, step, reveal}}
         */
        use(bytes: any, op: any, { reason, intent }?: {
            intent?: any;
        }): Promise<{
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
