export function createPointerStore(kv: any): {
    /**
     * The budget (its grant id, as the client gave it - a number) this computer holds on
     * that key, or null. Kept as JSON so the id comes back as it went in: stored as text,
     * "21" never matched the key's live budget 21 and a live budget read as gone
     * (Pixel, 2026-10-20).
     */
    budget(deviceId: any): Promise<any>;
    /** Remember it, or forget it (null). */
    setBudget(deviceId: any, grantId: any): Promise<void>;
};
/** For tests and for hosts with nothing else: a Map. */
export function memoryStore(): {
    getItem: (k: any) => any;
    setItem: (k: any, v: any) => void;
    removeItem: (k: any) => void;
};
