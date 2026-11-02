export function createRoomSync({ open, me, save, handleTrade, rules, randomBytes, selfId, answerMs, tell }: {
    open: any;
    me: any;
    save: any;
    handleTrade: any;
    rules: any;
    randomBytes: any;
    selfId?: (() => string) | undefined;
    answerMs?: number | undefined;
    tell?: {} | undefined;
}): {
    wire: (r: any, hooks: any, joinedAs: any) => void;
    changed: () => void;
    inQueue: (fn: any) => Promise<void>;
    rooms: () => Map<any, any>;
};
