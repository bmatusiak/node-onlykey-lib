declare const _exports: {
    rules: typeof import("./rules");
    FORMAT: "onlykey-bucket";
    SEALED_FORMAT: "onlykey-bucket-sealed";
    VERSION: 1;
    create: typeof import("./bucket").create;
    kv: typeof import("./bucket").kv;
    serialize: typeof import("./bucket").serialize;
    parse: typeof import("./bucket").parse;
    seal: typeof import("./bucket").seal;
    open: typeof import("./bucket").open;
    mergeKeys: typeof import("./bucket").mergeKeys;
    merge: typeof import("./bucket").merge;
    resolve: typeof import("./bucket").resolve;
};
export = _exports;
