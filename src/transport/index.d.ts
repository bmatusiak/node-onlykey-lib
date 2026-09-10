declare const _exports: {
    usb: typeof import("./usbDescriptors");
    IFACE: {
        KEYBOARD: 0;
        FIDO: 1;
        VENDOR: 2;
        SEREMU: 3;
    };
    DIR: {
        OUT: 0;
        IN: 1;
    };
    REPORT_SIZE: 64;
    REQUIRED: string[];
    assertTransport: typeof import("./contract").assertTransport;
    stripPadding: typeof import("./contract").stripPadding;
    toReport: typeof import("./contract").toReport;
    withReportId: typeof import("./contract").withReportId;
};
export = _exports;
