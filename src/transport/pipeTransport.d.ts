/**
 * Build a transport over a byte pipe.
 *
 * @param {object} opts
 * @param {string} opts.name          the transport's name, and the plugin's, for errors
 * @param {object} opts.pipe          the host's byte pipe (contract above)
 * @param {Function} opts.EventEmitter the host's EventEmitter class
 * @returns {{ transport: object, destroy: () => Promise<void> }}
 */
export function createPipeTransport({ name, pipe, EventEmitter }: {
    name: string;
    pipe: object;
    EventEmitter: Function;
}): {
    transport: object;
    destroy: () => Promise<void>;
};
