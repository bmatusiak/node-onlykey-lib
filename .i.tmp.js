const fs = require('fs');
const p = 'src/transport/index.js';
let t = fs.readFileSync(p, 'utf8');
const N = '\n';

const old = "'use strict';" + N + N + "module.exports = require('./contract');" + N;
if (!t.includes(old)) { console.error('MISS'); process.exit(1); }

const now = "'use strict';" + N + N +
"module.exports = {" + N +
"  ...require('./contract')," + N + N +
"  /*" + N +
"   * What the device looks like on a USB bus - the interface table, and how to" + N +
"   * tell interfaces apart that are identical in every other respect." + N +
"   *" + N +
"   * Namespaced rather than spread, because these are facts about ONE transport" + N +
"   * while the contract is the seam every transport meets. A host that never" + N +
"   * touches USB should not find `parseUsage` beside `assertTransport`." + N +
"   */" + N +
"  usb: require('./usbDescriptors')," + N +
"};" + N;

fs.writeFileSync(p, t.replace(old, now));
console.log('ok');
