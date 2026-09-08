# A locked device is silent to OKGETLABELS, though its source says it refuses

**Severity:** low (diagnosability, not correctness)
**Status:** measured on device; worked around in the library
**Applies to:** `libraries/onlykey/okcore.cpp:379-396`

## What the source says

```c
case OKGETLABELS:
    if (initialized == false && unlocked == true) {
        hidprint("Error OnlyKey must be initialized first");
        return;
    }
    else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2) {
        ...get_slot_labels(2);
    }
    else {
        hidprint("Error device locked");
        return;
    }
```

A locked device should answer `"Error device locked"`. The configmode filter
directly above it (`:347`) explicitly permits `OKGETLABELS`, so the case is
reachable.

## What actually happens

It answers nothing. Probed on a Samsung SM-S136DL running the emulated
firmware, freshly booted and locked: `OKGETLABELS` written to the vendor
interface, four seconds of capture.

```
vendor reports while locked: 5
["494e495449414c495a4544...", x5]
```

All five are `INITIALIZED` — the once-a-second `Task taskInitialized`
broadcast (`OnlyKey.ino:213`). The refusal never reaches the wire.

I did not chase which condition diverts it; the point for a client is that the
refusal cannot be relied on.

## Why it matters

From the host, "the device is locked" and "the device is not listening" become
indistinguishable: both are a timeout. That is the difference between telling a
user to enter their PIN and telling them something is broken.

It also makes the obvious client implementation wrong in a way that reads as
correct — waiting for the documented error is waiting for something that never
comes.

## What this library does

`LabelReader` counts status broadcasts, and `readLabels`'s timeout says so when
they were the only thing that arrived:

```
label read timed out after 4000ms - the device sent only status broadcasts (4),
so it is probably locked; call unlock() first
```

Inferred rather than reported, which is the best available: the broadcast is
the one thing a locked device reliably says.

## Suggested firmware follow-up

Make the refusal actually reach the wire, or document that it does not. A host
cannot tell a locked device from a dead one, and the source currently suggests
it can.
