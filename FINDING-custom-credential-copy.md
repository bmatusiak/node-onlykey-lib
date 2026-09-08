# The custom-credential path copies 256 bytes into a 70-byte member

**Severity:** low (data corruption, not memory-unsafety — see the bound below)
**Status:** reported only; firmware is read-only in this project
**Applies to:** `libraries/fido2/ctap_parse.cpp:929-948`, in a block marked
`// OnlyKey required change`

## What it does

When an allowList credential is neither 48 bytes (a U2F key handle) nor 70
(`sizeof(CredentialId)`), it is treated as a custom credential — the path the
OnlyKey vendor tunnel arrives on. That branch copies the credential twice:

```c
    else if (buflen != sizeof(CredentialId))
    {
        cred->type = PUB_KEY_CRED_CUSTOM;
        buflen = 256;
    	// OnlyKey required change start
        ret = cbor_value_copy_byte_string(&val, (uint8_t*)&cred->credential.id, &buflen, NULL);
        getAssertionState.customCredIdSize = buflen;
        // OnlyKey required change end
        ret = cbor_value_copy_byte_string(&val, getAssertionState.customCredId, &buflen, NULL);
        getAssertionState.customCredIdSize = buflen;
    }
```

The **second** copy is the correct one: `customCredId` is declared
`uint8_t customCredId[256]` (`ctap.h:395`), which is what the 256 was sized for,
and it is the buffer `is_extension_request()` and `bridge_to_onlykey()` actually
read.

The **first** copy writes the same up-to-256 bytes into `cred->credential.id`,
which is a `CredentialId` — 16 tag + 18 nonce + 32 rpIdHash + 4 count = **70
bytes**. It is redundant, and it writes up to 186 bytes past that member.

## How far it actually reaches

Worth stating precisely, because the obvious reading is worse than the truth.

`cred->credential` is a `struct Credential { CredentialId id; CTAP_userEntity
user; }`, and `CTAP_userEntity` is `id[64] + id_size + name[65] +
displayName[64] + icon[128]` = **322 bytes** (`ctap.h`, with `USER_ID_MAX_SIZE`,
`USER_NAME_LIMIT`, `DISPLAY_NAME_LIMIT`, `ICON_LIMIT`).

So the 186 bytes of overflow land entirely inside `credential.user`, which has
322 bytes to absorb them. It does **not** run past the end of the descriptor,
and it does **not** reach the next element of `GA.creds[ALLOW_LIST_MAX_SIZE]`.

This is therefore data corruption contained within one struct, not a
memory-safety defect. I checked because the first reading of it was that this
was an out-of-bounds write into the credential array, and that is not what the
sizes say.

## Why it still matters

The user entity it overwrites is not scratch space — it is parsed from the
request and used when building the assertion response. Every custom credential,
which includes every OnlyKey vendor tunnel request, silently clobbers it with
credential bytes.

It goes unnoticed because the tunnel path short-circuits before the user entity
is used for anything (`ctap.cpp:1949-1957` sets flags and skips real signing),
so the corrupted field never reaches an output today.

## Suggested fix

Delete the first copy. The second one already writes the same bytes to the
correctly-sized buffer and sets `customCredIdSize` identically, so removing the
OnlyKey-added lines changes nothing except that `credential.id` and
`credential.user` stop being overwritten.
