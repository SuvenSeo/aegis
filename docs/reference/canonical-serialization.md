# Canonical Serialization Specification

Every signed or hashed Aegis object uses the same canonical JSON implementation.

## Rules

- Encode output as UTF-8.
- Sort object keys lexicographically at every depth.
- Preserve array order.
- Preserve explicit `null` values.
- Reject `undefined`, functions, symbols, big integers, non-plain objects, and cyclic references.
- Reject `NaN`, positive infinity, and negative infinity.
- Normalize `Date` values to UTC RFC 3339 with milliseconds, such as `2026-07-11T18:00:00.000Z`.
- Emit no insignificant whitespace.

## Digests

SHA-256 values use lowercase hexadecimal and the prefix:

```text
sha256:<64 lowercase hexadecimal characters>
```

## Signatures

The development implementation uses Ed25519 signatures over the exact UTF-8 canonical bytes. Signature strings use unpadded Base64url.

## Compatibility warning

Any change to canonical bytes changes digests, signatures, policy-version identifiers, approval validity, and audit-chain integrity. Golden fixtures must fail rather than update silently when byte output changes.
