# Approval Grant Format

A signed grant binds:

- schema version and grant identifier;
- organization and subject;
- action digest and target digest;
- canonical capability;
- narrowing constraints;
- issue and expiry timestamps;
- maximum uses and random nonce;
- issuer key identifier.

Verification validates the schema and signature before comparing organization, subject, action, target, capability, constraints, expiry, replay state, and usage budget. A grant may narrow a policy ceiling but cannot increase a numeric maximum, add members to an allowed set, or change an exact target.

A signature mutation or target substitution invalidates the grant. Consumers persist nonce usage; the Phase 1 library accepts usage state as an injected input rather than owning persistence.
