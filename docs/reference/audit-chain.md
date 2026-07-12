# Audit Chain Format

Each event contains a zero-based sequence number, previous-event hash, canonical event hash, event type, UTC timestamp, signer identifier, payload, and signature.

The first event has `previous_event_hash: null`. Every subsequent event refers to the preceding event hash. Verification checks schema, duplicate identifiers, sequence continuity, previous hash, recomputed event hash, key revocation, signature, and timestamp ordering.

The verifier detects mutation, deletion, insertion, duplication, and reordering. Verification is descriptive only and never re-executes an action.
