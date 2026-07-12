# Aegis Phase 1 Threat Model

## Protected assets

- Policy integrity and deterministic meaning
- Repository and production-action intent
- Approval authority
- Action and target binding
- Audit evidence
- Secrets contained in commands, files, URLs, and records

## Trust boundaries

Policy, action, grant, and audit files are untrusted until runtime validation succeeds. Signing keys are supplied by the caller. Provider state is not available in Phase 1 and must later be verified by provider adapters. Model-derived labels are advisory and cannot change a deterministic deny into allow.

## Threats and controls

### Prompt injection

An agent may be induced to request a destructive operation. Canonical capabilities and deterministic policies govern the resulting tool call independently of prompt text.

### Target substitution

An attacker may approve one target and execute another. Approval signatures bind both action and target digests; mismatches fail verification.

### Approval replay

An attacker may reuse an approval. Grants include a nonce, maximum-use count, and expiry. Consumers inject persisted nonce and usage state during verification.

### Policy downgrade

An attacker may modify or replace policy content. Compiled policies include a source digest and version identifier. Future distribution layers must sign policy bundles and reject rollback.

### Audit mutation

An attacker may alter, remove, insert, duplicate, or reorder events. Sequence continuity, previous hashes, canonical event hashes, and signatures expose these attacks.

### Secret leakage

Inputs may contain credentials in headers, URLs, environment assignments, API tokens, private keys, or sensitive fields. Redaction occurs before summaries are returned; property tests assert that captured values do not appear in output metadata.

## Explicit limitations

Aegis Phase 1 does not provide host-level mandatory access control. A machine administrator can execute tools outside the Aegis process boundary.

Phase 1 does not replace IAM, branch protection, deployment protections, endpoint security, secret managers, or provider-side logs. It does not establish that locally asserted evidence is true. Later gateway and provider adapters must supply stronger interception and authoritative state.
