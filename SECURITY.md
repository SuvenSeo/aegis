# Security Policy

Aegis is a security-sensitive project. Changes to canonical serialization, policy evaluation, approval verification, audit-chain verification, redaction, and CLI output should be treated as security-relevant by default.

## Supported versions

Aegis is currently pre-1.0. Until the first tagged release, the `main` branch is the only supported development line.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Preferred process:

1. Create a private advisory if GitHub security advisories are enabled for the repository.
2. If advisories are not available, contact the repository owner privately.
3. Include reproduction steps, affected package(s), expected impact, and any proof-of-concept input files.

## Security-sensitive areas

Treat the following as high-risk code paths:

- Canonical JSON and digest generation
- Capability normalization and unknown-capability handling
- Policy precedence and narrowing-constraint logic
- Approval grant signature verification
- Nonce, expiry, and usage-limit enforcement
- Audit event hash/signature verification
- Audit sequence continuity checks
- Redaction patterns and diagnostic metadata
- CLI JSON output consumed by automation

## Disclosure expectations

A good report should include:

- A minimal policy/action/grant/audit input that reproduces the issue
- The expected safe result
- The actual unsafe result
- Whether the issue can change deny to allow, bypass approval, hide audit tampering, leak secrets, or break deterministic replay

## Security gates

Before merging security-sensitive changes:

- [ ] `npm run verify`
- [ ] `npm run test:mutation`
- [ ] New regression tests for the issue or invariant
- [ ] Review of docs and CLI behavior if user-visible output changed
