# Aegis Roadmap

Aegis is built in layers. Phase 1 establishes deterministic contracts and local verification before any gateway, provider adapter, or hosted service is introduced.

## Phase 1: Deterministic local security core

Status: implemented.

- Versioned action-envelope schemas
- Capability registry and evidence requirements
- Policy parsing, validation, compilation, and evaluation
- Deterministic decision reduction
- Target-bound signed approval grants
- Tamper-evident audit-chain verification
- Canonical JSON and stable digests
- Secret redaction before evidence leaves process boundaries
- CLI for local validation and simulation
- Coverage and mutation gates

## Phase 2: Enforcement foundation

Status: next.

- Signed policy bundle format
- Policy bundle rollback protection model
- Provider evidence contract for GitHub, shell, filesystem, and deployment actions
- External nonce/usage store contract for approval replay protection
- Structured audit export format
- CLI explain mode for policy decisions
- Golden fixtures for cross-language implementers

## Phase 3: Gateway and adapters

Status: planned.

- Local enforcement gateway prototype
- Provider adapters for GitHub repository operations
- Shell/process adapter contract
- Filesystem adapter contract
- Deployment adapter contract
- Gateway-side audit signing
- Policy-distribution verification

## Phase 4: Operator and ecosystem polish

Status: planned.

- Published packages
- Signed release artifacts
- Reference integration examples
- Security benchmark suite
- Documentation site
- Migration guide for policy versions
- Compatibility matrix for schema versions

## Non-goals for Phase 1

- Hosted enforcement service
- Model-powered risk classifier
- Replacing IAM, branch protection, endpoint security, or provider logs
- Preventing a machine administrator from bypassing user-space enforcement
