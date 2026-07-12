# Aegis

[![CI](https://github.com/SuvenSeo/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/SuvenSeo/aegis/actions/workflows/ci.yml)

Aegis Phase 1 is a deterministic, offline-first security core for governing AI-agent actions. It validates canonical action envelopes, compiles versioned policies, produces reproducible allow/deny/approval decisions, verifies signed approval grants, detects audit-chain tampering, and redacts secrets before evidence leaves a local process.

Phase 1 is deliberately **not** a hosted service, MCP proxy, shell interceptor, GitHub App, deployment adapter, database, dashboard, or model-powered risk classifier. Those components build on the contracts established here.

## Current status

| Area | Status |
|---|---|
| Canonical action envelopes | Implemented |
| Policy validation and compilation | Implemented |
| Deterministic decision reduction | Implemented |
| Signed approval verification | Implemented |
| Tamper-evident audit chain verification | Implemented |
| Secret redaction | Implemented |
| CLI | Implemented |
| Hosted enforcement gateway | Future phase |
| Provider adapters | Future phase |

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Install and verify

```bash
npm ci
npm run verify
```

Run the mutation gate separately:

```bash
npm run test:mutation
```

The verification gate enforces at least 90% statements, branches, functions, and lines across the production security packages. Approval-grant verification and decision reduction must each retain 100% branch coverage. Mutation testing must remain at or above 80%.

## CLI examples

Build before invoking the CLI directly:

```bash
npm run build
```

Validate a policy:

```bash
node apps/cli/dist/index.js policy validate examples/policies/production-code-guard.yaml --json
```

Run static policy checks:

```bash
node apps/cli/dist/index.js policy test examples/policies/production-code-guard.yaml --json
```

Validate an action envelope:

```bash
node apps/cli/dist/index.js action validate examples/actions/merge-main.json --json
```

Simulate a decision at an explicit timestamp:

```bash
node apps/cli/dist/index.js simulate \
  --policy examples/policies/production-code-guard.yaml \
  --action examples/actions/merge-main.json \
  --at 2026-07-11T18:00:00.000Z \
  --json
```

Verify an approval grant:

```bash
node apps/cli/dist/index.js approval verify grant.json --public-key approver-public.pem --json
```

Verify an audit chain:

```bash
node apps/cli/dist/index.js audit verify events.json --keys public-keys.json --json
```

The key file format is:

```json
{
  "keys": {
    "gateway-key-1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  },
  "revoked": []
}
```

## Package map

| Package | Responsibility |
|---|---|
| `@aegis/schemas` | Strict versioned runtime contracts |
| `@aegis/capabilities` | Canonical capabilities and evidence requirements |
| `@aegis/crypto` | Canonical JSON, SHA-256, and Ed25519 helpers |
| `@aegis/policy` | YAML parsing, validation, compilation, and evaluation |
| `@aegis/decision` | Precedence and narrowing-constraint reduction |
| `@aegis/approvals` | Target-bound signed approval grants |
| `@aegis/audit` | Signed tamper-evident event chains |
| `@aegis/redaction` | Deterministic secret-safe summaries |
| `@aegis/testkit` | Cross-package fixture builders for tests |
| `@aegis/cli` | Local command-line interface |

## Security guarantees

- Unknown capabilities fail closed.
- Explicit deny outranks every lower-precedence policy effect.
- Missing mandatory evidence cannot produce allow.
- Approval signatures bind organization, subject, action, target, capability, constraints, time, nonce, and usage limit.
- Audit mutation, deletion, insertion, duplication, and reordering are detectable.
- Canonical bytes are stable for a fixed input and evaluation timestamp.
- Supported secret patterns are removed from returned values and diagnostic metadata.

## Security limitations

Aegis Phase 1 operates inside a user-space process. It does not prevent a machine administrator from bypassing Aegis and invoking a provider or executable directly. It does not replace branch protection, IAM, secret managers, endpoint security, or provider-side audit logs. It provides deterministic contracts and evidence for later enforcement layers.

## Recommended repository controls

- Require CI before merge.
- Require mutation testing for security-sensitive PRs.
- Keep dependency updates separate from behavioral changes.
- Review changes to canonical serialization, approval verification, audit verification, redaction, and policy precedence as security-sensitive.
- Use signed releases once packages are published.

## Documentation

- [Enforcement architecture](docs/architecture/enforcement-foundation.md)
- [Policy language](docs/reference/policy-language.md)
- [Capability registry](docs/reference/capabilities.md)
- [Decision precedence](docs/reference/decision-precedence.md)
- [Canonical serialization](docs/reference/canonical-serialization.md)
- [Approval grants](docs/reference/approval-grants.md)
- [Audit chains](docs/reference/audit-chain.md)
- [Threat model](docs/security/threat-model.md)
- [Roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Security policy](SECURITY.md)
