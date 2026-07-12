# Enforcement Foundation Architecture

## Boundary

Phase 1 is a pure, local library and CLI layer. It has no listening network socket, persistent database, provider API client, UI framework, or model SDK. Callers supply validated actions, policies, evaluation timestamps, and signing interfaces.

## Dependency direction

```text
schemas ───────────────┐
capabilities ───────┐  │
crypto ──────────┐  │  │
                 ▼  ▼  ▼
policy        decision
  │              │
  ├──────────────┘
  ├── approvals
  ├── audit
  └── CLI

redaction is independent
```

Dependencies remain acyclic. The CLI contains orchestration and file handling, not policy semantics.

## Evaluation flow

```text
policy YAML
  → YAML parse
  → strict schema validation
  → semantic validation
  → deterministic compilation

action JSON
  → strict schema validation
  → capability lookup
  → mandatory-evidence check
  → scoped rule matching
  → precedence reduction
  → decision result
```

The evaluator is a pure function of compiled policies, a validated action, the capability registry, and a caller-supplied timestamp.

## Trust classes

- **Provider verified:** facts confirmed by a later provider adapter.
- **Local observed:** facts measured by the future gateway.
- **Model derived:** advisory labels that cannot override deterministic policy.
- **Signed decision or grant:** data whose canonical bytes and signer are verified.
- **Untrusted input:** all policy YAML, action JSON, grant JSON, and audit JSON until validated.

## Error model

Library packages use stable machine-readable reason codes. The CLI maps validation failures to exit code `2`, denied policy simulations to `3`, cryptographic or audit verification failures to `4`, and unexpected internal failures to `70`.
