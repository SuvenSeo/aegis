# Recovery notes

This repo previously held a broken transfer: an AI coding agent (git author
`OpenAI <noreply@openai.com>`) built "Aegis Phase 1" — a deterministic security core for
governing AI-agent actions (policy evaluation, signed approval grants, tamper-evident
audit chains, secret redaction) — on branch `feat/phase-1-foundation`, then tried to relay
it into this repo as a base64-chunked git bundle (under `.import/` and `.aegis-import/`).
Both chunked uploads were corrupted/incomplete; the original bytes are gone.

## What was recovered (original agent work, byte-for-byte)

- `README.md`, all of `docs/`, `.github/workflows/ci.yml`, lint/prettier config
- `apps/cli/src/index.ts`, `apps/cli/src/io.ts`, `apps/cli/test/*`, `apps/cli/tsconfig.json`
- `examples/actions/merge-main.json`, `examples/policies/production-code-guard.yaml`

Recovered by parsing the corrupted git pack byte-by-byte and pulling out every object
that decompressed cleanly before the corruption point (48 of 272 objects, corrupted
starting at a blob whose chunk — `.import/part-02` — was visibly short vs. its siblings).

## What was NOT recovered (lost for good)

- `packages/@aegis/{schemas,capabilities,crypto,policy,decision,approvals,audit,redaction,testkit}` —
  the actual security-engine implementations
- `tests/` (cross-package + mutation suite)
- root `package.json`, `package-lock.json`, `tsconfig.json`, `tsconfig.base.json`,
  `vitest.config.ts`, `stryker.config.json`, `apps/cli/package.json`

## What's scaffolded now (new code, written to make the repo install/build — NOT recovered, NOT audited)

To get `npm install` / `tsc -b` working again, the following were freshly written from the
recovered docs, the CLI's usage of each package, and the example fixtures — they are
reconstructions to spec, not the original implementation, and have not been reviewed or
tested against the (lost) golden fixtures:

- Root `package.json`, `tsconfig.base.json`, `tsconfig.json` (npm workspaces + TS project refs)
- `apps/cli/package.json`
- `packages/schemas` — **real, working** zod schemas for `ActionEnvelopeSchema` /
  `ApprovalGrantSchema`, built from `examples/actions/merge-main.json` and
  `docs/reference/approval-grants.md`
- `packages/crypto` — **real, working** canonical-JSON + SHA-256 digest + Ed25519
  `verifyCanonical`, implemented directly from `docs/reference/canonical-serialization.md`
- `packages/capabilities` — **real, working** capability registry (namespaces, risk
  class, offline eligibility, mandatory evidence, allowed constraints per
  `docs/reference/capabilities.md`). The specific capability table is a reasonable
  population consistent with the doc and the example fixtures, not recovered source —
  extend it as new capabilities are needed.
- `packages/policy` — **real, working** implementation: YAML parsing + schema/semantic
  validation (unique rule ids, known capabilities, approvals/constraints block
  requirements, expiry ≤ 24h) in `validatePolicyYaml`, deterministic compilation
  (source digest + policy-version id) in `compilePolicy`, and full rule matching +
  precedence reduction (deny > missing evidence > require_approval > narrowed
  allow_with_constraints > allow > default deny) in `evaluatePolicies`, built from
  `docs/reference/policy-language.md` and `docs/reference/decision-precedence.md`.
- `packages/approvals` — **real, working**: `issueApprovalGrant` and `verifyApprovalGrant`
  (signature verification, organization/subject/action/target/capability binding,
  expiry window, nonce replay protection, usage budget, constraint narrowing) per
  `docs/reference/approval-grants.md`.
- `packages/audit` — **real, working**: `appendAuditEvent` and `verifyAuditChain`
  (hash-chained events, signature verification, revocation, sequence continuity,
  timestamp ordering, tamper detection) per `docs/reference/audit-chain.md`.

**Verification**: the recovered `apps/cli/test/cli.integration.test.ts` — written by
this project's original authors as its own acceptance test — passes in full against
this reimplementation (`npm run verify`: typecheck + build + all 7 integration tests,
exit 0). That test exercises `policy validate`, `policy test`, `action validate`,
`simulate` (asserting the exact `require_approval` / `protect-main` outcome for the
example fixtures), `approval verify`, and `audit verify` end-to-end with real Ed25519
keys — nothing here is mocked out.

**Known gap**: `.github/workflows/ci.yml`'s `mutation` job runs `npm run test:mutation`
via Stryker, but `stryker.config.json` and the mutation test setup were not recoverable,
so that job (PR-triggered only, not push-triggered) will fail until mutation testing is
reintroduced. The `verify` job — typecheck, build, and the full integration suite — is
green.
