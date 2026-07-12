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
- `packages/policy`, `packages/approvals`, `packages/audit` — **stubs only**. Correctly
  typed (matching `apps/cli/src/index.ts` usage exactly) so the workspace type-checks and
  builds, but every exported function throws `NotImplementedError` at runtime. Each
  package's `src/index.ts` has a header comment describing what real implementation
  would need to do, sourced from the matching `docs/reference/*.md` file.

**Bottom line**: this repo now installs and type-checks, and the CLI's schema validation
and signature-verification primitives are real. Policy evaluation, approval-grant
verification, and audit-chain verification are not — those are the next things to build,
and `docs/reference/policy-language.md`, `decision-precedence.md`, `approval-grants.md`,
and `audit-chain.md` are the closest thing to a spec for them.
