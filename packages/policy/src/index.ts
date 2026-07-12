import type { ActionEnvelope } from "@aegis/schemas";

/**
 * STUB — not recovered.
 *
 * The pack transfer that brought this repo out of its sandbox broke partway through
 * (see RECOVERY_NOTES.md at the repo root), and @aegis/policy's real implementation —
 * policy compilation, semantic/capability/constraint checks, and deterministic
 * precedence evaluation — was never written to GitHub. Only the public shape (inferred
 * from apps/cli/src/index.ts and docs/reference/policy-language.md +
 * docs/reference/decision-precedence.md) is reconstructed here so the workspace
 * type-checks and builds. Every function throws NotImplementedError at runtime.
 *
 * To make this real: implement YAML parsing + schema/semantic/capability/constraint
 * validation in validatePolicyYaml, deterministic compilation (source digest +
 * policy-version id via @aegis/crypto) in compilePolicy, and precedence-based
 * evaluation (explicit deny > require_approval > allow, unknown capability => deny)
 * in evaluatePolicies, per docs/reference/decision-precedence.md.
 */
export class NotImplementedError extends Error {
  constructor(fn: string) {
    super(
      `@aegis/policy#${fn} is not implemented — original source was lost to pack ` +
        "corruption during transfer. See docs/reference/policy-language.md and " +
        "docs/reference/decision-precedence.md to reimplement.",
    );
    this.name = "NotImplementedError";
  }
}

export interface CompiledPolicy {
  readonly name: string;
  readonly version: number;
  readonly policyVersionId: string;
  readonly sourceDigest: string;
}

export interface PolicyValidationResult {
  readonly ok: boolean;
  readonly document?: unknown;
  readonly errors?: readonly unknown[];
  readonly warnings: readonly string[];
}

export interface EvaluatePoliciesInput {
  readonly policies: readonly CompiledPolicy[];
  readonly action: ActionEnvelope;
  readonly at: Date;
}

export interface Decision {
  readonly outcome: "allow" | "deny" | "require_approval";
  readonly reason_codes: readonly string[];
}

export function validatePolicyYaml(_source: string): PolicyValidationResult {
  throw new NotImplementedError("validatePolicyYaml");
}

export function compilePolicy(_document: unknown): CompiledPolicy {
  throw new NotImplementedError("compilePolicy");
}

export function evaluatePolicies(_input: EvaluatePoliciesInput): Decision {
  throw new NotImplementedError("evaluatePolicies");
}
