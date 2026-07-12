import { ApprovalGrantSchema, type ApprovalGrant } from "@aegis/schemas";

/**
 * Reimplementation of @aegis/approvals, whose original source was lost to pack
 * corruption during transfer (see RECOVERY_NOTES.md). Built from
 * docs/reference/approval-grants.md ("A grant may narrow a policy ceiling but cannot
 * increase a numeric maximum, add members to an allowed set, or change an exact
 * target... Consumers persist nonce usage; the Phase 1 library accepts usage state as
 * an injected input rather than owning persistence") and the recovered
 * apps/cli/src/index.ts / apps/cli/test/cli.integration.test.ts usage, which this
 * repo's original authors wrote as the acceptance test for this exact behavior.
 */

export interface ApprovalSigner {
  readonly keyId: string;
  randomNonce(): string;
  sign(value: unknown): string;
}

export interface ApprovalVerifier {
  verify(value: unknown, signature: string): boolean;
}

export interface IssueApprovalGrantInput {
  readonly grantId: string;
  readonly organizationId: string;
  readonly subjectId: string;
  readonly actionDigest: string;
  readonly targetDigest: string;
  readonly capability: string;
  readonly constraints: Readonly<Record<string, unknown>>;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly maxUses: number;
}

export function issueApprovalGrant(
  input: IssueApprovalGrantInput,
  signer: ApprovalSigner,
): ApprovalGrant {
  const unsigned = {
    schema_version: "1.0",
    grant_id: input.grantId,
    organization_id: input.organizationId,
    subject_id: input.subjectId,
    action_digest: input.actionDigest,
    target_digest: input.targetDigest,
    capability: input.capability,
    constraints: input.constraints,
    issued_at: input.issuedAt.toISOString(),
    expires_at: input.expiresAt.toISOString(),
    max_uses: input.maxUses,
    nonce: signer.randomNonce(),
    issuer_key_id: signer.keyId,
  };
  const signature = signer.sign(unsigned);
  return ApprovalGrantSchema.parse({ ...unsigned, signature });
}

export interface VerifyApprovalGrantInput {
  readonly grant: ApprovalGrant;
  readonly verifier: ApprovalVerifier;
  readonly organizationId: string;
  readonly subjectId: string;
  readonly actionDigest: string;
  readonly targetDigest: string;
  readonly capability: string;
  readonly requestedConstraints: Readonly<Record<string, unknown>>;
  readonly at: Date;
  readonly usedNonces: ReadonlySet<string>;
  readonly usedCount: number;
}

export interface ApprovalVerification {
  readonly valid: boolean;
  readonly code?: string;
}

function constraintsAreNarrowed(
  requested: Readonly<Record<string, unknown>>,
  granted: Readonly<Record<string, unknown>>,
): boolean {
  for (const [key, requestedValue] of Object.entries(requested)) {
    if (!(key in granted)) return false;
    const grantedValue = granted[key];

    if (typeof requestedValue === "number" && typeof grantedValue === "number") {
      if (requestedValue > grantedValue) return false;
      continue;
    }
    if (Array.isArray(requestedValue) && Array.isArray(grantedValue)) {
      if (!requestedValue.every((item) => grantedValue.includes(item))) return false;
      continue;
    }
    if (requestedValue !== grantedValue) return false;
  }
  return true;
}

export function verifyApprovalGrant(input: VerifyApprovalGrantInput): ApprovalVerification {
  const { grant } = input;
  const { signature, ...unsigned } = grant;

  if (!input.verifier.verify(unsigned, signature)) {
    return { valid: false, code: "SIGNATURE_INVALID" };
  }
  if (grant.organization_id !== input.organizationId) {
    return { valid: false, code: "ORGANIZATION_MISMATCH" };
  }
  if (grant.subject_id !== input.subjectId) {
    return { valid: false, code: "SUBJECT_MISMATCH" };
  }
  if (grant.action_digest !== input.actionDigest) {
    return { valid: false, code: "ACTION_MISMATCH" };
  }
  if (grant.target_digest !== input.targetDigest) {
    return { valid: false, code: "TARGET_MISMATCH" };
  }
  if (grant.capability !== input.capability) {
    return { valid: false, code: "CAPABILITY_MISMATCH" };
  }

  const issuedAtMs = Date.parse(grant.issued_at);
  const expiresAtMs = Date.parse(grant.expires_at);
  if (input.at.getTime() < issuedAtMs) {
    return { valid: false, code: "GRANT_NOT_YET_VALID" };
  }
  if (input.at.getTime() >= expiresAtMs) {
    return { valid: false, code: "GRANT_EXPIRED" };
  }

  if (input.usedNonces.has(grant.nonce)) {
    return { valid: false, code: "NONCE_REUSED" };
  }
  if (input.usedCount >= grant.max_uses) {
    return { valid: false, code: "USAGE_LIMIT_EXCEEDED" };
  }

  if (!constraintsAreNarrowed(input.requestedConstraints, grant.constraints)) {
    return { valid: false, code: "CONSTRAINT_NOT_NARROWED" };
  }

  return { valid: true };
}
