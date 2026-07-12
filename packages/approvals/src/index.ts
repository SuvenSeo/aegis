import type { ApprovalGrant } from "@aegis/schemas";

/**
 * STUB — not recovered. See RECOVERY_NOTES.md and @aegis/policy's index.ts header for
 * context: the pack transfer broke before @aegis/approvals' real implementation
 * reached GitHub. Shape reconstructed from apps/cli/src/index.ts usage and
 * docs/reference/approval-grants.md. Every function throws NotImplementedError.
 *
 * To make this real: verify the grant's signature via verifier.verify against its
 * canonical bytes, then check organization/subject/action-digest/target-digest/
 * capability match, that requestedConstraints narrow (never widen) the grant's
 * constraints, that `at` falls within [issued_at, expires_at), that the nonce is not
 * in usedNonces, and that usedCount < max_uses.
 */
export class NotImplementedError extends Error {
  constructor(fn: string) {
    super(
      `@aegis/approvals#${fn} is not implemented — original source was lost to pack ` +
        "corruption during transfer. See docs/reference/approval-grants.md to reimplement.",
    );
    this.name = "NotImplementedError";
  }
}

export interface ApprovalVerifier {
  verify(value: unknown, signature: string): boolean;
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

export function verifyApprovalGrant(_input: VerifyApprovalGrantInput): ApprovalVerification {
  throw new NotImplementedError("verifyApprovalGrant");
}
