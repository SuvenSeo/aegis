/**
 * STUB — not recovered. See RECOVERY_NOTES.md. Shape reconstructed from
 * apps/cli/src/index.ts usage and docs/reference/audit-chain.md. Every function
 * throws NotImplementedError.
 *
 * To make this real: for each event, validate schema, check for duplicate ids,
 * confirm sequence continuity from zero, confirm previous_event_hash matches the
 * prior event's recomputed canonical hash (null for the first event), recompute this
 * event's canonical hash, check the signer isn't revoked, verify its signature via
 * resolver.verify, and confirm non-decreasing timestamps. Return the first failing
 * index and a reason code, or valid:true with the total event count.
 */
export class NotImplementedError extends Error {
  constructor(fn: string) {
    super(
      `@aegis/audit#${fn} is not implemented — original source was lost to pack ` +
        "corruption during transfer. See docs/reference/audit-chain.md to reimplement.",
    );
    this.name = "NotImplementedError";
  }
}

export interface AuditKeyResolver {
  verify(signerId: string, value: unknown, signature: string): boolean;
  isRevoked(signerId: string): boolean;
}

export interface AuditVerification {
  readonly valid: boolean;
  readonly eventCount?: number;
  readonly index?: number;
  readonly code?: string;
}

export function verifyAuditChain(_events: unknown, _resolver: AuditKeyResolver): AuditVerification {
  throw new NotImplementedError("verifyAuditChain");
}
