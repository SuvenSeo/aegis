import { sha256Digest } from "@aegis/crypto";

/**
 * Reimplementation of @aegis/audit, whose original source was lost to pack corruption
 * during transfer (see RECOVERY_NOTES.md). Built from docs/reference/audit-chain.md
 * ("Each event contains a zero-based sequence number, previous-event hash, canonical
 * event hash, event type, UTC timestamp, signer identifier, payload, and signature...
 * Verification checks schema, duplicate identifiers, sequence continuity, previous
 * hash, recomputed event hash, key revocation, signature, and timestamp ordering") and
 * the recovered apps/cli/src/index.ts / apps/cli/test/cli.integration.test.ts usage,
 * which this repo's original authors wrote as the acceptance test for this exact
 * behavior (a single-event chain verifies to exactly `{ valid: true, eventCount: 1 }`).
 */

export interface AuditSigner {
  readonly keyId: string;
  sign(value: unknown): string;
}

export interface AuditKeyResolver {
  verify(signerId: string, value: unknown, signature: string): boolean;
  isRevoked(signerId: string): boolean;
}

export interface AppendAuditEventInput {
  readonly eventId: string;
  readonly eventType: string;
  readonly occurredAt: Date;
  readonly payload: unknown;
}

export interface AuditEvent {
  readonly sequence: number;
  readonly previous_event_hash: string | null;
  readonly event_id: string;
  readonly event_type: string;
  readonly occurred_at: string;
  readonly signer_id: string;
  readonly payload: unknown;
  readonly event_hash: string;
  readonly signature: string;
}

export function appendAuditEvent(
  previous: AuditEvent | undefined,
  input: AppendAuditEventInput,
  signer: AuditSigner,
): AuditEvent {
  const unsigned = {
    sequence: previous ? previous.sequence + 1 : 0,
    previous_event_hash: previous ? previous.event_hash : null,
    event_id: input.eventId,
    event_type: input.eventType,
    occurred_at: input.occurredAt.toISOString(),
    signer_id: signer.keyId,
    payload: input.payload,
  };
  const eventHash = sha256Digest(unsigned);
  const withHash = { ...unsigned, event_hash: eventHash };
  const signature = signer.sign(withHash);
  return { ...withHash, signature };
}

export interface AuditVerification {
  readonly valid: boolean;
  readonly eventCount?: number;
  readonly index?: number;
  readonly code?: string;
}

function isAuditEventShape(value: unknown): value is AuditEvent {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.sequence === "number" &&
    (record.previous_event_hash === null || typeof record.previous_event_hash === "string") &&
    typeof record.event_id === "string" &&
    typeof record.event_type === "string" &&
    typeof record.occurred_at === "string" &&
    typeof record.signer_id === "string" &&
    "payload" in record &&
    typeof record.event_hash === "string" &&
    typeof record.signature === "string"
  );
}

export function verifyAuditChain(events: unknown, resolver: AuditKeyResolver): AuditVerification {
  if (!Array.isArray(events)) {
    return { valid: false, index: 0, code: "AUDIT_SCHEMA_INVALID" };
  }

  const seenIds = new Set<string>();
  let previousHash: string | null = null;
  let previousTimestampMs = Number.NEGATIVE_INFINITY;

  for (let index = 0; index < events.length; index += 1) {
    const event: unknown = events[index];
    if (!isAuditEventShape(event)) {
      return { valid: false, index, code: "AUDIT_SCHEMA_INVALID" };
    }
    if (event.sequence !== index) {
      return { valid: false, index, code: "SEQUENCE_DISCONTINUITY" };
    }
    if (seenIds.has(event.event_id)) {
      return { valid: false, index, code: "DUPLICATE_EVENT_ID" };
    }
    seenIds.add(event.event_id);

    if (event.previous_event_hash !== previousHash) {
      return { valid: false, index, code: "PREVIOUS_HASH_MISMATCH" };
    }

    const { event_hash: claimedHash, signature, ...unsigned } = event;
    const recomputedHash = sha256Digest(unsigned);
    if (recomputedHash !== claimedHash) {
      return { valid: false, index, code: "EVENT_HASH_MISMATCH" };
    }

    if (resolver.isRevoked(event.signer_id)) {
      return { valid: false, index, code: "SIGNER_REVOKED" };
    }

    const withHash = { ...unsigned, event_hash: claimedHash };
    if (!resolver.verify(event.signer_id, withHash, signature)) {
      return { valid: false, index, code: "SIGNATURE_INVALID" };
    }

    const occurredAtMs = Date.parse(event.occurred_at);
    if (Number.isNaN(occurredAtMs) || occurredAtMs < previousTimestampMs) {
      return { valid: false, index, code: "TIMESTAMP_OUT_OF_ORDER" };
    }
    previousTimestampMs = occurredAtMs;
    previousHash = claimedHash;
  }

  return { valid: true, eventCount: events.length };
}
