import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256Digest, signCanonical, verifyCanonical } from "@aegis/crypto";
import { appendAuditEvent, verifyAuditChain, type AuditEvent, type AuditSigner } from "../src/index.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");

const signer: AuditSigner = { keyId: "signer-1", sign: (value) => signCanonical(value, privateKey) };

function resolver(overrides: { revoked?: readonly string[] } = {}) {
  const revoked = new Set(overrides.revoked ?? []);
  return {
    verify: (signerId: string, value: unknown, signature: string) =>
      signerId === "signer-1" && verifyCanonical(value, signature, publicKey),
    isRevoked: (signerId: string) => revoked.has(signerId),
  };
}

function chainOfTwo(): AuditEvent[] {
  const first = appendAuditEvent(
    undefined,
    { eventId: "evt_1", eventType: "approval.resolved", occurredAt: new Date("2026-07-11T18:00:00.000Z"), payload: { a: 1 } },
    signer,
  );
  const second = appendAuditEvent(
    first,
    { eventId: "evt_2", eventType: "approval.resolved", occurredAt: new Date("2026-07-11T18:01:00.000Z"), payload: { a: 2 } },
    signer,
  );
  return [first, second];
}

describe("appendAuditEvent / verifyAuditChain", () => {
  it("verifies a single-event chain to exactly {valid:true, eventCount:1}", () => {
    const [first] = chainOfTwo();
    expect(verifyAuditChain([first], resolver())).toEqual({ valid: true, eventCount: 1 });
  });

  it("verifies a multi-event chain", () => {
    const events = chainOfTwo();
    expect(verifyAuditChain(events, resolver())).toEqual({ valid: true, eventCount: 2 });
  });

  it("assigns sequence 0 with a null previous_event_hash to the first event", () => {
    const [first] = chainOfTwo();
    expect(first.sequence).toBe(0);
    expect(first.previous_event_hash).toBeNull();
  });

  it("assigns sequence 1 to a second appended event", () => {
    const [, second] = chainOfTwo();
    expect(second.sequence).toBe(1);
  });

  it("chains previous_event_hash to the prior event's hash", () => {
    const [first, second] = chainOfTwo();
    expect(second.previous_event_hash).toBe(first.event_hash);
  });

  it("rejects a non-array input", () => {
    expect(verifyAuditChain({ not: "an array" }, resolver())).toEqual({
      valid: false,
      index: 0,
      code: "AUDIT_SCHEMA_INVALID",
    });
  });

  it("rejects an empty array as vacuously valid with zero events", () => {
    expect(verifyAuditChain([], resolver())).toEqual({ valid: true, eventCount: 0 });
  });

  it("rejects a malformed event", () => {
    expect(verifyAuditChain([{ nope: true }], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "AUDIT_SCHEMA_INVALID",
    });
  });

  it("rejects a null event entry", () => {
    expect(verifyAuditChain([null], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "AUDIT_SCHEMA_INVALID",
    });
  });

  it("rejects a non-object event entry", () => {
    expect(verifyAuditChain(["not-an-event"], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "AUDIT_SCHEMA_INVALID",
    });
  });

  describe("isAuditEventShape field-by-field validation", () => {
    // Each case takes an otherwise-valid event and corrupts exactly one field, to
    // pin down every clause of the shape check independently.
    const fieldCases: Array<[string, (event: AuditEvent) => unknown]> = [
      ["sequence", (event) => ({ ...event, sequence: "0" })],
      ["previous_event_hash", (event) => ({ ...event, previous_event_hash: 123 })],
      ["event_id", (event) => ({ ...event, event_id: 42 })],
      ["event_type", (event) => ({ ...event, event_type: 42 })],
      ["occurred_at", (event) => ({ ...event, occurred_at: 42 })],
      ["signer_id", (event) => ({ ...event, signer_id: 42 })],
      ["payload", (event) => { const { payload: _payload, ...rest } = event; return rest; }],
      ["event_hash", (event) => ({ ...event, event_hash: 42 })],
      ["signature", (event) => ({ ...event, signature: 42 })],
    ];

    for (const [field, corrupt] of fieldCases) {
      it(`rejects an event with a wrong-typed/missing ${field}`, () => {
        const [valid] = chainOfTwo();
        expect(verifyAuditChain([corrupt(valid)], resolver())).toEqual({
          valid: false,
          index: 0,
          code: "AUDIT_SCHEMA_INVALID",
        });
      });
    }

    it("accepts a non-null string previous_event_hash on a first event only if it matches null-chain expectations", () => {
      // Sanity check that the shape guard itself accepts a string previous_event_hash
      // (the chain-continuity check, not the shape check, is what rejects a first
      // event with a non-null previous_event_hash).
      const [first] = chainOfTwo();
      const withStringHash = { ...first, previous_event_hash: "sha256:" + "0".repeat(64) };
      expect(verifyAuditChain([withStringHash], resolver())).toEqual({
        valid: false,
        index: 0,
        code: "PREVIOUS_HASH_MISMATCH",
      });
    });
  });

  it("detects a sequence discontinuity", () => {
    const events = chainOfTwo();
    const broken = [{ ...events[0], sequence: 5 }];
    expect(verifyAuditChain(broken, resolver())).toEqual({
      valid: false,
      index: 0,
      code: "SEQUENCE_DISCONTINUITY",
    });
  });

  it("detects a duplicate event id", () => {
    const [first] = chainOfTwo();
    const second = appendAuditEvent(
      first,
      { eventId: "evt_1", eventType: "x", occurredAt: new Date("2026-07-11T18:01:00.000Z"), payload: {} },
      signer,
    );
    expect(verifyAuditChain([first, second], resolver())).toEqual({
      valid: false,
      index: 1,
      code: "DUPLICATE_EVENT_ID",
    });
  });

  it("detects a previous-hash mismatch (deleted/reordered event)", () => {
    const events = chainOfTwo();
    const rewritten = { ...events[1], previous_event_hash: "sha256:" + "0".repeat(64) };
    expect(verifyAuditChain([events[0], rewritten], resolver())).toEqual({
      valid: false,
      index: 1,
      code: "PREVIOUS_HASH_MISMATCH",
    });
  });

  it("detects payload tampering via the recomputed event hash", () => {
    const [first] = chainOfTwo();
    const tampered = { ...first, payload: { a: 999 } };
    expect(verifyAuditChain([tampered], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "EVENT_HASH_MISMATCH",
    });
  });

  it("rejects a revoked signer", () => {
    const [first] = chainOfTwo();
    expect(verifyAuditChain([first], resolver({ revoked: ["signer-1"] }))).toEqual({
      valid: false,
      index: 0,
      code: "SIGNER_REVOKED",
    });
  });

  it("does not reject a signer that is not on the revocation list", () => {
    const [first] = chainOfTwo();
    expect(verifyAuditChain([first], resolver({ revoked: ["some-other-signer"] }))).toEqual({
      valid: true,
      eventCount: 1,
    });
  });

  it("rejects an invalid signature", () => {
    const [first] = chainOfTwo();
    const wrongSigner = { ...first, signature: signCanonical({ x: 1 }, otherKey.privateKey) };
    expect(verifyAuditChain([wrongSigner], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "SIGNATURE_INVALID",
    });
  });

  it("rejects a signer id the resolver does not recognize", () => {
    const [first] = chainOfTwo();
    const unrecognizing = { verify: () => false, isRevoked: () => false };
    expect(verifyAuditChain([first], unrecognizing)).toEqual({
      valid: false,
      index: 0,
      code: "SIGNATURE_INVALID",
    });
  });

  it("rejects out-of-order timestamps", () => {
    const first = appendAuditEvent(
      undefined,
      { eventId: "evt_1", eventType: "x", occurredAt: new Date("2026-07-11T18:05:00.000Z"), payload: {} },
      signer,
    );
    const secondUnsigned = appendAuditEvent(
      first,
      { eventId: "evt_2", eventType: "x", occurredAt: new Date("2026-07-11T18:00:00.000Z"), payload: {} },
      signer,
    );
    expect(verifyAuditChain([first, secondUnsigned], resolver())).toEqual({
      valid: false,
      index: 1,
      code: "TIMESTAMP_OUT_OF_ORDER",
    });
  });

  it("accepts two events with exactly equal timestamps (boundary, not out of order)", () => {
    const sameInstant = new Date("2026-07-11T18:00:00.000Z");
    const first = appendAuditEvent(
      undefined,
      { eventId: "evt_1", eventType: "x", occurredAt: sameInstant, payload: {} },
      signer,
    );
    const second = appendAuditEvent(
      first,
      { eventId: "evt_2", eventType: "x", occurredAt: sameInstant, payload: {} },
      signer,
    );
    expect(verifyAuditChain([first, second], resolver())).toEqual({ valid: true, eventCount: 2 });
  });

  it("rejects an unparseable occurred_at timestamp", () => {
    // Built by hand (not appendAuditEvent) so occurred_at can be garbage while the
    // hash and signature stay internally consistent, isolating the timestamp check
    // from the (earlier-running) event-hash check.
    const unsigned = {
      sequence: 0,
      previous_event_hash: null,
      event_id: "evt_bad_ts",
      event_type: "x",
      occurred_at: "not-a-date",
      signer_id: signer.keyId,
      payload: {},
    };
    const withHash = { ...unsigned, event_hash: sha256Digest(unsigned) };
    const badEvent = { ...withHash, signature: signer.sign(withHash) };
    expect(verifyAuditChain([badEvent], resolver())).toEqual({
      valid: false,
      index: 0,
      code: "TIMESTAMP_OUT_OF_ORDER",
    });
  });

  it("reports the failing index, not just the first event", () => {
    const events = chainOfTwo();
    const tampered = { ...events[1], payload: { a: "tampered" } };
    const result = verifyAuditChain([events[0], tampered], resolver());
    expect(result).toEqual({ valid: false, index: 1, code: "EVENT_HASH_MISMATCH" });
  });
});
