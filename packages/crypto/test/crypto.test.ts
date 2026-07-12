import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CanonicalizationError,
  canonicalize,
  sha256Digest,
  signCanonical,
  verifyCanonical,
} from "../src/index.js";

describe("canonicalize", () => {
  it("sorts object keys lexicographically at every depth", () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it("preserves array order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("preserves explicit null", () => {
    expect(canonicalize({ a: null })).toBe('{"a":null}');
  });

  it("normalizes Date to UTC RFC3339 with milliseconds", () => {
    const date = new Date("2026-07-11T18:00:00.000Z");
    expect(canonicalize(date)).toBe('"2026-07-11T18:00:00.000Z"');
  });

  it("rejects undefined", () => {
    expect(() => canonicalize(undefined)).toThrow(CanonicalizationError);
  });

  it("rejects functions and symbols", () => {
    expect(() => canonicalize(() => {})).toThrow(CanonicalizationError);
    expect(() => canonicalize(Symbol("x"))).toThrow(CanonicalizationError);
  });

  it("rejects bigint", () => {
    expect(() => canonicalize(10n)).toThrow(CanonicalizationError);
  });

  it("rejects NaN and Infinity", () => {
    expect(() => canonicalize(Number.NaN)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Number.NEGATIVE_INFINITY)).toThrow(CanonicalizationError);
  });

  it("rejects an invalid Date", () => {
    expect(() => canonicalize(new Date("not-a-date"))).toThrow(CanonicalizationError);
  });

  it("rejects a cyclic object reference", () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(() => canonicalize(obj)).toThrow(CanonicalizationError);
  });

  it("rejects a cyclic array reference", () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr);
    expect(() => canonicalize(arr)).toThrow(CanonicalizationError);
  });

  it("rejects non-plain objects", () => {
    expect(() => canonicalize(new Map())).toThrow(CanonicalizationError);
  });

  it("emits no insignificant whitespace", () => {
    expect(canonicalize({ a: [1, 2], b: "x" })).toBe('{"a":[1,2],"b":"x"}');
  });
});

describe("sha256Digest", () => {
  it("returns a lowercase sha256:<hex> digest", () => {
    const digest = sha256Digest({ a: 1 });
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is deterministic regardless of key order", () => {
    expect(sha256Digest({ a: 1, b: 2 })).toBe(sha256Digest({ b: 2, a: 1 }));
  });

  it("changes when content changes", () => {
    expect(sha256Digest({ a: 1 })).not.toBe(sha256Digest({ a: 2 }));
  });
});

describe("signCanonical / verifyCanonical", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");

  it("round-trips a valid signature", () => {
    const value = { hello: "world", n: 42 };
    const signature = signCanonical(value, privateKey);
    expect(verifyCanonical(value, signature, publicKey)).toBe(true);
  });

  it("rejects a signature over tampered content", () => {
    const signature = signCanonical({ hello: "world" }, privateKey);
    expect(verifyCanonical({ hello: "mars" }, signature, publicKey)).toBe(false);
  });

  it("rejects a mutated signature string", () => {
    // Mutate a character in the middle of the signature, not the last one: the
    // trailing base64url character of an unpadded, non-multiple-of-3-byte payload
    // encodes some unused padding bits, so flipping it can leave the decoded bytes
    // unchanged and make this assertion flaky.
    const value = { hello: "world" };
    const signature = signCanonical(value, privateKey);
    const index = Math.floor(signature.length / 2);
    const replacement = signature[index] === "A" ? "B" : "A";
    const tampered = signature.slice(0, index) + replacement + signature.slice(index + 1);
    expect(verifyCanonical(value, tampered, publicKey)).toBe(false);
  });

  it("rejects a signature checked against a different key", () => {
    const other = generateKeyPairSync("ed25519");
    const value = { hello: "world" };
    const signature = signCanonical(value, privateKey);
    expect(verifyCanonical(value, signature, other.publicKey)).toBe(false);
  });

  it("returns false instead of throwing on malformed signature input", () => {
    expect(verifyCanonical({ a: 1 }, "not-valid-base64url!!", publicKey)).toBe(false);
  });

  it("returns false instead of throwing when the value itself is not canonicalizable", () => {
    const signature = signCanonical({ a: 1 }, privateKey);
    expect(verifyCanonical(undefined, signature, publicKey)).toBe(false);
  });

  it("produces unpadded base64url signatures", () => {
    const signature = signCanonical({ a: 1 }, privateKey);
    expect(signature).not.toMatch(/[+/=]/);
  });
});
