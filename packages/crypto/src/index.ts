import { createHash, verify as verifySignature, type KeyObject } from "node:crypto";

/**
 * Rebuilt from docs/reference/canonical-serialization.md — the original @aegis/crypto
 * implementation was lost to pack corruption. This follows the documented rules
 * (UTF-8, lexicographic key order, reject undefined/NaN/Infinity/cycles, RFC3339-ms
 * dates, sha256:<hex> digests, unpadded base64url Ed25519 signatures) but has not been
 * checked against the original golden fixtures, which were also not recoverable.
 */
export class CanonicalizationError extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function canonicalize(value: unknown, seen: Set<unknown> = new Set()): string {
  if (value === null) return "null";
  if (value === undefined) throw new CanonicalizationError("undefined is not canonicalizable");

  const t = typeof value;
  if (t === "function" || t === "symbol" || t === "bigint") {
    throw new CanonicalizationError(`${t} is not canonicalizable`);
  }
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new CanonicalizationError("NaN and Infinity are not canonicalizable");
    }
    return JSON.stringify(value);
  }

  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) {
      throw new CanonicalizationError("Invalid Date is not canonicalizable");
    }
    return JSON.stringify(value.toISOString());
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) throw new CanonicalizationError("cyclic reference");
    seen.add(value);
    const items = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return `[${items.join(",")}]`;
  }

  if (isPlainObject(value)) {
    if (seen.has(value)) throw new CanonicalizationError("cyclic reference");
    seen.add(value);
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`);
    seen.delete(value);
    return `{${entries.join(",")}}`;
  }

  throw new CanonicalizationError("non-plain objects are not canonicalizable");
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}

export function sha256Digest(value: unknown): string {
  const hash = createHash("sha256").update(canonicalBytes(value)).digest("hex");
  return `sha256:${hash}`;
}

function base64UrlToBuffer(input: string): Buffer {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + "=".repeat(padLength), "base64");
}

export function verifyCanonical(value: unknown, signature: string, key: KeyObject): boolean {
  try {
    const bytes = canonicalBytes(value);
    const signatureBytes = base64UrlToBuffer(signature);
    // Ed25519 is a one-shot signature scheme: pass null for the digest algorithm.
    return verifySignature(null, bytes, key, signatureBytes);
  } catch {
    return false;
  }
}
