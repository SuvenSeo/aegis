import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signCanonical, verifyCanonical } from "@aegis/crypto";
import { issueApprovalGrant, verifyApprovalGrant, type ApprovalSigner } from "../src/index.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const signer: ApprovalSigner = {
  keyId: "test-key",
  randomNonce: () => "nonce-0000000000000001",
  sign: (value) => signCanonical(value, privateKey),
};

const verifier = { verify: (value: unknown, signature: string) => verifyCanonical(value, signature, publicKey) };

function issue(overrides: Partial<Parameters<typeof issueApprovalGrant>[0]> = {}) {
  const issuedAt = new Date("2026-07-11T18:00:00.000Z");
  return issueApprovalGrant(
    {
      grantId: "grt_1",
      organizationId: "org_1",
      subjectId: "agt_1",
      actionDigest: `sha256:${"a".repeat(64)}`,
      targetDigest: `sha256:${"b".repeat(64)}`,
      capability: "pull_request.merge",
      constraints: { branch: "main", max_changed_files: 20 },
      issuedAt,
      expiresAt: new Date(issuedAt.getTime() + 600_000),
      maxUses: 1,
      ...overrides,
    },
    signer,
  );
}

function verifyOf(
  grant: ReturnType<typeof issue>,
  overrides: Partial<Parameters<typeof verifyApprovalGrant>[0]> = {},
) {
  return verifyApprovalGrant({
    grant,
    verifier,
    organizationId: grant.organization_id,
    subjectId: grant.subject_id,
    actionDigest: grant.action_digest,
    targetDigest: grant.target_digest,
    capability: grant.capability,
    requestedConstraints: grant.constraints,
    at: new Date("2026-07-11T18:05:00.000Z"),
    usedNonces: new Set(),
    usedCount: 0,
    ...overrides,
  });
}

describe("issueApprovalGrant / verifyApprovalGrant", () => {
  it("verifies a validly issued grant", () => {
    const grant = issue();
    expect(verifyOf(grant)).toEqual({ valid: true });
  });

  it("rejects a grant whose payload was tampered with after signing", () => {
    const grant = issue();
    const tampered = { ...grant, capability: "deployment.trigger" };
    expect(verifyOf(tampered).code).toBe("SIGNATURE_INVALID");
  });

  it("rejects an organization mismatch", () => {
    const grant = issue();
    expect(verifyOf(grant, { organizationId: "org_other" }).code).toBe("ORGANIZATION_MISMATCH");
  });

  it("rejects a subject mismatch", () => {
    const grant = issue();
    expect(verifyOf(grant, { subjectId: "agt_other" }).code).toBe("SUBJECT_MISMATCH");
  });

  it("rejects an action digest mismatch", () => {
    const grant = issue();
    expect(verifyOf(grant, { actionDigest: `sha256:${"c".repeat(64)}` }).code).toBe("ACTION_MISMATCH");
  });

  it("rejects a target digest mismatch", () => {
    const grant = issue();
    expect(verifyOf(grant, { targetDigest: `sha256:${"c".repeat(64)}` }).code).toBe("TARGET_MISMATCH");
  });

  it("rejects a capability mismatch", () => {
    const grant = issue();
    expect(verifyOf(grant, { capability: "repository.write" }).code).toBe("CAPABILITY_MISMATCH");
  });

  it("rejects verification before the grant is valid", () => {
    const grant = issue();
    expect(verifyOf(grant, { at: new Date("2026-07-11T17:00:00.000Z") }).code).toBe("GRANT_NOT_YET_VALID");
  });

  it("rejects an expired grant", () => {
    const grant = issue();
    expect(verifyOf(grant, { at: new Date("2026-07-11T19:00:00.000Z") }).code).toBe("GRANT_EXPIRED");
  });

  it("rejects a reused nonce", () => {
    const grant = issue();
    expect(verifyOf(grant, { usedNonces: new Set([grant.nonce]) }).code).toBe("NONCE_REUSED");
  });

  it("rejects a grant that has hit its usage budget", () => {
    const grant = issue({ maxUses: 2 });
    expect(verifyOf(grant, { usedCount: 2 }).code).toBe("USAGE_LIMIT_EXCEEDED");
  });

  it("allows a requested numeric constraint that narrows the grant", () => {
    const grant = issue({ constraints: { max_changed_files: 20 } });
    expect(verifyOf(grant, { requestedConstraints: { max_changed_files: 5 } }).valid).toBe(true);
  });

  it("rejects a requested numeric constraint that widens the grant", () => {
    const grant = issue({ constraints: { max_changed_files: 20 } });
    expect(verifyOf(grant, { requestedConstraints: { max_changed_files: 100 } }).code).toBe(
      "CONSTRAINT_NOT_NARROWED",
    );
  });

  it("allows a requested set constraint that is a subset of the grant's", () => {
    const grant = issue({ constraints: { hosts: ["a.example.com", "b.example.com"] } });
    expect(verifyOf(grant, { requestedConstraints: { hosts: ["a.example.com"] } }).valid).toBe(true);
  });

  it("rejects a requested set constraint containing a value outside the grant's", () => {
    const grant = issue({ constraints: { hosts: ["a.example.com"] } });
    expect(verifyOf(grant, { requestedConstraints: { hosts: ["a.example.com", "evil.example.com"] } }).code).toBe(
      "CONSTRAINT_NOT_NARROWED",
    );
  });

  it("rejects a requested constraint key the grant never mentions", () => {
    const grant = issue({ constraints: { branch: "main" } });
    expect(verifyOf(grant, { requestedConstraints: { environment: "production" } }).code).toBe(
      "CONSTRAINT_NOT_NARROWED",
    );
  });

  it("rejects a requested exact-match constraint that changes the target", () => {
    const grant = issue({ constraints: { branch: "main" } });
    expect(verifyOf(grant, { requestedConstraints: { branch: "develop" } }).code).toBe(
      "CONSTRAINT_NOT_NARROWED",
    );
  });
});
