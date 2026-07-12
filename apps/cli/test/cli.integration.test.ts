import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendAuditEvent, type AuditSigner } from "@aegis/audit";
import { issueApprovalGrant, type ApprovalSigner } from "@aegis/approvals";
import { signCanonical } from "@aegis/crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execa } from "execa";

const cli = "apps/cli/dist/index.js";
const id = "01J2M8X7Y6Z5W4V3T2S1R0Q9P8";
let fixtureDirectory = "";
let approvalPath = "";
let publicKeyPath = "";
let auditPath = "";
let keyFilePath = "";

async function run(args: readonly string[]) {
  return execa("node", [cli, ...args], { reject: false });
}

beforeAll(async () => {
  fixtureDirectory = await mkdtemp(join(tmpdir(), "aegis-cli-"));
  approvalPath = join(fixtureDirectory, "grant.json");
  publicKeyPath = join(fixtureDirectory, "public.pem");
  auditPath = join(fixtureDirectory, "events.json");
  keyFilePath = join(fixtureDirectory, "keys.json");

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer: ApprovalSigner & AuditSigner = {
    keyId: "cli-test-key",
    randomNonce: () => "0123456789abcdefghijklmn",
    sign: (value) => signCanonical(value, privateKey),
  };
  const issuedAt = new Date();
  const grant = issueApprovalGrant(
    {
      grantId: `grt_${id}`,
      organizationId: `org_${id}`,
      subjectId: `agt_${id}`,
      actionDigest: `sha256:${"a".repeat(64)}`,
      targetDigest: `sha256:${"b".repeat(64)}`,
      capability: "pull_request.merge",
      constraints: { branch: "main" },
      issuedAt,
      expiresAt: new Date(issuedAt.getTime() + 600_000),
      maxUses: 1,
    },
    signer,
  );
  const event = appendAuditEvent(
    undefined,
    {
      eventId: `evt_${id}`,
      eventType: "approval.resolved",
      occurredAt: issuedAt,
      payload: grant,
    },
    signer,
  );
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  await Promise.all([
    writeFile(approvalPath, JSON.stringify(grant), "utf8"),
    writeFile(publicKeyPath, publicPem, "utf8"),
    writeFile(auditPath, JSON.stringify([event]), "utf8"),
    writeFile(
      keyFilePath,
      JSON.stringify({ keys: { [signer.keyId]: publicPem }, revoked: [] }),
      "utf8",
    ),
  ]);
});

afterAll(async () => {
  if (fixtureDirectory) await rm(fixtureDirectory, { recursive: true, force: true });
});

describe("aegis CLI", () => {
  it("simulates a protected main merge as approval-required", async () => {
    const result = await run([
      "simulate",
      "--policy",
      "examples/policies/production-code-guard.yaml",
      "--action",
      "examples/actions/merge-main.json",
      "--at",
      "2026-07-11T18:00:00.000Z",
      "--json",
    ]);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: "require_approval",
      reason_codes: ["APPROVAL_REQUIRED_BY_POLICY"],
      matched_rule_ids: ["protect-main"],
    });
  });

  it("validates the example policy", async () => {
    const result = await run([
      "policy",
      "validate",
      "examples/policies/production-code-guard.yaml",
      "--json",
    ]);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ ok: true, policy: "production-code-guard" });
  });

  it("runs deterministic static policy tests", async () => {
    const result = await run([
      "policy",
      "test",
      "examples/policies/production-code-guard.yaml",
      "--json",
    ]);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: true,
      checks: ["schema", "semantic", "capabilities", "constraints", "deterministic_compile"],
    });
  });

  it("validates the example action", async () => {
    const result = await run(["action", "validate", "examples/actions/merge-main.json", "--json"]);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: true,
      capability: "pull_request.merge",
    });
  });

  it("verifies a signed approval grant", async () => {
    const result = await run([
      "approval",
      "verify",
      approvalPath,
      "--public-key",
      publicKeyPath,
      "--json",
    ]);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ valid: true });
  });

  it("verifies a signed audit chain", async () => {
    const result = await run(["audit", "verify", auditPath, "--keys", keyFilePath, "--json"]);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ valid: true, eventCount: 1 });
  });

  it("returns exit code 2 without echoing raw invalid action input", async () => {
    const invalidPath = "apps/cli/test/invalid-action.fixture.json";
    const result = await run(["action", "validate", invalidPath, "--json"]);

    expect(result.exitCode).toBe(2);
    expect(JSON.parse(result.stdout)).toMatchObject({ ok: false, code: "ACTION_INVALID" });
    expect(result.stdout).not.toContain("sk-proj-super-secret");
  });
});
