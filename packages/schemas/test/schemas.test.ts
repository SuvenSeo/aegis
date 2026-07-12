import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { ActionEnvelopeSchema, ApprovalGrantSchema, PolicyDocumentSchema } from "../src/index.js";

const validAction = JSON.parse(
  readFileSync(new URL("../../../examples/actions/merge-main.json", import.meta.url), "utf8"),
);

const validPolicy = parseYaml(
  readFileSync(new URL("../../../examples/policies/production-code-guard.yaml", import.meta.url), "utf8"),
);

describe("ActionEnvelopeSchema", () => {
  it("accepts the example action fixture", () => {
    expect(ActionEnvelopeSchema.safeParse(validAction).success).toBe(true);
  });

  it("rejects a missing required field", () => {
    const { capability, ...rest } = validAction;
    expect(ActionEnvelopeSchema.safeParse(rest).success).toBe(false);
  });

  it("rejects a malformed operation digest", () => {
    const invalid = { ...validAction, operation: { ...validAction.operation, arguments_digest: "not-a-digest" } };
    expect(ActionEnvelopeSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects a non-string capability", () => {
    const invalid = { ...validAction, capability: 42 };
    expect(ActionEnvelopeSchema.safeParse(invalid).success).toBe(false);
  });

  it("allows unknown extra fields on target and context (passthrough)", () => {
    const withExtra = {
      ...validAction,
      target: { ...validAction.target, extra_field: "x" },
    };
    expect(ActionEnvelopeSchema.safeParse(withExtra).success).toBe(true);
  });

  it("rejects a timestamp carrying a non-Z timezone offset", () => {
    const invalid = { ...validAction, timestamp: "2026-07-11T18:00:00.000+00:00" };
    expect(ActionEnvelopeSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects non-array evidence fields", () => {
    const invalid = { ...validAction, evidence: { ...validAction.evidence, provider_verified: "repository" } };
    expect(ActionEnvelopeSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects a non-string entry inside an evidence array", () => {
    const invalid = { ...validAction, evidence: { ...validAction.evidence, provider_verified: [1, 2] } };
    expect(ActionEnvelopeSchema.safeParse(invalid).success).toBe(false);
  });
});

describe("ApprovalGrantSchema", () => {
  const validGrant = {
    schema_version: "1.0",
    grant_id: "grt_1",
    organization_id: "org_1",
    subject_id: "agt_1",
    action_digest: `sha256:${"a".repeat(64)}`,
    target_digest: `sha256:${"b".repeat(64)}`,
    capability: "pull_request.merge",
    constraints: { branch: "main" },
    issued_at: "2026-07-11T18:00:00.000Z",
    expires_at: "2026-07-11T18:10:00.000Z",
    max_uses: 1,
    nonce: "0123456789abcdef",
    issuer_key_id: "cli-test-key",
    signature: "abc123",
  };

  it("accepts a well-formed grant", () => {
    expect(ApprovalGrantSchema.safeParse(validGrant).success).toBe(true);
  });

  it("defaults constraints to an empty object when omitted", () => {
    const { constraints, ...rest } = validGrant;
    const result = ApprovalGrantSchema.safeParse(rest);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.constraints).toEqual({});
  });

  it("rejects a non-positive max_uses", () => {
    expect(ApprovalGrantSchema.safeParse({ ...validGrant, max_uses: 0 }).success).toBe(false);
  });

  it("rejects a malformed action_digest", () => {
    expect(ApprovalGrantSchema.safeParse({ ...validGrant, action_digest: "bad" }).success).toBe(false);
  });

  it("rejects a digest with extra leading or trailing characters (anchored regex)", () => {
    const suffixed = { ...validGrant, action_digest: `sha256:${"a".repeat(64)}extra` };
    const prefixed = { ...validGrant, action_digest: `xsha256:${"a".repeat(64)}` };
    expect(ApprovalGrantSchema.safeParse(suffixed).success).toBe(false);
    expect(ApprovalGrantSchema.safeParse(prefixed).success).toBe(false);
  });

  it("rejects a target_digest with extra leading or trailing characters (anchored regex)", () => {
    const suffixed = { ...validGrant, target_digest: `sha256:${"b".repeat(64)}extra` };
    const prefixed = { ...validGrant, target_digest: `xsha256:${"b".repeat(64)}` };
    expect(ApprovalGrantSchema.safeParse(suffixed).success).toBe(false);
    expect(ApprovalGrantSchema.safeParse(prefixed).success).toBe(false);
  });

  it("rejects issued_at/expires_at carrying a non-Z timezone offset", () => {
    expect(
      ApprovalGrantSchema.safeParse({ ...validGrant, issued_at: "2026-07-11T18:00:00.000+00:00" }).success,
    ).toBe(false);
    expect(
      ApprovalGrantSchema.safeParse({ ...validGrant, expires_at: "2026-07-11T18:10:00.000+00:00" }).success,
    ).toBe(false);
  });
});

describe("PolicyDocumentSchema", () => {
  it("accepts the example policy fixture", () => {
    const result = PolicyDocumentSchema.safeParse(validPolicy);
    expect(result.success).toBe(true);
  });

  it("rejects an unknown apiVersion", () => {
    expect(
      PolicyDocumentSchema.safeParse({ ...validPolicy, apiVersion: "aegis.dev/v2" }).success,
    ).toBe(false);
  });

  it("rejects a rule with an unknown effect", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[0].effect = "maybe";
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects a rule with an empty capabilities list", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[0].capabilities = [];
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects an unrecognized top-level key (strict)", () => {
    expect(PolicyDocumentSchema.safeParse({ ...validPolicy, extra: true }).success).toBe(false);
  });

  it("rejects an empty-string effect", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[0].effect = "";
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });

  it("accepts a {min,max} numeric-bound condition", () => {
    const withBound = structuredClone(validPolicy);
    withBound.spec.rules[0].when = { changed_files: { min: 1, max: 10 } };
    expect(PolicyDocumentSchema.safeParse(withBound).success).toBe(true);
  });

  it("rejects a {min,max}-shaped condition with an extraneous key (strict)", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[0].when = { changed_files: { min: 1, unexpected: true } };
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });

  it("accepts a numeric allowed-value array condition", () => {
    const withNumericArray = structuredClone(validPolicy);
    withNumericArray.spec.rules[0].when = { prior_denials_in_session: [0, 1, 2] };
    expect(PolicyDocumentSchema.safeParse(withNumericArray).success).toBe(true);
  });

  it("defaults subjects and resources lists to empty arrays when omitted", () => {
    const minimal = {
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "minimal", version: 1 },
      spec: {
        subjects: {},
        resources: {},
        rules: [{ id: "allow-all", effect: "allow", capabilities: ["repository.read"] }],
      },
    };
    const result = PolicyDocumentSchema.safeParse(minimal);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.spec.subjects).toEqual({ agents: [], roles: [] });
      expect(result.data.spec.resources).toEqual({ repositories: [], environments: [] });
    }
  });

  it("rejects an approvals block missing its required fields", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[1].approvals = {};
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });

  it("rejects an approvals.minimum that is not a positive integer", () => {
    const invalid = structuredClone(validPolicy);
    invalid.spec.rules[1].approvals.minimum = 0;
    expect(PolicyDocumentSchema.safeParse(invalid).success).toBe(false);
  });
});
