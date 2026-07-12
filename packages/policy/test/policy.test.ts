import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { ActionEnvelope } from "@aegis/schemas";
import {
  compilePolicy,
  evaluatePolicies,
  validatePolicyYaml,
  type CompiledPolicy,
  type PolicyDocument,
} from "../src/index.js";

const examplePolicyYaml = readFileSync(
  new URL("../../../examples/policies/production-code-guard.yaml", import.meta.url),
  "utf8",
);
const exampleAction: ActionEnvelope = JSON.parse(
  readFileSync(new URL("../../../examples/actions/merge-main.json", import.meta.url), "utf8"),
);

function baseAction(overrides: Partial<ActionEnvelope> = {}): ActionEnvelope {
  return { ...exampleAction, ...overrides };
}

describe("validatePolicyYaml", () => {
  it("accepts the example policy", () => {
    const result = validatePolicyYaml(examplePolicyYaml);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.document.metadata.name).toBe("production-code-guard");
  });

  it("reports a YAML parse error", () => {
    const result = validatePolicyYaml("apiVersion: [unterminated");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]?.code).toBe("YAML_PARSE_ERROR");
  });

  it("reports a schema validation error for a missing metadata.name", () => {
    const broken = examplePolicyYaml.replace("name: production-code-guard", "notname: x");
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
  });

  it("rejects an unknown capability", () => {
    const broken = examplePolicyYaml.replace("repository.read", "teleport.activate");
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "CAPABILITY_UNKNOWN")).toBe(true);
  });

  it("rejects a duplicate rule id", () => {
    const broken = examplePolicyYaml.replace("id: deny-workflow-escalation", "id: allow-repository-read");
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "DUPLICATE_RULE_ID")).toBe(true);
  });

  it("rejects require_approval without an approvals block", () => {
    const broken = `
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: missing-approvals
  version: 1
spec:
  subjects:
    agents: []
    roles: []
  resources:
    repositories: []
    environments: []
  rules:
    - id: protect-main
      effect: require_approval
      capabilities: [pull_request.merge]
`;
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "APPROVALS_REQUIRED")).toBe(true);
  });

  it("rejects an approvals.expires_in longer than 24 hours", () => {
    const broken = examplePolicyYaml.replace("expires_in: 10m", "expires_in: 25h");
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "APPROVAL_EXPIRY_TOO_LONG")).toBe(true);
  });

  it("accepts approvals.expires_in in seconds", () => {
    const withSeconds = examplePolicyYaml.replace("expires_in: 10m", "expires_in: 30s");
    expect(validatePolicyYaml(withSeconds).ok).toBe(true);
  });

  it("accepts approvals.expires_in right at the 24-hour boundary", () => {
    const atBoundary = examplePolicyYaml.replace("expires_in: 10m", "expires_in: 24h");
    expect(validatePolicyYaml(atBoundary).ok).toBe(true);
  });

  it("rejects an approvals.expires_in with an invalid duration format", () => {
    const broken = `
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: bad-duration
  version: 1
spec:
  subjects:
    agents: []
    roles: []
  resources:
    repositories: []
    environments: []
  rules:
    - id: protect-main
      effect: require_approval
      capabilities: [pull_request.merge]
      approvals:
        minimum: 1
        roles: [maintainer]
        expires_in: forever
`;
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "APPROVAL_EXPIRY_INVALID")).toBe(true);
  });

  it("rejects an approvals block on a rule whose effect is not require_approval", () => {
    const broken = `
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: bad-approvals-placement
  version: 1
spec:
  subjects:
    agents: []
    roles: []
  resources:
    repositories: []
    environments: []
  rules:
    - id: allow-read
      effect: allow
      capabilities: [repository.read]
      approvals:
        minimum: 1
        roles: [maintainer]
        expires_in: 10m
`;
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "APPROVALS_NOT_ALLOWED")).toBe(true);
  });

  it("rejects allow_with_constraints without a constraints block", () => {
    const broken = `
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: missing-constraints
  version: 1
spec:
  subjects:
    agents: []
    roles: []
  resources:
    repositories: []
    environments: []
  rules:
    - id: bounded-read
      effect: allow_with_constraints
      capabilities: [repository.read]
`;
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "CONSTRAINTS_REQUIRED")).toBe(true);
  });

  it("rejects a constraint not allowed for its capability", () => {
    const broken = `
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: bad-constraint
  version: 1
spec:
  subjects:
    agents: []
    roles: []
  resources:
    repositories: []
    environments: []
  rules:
    - id: bounded-read
      effect: allow_with_constraints
      capabilities: [repository.read]
      constraints:
        not_a_real_constraint: 1
`;
    const result = validatePolicyYaml(broken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.some((e) => e.code === "CONSTRAINT_NOT_ALLOWED")).toBe(true);
  });
});

describe("compilePolicy", () => {
  const document = (validatePolicyYaml(examplePolicyYaml) as { document: PolicyDocument }).document;

  it("is deterministic: same document compiles to the same digest and version id", () => {
    const first = compilePolicy(document);
    const second = compilePolicy(document);
    expect(first.sourceDigest).toBe(second.sourceDigest);
    expect(first.policyVersionId).toBe(second.policyVersionId);
  });

  it("changes sourceDigest when the document changes", () => {
    const first = compilePolicy(document);
    const mutated = { ...document, metadata: { ...document.metadata, version: document.metadata.version + 1 } };
    const second = compilePolicy(mutated);
    expect(first.sourceDigest).not.toBe(second.sourceDigest);
  });

  it("carries name and version through", () => {
    const compiled = compilePolicy(document);
    expect(compiled.name).toBe("production-code-guard");
    expect(compiled.version).toBe(1);
  });

  it("falls back to a zero expiry when called directly with an unvalidated duration", () => {
    // compilePolicy can be invoked without going through validatePolicyYaml first, so
    // it must not propagate an unparseable expires_in as undefined/NaN.
    const unvalidated: PolicyDocument = {
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "unvalidated", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "protect-main",
            effect: "require_approval",
            capabilities: ["pull_request.merge"],
            approvals: { minimum: 1, roles: ["maintainer"], expires_in: "not-a-duration" },
          },
        ],
      },
    };
    const compiled = compilePolicy(unvalidated);
    expect(compiled.rules[0]?.approvals?.expiresInMs).toBe(0);
  });
});

describe("evaluatePolicies", () => {
  const document = (validatePolicyYaml(examplePolicyYaml) as { document: PolicyDocument }).document;
  const compiled = compilePolicy(document);
  const at = new Date("2026-07-11T18:00:00.000Z");

  it("requires approval for a protected main-branch merge", () => {
    const decision = evaluatePolicies({ policies: [compiled], action: exampleAction, at });
    expect(decision.outcome).toBe("require_approval");
    expect(decision.reason_codes).toEqual(["APPROVAL_REQUIRED_BY_POLICY"]);
    expect(decision.matched_rule_ids).toEqual(["protect-main"]);
    expect(decision.approval_requirements?.minimum).toBe(1);
    expect(decision.approval_requirements?.roles).toEqual(["maintainer", "security"]);
  });

  it("denies an unknown capability", () => {
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({ capability: "teleport.activate" }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["CAPABILITY_UNKNOWN"]);
  });

  it("denies when mandatory evidence is missing", () => {
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({ evidence: { provider_verified: [], local_observed: [], model_derived: [] } }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["MANDATORY_EVIDENCE_MISSING"]);
  });

  it("denies on an explicit deny rule (permission escalation on a workflow file)", () => {
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({
        capability: "repository.write",
        context: {
          ...exampleAction.context,
          sensitive_paths_touched: [".github/workflows/"],
          requested_permissions_increase: true,
        },
      }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["DENIED_BY_POLICY"]);
    expect(decision.matched_rule_ids).toEqual(["deny-workflow-escalation"]);
  });

  it("allows a plain repository read", () => {
    const { branch: _branch, ...targetWithoutBranch } = exampleAction.target;
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({
        capability: "repository.read",
        target: targetWithoutBranch,
      }),
      at,
    });
    expect(decision.outcome).toBe("allow");
    expect(decision.matched_rule_ids).toEqual(["allow-repository-read"]);
  });

  it("defaults to deny when scoping does not match (wrong repository)", () => {
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({
        capability: "repository.read",
        target: { ...exampleAction.target, repository: "acme/unrelated" },
      }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("narrows constraints across matching allow_with_constraints rules", () => {
    const stagingPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "staging-deploys", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "bounded-staging-deploy",
            effect: "allow_with_constraints",
            capabilities: ["deployment.trigger"],
            when: { environment: "staging" },
            constraints: { environment: "staging", max_duration: 900000 },
          },
          {
            id: "tighter-staging-deploy",
            effect: "allow_with_constraints",
            capabilities: ["deployment.trigger"],
            when: { environment: "staging" },
            constraints: { environment: "staging", max_duration: 300000 },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [stagingPolicy],
      action: baseAction({
        capability: "deployment.trigger",
        target: { ...exampleAction.target, environment: "staging" },
        evidence: {
          provider_verified: ["repository", "environment"],
          local_observed: [],
          model_derived: [],
        },
      }),
      at,
    });
    expect(decision.outcome).toBe("allow_with_constraints");
    expect(decision.constraints.max_duration).toBe(300000);
  });

  it("denies on an unreconcilable constraint conflict", () => {
    const conflictingPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "conflicting-deploys", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "staging-only",
            effect: "allow_with_constraints",
            capabilities: ["deployment.trigger"],
            constraints: { environment: "staging" },
          },
          {
            id: "production-only",
            effect: "allow_with_constraints",
            capabilities: ["deployment.trigger"],
            constraints: { environment: "production" },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [conflictingPolicy],
      action: baseAction({
        capability: "deployment.trigger",
        target: { ...exampleAction.target, environment: "staging" },
        evidence: {
          provider_verified: ["repository", "environment"],
          local_observed: [],
          model_derived: [],
        },
      }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["CONSTRAINT_CONFLICT"]);
  });

  it("narrows a set-valued (array) constraint to the intersection", () => {
    const shellPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "shell-exec", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "allow-a-b",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: ["a", "b"] },
          },
          {
            id: "allow-a-c",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: ["a", "c"] },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [shellPolicy],
      action: baseAction({ capability: "shell.execute" }),
      at,
    });
    expect(decision.outcome).toBe("allow_with_constraints");
    expect(decision.constraints.executables).toEqual(["a"]);
  });

  it("denies when set-valued constraints have no overlap", () => {
    const shellPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "shell-exec-conflict", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "allow-a",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: ["a"] },
          },
          {
            id: "allow-b",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: ["b"] },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [shellPolicy],
      action: baseAction({ capability: "shell.execute" }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["CONSTRAINT_CONFLICT"]);
  });

  it("does not match a when condition shaped as an unsupported object", () => {
    // Bypass compilePolicy (which schema-validates `when` shapes) to exercise
    // evaluatePolicies' own defensive handling of a malformed CompiledPolicy, e.g.
    // one constructed by a future caller that skips validatePolicyYaml/compilePolicy.
    const oddPolicy: CompiledPolicy = {
      name: "odd-condition",
      version: 1,
      policyVersionId: "sha256:" + "0".repeat(64),
      sourceDigest: "sha256:" + "1".repeat(64),
      subjects: { agents: [], roles: [] },
      resources: { repositories: [], environments: [] },
      rules: [
        {
          id: "never-matches",
          effect: "allow",
          capabilities: ["repository.read"],
          when: { branch: { unsupported: true } as unknown as string },
        },
      ],
    };
    const decision = evaluatePolicies({
      policies: [oddPolicy],
      action: baseAction({ capability: "repository.read" }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("matches a numeric {min,max} bound condition", () => {
    const boundedPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "bounded", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "small-changes-only",
            effect: "allow",
            capabilities: ["repository.write"],
            when: { changed_files: { max: 5 } },
          },
        ],
      },
    });
    const withinBound = evaluatePolicies({
      policies: [boundedPolicy],
      action: baseAction({
        capability: "repository.write",
        context: { ...exampleAction.context, changed_files: 3 },
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(withinBound.outcome).toBe("allow");

    const overBound = evaluatePolicies({
      policies: [boundedPolicy],
      action: baseAction({
        capability: "repository.write",
        context: { ...exampleAction.context, changed_files: 50 },
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(overBound.outcome).toBe("deny");
    expect(overBound.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("matches an {any:[...]} string-set overlap condition", () => {
    const pathPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "path-sensitive", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "flag-ci-touch",
            effect: "deny",
            capabilities: ["repository.write"],
            when: { sensitive_paths_touched: { any: [".github/workflows/"] } },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [pathPolicy],
      action: baseAction({
        capability: "repository.write",
        context: { ...exampleAction.context, sensitive_paths_touched: [".github/workflows/"] },
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.matched_rule_ids).toEqual(["flag-ci-touch"]);
  });

  it("does not match rules outside their subject/resource scope", () => {
    const decision = evaluatePolicies({
      policies: [compiled],
      action: baseAction({ context: { ...exampleAction.context, agent_name: "some-other-agent" } }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("does not scope-match when a required resource field is absent on the action", () => {
    const scopedToEnvironment = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "env-scoped", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: ["production"] },
        rules: [{ id: "allow-read", effect: "allow", capabilities: ["repository.read"] }],
      },
    });
    const { environment: _env, ...targetWithoutEnvironment } = exampleAction.target;
    const decision = evaluatePolicies({
      policies: [scopedToEnvironment],
      action: baseAction({ capability: "repository.read", target: targetWithoutEnvironment }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("matches every documented condition source key", () => {
    const omniPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "omni-condition", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "all-conditions",
            effect: "allow",
            capabilities: ["repository.write"],
            when: {
              agent_id: exampleAction.agent_id,
              user_role: exampleAction.context.user_role,
              repository: exampleAction.target.repository,
              capability: "repository.write",
              interactive_user_present: exampleAction.context.interactive_user_present,
              prior_denials_in_session: exampleAction.context.prior_denials_in_session,
              provider_verified: { any: ["repository"] },
              utc_hour: at.getUTCHours(),
            },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [omniPolicy],
      action: baseAction({
        capability: "repository.write",
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(decision.outcome).toBe("allow");
    expect(decision.matched_rule_ids).toEqual(["all-conditions"]);
  });

  it("does not match on an unrecognized condition key", () => {
    const unknownKeyPolicy: CompiledPolicy = {
      name: "unknown-key",
      version: 1,
      policyVersionId: "sha256:" + "2".repeat(64),
      sourceDigest: "sha256:" + "3".repeat(64),
      subjects: { agents: [], roles: [] },
      resources: { repositories: [], environments: [] },
      rules: [
        {
          id: "never-matches",
          effect: "allow",
          capabilities: ["repository.read"],
          when: { not_a_real_condition_key: "anything" },
        },
      ],
    };
    const decision = evaluatePolicies({
      policies: [unknownKeyPolicy],
      action: baseAction({ capability: "repository.read" }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("matches an allowed-value array condition and rejects a value outside it", () => {
    const allowedValuesPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "allowed-values", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "main-or-develop",
            effect: "allow",
            capabilities: ["branch.push"],
            when: { branch: ["main", "develop"] },
          },
        ],
      },
    });
    const matching = evaluatePolicies({
      policies: [allowedValuesPolicy],
      action: baseAction({
        capability: "branch.push",
        target: { ...exampleAction.target, branch: "develop" },
      }),
      at,
    });
    expect(matching.outcome).toBe("allow");

    const nonMatching = evaluatePolicies({
      policies: [allowedValuesPolicy],
      action: baseAction({
        capability: "branch.push",
        target: { ...exampleAction.target, branch: "feature/x" },
      }),
      at,
    });
    expect(nonMatching.outcome).toBe("deny");
    expect(nonMatching.reason_codes).toEqual(["NO_MATCHING_RULE"]);
  });

  it("matches an {any:[...]} condition against a scalar (non-array) actual value", () => {
    const scalarAnyPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "scalar-any", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "main-or-develop-any",
            effect: "allow",
            capabilities: ["branch.push"],
            when: { branch: { any: ["main", "develop"] } },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [scalarAnyPolicy],
      action: baseAction({
        capability: "branch.push",
        target: { ...exampleAction.target, branch: "develop" },
      }),
      at,
    });
    expect(decision.outcome).toBe("allow");
  });

  it("evaluates min-only and max-only numeric bounds, and rejects a non-numeric actual", () => {
    const minOnlyPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "min-only", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "at-least-one-file",
            effect: "allow",
            capabilities: ["repository.write"],
            when: { changed_files: { min: 1 } },
          },
        ],
      },
    });
    const withinMin = evaluatePolicies({
      policies: [minOnlyPolicy],
      action: baseAction({
        capability: "repository.write",
        context: { ...exampleAction.context, changed_files: 1 },
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(withinMin.outcome).toBe("allow");

    const belowMin = evaluatePolicies({
      policies: [minOnlyPolicy],
      action: baseAction({
        capability: "repository.write",
        context: { ...exampleAction.context, changed_files: 0 },
        evidence: { provider_verified: ["repository"], local_observed: [], model_derived: [] },
      }),
      at,
    });
    expect(belowMin.outcome).toBe("deny");

    const nonNumericActualPolicy: CompiledPolicy = {
      name: "non-numeric",
      version: 1,
      policyVersionId: "sha256:" + "4".repeat(64),
      sourceDigest: "sha256:" + "5".repeat(64),
      subjects: { agents: [], roles: [] },
      resources: { repositories: [], environments: [] },
      rules: [
        {
          id: "bound-on-repository",
          effect: "allow",
          capabilities: ["repository.read"],
          // "repository" resolves to a string, not a number — {min} must not match it.
          when: { repository: { min: 1 } },
        },
      ],
    };
    const nonNumeric = evaluatePolicies({
      policies: [nonNumericActualPolicy],
      action: baseAction({ capability: "repository.read" }),
      at,
    });
    expect(nonNumeric.outcome).toBe("deny");
  });

  it("denies with a constraint conflict when narrowing types disagree (array vs scalar)", () => {
    const mismatchedPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "mismatched-constraints", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          {
            id: "array-form",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: ["a"] },
          },
          {
            id: "scalar-form",
            effect: "allow_with_constraints",
            capabilities: ["shell.execute"],
            constraints: { executables: "a" },
          },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [mismatchedPolicy],
      action: baseAction({ capability: "shell.execute" }),
      at,
    });
    expect(decision.outcome).toBe("deny");
    expect(decision.reason_codes).toEqual(["CONSTRAINT_CONFLICT"]);
  });

  it("treats a matched allow_with_constraints rule with no constraints block as unconstrained", () => {
    const noConstraintsPolicy = compilePolicy({
      apiVersion: "aegis.dev/v1",
      kind: "Policy",
      metadata: { name: "no-constraints-block", version: 1 },
      spec: {
        subjects: { agents: [], roles: [] },
        resources: { repositories: [], environments: [] },
        rules: [
          { id: "bounded-read", effect: "allow_with_constraints", capabilities: ["repository.read"] },
        ],
      },
    });
    const decision = evaluatePolicies({
      policies: [noConstraintsPolicy],
      action: baseAction({ capability: "repository.read" }),
      at,
    });
    expect(decision.outcome).toBe("allow_with_constraints");
    expect(decision.constraints).toEqual({});
  });

  it("does not crash merging approval requirements for a matched rule missing its approvals block", () => {
    // Defensive path: only reachable if a CompiledPolicy is built by hand (bypassing
    // compilePolicy's approvals-required validation), e.g. by a future caller.
    const malformedPolicy: CompiledPolicy = {
      name: "malformed-approval",
      version: 1,
      policyVersionId: "sha256:" + "6".repeat(64),
      sourceDigest: "sha256:" + "7".repeat(64),
      subjects: { agents: [], roles: [] },
      resources: { repositories: [], environments: [] },
      rules: [{ id: "protect-main", effect: "require_approval", capabilities: ["pull_request.merge"] }],
    };
    const decision = evaluatePolicies({
      policies: [malformedPolicy],
      action: exampleAction,
      at,
    });
    expect(decision.outcome).toBe("require_approval");
    expect(decision.approval_requirements).toEqual({ minimum: 0, roles: [], expires_in_ms: 0 });
  });
});
