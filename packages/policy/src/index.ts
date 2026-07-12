import { parse as parseYaml } from "yaml";
import { sha256Digest } from "@aegis/crypto";
import { isKnownCapability, lookupCapability } from "@aegis/capabilities";
import { PolicyDocumentSchema, type ActionEnvelope, type PolicyDocument } from "@aegis/schemas";

/**
 * Reimplementation of @aegis/policy, whose original source was lost to pack
 * corruption during transfer (see RECOVERY_NOTES.md). Built from
 * docs/reference/policy-language.md, docs/reference/decision-precedence.md,
 * docs/architecture/enforcement-foundation.md, and the recovered example fixtures.
 * Verified against the recovered apps/cli/test/cli.integration.test.ts, which this
 * repo's original authors wrote as the acceptance test for this exact behavior.
 */

export interface ValidationIssue {
  readonly code: string;
  readonly message: string;
  readonly path?: string;
}

export type PolicyValidationResult =
  | { readonly ok: true; readonly document: PolicyDocument; readonly warnings: readonly string[] }
  | {
      readonly ok: false;
      readonly errors: readonly ValidationIssue[];
      readonly warnings: readonly string[];
    };

export interface CompiledApprovalSettings {
  readonly minimum: number;
  readonly roles: readonly string[];
  readonly expiresInMs: number;
}

export interface CompiledRule {
  readonly id: string;
  readonly effect: "allow" | "deny" | "require_approval" | "allow_with_constraints";
  readonly capabilities: readonly string[];
  readonly when?: Readonly<Record<string, unknown>>;
  readonly constraints?: Readonly<Record<string, unknown>>;
  readonly approvals?: CompiledApprovalSettings;
}

export interface CompiledPolicy {
  readonly name: string;
  readonly version: number;
  readonly policyVersionId: string;
  readonly sourceDigest: string;
  readonly subjects: { readonly agents: readonly string[]; readonly roles: readonly string[] };
  readonly resources: {
    readonly repositories: readonly string[];
    readonly environments: readonly string[];
  };
  readonly rules: readonly CompiledRule[];
}

export interface EvaluatePoliciesInput {
  readonly policies: readonly CompiledPolicy[];
  readonly action: ActionEnvelope;
  readonly at: Date;
}

export interface ApprovalRequirement {
  readonly minimum: number;
  readonly roles: readonly string[];
  readonly expires_in_ms: number;
}

export interface Decision {
  readonly action_digest: string;
  readonly outcome: "allow" | "allow_with_constraints" | "require_approval" | "deny";
  readonly reason_codes: readonly string[];
  readonly matched_rule_ids: readonly string[];
  readonly policy_version_ids: readonly string[];
  readonly constraints: Readonly<Record<string, unknown>>;
  readonly approval_requirements?: ApprovalRequirement;
}

const DURATION_PATTERN = /^(\d+)([smh])$/;
const MAX_APPROVAL_EXPIRY_MS = 24 * 60 * 60 * 1000;

function parseDuration(expiresIn: string): number | undefined {
  const match = DURATION_PATTERN.exec(expiresIn);
  if (!match) return undefined;
  const value = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000;
  return value * multiplier;
}

export function validatePolicyYaml(source: string): PolicyValidationResult {
  const warnings: string[] = [];
  let parsed: unknown;
  try {
    parsed = parseYaml(source);
  } catch (error) {
    return {
      ok: false,
      errors: [{ code: "YAML_PARSE_ERROR", message: (error as Error).message }],
      warnings,
    };
  }

  const schemaResult = PolicyDocumentSchema.safeParse(parsed);
  if (!schemaResult.success) {
    return {
      ok: false,
      errors: schemaResult.error.issues.map((issue) => ({
        code: `SCHEMA_${issue.code.toUpperCase()}`,
        message: issue.message,
        path: issue.path.join("."),
      })),
      warnings,
    };
  }

  const document = schemaResult.data;
  const errors: ValidationIssue[] = [];
  const seenIds = new Set<string>();

  for (const rule of document.spec.rules) {
    if (seenIds.has(rule.id)) {
      errors.push({ code: "DUPLICATE_RULE_ID", message: `Duplicate rule id: ${rule.id}` });
    }
    seenIds.add(rule.id);

    for (const capability of rule.capabilities) {
      if (!isKnownCapability(capability)) {
        errors.push({ code: "CAPABILITY_UNKNOWN", message: `Unknown capability: ${capability}` });
      }
    }

    if (rule.effect === "require_approval" && !rule.approvals) {
      errors.push({
        code: "APPROVALS_REQUIRED",
        message: `Rule ${rule.id} has effect require_approval but no approvals block`,
      });
    }
    if (rule.effect !== "require_approval" && rule.approvals) {
      errors.push({
        code: "APPROVALS_NOT_ALLOWED",
        message: `Rule ${rule.id} defines approvals but effect is not require_approval`,
      });
    }
    if (rule.effect === "allow_with_constraints" && !rule.constraints) {
      errors.push({
        code: "CONSTRAINTS_REQUIRED",
        message: `Rule ${rule.id} has effect allow_with_constraints but no constraints block`,
      });
    }

    if (rule.approvals) {
      const ms = parseDuration(rule.approvals.expires_in);
      if (ms === undefined) {
        errors.push({
          code: "APPROVAL_EXPIRY_INVALID",
          message: `Rule ${rule.id} has an invalid approvals.expires_in value`,
        });
      } else if (ms > MAX_APPROVAL_EXPIRY_MS) {
        errors.push({
          code: "APPROVAL_EXPIRY_TOO_LONG",
          message: `Rule ${rule.id} approvals.expires_in exceeds 24 hours`,
        });
      }
    }

    for (const key of Object.keys(rule.constraints ?? {})) {
      for (const capability of rule.capabilities) {
        const definition = lookupCapability(capability);
        if (definition && !definition.allowedConstraints.includes(key)) {
          errors.push({
            code: "CONSTRAINT_NOT_ALLOWED",
            message: `Constraint "${key}" is not allowed for capability ${capability} in rule ${rule.id}`,
          });
        }
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors, warnings };
  return { ok: true, document, warnings };
}

export function compilePolicy(document: PolicyDocument): CompiledPolicy {
  const parsed = PolicyDocumentSchema.parse(document);
  const sourceDigest = sha256Digest(parsed);
  const policyVersionId = sha256Digest({
    name: parsed.metadata.name,
    version: parsed.metadata.version,
    source_digest: sourceDigest,
  });

  const rules: CompiledRule[] = parsed.spec.rules.map((rule) => ({
    id: rule.id,
    effect: rule.effect,
    capabilities: rule.capabilities,
    ...(rule.when ? { when: rule.when } : {}),
    ...(rule.constraints ? { constraints: rule.constraints } : {}),
    ...(rule.approvals
      ? {
          approvals: {
            minimum: rule.approvals.minimum,
            roles: rule.approvals.roles,
            expiresInMs: parseDuration(rule.approvals.expires_in) ?? 0,
          },
        }
      : {}),
  }));

  return {
    name: parsed.metadata.name,
    version: parsed.metadata.version,
    policyVersionId,
    sourceDigest,
    subjects: parsed.spec.subjects,
    resources: parsed.spec.resources,
    rules,
  };
}

function matchesWildcardList(list: readonly string[], value: string | undefined): boolean {
  if (list.length === 0) return true;
  if (value === undefined) return false;
  return list.includes(value);
}

function subjectsMatch(subjects: CompiledPolicy["subjects"], action: ActionEnvelope): boolean {
  return (
    matchesWildcardList(subjects.agents, action.context.agent_name) &&
    matchesWildcardList(subjects.roles, action.context.user_role)
  );
}

function resourcesMatch(resources: CompiledPolicy["resources"], action: ActionEnvelope): boolean {
  return (
    matchesWildcardList(resources.repositories, action.target.repository) &&
    matchesWildcardList(resources.environments, action.target.environment)
  );
}

function resolveConditionSource(key: string, action: ActionEnvelope, at: Date): unknown {
  switch (key) {
    case "agent_id":
      return action.agent_id;
    case "user_role":
      return action.context.user_role;
    case "repository":
      return action.target.repository;
    case "environment":
      return action.target.environment;
    case "capability":
      return action.capability;
    case "branch":
      return action.target.branch;
    case "sensitive_paths_touched":
      return action.context.sensitive_paths_touched;
    case "interactive_user_present":
      return action.context.interactive_user_present;
    case "changed_files":
      return action.context.changed_files;
    case "prior_denials_in_session":
      return action.context.prior_denials_in_session;
    case "provider_verified":
      return action.evidence.provider_verified;
    case "requested_permissions_increase":
      return action.context.requested_permissions_increase;
    case "utc_hour":
      return at.getUTCHours();
    default:
      return undefined;
  }
}

function matchCondition(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return expected.some((allowed) => allowed === actual);
  }
  if (expected !== null && typeof expected === "object") {
    const obj = expected as Record<string, unknown>;
    if ("any" in obj) {
      const list = obj.any as readonly string[];
      if (Array.isArray(actual)) return actual.some((item) => list.includes(item as string));
      return list.includes(actual as string);
    }
    if ("min" in obj || "max" in obj) {
      if (typeof actual !== "number") return false;
      if (typeof obj.min === "number" && actual < obj.min) return false;
      if (typeof obj.max === "number" && actual > obj.max) return false;
      return true;
    }
    return false;
  }
  return actual === expected;
}

function conditionsMatch(
  when: Readonly<Record<string, unknown>> | undefined,
  action: ActionEnvelope,
  at: Date,
): boolean {
  if (!when) return true;
  return Object.entries(when).every(([key, expected]) =>
    matchCondition(resolveConditionSource(key, action, at), expected),
  );
}

function sortedRuleIds(matches: ReadonlyArray<{ rule: CompiledRule }>): readonly string[] {
  return Array.from(new Set(matches.map((match) => match.rule.id))).sort();
}

function sortedPolicyVersionIds(policies: readonly CompiledPolicy[]): readonly string[] {
  return Array.from(new Set(policies.map((policy) => policy.policyVersionId))).sort();
}

function narrowConstraints(
  list: ReadonlyArray<Readonly<Record<string, unknown>>>,
): Record<string, unknown> | null {
  const result: Record<string, unknown> = {};
  const keys = new Set<string>();
  for (const constraints of list) for (const key of Object.keys(constraints)) keys.add(key);

  for (const key of keys) {
    const values = list.map((constraints) => constraints[key]).filter((value) => value !== undefined);
    if (values.length === 0) continue;
    const first = values[0];

    if (typeof first === "number") {
      if (!values.every((value) => typeof value === "number")) return null;
      result[key] = Math.min(...(values as number[]));
    } else if (Array.isArray(first)) {
      if (!values.every((value) => Array.isArray(value))) return null;
      let intersection = values[0] as unknown[];
      for (const value of values.slice(1)) {
        intersection = intersection.filter((item) => (value as unknown[]).includes(item));
      }
      if (intersection.length === 0) return null;
      result[key] = intersection;
    } else {
      if (!values.every((value) => value === first)) return null;
      result[key] = first;
    }
  }

  return result;
}

function mergeApprovalRequirements(
  matches: ReadonlyArray<{ rule: CompiledRule }>,
): ApprovalRequirement {
  let minimum = 0;
  let expiresInMs = Number.POSITIVE_INFINITY;
  const roles = new Set<string>();

  for (const { rule } of matches) {
    if (!rule.approvals) continue;
    minimum = Math.max(minimum, rule.approvals.minimum);
    expiresInMs = Math.min(expiresInMs, rule.approvals.expiresInMs);
    for (const role of rule.approvals.roles) roles.add(role);
  }

  return {
    minimum,
    roles: Array.from(roles).sort(),
    expires_in_ms: Number.isFinite(expiresInMs) ? expiresInMs : 0,
  };
}

export function evaluatePolicies(input: EvaluatePoliciesInput): Decision {
  const { policies, action, at } = input;
  const actionDigest = sha256Digest(action);
  const policyVersionIds = sortedPolicyVersionIds(policies);

  const capabilityDefinition = lookupCapability(action.capability);
  if (!capabilityDefinition) {
    return {
      action_digest: actionDigest,
      outcome: "deny",
      reason_codes: ["CAPABILITY_UNKNOWN"],
      matched_rule_ids: [],
      policy_version_ids: policyVersionIds,
      constraints: {},
    };
  }

  const missingEvidence = capabilityDefinition.mandatoryEvidence.filter(
    (item) => !action.evidence.provider_verified.includes(item),
  );
  if (missingEvidence.length > 0) {
    return {
      action_digest: actionDigest,
      outcome: "deny",
      reason_codes: ["MANDATORY_EVIDENCE_MISSING"],
      matched_rule_ids: [],
      policy_version_ids: policyVersionIds,
      constraints: {},
    };
  }

  const matches: Array<{ policy: CompiledPolicy; rule: CompiledRule }> = [];
  for (const policy of policies) {
    if (!subjectsMatch(policy.subjects, action)) continue;
    if (!resourcesMatch(policy.resources, action)) continue;
    for (const rule of policy.rules) {
      if (!rule.capabilities.includes(action.capability)) continue;
      if (!conditionsMatch(rule.when, action, at)) continue;
      matches.push({ policy, rule });
    }
  }

  const denyMatches = matches.filter((match) => match.rule.effect === "deny");
  if (denyMatches.length > 0) {
    return {
      action_digest: actionDigest,
      outcome: "deny",
      reason_codes: ["DENIED_BY_POLICY"],
      matched_rule_ids: sortedRuleIds(denyMatches),
      policy_version_ids: policyVersionIds,
      constraints: {},
    };
  }

  const approvalMatches = matches.filter((match) => match.rule.effect === "require_approval");
  if (approvalMatches.length > 0) {
    return {
      action_digest: actionDigest,
      outcome: "require_approval",
      reason_codes: ["APPROVAL_REQUIRED_BY_POLICY"],
      matched_rule_ids: sortedRuleIds(approvalMatches),
      policy_version_ids: policyVersionIds,
      constraints: {},
      approval_requirements: mergeApprovalRequirements(approvalMatches),
    };
  }

  const constrainedMatches = matches.filter((match) => match.rule.effect === "allow_with_constraints");
  if (constrainedMatches.length > 0) {
    const narrowed = narrowConstraints(constrainedMatches.map((match) => match.rule.constraints ?? {}));
    if (narrowed === null) {
      return {
        action_digest: actionDigest,
        outcome: "deny",
        reason_codes: ["CONSTRAINT_CONFLICT"],
        matched_rule_ids: sortedRuleIds(constrainedMatches),
        policy_version_ids: policyVersionIds,
        constraints: {},
      };
    }
    return {
      action_digest: actionDigest,
      outcome: "allow_with_constraints",
      reason_codes: ["ALLOWED_WITH_CONSTRAINTS"],
      matched_rule_ids: sortedRuleIds(constrainedMatches),
      policy_version_ids: policyVersionIds,
      constraints: narrowed,
    };
  }

  const allowMatches = matches.filter((match) => match.rule.effect === "allow");
  if (allowMatches.length > 0) {
    return {
      action_digest: actionDigest,
      outcome: "allow",
      reason_codes: ["ALLOWED_BY_POLICY"],
      matched_rule_ids: sortedRuleIds(allowMatches),
      policy_version_ids: policyVersionIds,
      constraints: {},
    };
  }

  return {
    action_digest: actionDigest,
    outcome: "deny",
    reason_codes: ["NO_MATCHING_RULE"],
    matched_rule_ids: [],
    policy_version_ids: policyVersionIds,
    constraints: {},
  };
}
