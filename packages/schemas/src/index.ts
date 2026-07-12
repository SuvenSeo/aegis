import { z } from "zod";

/**
 * Reconstructed from the recovered example fixture (examples/actions/merge-main.json)
 * and CLI usage (apps/cli/src/index.ts). The original @aegis/schemas implementation
 * was lost to pack corruption; this is a faithful-to-spec rebuild, not recovered source.
 */
export const ActionTargetSchema = z
  .object({
    repository: z.string().min(1),
    branch: z.string().optional(),
    environment: z.string().optional(),
    pull_request: z.number().int().optional(),
  })
  .passthrough();

export const ActionOperationSchema = z.object({
  method: z.string().min(1),
  arguments_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  redacted_summary: z.string(),
});

export const ActionContextSchema = z
  .object({
    agent_name: z.string(),
    user_role: z.string(),
    interactive_user_present: z.boolean(),
    changed_files: z.number().int().nonnegative(),
    sensitive_paths_touched: z.array(z.string()),
    prior_denials_in_session: z.number().int().nonnegative(),
    requested_permissions_increase: z.boolean(),
  })
  .passthrough();

export const ActionEvidenceSchema = z.object({
  provider_verified: z.array(z.string()),
  local_observed: z.array(z.string()),
  model_derived: z.array(z.string()),
});

export const ActionEnvelopeSchema = z.object({
  schema_version: z.string(),
  action_id: z.string().min(1),
  organization_id: z.string().min(1),
  gateway_id: z.string().min(1),
  user_id: z.string().min(1),
  agent_id: z.string().min(1),
  session_id: z.string().min(1),
  timestamp: z.string().datetime({ offset: false }),
  provider: z.string().min(1),
  capability: z.string().min(1),
  target: ActionTargetSchema,
  operation: ActionOperationSchema,
  context: ActionContextSchema,
  evidence: ActionEvidenceSchema,
});

export type ActionEnvelope = z.infer<typeof ActionEnvelopeSchema>;

/**
 * Field list reconstructed from docs/reference/approval-grants.md ("A signed grant
 * binds: schema version and grant identifier; organization and subject; action digest
 * and target digest; canonical capability; narrowing constraints; issue and expiry
 * timestamps; maximum uses and random nonce; issuer key identifier.") and CLI usage.
 */
export const ApprovalGrantSchema = z.object({
  schema_version: z.string(),
  grant_id: z.string().min(1),
  organization_id: z.string().min(1),
  subject_id: z.string().min(1),
  action_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  target_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  capability: z.string().min(1),
  constraints: z.record(z.string(), z.unknown()).default({}),
  issued_at: z.string().datetime({ offset: false }),
  expires_at: z.string().datetime({ offset: false }),
  max_uses: z.number().int().positive(),
  nonce: z.string().min(1),
  issuer_key_id: z.string().min(1),
  signature: z.string().min(1),
});

export type ApprovalGrant = z.infer<typeof ApprovalGrantSchema>;

/**
 * Policy envelope reconstructed from docs/reference/policy-language.md and
 * examples/policies/production-code-guard.yaml. Condition values may be a primitive,
 * an array of allowed values, a numeric bound, or a string-set overlap test.
 */
const ConditionValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.union([z.string(), z.number()])),
  z.object({ min: z.number().optional(), max: z.number().optional() }).strict(),
  z.object({ any: z.array(z.string()) }).strict(),
]);

// expires_in's format (\d+[smh]) and 24h ceiling are semantic rules, validated in
// @aegis/policy's validatePolicyYaml — not duplicated here, to keep one source of
// truth (APPROVAL_EXPIRY_INVALID / APPROVAL_EXPIRY_TOO_LONG).
const ApprovalSettingsSchema = z.object({
  minimum: z.number().int().positive(),
  roles: z.array(z.string()),
  expires_in: z.string().min(1),
});

const PolicyRuleSchema = z
  .object({
    id: z.string().min(1),
    effect: z.enum(["allow", "deny", "require_approval", "allow_with_constraints"]),
    capabilities: z.array(z.string().min(1)).min(1),
    when: z.record(z.string(), ConditionValueSchema).optional(),
    constraints: z.record(z.string(), z.unknown()).optional(),
    approvals: ApprovalSettingsSchema.optional(),
  })
  .strict();

export const PolicyDocumentSchema = z
  .object({
    apiVersion: z.literal("aegis.dev/v1"),
    kind: z.literal("Policy"),
    metadata: z
      .object({
        name: z.string().min(1),
        version: z.number().int().positive(),
      })
      .strict(),
    spec: z
      .object({
        subjects: z
          .object({
            agents: z.array(z.string()).default([]),
            roles: z.array(z.string()).default([]),
          })
          .strict(),
        resources: z
          .object({
            repositories: z.array(z.string()).default([]),
            environments: z.array(z.string()).default([]),
          })
          .strict(),
        rules: z.array(PolicyRuleSchema).min(1),
      })
      .strict(),
  })
  .strict();

export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
