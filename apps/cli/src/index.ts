#!/usr/bin/env node
import { createPublicKey, type KeyObject } from "node:crypto";
import { Command } from "commander";
import { verifyAuditChain, type AuditKeyResolver } from "@aegis/audit";
import { verifyApprovalGrant, type ApprovalVerifier } from "@aegis/approvals";
import { verifyCanonical } from "@aegis/crypto";
import { compilePolicy, evaluatePolicies, validatePolicyYaml } from "@aegis/policy";
import { ActionEnvelopeSchema, ApprovalGrantSchema } from "@aegis/schemas";
import { CliError, emitHuman, emitJson, readJsonFile, readUtf8File, safeFailure } from "./io.js";

interface OutputOptions {
  readonly json?: boolean;
}

interface KeysFile {
  readonly keys: Readonly<Record<string, string>>;
  readonly revoked?: readonly string[];
}

function output(value: unknown, options: OutputOptions, humanMessage: string): void {
  if (options.json) emitJson(value);
  else emitHuman(humanMessage);
}

async function runCommand(
  options: OutputOptions,
  operation: () => Promise<{
    readonly value: unknown;
    readonly human: string;
    readonly exitCode?: number;
  }>,
): Promise<void> {
  try {
    const result = await operation();
    output(result.value, options, result.human);
    if (result.exitCode !== undefined) process.exitCode = result.exitCode;
  } catch (error) {
    const failure = safeFailure(error);
    const envelope = {
      ok: false,
      code: failure.code,
      message: failure.message,
      ...(failure.details === undefined ? {} : { details: failure.details }),
    };
    output(envelope, options, `${failure.code}: ${failure.message}`);
    process.exitCode = failure.exitCode;
  }
}

function requireValidDate(value: string): Date {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    throw new CliError("TIMESTAMP_INVALID", "Timestamp must be UTC RFC 3339 with milliseconds.", 2);
  }
  return date;
}

async function loadPolicy(path: string) {
  const result = validatePolicyYaml(await readUtf8File(path));
  if (!result.ok) {
    throw new CliError("POLICY_INVALID", "Policy validation failed.", 2, {
      errors: result.errors,
      warnings: result.warnings,
    });
  }
  return {
    document: result.document,
    warnings: result.warnings,
    compiled: compilePolicy(result.document),
  };
}

async function loadAction(path: string) {
  const parsed = ActionEnvelopeSchema.safeParse(await readJsonFile(path));
  if (!parsed.success) {
    throw new CliError("ACTION_INVALID", "Action validation failed.", 2, {
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        code: issue.code,
      })),
    });
  }
  return parsed.data;
}

function parseKeysFile(input: unknown): KeysFile {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new CliError("KEYS_INVALID", "Key file must contain an object.", 2);
  }
  const record = input as Record<string, unknown>;
  if (!record.keys || typeof record.keys !== "object" || Array.isArray(record.keys)) {
    throw new CliError("KEYS_INVALID", "Key file must contain a keys object.", 2);
  }
  const keys: Record<string, string> = {};
  for (const [keyId, pem] of Object.entries(record.keys)) {
    if (typeof pem !== "string")
      throw new CliError("KEYS_INVALID", "Every public key must be PEM text.", 2);
    keys[keyId] = pem;
  }
  const revoked = Array.isArray(record.revoked)
    ? record.revoked.filter((value): value is string => typeof value === "string")
    : undefined;
  return { keys, ...(revoked ? { revoked } : {}) };
}

function createKeyObjects(keys: Readonly<Record<string, string>>): ReadonlyMap<string, KeyObject> {
  const result = new Map<string, KeyObject>();
  try {
    for (const [keyId, pem] of Object.entries(keys)) result.set(keyId, createPublicKey(pem));
  } catch {
    throw new CliError("PUBLIC_KEY_INVALID", "A supplied public key is invalid.", 2);
  }
  return result;
}

const program = new Command();
program
  .name("aegis")
  .description("Aegis deterministic agent-governance security core")
  .version("0.1.0");

const policy = program.command("policy").description("Validate and test policy files");
policy
  .command("validate")
  .argument("<file>")
  .option("--json", "emit machine-readable JSON")
  .action(async (file: string, options: OutputOptions) => {
    await runCommand(options, async () => {
      const loaded = await loadPolicy(file);
      return {
        value: {
          ok: true,
          policy: loaded.compiled.name,
          version: loaded.compiled.version,
          policy_version_id: loaded.compiled.policyVersionId,
          source_digest: loaded.compiled.sourceDigest,
          warnings: loaded.warnings,
        },
        human: `Policy ${loaded.compiled.name} v${String(loaded.compiled.version)} is valid.`,
      };
    });
  });

policy
  .command("test")
  .argument("<file>")
  .option("--json", "emit machine-readable JSON")
  .action(async (file: string, options: OutputOptions) => {
    await runCommand(options, async () => {
      const loaded = await loadPolicy(file);
      const repeated = compilePolicy(loaded.document);
      const deterministic = repeated.sourceDigest === loaded.compiled.sourceDigest;
      if (!deterministic)
        throw new CliError(
          "POLICY_NONDETERMINISTIC",
          "Policy compilation was not deterministic.",
          70,
        );
      return {
        value: {
          ok: true,
          policy: loaded.compiled.name,
          checks: ["schema", "semantic", "capabilities", "constraints", "deterministic_compile"],
        },
        human: `Policy ${loaded.compiled.name} passed static tests.`,
      };
    });
  });

program
  .command("action")
  .description("Action envelope operations")
  .command("validate")
  .argument("<file>")
  .option("--json", "emit machine-readable JSON")
  .action(async (file: string, options: OutputOptions) => {
    await runCommand(options, async () => {
      const action = await loadAction(file);
      return {
        value: { ok: true, action_id: action.action_id, capability: action.capability },
        human: `Action ${action.action_id} is valid.`,
      };
    });
  });

program
  .command("simulate")
  .requiredOption("--policy <file>")
  .requiredOption("--action <file>")
  .requiredOption("--at <timestamp>")
  .option("--json", "emit machine-readable JSON")
  .action(async (options: OutputOptions & { policy: string; action: string; at: string }) => {
    await runCommand(options, async () => {
      const [loadedPolicy, action] = await Promise.all([
        loadPolicy(options.policy),
        loadAction(options.action),
      ]);
      const decision = evaluatePolicies({
        policies: [loadedPolicy.compiled],
        action,
        at: requireValidDate(options.at),
      });
      return {
        value: decision,
        human: `${decision.outcome}: ${decision.reason_codes.join(", ")}`,
        ...(decision.outcome === "deny" ? { exitCode: 3 } : {}),
      };
    });
  });

program
  .command("approval")
  .description("Approval grant operations")
  .command("verify")
  .argument("<file>")
  .requiredOption("--public-key <file>")
  .option("--json", "emit machine-readable JSON")
  .action(async (file: string, options: OutputOptions & { publicKey: string }) => {
    await runCommand(options, async () => {
      const parsed = ApprovalGrantSchema.safeParse(await readJsonFile(file));
      if (!parsed.success)
        throw new CliError("APPROVAL_SCHEMA_INVALID", "Approval grant is malformed.", 4);
      let key: KeyObject;
      try {
        key = createPublicKey(await readUtf8File(options.publicKey, 65_536));
      } catch (error) {
        if (error instanceof CliError) throw error;
        throw new CliError("PUBLIC_KEY_INVALID", "Public key is invalid.", 2);
      }
      const verifier: ApprovalVerifier = {
        verify: (value, signature) => verifyCanonical(value, signature, key),
      };
      const verification = verifyApprovalGrant({
        grant: parsed.data,
        verifier,
        organizationId: parsed.data.organization_id,
        subjectId: parsed.data.subject_id,
        actionDigest: parsed.data.action_digest,
        targetDigest: parsed.data.target_digest,
        capability: parsed.data.capability,
        requestedConstraints: parsed.data.constraints,
        at: new Date(),
        usedNonces: new Set(),
        usedCount: 0,
      });
      return {
        value: verification,
        human: verification.valid
          ? "Approval grant is valid."
          : `Approval grant failed: ${verification.code}`,
        ...(verification.valid ? {} : { exitCode: 4 }),
      };
    });
  });

program
  .command("audit")
  .description("Audit chain operations")
  .command("verify")
  .argument("<file>")
  .requiredOption("--keys <file>")
  .option("--json", "emit machine-readable JSON")
  .action(async (file: string, options: OutputOptions & { keys: string }) => {
    await runCommand(options, async () => {
      const events = await readJsonFile(file, 16_777_216);
      if (!Array.isArray(events))
        throw new CliError("AUDIT_INPUT_INVALID", "Audit input must be a JSON array.", 2);
      const keyFile = parseKeysFile(await readJsonFile(options.keys));
      const publicKeys = createKeyObjects(keyFile.keys);
      const revoked = new Set(keyFile.revoked ?? []);
      const resolver: AuditKeyResolver = {
        verify: (signerId, value, signature) => {
          const key = publicKeys.get(signerId);
          return key ? verifyCanonical(value, signature, key) : false;
        },
        isRevoked: (signerId) => revoked.has(signerId),
      };
      const verification = verifyAuditChain(events, resolver);
      return {
        value: verification,
        human: verification.valid
          ? `Audit chain is valid (${String(verification.eventCount)} events).`
          : `Audit verification failed at event ${String(verification.index)}: ${verification.code}`,
        ...(verification.valid ? {} : { exitCode: 4 }),
      };
    });
  });

await program.parseAsync(process.argv);
