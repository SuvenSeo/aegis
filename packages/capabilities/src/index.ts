/**
 * Rebuilt from docs/reference/capabilities.md — the original @aegis/capabilities
 * registry was lost to pack corruption. The doc specifies the namespaces
 * (repository, branch, pull_request, workflow, deployment, environment, shell,
 * filesystem, process, network, secret, infrastructure), that every entry carries
 * read/write access, risk class, offline eligibility, mandatory evidence, and allowed
 * constraints, that critical writes are offline-ineligible by default, and that
 * unknown capabilities always deny with CAPABILITY_UNKNOWN. The specific entries below
 * are a reasonable, spec-consistent population, not recovered source — extend this
 * table as real capabilities are needed.
 */
export type CapabilityAccess = "read" | "write";
export type CapabilityRiskClass = "low" | "medium" | "high" | "critical";

export interface CapabilityDefinition {
  readonly capability: string;
  readonly access: CapabilityAccess;
  readonly riskClass: CapabilityRiskClass;
  readonly offlineEligible: boolean;
  readonly mandatoryEvidence: readonly string[];
  readonly allowedConstraints: readonly string[];
}

function define(def: CapabilityDefinition): [string, CapabilityDefinition] {
  return [def.capability, def];
}

const REGISTRY = new Map<string, CapabilityDefinition>([
  define({
    capability: "repository.read",
    access: "read",
    riskClass: "low",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["path_prefixes"],
  }),
  define({
    capability: "repository.write",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: ["branch", "path_prefixes", "max_changed_files"],
  }),
  define({
    capability: "branch.push",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "branch"],
    allowedConstraints: ["branch", "max_changed_files"],
  }),
  define({
    capability: "pull_request.read",
    access: "read",
    riskClass: "low",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: [],
  }),
  define({
    capability: "pull_request.merge",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "branch"],
    allowedConstraints: ["branch", "max_changed_files"],
  }),
  define({
    capability: "workflow.dispatch",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: ["path_prefixes"],
  }),
  define({
    capability: "deployment.trigger",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "environment"],
    allowedConstraints: ["environment", "max_duration"],
  }),
  define({
    capability: "deployment.rollback",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "environment"],
    allowedConstraints: ["environment"],
  }),
  define({
    capability: "environment.write",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["environment"],
    allowedConstraints: ["environment"],
  }),
  define({
    capability: "shell.execute",
    access: "write",
    riskClass: "high",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["executables", "max_duration"],
  }),
  define({
    capability: "filesystem.write",
    access: "write",
    riskClass: "medium",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["path_prefixes"],
  }),
  define({
    capability: "process.spawn",
    access: "write",
    riskClass: "high",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["executables", "max_duration"],
  }),
  define({
    capability: "network.request",
    access: "write",
    riskClass: "medium",
    offlineEligible: false,
    mandatoryEvidence: [],
    allowedConstraints: ["hosts"],
  }),
  define({
    capability: "secret.read",
    access: "read",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: [],
  }),
  define({
    capability: "infrastructure.mutate",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["environment"],
    allowedConstraints: ["environment"],
  }),
]);

export function lookupCapability(capability: string): CapabilityDefinition | undefined {
  return REGISTRY.get(capability);
}

export function isKnownCapability(capability: string): boolean {
  return REGISTRY.has(capability);
}

export function listCapabilities(): readonly CapabilityDefinition[] {
  return Array.from(REGISTRY.values());
}
