import { describe, expect, it } from "vitest";
import { isKnownCapability, listCapabilities, lookupCapability } from "../src/index.js";

// Exact expected values for every registry entry — asserted field-by-field so any
// change to a capability's access/riskClass/offlineEligible/mandatoryEvidence/
// allowedConstraints is caught, not just its presence.
const EXPECTED: Record<string, ReturnType<typeof lookupCapability>> = {
  "repository.read": {
    capability: "repository.read",
    access: "read",
    riskClass: "low",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["path_prefixes"],
  },
  "repository.write": {
    capability: "repository.write",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: ["branch", "path_prefixes", "max_changed_files"],
  },
  "branch.push": {
    capability: "branch.push",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "branch"],
    allowedConstraints: ["branch", "max_changed_files"],
  },
  "pull_request.read": {
    capability: "pull_request.read",
    access: "read",
    riskClass: "low",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: [],
  },
  "pull_request.merge": {
    capability: "pull_request.merge",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "branch"],
    allowedConstraints: ["branch", "max_changed_files"],
  },
  "workflow.dispatch": {
    capability: "workflow.dispatch",
    access: "write",
    riskClass: "high",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: ["path_prefixes"],
  },
  "deployment.trigger": {
    capability: "deployment.trigger",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "environment"],
    allowedConstraints: ["environment", "max_duration"],
  },
  "deployment.rollback": {
    capability: "deployment.rollback",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository", "environment"],
    allowedConstraints: ["environment"],
  },
  "environment.write": {
    capability: "environment.write",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["environment"],
    allowedConstraints: ["environment"],
  },
  "shell.execute": {
    capability: "shell.execute",
    access: "write",
    riskClass: "high",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["executables", "max_duration"],
  },
  "filesystem.write": {
    capability: "filesystem.write",
    access: "write",
    riskClass: "medium",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["path_prefixes"],
  },
  "process.spawn": {
    capability: "process.spawn",
    access: "write",
    riskClass: "high",
    offlineEligible: true,
    mandatoryEvidence: [],
    allowedConstraints: ["executables", "max_duration"],
  },
  "network.request": {
    capability: "network.request",
    access: "write",
    riskClass: "medium",
    offlineEligible: false,
    mandatoryEvidence: [],
    allowedConstraints: ["hosts"],
  },
  "secret.read": {
    capability: "secret.read",
    access: "read",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["repository"],
    allowedConstraints: [],
  },
  "infrastructure.mutate": {
    capability: "infrastructure.mutate",
    access: "write",
    riskClass: "critical",
    offlineEligible: false,
    mandatoryEvidence: ["environment"],
    allowedConstraints: ["environment"],
  },
};

describe("capabilities registry", () => {
  it("has exactly the expected number of entries", () => {
    expect(listCapabilities().length).toBe(Object.keys(EXPECTED).length);
  });

  for (const [capability, expected] of Object.entries(EXPECTED)) {
    it(`defines ${capability} exactly`, () => {
      expect(lookupCapability(capability)).toEqual(expected);
    });
  }

  it("reports unknown capabilities as unknown", () => {
    expect(isKnownCapability("teleport.activate")).toBe(false);
    expect(lookupCapability("teleport.activate")).toBeUndefined();
  });

  it("reports known capabilities as known, consistently with lookupCapability", () => {
    for (const capability of Object.keys(EXPECTED)) {
      expect(isKnownCapability(capability)).toBe(true);
    }
  });

  it("lists exactly the same entries lookupCapability returns", () => {
    const listed = new Map(listCapabilities().map((def) => [def.capability, def]));
    for (const [capability, expected] of Object.entries(EXPECTED)) {
      expect(listed.get(capability)).toEqual(expected);
    }
  });

  it("every critical-write capability is offline-ineligible", () => {
    for (const definition of listCapabilities()) {
      if (definition.riskClass === "critical" && definition.access === "write") {
        expect(definition.offlineEligible).toBe(false);
      }
    }
  });
});
