# Capability Registry

The canonical registry maps provider-specific operations into stable capabilities. Every entry specifies read/write access, risk class, offline eligibility, mandatory evidence, and allowed constraints.

Initial namespaces are `repository`, `branch`, `pull_request`, `workflow`, `deployment`, `environment`, `shell`, `filesystem`, `process`, `network`, `secret`, and `infrastructure`.

Unknown capabilities always return `CAPABILITY_UNKNOWN` and deny. A policy cannot activate when it references an unknown capability or a constraint unsupported by that capability.

Critical writes—including protected merges, deployments, rollback, environment mutation, secret reads, deletion, and infrastructure changes—are offline-ineligible by default.
