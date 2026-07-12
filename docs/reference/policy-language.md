# Policy Language Reference

## Envelope

Every policy uses:

```yaml
apiVersion: aegis.dev/v1
kind: Policy
metadata:
  name: production-code-guard
  version: 1
```

Unknown versions, kinds, or keys are rejected.

## Subjects and resources

```yaml
spec:
  subjects:
    agents: [coding-agent]
    roles: [developer]
  resources:
    repositories: [acme/api]
    environments: [production]
```

An empty list is a wildcard. Repository patterns support exact path segments and `*` as a complete segment; arbitrary regular expressions are prohibited.

## Effects

Precedence from strongest to weakest:

1. `deny`
2. missing mandatory evidence
3. `require_approval`
4. `allow_with_constraints`
5. `allow`
6. default deny

## Supported conditions

| Condition                        | Source                               |
| -------------------------------- | ------------------------------------ |
| `agent_id`                       | action identity                      |
| `user_role`                      | action context                       |
| `repository`                     | action target                        |
| `environment`                    | action target                        |
| `capability`                     | canonical capability                 |
| `branch`                         | action target                        |
| `sensitive_paths_touched`        | action context                       |
| `interactive_user_present`       | action context                       |
| `changed_files`                  | action context                       |
| `prior_denials_in_session`       | action context                       |
| `provider_verified`              | evidence provenance                  |
| `requested_permissions_increase` | action context                       |
| `utc_hour`                       | caller-supplied evaluation timestamp |

Conditions support exact primitive equality, allowed-value arrays, numeric `{ min, max }` bounds, and string-set `{ any: [...] }` overlap.

## Constraints

Constraints are capability-specific. Examples include `branch`, `max_changed_files`, `path_prefixes`, `environment`, `max_duration`, `hosts`, and `executables`. Multiple constrained allows are combined only when their values can be narrowed: numeric maxima take the smallest value and sets use intersection. Conflicts produce deny.

## Approval settings

Only `require_approval` rules may define:

```yaml
approvals:
  minimum: 1
  roles: [maintainer, security]
  expires_in: 10m
```

Phase 1 accepts `s`, `m`, and `h` duration units up to 24 hours.

## Complete examples

Allow:

```yaml
- id: allow-read
  effect: allow
  capabilities: [repository.read]
```

Deny:

```yaml
- id: deny-permission-escalation
  effect: deny
  capabilities: [repository.write]
  when:
    requested_permissions_increase: true
```

Constrained allow:

```yaml
- id: bounded-staging-deploy
  effect: allow_with_constraints
  capabilities: [deployment.trigger]
  when:
    environment: staging
  constraints:
    environment: staging
    max_duration: 900000
```

Approval:

```yaml
- id: protect-main
  effect: require_approval
  capabilities: [branch.push, pull_request.merge]
  when:
    branch: main
  approvals:
    minimum: 1
    roles: [maintainer]
    expires_in: 10m
```
