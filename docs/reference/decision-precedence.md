# Decision Precedence

The decision reducer is deterministic and order-independent for security outcomes.

1. An explicit deny wins immediately.
2. Missing mandatory evidence returns deny.
3. Any matching approval rule returns `require_approval`.
4. Matching constrained allows are narrowed; conflict returns deny.
5. Matching allows return allow.
6. No match returns default deny.

Decision results include the action digest, outcome, stable reason codes, sorted matched rule identifiers, sorted policy-version identifiers, normalized constraints, and approval requirements when applicable. Human-readable explanations are derived from these fields and never serve as policy input.
