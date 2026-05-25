# Release Decision Record

Use this compact record when `workforce-qa-release` is asked whether work is ready to ship.

```text
RELEASE DECISION
Artifact:
Decision: ship | no-ship | not-applicable
Confidence: N/10

Scope:
- What changed:
- Explicitly out of scope:
- Baseline or previous release/diff range:

Evidence:
- Tests/checks run:
- Code review result:
- Research/source checks:
- Manual or browser QA:
- UI screenshots/console/network/viewports:
- Accessibility checks for UI changes:

Risk:
- Blockers:
- Warnings:
- Rollout or flag plan:
- Flag/canary cleanup owner:
- Rollback path:
- Monitoring signal:
- On-call, communication, and deploy window:

Owner:
- Next action:
```

Rules:

- `ship` requires evidence, not intention.
- Required checks must pass, be expectedly skipped with rationale, or be explicitly waived by the user.
- Unresolved `P1` review findings block `ship` unless the user explicitly waives and records the risk.
- `no-ship` must name the smallest blocker-clearing action.
- `not-applicable` is valid for planning-only or documentation-only work.
- If checks could not run, list them under warnings or blockers; do not imply verification.
