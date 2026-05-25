# Code Review Board

The review board uses multiple lenses. For small diffs, one reviewer may cover all lenses. For risky diffs, run them as independent passes and merge findings by confidence.

## Review Lenses

- `Correctness`: logic errors, edge cases, missing state transitions, and time, money, or locale handling.
- `Data safety`: migrations, destructive writes, idempotency, rollback.
- `Rollback`: reversibility, backups, forward-only migrations, last-good version, recovery steps, and owner clarity.
- `Security`: auth/session lifecycle, CSRF/CORS/session-cookie boundaries, cryptography and key management, object/property/function-level authorization, tenant isolation, mass assignment, input validation at trust boundaries, injection, LLM prompt/tool-output injection, cloud/IaC misconfiguration, repository rulesets, CODEOWNERS, protected reviews/checks, required workflows/deployments, merge queues, security logging and audit-log integrity, committed credentials or private data, PII in logs or telemetry, SSRF, path traversal, unsafe file upload processing, unsafe deserialization, dependency or license risk, destructive commands, and permission expansion, plus missing rate limits or quotas on abuse-prone endpoints.
- `Concurrency`: races, retries, timeouts, cancellation, locks, async/sync boundaries.
- `API contracts`: released API, wire, CLI/config/env, request/response compatibility, schema drift, defaults, required parameters, and error handling.
- `Maintainability`: architecture fit, cohesion, duplication, avoidable complexity, naming, and local convention drift.
- `Performance`: latency, memory, repeated I/O, algorithmic complexity, bundle size, payload size, LLM/API token cost, quota consumption, and unbounded resource use.
- `Accessibility`: semantic HTML, labels, keyboard navigation, focus management, ARIA, contrast, media alternatives, and screen-reader state.
- `Docs`: README, API docs, examples, changelog, release notes, and config references match changed behavior.
- `Tests`: missing coverage for changed behavior, missing bug regression check, missing AI golden/regression evals, flaky test risk, or tests changed to match implementation instead of spec.
- `UX/DX`: confusing workflow, poor errors, hard-to-debug interfaces.

## Reviewer Selection

| Scenario | Required Lenses |
| --- | --- |
| API or backend endpoint | Correctness, Security, API contracts, Tests |
| Frontend or user flow | Correctness, UX/DX, Tests, Accessibility if relevant |
| Database migration or data job | Data safety, Correctness, Rollback, Tests |
| Auth, permissions, secrets | Security, Correctness, Tests |
| AI prompts, RAG, agents, or tool calls | Security, API contracts, Correctness, Tests |
| Terraform, Kubernetes, Docker, or cloud IAM changes | Security, Data safety, Rollback, Tests |
| Dependency manifests, lockfiles, package scripts, artifact metadata, license metadata, or CI installers | Security, Correctness, Tests |
| Hot paths, loops, queries, caching, bundles, async I/O, payload size, or LLM/API calls | Performance, Correctness, Tests |
| Agent instructions, skills, or routing docs | Security, Correctness, Tests |
| Full feature | Correctness, Security, Tests, Docs, QA/release |

For small diffs, one reviewer can cover all required lenses. For risky or large diffs, split lenses across independent reviewers and consolidate.

## Finding Merge Rules

- Same file, line, and issue: merge and keep the clearest description.
- Same location but different issue: keep separate findings.
- Same issue across locations: keep separate but cross-reference.
- Conflicting severity: use the higher severity and explain why.
- Conflicting fixes: include both options and assign an owner to decide.

## Finding Format

```text
[P1|P2|P3] (confidence: N/10) path:line - summary
Evidence:
Impact:
Fix:
Owner:
```

Findings should be pinned to a project-relative file and line whenever the claim depends on code. If a concern cannot be pinned, make it an open question unless it is genuinely repo-wide.

## Severity

- `P1`: likely production break, data loss, security issue, or blocked release.
- `P2`: real defect or missing coverage that should be fixed before merge.
- `P3`: improvement, maintainability, or follow-up.

Confidence gates:

- `7/10+`: include in the main findings.
- `5-6/10`: appendix or explicit escalation; do not present as a confirmed defect.
- `<5/10`: suppress unless the user explicitly asks for raw suspicions.
- Scanner, SAST, Scorecard, or AI findings are leads; independently validate before presenting them as confirmed defects.
