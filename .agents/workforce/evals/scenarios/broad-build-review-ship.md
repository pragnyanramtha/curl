# Workforce Eval Scenario: Broad Build, Review, Ship

You are evaluating the local company-style workforce in `/home/ubuntu/workforce`.

Simulated user request:

> I need you to build a small feature, research any unknowns, review the code, and tell me if it is ready to ship.

Inspect the local files only. Do not edit files. Use the workforce docs and scripts in:

- `.agents/workforce/`
- `.agents/skills/workforce-*`

Expected output: evaluate whether the workforce routes this request like a company. Check:

1. The primary owner for this broad multi-team request.
2. Which departments should be staffed.
3. Whether low confidence escalates to HR.
4. Whether research, code review, and QA/release have clear responsibilities.
5. Whether any issue would block a ship decision.

This is a read-only routing evaluation. There is no feature artifact, code diff, deployment, or manual QA target to release. If the workforce routes the request correctly, `release_decision` must be `not-applicable`. Use `no-ship` only if a workforce issue blocks evaluation, and never use `ship` for this scenario.

Return a concise JSON result matching the provided output schema.
Include at least one recommendation, even when there are no blocking issues.
Do not claim that the Codex AI eval was skipped; this run is the Codex AI eval.
