# Contribution Gate

Use this gate before adding or changing workforce skills. The goal is a sharper company, not a bigger company.

## Accept A Change Only If

- It fixes a verified routing, review, research, QA, or escalation failure.
- It reduces repeated decision friction across more than one future task.
- It adds a test, evidence artifact, or safety check that catches real regressions.
- It replaces larger instructions with a smaller clearer rule.
- It is backed by a source, local eval, or observed failure.

## Reject Or Defer If

- It adds a new role or overlapping trigger/description when an existing skill can own the job with a small section.
- It duplicates guidance already present in the shared docs.
- It is just a list of best practices without a concrete routing or eval effect.
- It requires installing an external skill before the need is proven.
- It imports generic or version-mismatched skill guidance without project-specific acceptance checks proving value.
- It makes common tasks slower or more ceremonial.

## Size Rules

- Prefer editing shared docs before adding a new skill.
- Add a new skill only when it owns a recurring workflow with distinct triggers.
- Keep each workforce `SKILL.md` under 180 lines unless the extra length is validated by evals.
- When `route-cases.json` approaches its cap, compact or replace related cases before adding new ones; raising the cap needs separate evidence.
- Put detailed examples in references only when the core skill would otherwise become noisy.
- Every accepted contribution should preserve or improve `run-workforce-evals.py`.

## Research Intake

When borrowing from other skill implementations, record:

- Source repo or skill.
- Pattern observed.
- Accepted, rejected, or deferred.
- Reason.
- Local file changed, if any.

After non-trivial work, capture a reusable lesson only when there was a user correction, repeated workflow, stale map, or verified failure. Otherwise, do not create a learning artifact.

## Verification Gate

- Run deterministic evals before every contribution. Use fresh output; do not rely on previous or delegated results.
- Run the Codex AI eval for orchestration or routing changes.
- For non-trivial claims, write the claim and the contract, then try to disprove it before committing.
- If a framework or external API pattern matters, use primary documentation rather than memory.
- New skills, rules, and self-improvement notes must name the current baseline plus the behavior or eval they should improve; defer broad self-generated guidance without verifier, external, or repeated local feedback.
- Do not credit a skill or rule when the evidence is better explained by model, tool, dependency, or environment changes.
- New scripts or CLI commands must default to read-only or reversible behavior when possible and document network, filesystem, credential, posting, or destructive side effects.
- For every new role, file, script, or rule, record the evidence for adding it and what breaks if it is not added; defer if the consequence is vague.
