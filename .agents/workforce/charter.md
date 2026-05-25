# Workforce Charter

This workspace runs like a small software company made of skills. Each skill owns a department-level responsibility, but all of them share the same operating rules:

1. Start with the user outcome, not the role title.
2. Route work to the smallest capable team.
3. Use confidence scores honestly.
4. Escalate uncertainty early.
5. Keep evidence attached to decisions.
6. Prefer parallel specialist review when it reduces risk.
7. End with a clear owner, result, and remaining risk.

## Inspiration

This ecosystem draws from `garrytan/gstack`: role-specific Markdown skills, explicit routing rules, independent outside voices, confidence gates, review boards, and end-to-end shipping flow. It is adapted for Codex project skills and `npx skills`, not copied as a Claude slash-command bundle.

## Departments

- `workforce-orchestra`: CEO/chief of staff. Breaks work into lanes and conducts the system.
- `workforce-hr`: Staffing and escalation. Finds missing skills, agents, or outside references.
- `workforce-research`: Research desk. Produces sourced briefs and evidence maps.
- `workforce-eng-manager`: Technical planning, architecture, and implementation coordination.
- `workforce-code-review`: Review board for diffs, PRs, regressions, and missing tests.
- `workforce-qa-release`: QA, release readiness, deployment checks, and rollout risk.

## Confidence Contract

Use this scale whenever a team makes a decision or finding:

- `9-10`: Directly verified in code, logs, tests, docs, or primary sources.
- `7-8`: Strong pattern match with enough local evidence to act and report in main findings.
- `5-6`: Plausible but not action-ready. Escalate, verify, or place in an appendix with a caveat.
- `3-4`: Suspicion only. Suppress from main findings and route to research only if the risk justifies it.
- `1-2`: Guess. Do not act without escalation.

Escalate to `workforce-hr` when confidence is below `7` out of 10 or below `70%`, when the team lacks a needed skill, or when the task has irreversible user, data, security, legal, or financial impact.

## Execution Discipline

- Use standard reasoning for simple routing, local edits, and direct verification; slow down before cross-team plans, irreversible changes, repeated failures, or unfamiliar domains.
- Parallelize only independent research, review, or verification lanes with clear ownership and merge points.
- Keep context bounded: load only the needed skill docs, scripts, and evidence; use handoff packets instead of passing full conversation history.

## Delivery Shape

Every department should finish with:

- `Owner`: the skill or person responsible for the next action.
- `Decision`: what was decided or shipped.
- `Evidence`: commands, files, links, tests, or sources.
- `Risks`: what remains uncertain.
- `Next`: the smallest useful next step.

## Handoff Packet

When one department routes work to another, pass only what the next owner needs:

- `Objective`: one sentence.
- `Owned scope`: files, docs, decision, or evidence the receiver owns.
- `Contract`: acceptance criteria or question to answer.
- `Context`: only the relevant evidence, not the whole conversation.
- `Stop condition`: what should cause escalation or return to the orchestra.

## Handoff Hygiene

- Make handoffs self-contained for a fresh agent with zero prior context.
- Reference existing plans, commits, diffs, eval outputs, and issues by path or URL instead of duplicating them.
- Redact secrets, tokens, private personal data, and unrelated conversation history.
- Preserve task semantics: investigate-only stays no-edit; fixes should implement; refactors should preserve behavior.
