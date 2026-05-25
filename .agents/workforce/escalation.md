# HR Escalation Protocol

HR is the staffing and capability layer. HR does not pretend to know everything. It finds the right people, skills, docs, and escalation path.

## Intake

When a department escalates, HR records:

- Task summary
- Current owner
- Confidence score and reason
- Missing capability
- Risk if wrong
- Evidence already checked

Do not escalate on "maybe someone smarter can solve it." First capture the failed hypothesis, command/output or source checked, and whether the gap is knowledge, capability, tool access, permission, or ownership.

## Decision Tree

1. If the task needs external facts, send it to `workforce-research`.
2. If a local skill exists, route to that skill and explain why.
3. If no local skill exists, run skill discovery:
   - `bash .agents/workforce/scripts/skill-scout.sh "<query>"`
   - Review results for relevance, maintainer quality, and risk.
   - Apply `.agents/workforce/skill-risk.md` before recommending install.
4. If skill search is weak, look for public `AGENTS.md` patterns:
   - `bash .agents/workforce/scripts/agents-md-scout.sh "<query>"`
   - Prefer primary repos from credible teams.
5. If internet results are weak or the action is high impact, ask the user for a decision.

## Skill Install Policy

Do not install a skill silently unless the user has clearly asked to install it. When recommending installation, include:

- Exact package string for `npx skills add`
- Why it matches the task
- Risks or trust concerns
- Whether it should be project or global scope

## Reassignment Format

```text
HR DECISION
Task:
Current confidence:
Missing capability:
Assigned to:
Reason:
Evidence to carry forward:
Expected output:
```
