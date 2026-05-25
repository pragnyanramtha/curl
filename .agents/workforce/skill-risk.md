# Skill Risk Checklist

Use before recommending or installing a third-party skill.

## Minimum Review

- Source: exact `owner/repo@skill` and URL.
- Purpose and selection: capability gap, output contract, boundaries/example, stated scope, and whether name, description, triggers, and instructions align without stuffing.
- Scope and compatibility: install scope, required runtimes/packages/accounts/network, and why.
- Trust: maintainer, popularity, recent activity, and license.
- Registry install counts are weak popularity signals, not proof of relevance, source quality, or safety.
- Provenance: pinned release tag, commit SHA, or lock/hash for the exact skill reviewed.
- Contents: read `SKILL.md`; inspect scripts, hooks, dynamic context injections, symlinks, and package manifests before execution.
- Automated scans: treat findings as advisory only; a clean scan never replaces reading the skill and scripts.
- Permissions: note network, filesystem, shell, credential, posting behavior, least-privilege rationale, and whether claimed tool limits are enforced here.
- Activation, context footprint, and trust surface: note broad triggers, bulk/recursive refs, hooks/chains, allowed tools, remote references, MCPs, and whether external outputs are treated as untrusted data.
- Alternatives: local skill update, manual instructions, or no install.

## Blockers

Do not recommend installation if:

- It asks to expose secrets, tokens, private files, chat history, or unrelated workspace/user data without a clear user-approved need.
- It sends email, posts publicly, changes cloud resources, or modifies repos by default.
- It includes opaque scripts, hooks, or dynamic context injections that run before the agent can inspect or approve them.
- It asks the agent to follow remote references, tool output, or fetched content as instructions without validation or trust boundaries.
- It self-updates, downloads, or replaces skill artifacts without a pinned digest/ref and explicit user approval.
- It bundles archives, symlinks, or hard links with absolute paths, path traversal, or links that escape the skill directory.
- It bundles model, binary, or opaque artifacts whose provenance and behavior cannot be reviewed.
- It creates automatic trigger loops or background chains that act without user approval.
- It pre-approves shell/bash execution, removes command confirmation without explicit approval, or relies on unsupported frontmatter safety controls.
- It tries to override host instructions, disable safety, impersonate system/admin messages, or hide directives in encoded text, invisible Unicode, hidden HTML/CSS, comments, metadata, or filenames.
- It duplicates a local workforce capability, lacks an output/boundary contract, requires undeclared runtimes/accounts/network access, forces broad triggers or bulk context loading, uses misleading name/description/trigger stuffing, has vague or untestable safety limits, or the source/license/trust story is unclear.

## Recommendation Shape

```text
SKILL RISK REVIEW
Candidate:
Capability gap:
Install scope:
Trust notes:
Provenance notes:
Permission notes:
Tool/trust surface notes:
Risk level: critical | high | medium | low | clean
Alternatives:
Recommendation: install | do not install | ask user
```
