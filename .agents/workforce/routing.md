# Workforce Routing

Use this table before doing substantial work.

| User Need | Primary Skill | Support Skills |
| --- | --- | --- |
| "Build this", broad or multi-step request | `workforce-orchestra` | HR, eng manager, research, review, QA |
| Missing capability, low confidence, unclear owner | `workforce-hr` | research |
| External facts, current docs, competitor or API research | `workforce-research` | HR |
| Architecture, implementation plan, bug fix, debugging, root-cause analysis, work decomposition | `workforce-eng-manager` | research, review, QA |
| Code review, PR review, diff safety, regressions | `workforce-code-review` | research, QA |
| Test plan, CI failure triage, browser QA, release/deploy readiness | `workforce-qa-release` | review, eng manager |

## Escalation Rules

Route to `workforce-hr` immediately when:

- Confidence is below `7/10` or `70%` and acting would create meaningful risk.
- The right skill is missing from `.agents/skills`.
- The task needs a domain expert the current agent cannot simulate well.
- The user asks for an agent, skill, `AGENTS.md`, or workflow from the internet.
- A specialist loops on the same failed approach twice.

Route to `workforce-research` when:

- The answer depends on current external information.
- The repo, API, library, product, law, price, model, or standard may have changed.
- There are conflicting claims or no primary source.
- HR needs evidence before installing or recommending a skill.

Route to `workforce-code-review` when:

- There is a diff, PR, branch, migration, auth change, data model change, API contract or wire-format change, or deployment path.
- A previous agent produced code and did not run tests.
- The issue may be a regression, security flaw, race, data loss, or hidden coupling.
- The issue changes timezones, DST, currency/rounding, localized formatting, pagination, idempotency, retries, timeouts, cancellation, or locking behavior.
- The issue may involve SQL, NoSQL, command, XSS, template, LDAP, or deserialization injection.
- The issue changes email sending, email authentication, SPF/DKIM/DMARC, or mail headers.
- The issue changes API field allowlists, response DTOs, object-property authorization, or mass-assignment boundaries.
- The issue changes README/API docs, examples, release notes, config references, CLI flags, or env vars.
- The issue changes `AGENTS.md`, `SKILL.md`, routing, tool access, install policy, or agent safety boundaries.
- The issue changes admin actions, role/group checks, RBAC/ABAC policy, or function-level authorization.
- The issue changes cryptography, password hashing, TLS/certificate validation, signatures, HMAC, key management, or random token generation.
- The issue changes payments, billing, subscriptions, webhooks, signature verification, replay/dedupe, or idempotent event processing.
- The issue may involve LLM prompt injection, RAG or tool-output trust boundaries, unsafe tool calls, or model-output handling.
- The issue changes prompts, models, RAG behavior, vector/search indexes, golden datasets, or AI regression evals.
- The issue changes file uploads, downloads, previews, archive extraction, storage paths, or server-side URL fetching.
- The issue changes CSRF defenses, CORS, cookies, sessions, or browser security headers.
- The issue changes browser storage of session IDs, JWTs, refresh tokens, auth tokens, or sensitive data.
- The issue changes dangling DNS/CNAME records, subdomain ownership, CAA, DNSSEC, or zone delegation.
- The issue changes browser extensions, Electron desktop security, extension/native messaging, webviews, IPC, preload/contextBridge, or privileged client bridges.
- The issue changes mobile deep links, Android App Links, iOS Universal Links, intent filters, custom URL schemes, exported Android components, mobile permissions, iOS entitlements, or app groups.
- The issue changes SCIM/provisioning, SAML/SSO, OAuth/OIDC/JWT tokens, workload identity federation, API Gateway/Lambda authorizers, GraphQL, WebSockets, cache/CDN or private-content behavior, or security audit logging.
- The issue changes Terraform, Kubernetes manifests, pod/admission/network policies, Dockerfiles, container images, cloud IAM, organization guardrails, serverless ingress, network exposure, encryption, or secret handling.
- The issue changes public access, grants, or resource policies for managed databases, warehouse datasets/shares, caches, search clusters, queues, topics, event buses, or data stores.
- The issue may be a performance regression such as N+1 queries, latency, memory leaks, bundle size, payload size, or hot-path resource growth.
- The issue may be an accessibility regression such as missing labels, broken keyboard navigation, focus traps, ARIA misuse, contrast failure, or screen-reader state.
- The issue may expose PII, private data, secrets, credentials, API keys, private keys, raw payloads, user identifiers, or sensitive data in logs or telemetry.
- The issue changes data retention, deletion/export, anonymization, backups, analytics, search indexes, or legal holds.

Route to `workforce-eng-manager` when:

- The user asks to fix a bug, debug a failing test, find a root cause, or decompose implementation work.
- The fix needs implementation ownership before review or release validation.

Route to `workforce-qa-release` when:

- The user asks whether it works.
- A GitHub check fails, is inconclusive, or disagrees with local verification.
- A web app, API, CLI, package, or deployment needs acceptance checks.
- A release decision, rollback decision, or monitoring checklist is needed.
