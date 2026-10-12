# SHARAY implementation plan

October 12 update: `MAIN_PROMPT.txt` is the complete expanded brief; `TEAM_ASSIGNMENTS.md` divides eight named packages per assistant. Codex continues platform/desktop/control-plane work; Claude is assigned isolation/adapters/recon/source/AI/evaluation. `LIVE_SCOPE_PLAN.md` defines the gates before broader targets execute. `SESSION_LOG.md` records actual iterations and two-way review requests. The original October 11 plan below remains the baseline; its initial vertical slice is now tested through the browser. Shared typed tool contracts and cold-start/log tooling are implemented; external live tools/AI remain unavailable.

October 11, 2026. Baseline: engineering collector and 19 passing standard-library tests; no product, Git repository, database, Docker executable or application dependencies.

The complete supplied specification is the product backlog. This increment implements its first end-to-end vertical slice and the requested desktop entrance. Later phases are not declared complete by scaffolding. No Internet target will be assessed during development.

## Architecture decision before implementation

Use Next.js/React/TypeScript static export, served by a Python FastAPI API in a single local desktop window. An optional pywebview native wrapper and a Python launcher own the API and dedicated worker lifecycle. Node is a build prerequisite, not a running service. SQLite/SQLAlchemy is the local desktop database; PostgreSQL, Redis, object storage and container-enforced egress belong to the server deployment phase. This local adaptation avoids requiring unavailable Docker to open a desktop application. Alembic versions the local schema. Assessment state is durable in the database and one dedicated process handles the bounded safe-HTTP adapter. Only explicitly approved literal loopback laboratory targets are executable in this increment. Broader network scopes and external scanner execution remain disabled until worker egress and filesystem isolation are implemented.

## Acceptance criteria and ownership

1. Python starts a rain-themed SHARAY entrance; reduced motion and keyboard access work. The authenticated workspace opens only after valid credentials. Frontend owns `apps/web/`.
2. Owner provisioning uses a local CLI, Argon2 hashing, no default password, expiring opaque sessions, login throttling, CSRF checks, logout invalidation and organization-scoped RBAC. API owns `aegis/`, migrations and launcher.
3. Owner creates a project, reviews a complete scope, explicitly approves a loopback lab and launches a safe assessment. URLs, paths, addresses, redirects, expiry and test categories are checked by a deterministic policy independent of AI. Policy/scanner owns `packages/security_policies/`, `packages/scanner_adapters/`, fixtures and policy tests.
4. A dedicated worker collects real bounded HTTP observations, preserves sanitized evidence with hashes, records failure/cancellation and stores findings with separate severity and confidence. Successful retests resolve absent header issues; failed checks cannot imply a fix.
5. Authenticated HTML/JSON/Markdown/PDF reports contain actual scope, evidence, methodology and limitations. Reporting owns `packages/reporting/` and its tests.
6. Tests exercise a controlled target, cross-organization denial, RBAC, sessions, CSRF, malicious redirects, policy expiry, redaction, cancellation and a seeded issue/fix/retest. Existing foundation tests remain passing. Build, lint and type checks run against actual code.
7. Documentation and status explicitly identify implemented, partial, planned and unavailable capabilities, with commands and observed results. Requirements retain every original line.

## Sequence

- Preserve baseline and capture the full specification.
- Implement policy and scanner, frontend, and reporting in independent bounded paths; implement authentication/persistence/API/worker in parallel.
- Install locally scoped dependencies and commit reproducible lockfiles as files (no remote repository supplied).
- Integrate the end-to-end workflow; test real local HTTP responses, failure paths and retest.
- Build and inspect actual UI, verify startup, review access boundaries, update evidence ledger and status.
- Expand only with evidence and preserve incomplete requirements in the backlog. Production release and external scanning are not authorized by startup.
