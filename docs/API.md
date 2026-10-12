# Implemented local API

Base URL: `http://127.0.0.1:8765/api/v1`. The authenticated `/openapi.json` is generated from real FastAPI input schemas. The browser UI is the usual client. Requests are same-origin; no CORS wildcard is configured. Every mutation requires the exact Origin. Authenticated mutations also require `X-CSRF-Token` from `/auth/login` or `/auth/session`. Login uses an HttpOnly SameSite=Strict opaque cookie. Passwords, hashes and session tokens are not returned in JSON.

| Operation | Implementation |
| --- | --- |
| GET /auth/bootstrap | Initial owner availability only |
| POST /auth/login; GET /auth/session; POST /auth/logout | Real sessions, login throttling, logout invalidation |
| GET/POST /auth/members | Owner provisions roles; administrator can list members |
| GET /overview | Counts and recent records from the current organization database |
| GET/POST /projects; GET/PATCH /projects/{id} | Organization-scoped project records and archive flag |
| POST /projects/{id}/targets | Validate literal-loopback URL and full scope before storage |
| POST /targets/{id}/approve | Exact explicit controlled-laboratory acknowledgement |
| GET /assets | Registered targets and their scope/approval status |
| GET/POST /assessments; GET /assessments/{id} | Durable worker jobs, evidence, checks and events |
| POST /assessments/{id}/cancel | Cancel queued/running work |
| GET /findings; PATCH /findings/{id} | Evidence records and analyst triage |
| GET /reports/{assessment_id}?format=html/json/markdown/pdf | Authenticated export of a stopped assessment |
| GET /integrations | Built-in adapter capabilities; missing external tools; AI disabled |
| GET /tool-contracts | Authenticated shared action schema/adapter roadmap; read-only and live execution disabled |
| GET /audit | Owner/administrator audit history and hash-chain validation |
| GET /health/live; GET /health/ready | Local process/database/worker readiness |

Collection endpoints use `limit` (1–100) and `offset`, returning `items`, `total`, `limit`, `offset`. Findings additionally accept `status` and `severity`. Unknown organization identifiers return 404; insufficient roles and CSRF/origin failures return 403; missing/expired sessions return 401; malformed inputs return 422 with sanitized errors; login/queue limits return 429. Request bodies are bounded to 64 KiB. Errors include request IDs; validation errors omit submitted values.

Assessment creation requires `{target_id,idempotency_key,retest_of?}`. Reusing a key for the same request returns the same assessment; a conflicting request returns 409. Only `safe_http` executes. Owner privileges never bypass scope. Reports and sensitive record routes always require authentication and organization checks. Findings may be triaged to needs_triage/suspected/inconclusive/false_positive/accepted_risk/remediation_in_progress; confirmed/fixed states require deterministic observation/retest evidence.

Scope input fields are `hosts`, `allowed_origins`, `allowed_paths`, `excluded_paths`, `allowed_cidrs`, `categories`, `authenticated`, `credential_refs`, `request_rate`, `max_concurrency`, `starts_at`, `expires_at`, `intrusive`, `approval_required`, `emergency_stop_conditions`. Approval identity, time, method and scope version are stored by the API, never trusted from a caller. Input schemas disallow unknown fields. Scope versions are immutable per registered target in this increment; scope editing and DNS/HTTP ownership challenges are not implemented. Register a new explicit target scope when changing authorization.

Organization/membership administration is a local subset, not a complete hosted organization platform. Source upload, AI requests, credential vaults, external integration configuration, pause, notifications and separate report-generation jobs remain unavailable.
