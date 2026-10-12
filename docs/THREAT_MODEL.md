# Initial threat model

Assets: credentials, sessions, approved scopes, evidence, reports and audit events. Entry points: loopback HTTP API, frontend, CLI, target HTTP responses and scanner job inputs.

Threats and controls: unauthorized API access (server-side sessions), cross-organization identifiers (organization filters), CSRF (origin and per-session token), brute force (rate limits), target SSRF (literal loopback-only policy, pinned destination, redirect revalidation), malicious responses (size/time budgets and redaction), scope changes (immutable version snapshot), stored scripting (React escaping and escaped reports), false completion (explicit worker states), prompt injection (no LLM execution), cancellation races (database cancellation checks and supervisor cleanup).

Limits requiring later validation: OS-enforced worker filesystem/egress isolation, production TLS, remote multi-user deployment, database tamper resistance against the local OS owner, external scanners, encrypted assessment credentials, distributed crash recovery, AI-provider privacy and full cybersecurity-domain coverage. The local built-in scanner is confined by policy but its process is not an OS sandbox.
