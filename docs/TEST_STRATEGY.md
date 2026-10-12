# Test strategy

Preserve the 19-test foundation baseline. Product tests use temporary databases, synthetic credentials and a controlled loopback fixture. Validate denied API access, cross-tenant paths, CSRF, RBAC, session expiry/revocation, scope parsing, encoded paths, redirect scope, non-loopback destination rejection, expiry and budgets. Exercise the actual worker and adapter against the fixture, generate reports, change seeded headers and retest. Cancellation and failures must remain distinct from completion.

Run Python unit/integration tests, Python lint/type checks, frontend type/lint/build checks and the reviewed engineering gates. Browser QA covers entrance, provisioning guidance, authenticated workflow, empty states, report exports, keyboard focus and reduced motion. Tests provide evidence for their scope, not a complete security certification or universal vulnerability-detection accuracy.
