# Security controls

Every assessment requires an authenticated role, organization ownership, explicit laboratory approval, an unexpired scope snapshot and the fixed non-intrusive profile. Only literal loopback targets with explicit permitted addresses, origins and paths can execute. Metadata/link-local/private/public destinations are unavailable. Requests have bounded counts, rates, concurrency, response size and duration. Redirects are scope checked before connection.

No default credentials, no arbitrary shell input, no target build scripts, no scanner installation, no remote model calls and no automatic production patch/deployment. Passwords use Argon2. Session tokens are random and stored as hashes. Evidence and reports exclude credentials and raw response bodies. Audit events record privileged actions and execution decisions. Authentication does not override assessment scope for an owner.

This is the control design for the first slice; IMPLEMENTATION_STATUS records which controls were exercised. Missing isolation cannot be labelled passed. Source uploads, credentialed scanning and Internet exposure remain unavailable until their required boundaries are implemented.
