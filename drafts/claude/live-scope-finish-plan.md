# Finish plan: live authorized-target scanning (critical path)

Goal: let SHARAY scan a verified-owned external target (e.g. shardulchaulagain.com) safely.
Ownership for that domain is already verified (SHARAY-VERIFIED marker in the `portfolio` repo).
The remaining gates, in order, with owners:

## Hard host blocker (do first — not code)
- **No container runtime is installed** (docker/podman/colima/lima absent). The loopback-only
  Seatbelt backend *cannot* enforce a non-loopback egress allowlist ("Only literal loopback
  destinations are enforceable"). A real destination allowlist needs a container/VM.
- Action (human/host): install Podman or Docker (likely needs the user's password; neither
  Claude nor Codex can). Until then, live external scanning cannot be made safe on this host and
  stays disabled regardless of policy code.

## L1 — isolated egress backend (Claude's half)
- Add a container-based runner alongside `services/scanner_worker` that runs a tool in a
  rootless container with: no network except an explicit destination allowlist (host:port),
  no host FS mounts beyond the staged input, CPU/mem/time budgets, and teardown.
- Enforcement must be OS/runtime-level, not application-level. Design draft exists:
  `drafts/gemini/container_isolation_backend_design.md` (rootless Podman, 13 REQUIRED controls).
- Cannot be built/tested here without a runtime; ship only with real tests against it.

## C4 — live scope policy (Codex's half)
- Extend `ScopePolicy`/`normalize_url` to permit a **verified** non-loopback host + CIDR only when:
  explicit operator approval, an immutable allowlist of exact hosts/IPs (no wildcards), verified
  ownership reference (C3), time window, rate/concurrency budget, and `intrusive=False` unless a
  separate approved profile. Keep deny-by-default; add live hosts as data, never relax the parser.
- Add connect-time revalidation: re-resolve DNS and pin the IP, refuse redirects to off-scope
  hosts (the egress allowlist in L1 enforces it, policy declares it). This is the SSRF/rebinding
  surface that the literal-loopback gate currently makes moot.

## C3 — ownership verification workflow (Codex's half)
- Generalise what was done by hand for shardulchaulagain.com: a unique marker (DNS TXT or a file
  on the target) issued per target, checked before a scope goes live. The portfolio-repo marker
  check is the manual precedent.

## C5/C6 — wiring (Codex's half)
- Dispatch: scope-gate -> L1 container runner (with the approved egress allowlist) -> parser ->
  `normalize_parsed_finding` -> `Finding`. The L-half parse/normalize chain is done and live-proven
  on loopback (gitleaks + nuclei). Only the gated live egress is missing.

## What already works (no further L-half work needed)
- Full parse->normalize->Finding for 8 sources; gitleaks and nuclei proven end-to-end live on
  loopback fixtures through Seatbelt; AI (Gemini) adapter authenticates (TLS via certifi).
