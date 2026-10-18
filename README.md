# SHARAY — Security Assessment Platform

**SHARAY** is a local-first, defensive security-assessment platform and penetration-testing
workspace built around one rule: **no verified evidence → no confirmed vulnerability.** Every
candidate finding is treated as a hypothesis and only promoted to *confirmed* after a cold,
deterministic re-execution with a negative-control canary, or an isolated executable proof.

Around that verification core it provides verified target scoping, rootless-container scanner
engines with single-destination egress locking, a cryptographically hash-linked audit ledger,
protocol-accurate reporting, an AI attack-graph reasoning layer, and an interactive
human-in-the-loop operator console.

> A finding is a hypothesis until a cold replay proves it.

A full technical write-up — architecture, every major feature, code walkthrough, and honest
limitations — is in **[docs/research-paper/SHARAY.md](docs/research-paper/SHARAY.md)** (with UI
screenshots in [docs/research-paper/screenshots/](docs/research-paper/screenshots/)).

By Shardul · <https://shardulchaulagain.com>

---

## Quick start

Requires Python 3.11+ and Node.js (for building the frontend once).

```sh
# 1. Python environment
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-desktop.txt

# 2. Build the static frontend
npm --prefix apps/web ci --ignore-scripts
npm --prefix apps/web run build

# 3. Database + preflight
.venv/bin/python -m sharay migrate
.venv/bin/python -m sharay preflight     # reports scanner availability; runs nothing

# 4. Create the first owner (no default credentials exist; password ≥ 12 chars)
.venv/bin/python -m sharay init-owner

# 5. Launch
.venv/bin/python -m sharay desktop       # native window
#   or
.venv/bin/python -m sharay desktop --browser
```

On macOS, double-clicking `SHARAY.app` or `SHARAY.command` also launches the desktop app.

---

## Run modes

| Command | Purpose |
| --- | --- |
| `sharay desktop` *(default)* | Native window + loopback API + worker |
| `sharay desktop --browser` | Same, opened in the system browser |
| `sharay serve` | Headless loopback API + worker (`http://127.0.0.1:8765`) |
| `sharay migrate` | Apply forward-only database migrations |
| `sharay init-owner` | Provision the first owner account |
| `sharay issue-recovery` / `reset-password` | Local-OS single-use account recovery |
| `sharay backup <dest>` / `restore <snap>` | Consistent private database snapshots |
| `sharay preflight` | Report scanner availability without executing |

**Decoupled web mode** (teams / headless nodes): run `sharay serve` in one terminal and
`npm --prefix apps/web run dev` in another (`http://localhost:3000`, proxies to the API).
Host, port and data dir are configurable via `SHARAY_PORT` / `SHARAY_DATA_DIR`.

**CLI automation** (`aegis/cli.py`): `scan`, `probe`, `status`, `findings` — e.g.
`.venv/bin/python -m sharay scan https://example.com/ --profile comprehensive --mode adaptive`.

---

## How it works

1. **Scope** — Register a target and define a typed scope (allowed origins, included/excluded
   paths, rate and concurrency ceilings, validity window ≤ 24 h). SHARAY shows the exact,
   reproducible resolved scope before anything runs.
2. **Authorize** — An operator must explicitly record authorization within the displayed scope.
   Live execution is refused without it; private/internal address ranges are refused outright.
3. **Assess** — Choose a profile:
   - `safe_http` — bounded, in-process header/TLS analysis for approved loopback labs.
   - `approved_templates` — containerized Nuclei over locked single-destination egress.
   - `comprehensive` — the full ten-stage pipeline (recon, TLS, DNS, ports, crawler, DOM/SPA,
     schema ingestion, adaptive strategy, active differential/fuzzing/IDOR, external engines),
     with the verification gate between native and external stages.
4. **Verify** — Candidates are replayed 3× with a negative-control canary; survivors can be
   proven by a synthesized, sandboxed AutoPyVerifier script. Only reproduced or exit-code-0
   findings become `confirmed`. Demoted candidates are marked `demoted`/`false_positive`.
5. **Report** — Export PDF / HTML / Markdown / JSON. Reports separate verified vulnerabilities
   from hardening posture, carry CWE/CVSS and protocol-accurate PoCs, and redact secrets.

Every authorization and execution decision is recorded in an append-only, hash-linked audit
ledger. An interactive operator console (`probe`, `dns`, `ssl`, `beacon`, `retest`, `whoami`, …)
runs scoped diagnostics over the same egress-locked path.

---

## Offline demonstration

No internet target is needed. Start the synthetic vulnerable fixture and point SHARAY at it:

```sh
.venv/bin/python -m fixtures.safe_targets.server --port 8766
```

Register `http://127.0.0.1:8766/`, approve scope, run a **Standard** or **Comprehensive**
assessment, review the findings, then restart the fixture with `--secure-headers` and use
**Review retest** to watch findings resolve. For a one-command throwaway UI with a disposable
test account, use `scripts/ui_fixture.py`.

---

## Verification

```sh
source .venv/bin/activate
python3 -m pytest -q
python3 engineering/check.py --run-gates
ruff check aegis sharay packages services engineering scripts tests
ruff format --check aegis sharay packages services engineering scripts tests
mypy --explicit-package-bases aegis sharay packages services
npm --prefix apps/web run test
npm --prefix apps/web run typecheck
npm --prefix apps/web run lint
npm --prefix apps/web run build
```

Tests use temporary databases, synthetic accounts, ephemeral TLS certificates and loopback
fixtures; they need local socket permission and scan no real target. `engineering/check.py`
runs the reviewed gates from `engineering/gates.json` with `shell=False`, a timeout, and no
inherited credentials, and writes local reports under `.engineering/` (gitignored). The gate
runner is not an OS sandbox — use an externally sandboxed environment for untrusted repositories.

---

## Account recovery

The local OS owner can issue a ten-minute, single-use recovery token with
`sharay issue-recovery USERNAME`, then run `sharay reset-password`. The reset revokes existing
sessions. There is no email or MFA recovery workflow.

---

## Limitations

SHARAY states its own boundaries plainly (full list in the research paper):

- Single-destination egress enforcement is **podman-specific and IPv4-only**; other runtimes are
  no-network only.
- The in-process `safe_http` profile is **loopback-only** (no DNS, no authenticated testing, no
  external scanners).
- Live execution requires manually-verified ownership and a **public** address.
- Authenticated and intrusive testing are **off by contract**.
- Throughput is a **single serialized worker** — no distributed scanning.
- The audit ledger is local tamper-**evidence**, not external tamper-protection.
- Evidence retention is indefinite; automatic deletion is not implemented.
- The native window and egress backend are developed and tested on macOS + the podman machine.

---

## Repository layout

| Path | Purpose |
| --- | --- |
| `sharay/`, `aegis/` | Launcher and backend (API, worker, auth, models, audit, reporting glue) |
| `packages/scanner_adapters/` | Safe-HTTP adapter, pipeline orchestrator, reproducer, integrations |
| `packages/security_policies/` | Scope policy, target normalization, DNS-pinning resolver |
| `packages/reporting/` | PDF/HTML/Markdown/JSON report rendering and PoC engine |
| `services/scanner_worker/` | Rootless container runner and single-destination egress firewall |
| `services/ai_analysis_worker/` | Attack-graph reasoning, AutoPyVerifier, consensus/entropy |
| `apps/web/` | Next.js operator workspace (static export) |
| `fixtures/`, `tests/` | Synthetic targets and the unit/integration/product/eval suites |
| `engineering/` | Reviewed test/lint/format/type gates and local dashboard |
| `docs/research-paper/` | Full technical write-up and UI screenshots |
