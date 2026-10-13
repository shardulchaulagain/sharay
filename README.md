# SHARAY desktop security workspace

At every cold start, follow [AGENTS.md](AGENTS.md): read [MAIN_PROMPT.txt](MAIN_PROMPT.txt) completely unless its hash matches your recorded complete read, then read [team assignments](docs/TEAM_ASSIGNMENTS.md) and the latest [shared session log](docs/SESSION_LOG.md). Refresh them with `.venv/bin/python -m sharay refresh --agent codex` (full prompt and open inbox) or `refresh --summary --agent claude` (checkpoint index and Claude inbox). Give [CLAUDE_HANDOFF_PROMPT.txt](CLAUDE_HANDOFF_PROMPT.txt) to Claude in the same checkout. Codex and Claude append addressed checks/reviews/handoffs using `python -m scripts.session_log --agent codex|claude --to claude|codex ... --reply-to entry-ID`; add `--log ideas` for the separate ideas channel. The user-approved Codex thread heartbeat checks coordination every minute when the app scheduler is available; the shared log retains real replies and cannot make an offline counterpart respond.

The October 12 expansion targets verified authorized live sites/systems and integrated Nmap/ZAP/Nuclei/Metasploit/recon/source/AI workflows. Shared typed contracts now define approved operations and independently require scope, approval, budgets and runner readiness. Those external integrations remain planned/disabled. Claude owns isolation and adapters; Codex owns the platform and operator experience. Exact ownership and open review IDs are in the log.

SHARAY is the public product/CLI name. Existing `aegis` Python modules, `.aegis/aegis.db`, cookie/evidence schema identifiers and legacy environment variables remain compatible to preserve stored data. No destructive data migration is performed by the rename.

The first working product slice is a local Python desktop application with a rain-themed entrance, authenticated workspace, projects, explicit laboratory scope approval, a dedicated background HTTP scanner, stored evidence/findings, triage, retests and HTML/JSON/Markdown/PDF reports. Results and metrics come from actual stored observations. No default credentials or model calls exist.

This is an initial implementation of the supplied [product specification](docs/PRODUCT_SPECIFICATION.txt). The full AI-assisted platform and all cybersecurity domains are not complete. Internet/private-network assessment, external scanner execution, source uploads, authenticated target testing, AI providers, CVSS scoring and PostgreSQL/Redis/S3 remain unavailable. A separate partial Seatbelt backend has controlled-fixture review evidence; product assessments do not yet use it. The runnable profile is limited to explicitly approved literal `127.0.0.1` / `::1` laboratory targets. See [implementation status](docs/IMPLEMENTATION_STATUS.md) and [acceptance checklist](docs/FEATURE_CHECKLIST.md).

## Open the installed desktop app

From this directory, choose your own owner credentials once:

```sh
.venv/bin/python -m sharay init-owner
.venv/bin/python -m sharay desktop
```

Or double-click `SHARAY.app` or `SHARAY.command` after provisioning. The local app bundle uses this checkout and its virtual environment; it is not a signed, self-contained distribution. Password entry is hidden. Use at least 12 characters. The native macOS window serves the built Next.js UI from a loopback FastAPI API; the Python launcher starts and stops the worker with the window. Login unlocks application records; the operating-system account still controls local files. There is no master bypass of approved assessment scope.

For an explicit browser launch, use `.venv/bin/python -m sharay desktop --browser`. For API-only development, use `.venv/bin/python -m sharay serve`. The default origin is `http://127.0.0.1:8765`; `localhost` is not the same approved origin. Export `SHARAY_PORT` and `SHARAY_DATA_DIR` to override port and private data directory. Production Internet exposure is unsupported.

## Install / rebuild

Python 3.11+ is required; use Node.js 24.21.0 for the verified build/test toolchain. The verified environment is macOS arm64 and Python 3.13.1. These commands install locally and never install scanner tools or target dependencies:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install pip==26.2.1
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-desktop.txt
npm --prefix apps/web ci --ignore-scripts --strict-peer-deps
npm --prefix apps/web run build
.venv/bin/python -m sharay migrate
.venv/bin/python -m sharay preflight
```

`requirements-lock-macos-py313.txt` captures the tested transitive environment, including macOS desktop dependencies. Use it only on compatible macOS/Python installations. Direct cross-platform API dependencies are pinned separately. `apps/web/package-lock.json` pins the frontend dependency graph. See [deployment and recovery](docs/DEPLOYMENT.md) for upgrade responsibilities and platform limitations. Node is needed for the build, not at runtime.

Frontend lint uses maintained ESLint 10 for TypeScript/React hooks and Oxlint for the 31 configured accessibility rules. The checked-in corpus preserves 81 measured decisions from the prior checker; this is a lint regression, not a full accessibility audit. CI configuration now prepares a separate frontend install/lint/type/test/build job with pinned Node/action versions and no deployment credentials. The private remote has a passing committed CI run; current working changes require their own remote verification.

## Complete a real local assessment

Start the synthetic fixture in another terminal:

```sh
.venv/bin/python -m fixtures.safe_targets.server --port 8766
```

Sign in → Projects → create a project → register `http://127.0.0.1:8766/` → review origins, included/excluded paths and expiration → record explicit controlled-lab authorization → review and launch. The worker collects real HTTP configuration facts, showing skipped TLS/DNS coverage for this HTTP literal-IP fixture. Review findings and evidence, and download reports from the assessment or Reports view.

Use **Edit scope** in Projects to revise a target or renew its validity window (up to 24 hours). Review the complete replacement before saving. A change clears authorization, cancels queued jobs and requests cancellation of active jobs; collected facts and historical reports retain their original scope. Approve the new version before launching. Stale open forms are rejected and must reload the current version.

To retest remediation, stop the fixture with Ctrl+C and restart it with `--secure-headers`. Select Review retest on the completed assessment and review the captured current scope version. Only a complete successful relevant check can mark an absent header issue fixed; a connection error or cancellation cannot. A confirmed missing header is a verified configuration fact, not a claim of exploitation or complete application security.

## Product verification

```sh
source .venv/bin/activate
python3 -m unittest discover -s tests -v
python3 engineering/check.py
python3 engineering/check.py --run-gates
python3 engineering/check.py --run-gates --caller codex
python3 -m pytest -q
ruff check aegis sharay packages migrations fixtures tests/product scripts services tests/integration tests/evaluation engineering tests/test_engineering.py
ruff format --check aegis sharay packages migrations fixtures tests/product scripts services tests/integration tests/evaluation engineering tests/test_engineering.py
mypy --explicit-package-bases aegis sharay packages services engineering scripts/log_view.py scripts/session_log.py
npm --prefix apps/web run test
npm --prefix apps/web run typecheck
npm --prefix apps/web run lint
npm --prefix apps/web run build
```

Product tests create temporary databases, synthetic accounts, ephemeral TLS certificates and loopback fixtures. They need local socket permission. No real Internet target is scanned. The prior dependency-free collector and foundation tests are retained below.

## Account recovery

The local OS owner can issue a ten-minute, single-use recovery token with `.venv/bin/python -m sharay issue-recovery USERNAME`, then run `.venv/bin/python -m sharay reset-password`. Token and password entry is interactive; reset revokes sessions. Keep the displayed bearer token private. No email/MFA recovery workflow is implemented.

## Engineering foundation

The independent evidence collector and its original tests use only the Python standard library. The collector dashboard is buildless HTML/JavaScript. Product dependencies are separate; activate the virtual environment to discover the full product suite.

## Run

```sh
python3 -m unittest discover -s tests -v
python3 engineering/check.py
python3 engineering/check.py --run-gates
```

Open `.engineering/reports/index.html` in a browser. Each collector run saves a dated JSON snapshot and `latest.json`. The dashboard supports path filtering, JSON import and export. It operates locally and makes no network requests. Reports contain file paths and may reveal private repository structure; keep them private.

During shared engineering sessions, pass `--caller codex`, `claude`, `gemini` or `human` to keep default reports under `.engineering/reports/<caller>/`. The label is supplied attribution, not authentication. An explicit `--output` retains its chosen path; omitting the caller retains the original report location. Coordinate full-suite runs because report separation does not isolate test fixtures or serialize execution.

`--run-gates` executes commands from `engineering/gates.json` with `shell=False`, a timeout, no inherited credential variables, and no raw output capture. A nonzero exit, missing executable or timeout fails the collection exit status. Commands remain arbitrary programs: this runner does not provide an OS sandbox, filesystem confinement, or network isolation. Review gates and use an externally sandboxed environment for untrusted repositories. Full commands and raw output are intentionally not added to shareable reports; reproduce a failed trusted command locally to inspect its output.

The unittest runner writes a private temporary metadata sidecar containing counts and safe base IDs for failures, errors and unexpected successes. Reports exclude messages, tracebacks and subtest parameters; unsupported or credential-shaped IDs are omitted with a truncation flag. Missing, invalid or unsafe metadata is `unavailable`. Optional sidecar cleanup problems are recorded separately from the actual gate result. Other commands do not automatically supply unittest diagnostics, and the earlier unidentified failed run cannot be reconstructed from discarded output.

The dashboard shows repository metadata, actual gate status, gate timings and the collector process's peak RSS/CPU time. It does not yet collect application coverage, dependency resolution, scanner findings, product logs/traces, service resource utilization, API/database/network metrics, Codex session events, tokens or cost. Those fields are explicitly unavailable. The collector never reads source contents during inventory, follows directory symlinks, installs packages, or invokes an LLM.

## Files

| Path | Purpose |
| --- | --- |
| `AGENTS.md` | Codex working agreements and approval boundaries |
| `engineering/check.py` | Metadata audit, reviewed gate execution and report generation |
| `engineering/gates.json` | Four reviewed Python test/lint/format/type gates, stored as argv arrays |
| `engineering/dashboard.html` | Local interactive dashboard template |
| `tests/test_engineering.py` | Gate failure, timeout, credential handling, inventory and output-injection checks |
| `.github/workflows/quality.yml` | Pinned CI test/build checks on the private GitHub repository; read-only permissions and retained collector evidence |
| `docs/` | Architecture, roadmap, decisions and change evidence |

Repository output ignores `.engineering`, Git internals, generated caches, dependency trees, virtual environments and build folders. Exclusions are disclosed in the report; this is not a complete audit of excluded content. Hidden file names are inventoried. Environment files' contents are never read by inventory.

See `docs/roadmap.md` for the original foundation decisions and `docs/ARCHITECTURE.md` for current component and telemetry boundaries. Global engineering skills are separate instructions available to this user. The approved recurring automation coordinates engineering through this conversation. A private GitHub remote and observed CI runs exist; branch protection is not verified. Production deployment, external scanner execution and an observability service remain unavailable.
