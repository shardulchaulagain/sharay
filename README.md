# SHARAY

A scope-controlled, egress-locked security assessment platform. SHARAY performs authorized web
application and infrastructure testing — recon, crawling, DAST vulnerability detection, and bounded
exploitation — behind a hard authorization boundary: nothing is probed until the operator records
the target scope, and all third-party tooling runs inside a single-destination network jail.

It runs entirely on the operator's machine: a loopback-only API, a local worker, a SQLite database,
and a bundled web UI. There is no telemetry and no cloud dependency.

## Safety model (read this first)

- **No default credentials.** The first owner is created explicitly with `init-owner`.
- **Authorization precedes execution.** A target's scope must be recorded and approved before any
  active probe is sent. A live (non-loopback) target additionally requires the operator to assert
  ownership (`--authorized` on the CLI).
- **Egress is jailed.** Containerized tools (nuclei, ZAP, nmap, …) run under a single-destination
  firewall via Podman. If the isolation layer cannot be established, those stages **fail closed** —
  SHARAY sends no uncontained traffic.
- **Findings are verified.** Candidate findings are re-tested with a deterministic reproducer and a
  negative control before they are reported, which keeps false positives low.

## Requirements

- Python 3.13
- [Podman](https://podman.io/) (for egress-isolated container tools). On macOS: `podman machine init && podman machine start`.
- Nuclei templates on disk (for the Nuclei stage).

Optional system tools are auto-detected; run `python -m aegis preflight` to see what is available.

## Install

Quickest path — one script sets up a virtualenv, installs dependencies, and creates **this install's
own fresh database**:

```bash
./install.sh
```

Or manually:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # core runtime
# pip install -r requirements-desktop.txt  # native desktop app
# pip install -r requirements-dev.txt      # tests / development
python -m aegis migrate                   # creates + migrates the database
```

### Your database is per-install and never shipped

Each install creates its own SQLite database (`aegis.db`) inside the data directory — the default is
`.aegis/`, configurable via `SHARAY_DATA_DIR` (and `SHARAY_PORT` for the port; see `.env.example`).
The data directory and all database files are **gitignored**, so cloning this repository never brings
anyone else's assessments or findings, and your own data is never committed when you push. The
database is created and migrated automatically the first time you run any command that needs it.

## First run

```bash
python -m aegis init-owner        # create the first operator (no default credentials)
python -m aegis status            # platform + scanner integration status
```

## Running

Server + worker (loopback API and web UI on port 8765 by default):

```bash
python -m aegis serve
```

Native desktop app:

```bash
python -m sharay desktop          # or launch SHARAY.command
```

Run an assessment from the command line (same pipeline the UI uses):

```bash
# a verified lab on loopback needs no ownership assertion:
python -m aegis scan http://127.0.0.1:8080/

# a live target you own requires --authorized:
python -m aegis scan https://example.com/ --authorized --profile comprehensive
```

Profiles: `comprehensive` (full pipeline), `safe_http` (headers/TLS only), `approved_templates`
(Nuclei only). See `python -m aegis scan --help` for mode, rate, depth, and severity options.

List recorded findings:

```bash
python -m aegis findings
```

## Capabilities

- **Recon & enumeration** — passive inventory, DNS/email-spoofing posture, subdomains, port/service
  scanning (native + nmap), TLS/certificate inspection, security-header and cookie audit, secret and
  dependency (SCA) scanning.
- **Attack-surface discovery** — in-scope crawler, headless DOM analysis, OpenAPI/GraphQL/WSDL schema
  ingestion, per-endpoint parameter association, parameter mining, and JS endpoint/parameter/secret
  extraction; inputs are fuzzed across query, form, cookie, header, and JSON-body vectors.
- **Vulnerability detection (DAST)** — SQLi, XSS (reflected/DOM), command injection, path traversal /
  LFI, SSRF (incl. out-of-band), LDAP/XPath/NoSQL/SSTI/XXE injection, open redirect, CSRF, insecure
  TLS/headers, and more — each confirmed by a reproducer + negative control.
- **Bounded exploitation** — operator-authorized active exploitation (e.g. sqlmap) pinned to the
  approved target, under the egress jail.
- **Reporting** — PDF/HTML/Markdown/JSON reports with formal CVSS v3.1 vectoring and runnable PoCs.

## Architecture

```
aegis/      core app: CLI, loopback FastAPI, auth, worker supervisor, database, config
packages/   scanner engines, security policies, reporting, CVSS, offensive capability
  scanner_adapters/   the assessment pipeline + tool integrations
services/   out-of-process workers (scanner, source analysis, AI analysis, updates)
sharay/     native desktop entry point
apps/       web UI (served by the API)
migrations/ Alembic database migrations
tests/      test suite
```

## Development

```bash
pip install -r requirements-dev.txt
pytest                      # full suite
pytest tests/integration    # a subset
```

Some tests exercise containerized tools and require Podman running.

---

SHARAY is for **authorized** security testing only. The scope and egress controls are the operator's
tools for staying inside their authorization — they are not a substitute for it.
