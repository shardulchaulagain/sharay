# Product architecture

October 12 expansion: SHARAY's goal includes verified authorized live sites, hosts, networks and supplied artifacts. Current execution remains an approved loopback-only slice. `MAIN_PROMPT.txt` and TEAM_ASSIGNMENTS define the complete requirements and equal named work split. Shared typed tool contracts are exposed read-only through the authenticated `/api/v1/tool-contracts`; they dispatch nothing. Live policy, verified scope, approvals and enforced worker isolation must all pass before Claude's integrations can execute. Metasploit has catalog/approved-auxiliary contract definitions; no arbitrary console or exploit execution is available.

The initial desktop slice uses a Next.js static application inside a Python-owned local window, a loopback-only FastAPI API, SQLAlchemy/SQLite persistence, Alembic schema versions, and a separate Python worker process. The engineering metadata collector remains independent.

The API authenticates sessions and authorizes organization resources. A deterministic scope policy validates every scanner destination. A fixed safe HTTP adapter performs bounded GET requests; it never executes target code. The worker stores redacted observations and evidence, then derives header configuration findings. Reports read stored assessment data and contain no fabricated scanner claims. LLM use is disabled; it cannot expand scope or invoke commands.

Local desktop mode is a documented adaptation of the server-stack specification. PostgreSQL/Redis/S3 and container isolation are planned server capabilities. Public/private-network scanner execution is unavailable until isolation and egress controls are complete. Static frontend assets are public application code; sensitive data is always fetched from authenticated APIs.

The operator controls the first local owner account through a CLI. No built-in credentials exist. Local file permissions protect persistence from other OS users, but this is not protection against an administrator, malware running as the same user, or an unlocked authenticated desktop session. Login is an application boundary, not an operating-system security boundary.

## Preserved engineering collector boundaries

The collector walks file metadata without source-content inspection or directory-symlink traversal. Reviewed argv gates run only with `--run-gates`, using `shell=False`, a timeout and an environment without inherited credential variables. That gate runner is not an OS sandbox. It retains exit status, durations and command hashes, not stdout/stderr or complete commands. Collector reports distinguish not_run, passed, failed, blocked and timeout. Inventory must not be described as a dependency graph, architecture audit or vulnerability scan.

The local engineering HTML dashboard renders strings via textContent and escapes embedded report JSON. It has no network/command capability. Collector CPU and peak RSS describe only that collector process, not product workers or APIs. File history and latest/index snapshots are not a multi-file transaction; use one collector at a time. Private `.aegis` storage and build/dependency trees are excluded with disclosed paths. Hidden filenames are metadata, not read source.

Product metrics come from the authenticated database API. Collector imports for those metrics, coverage, frontend build state, scanner findings, Codex session telemetry, AI token/cost data and distributed observability remain unavailable. Logs, traces and model costs require explicit real evidence sources. No scheduled autonomous monitoring or production release has been enabled.

## Primary implementation references

The static frontend uses the supported [Next.js static export](https://nextjs.org/docs/app/guides/static-exports) path. API lifecycle/cookies follow [FastAPI](https://fastapi.tiangolo.com/advanced/response-cookies/). Password hashing uses the [argon2-cffi PasswordHasher](https://argon2-cffi.readthedocs.io/en/stable/api.html). The local window follows [pywebview usage](https://pywebview.flowrl.com/guide/usage.html); it opens the same local HTTP application. These references informed the implementation; passing local tests establish only the exercised behavior.
