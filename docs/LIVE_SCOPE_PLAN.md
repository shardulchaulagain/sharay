# SHARAY live execution readiness

The October 12 user expansion is a product requirement, not authorization for an unspecified real target. SHARAY must support approved live web/API/network/host and supplied artifact assessments through seamless adapters. It does not currently execute those integrations.

Codex owns target registration/verification, immutable scope, RBAC/approval policy and orchestration. Claude L1 owns execution isolation and egress; L2–L6 own scanners and reconnaissance. Before a live operation becomes available, both must establish the actual evidence below. The shared `ProposedToolAction` interface accepts operation/reference/budget fields, never shell commands, argv, arbitrary flags or console input. `ExecutionReadiness` is trusted server state, never user/model input.

| Gate | Acceptance evidence | Current state |
| --- | --- | --- |
| Target control and authorization | DNS TXT/HTTP/admin challenge or explicit verified laboratory record, authorizing identity, expiry and immutable scope version | Explicit loopback lab workflow implemented; live challenges planned |
| URL/DNS/address/redirect policy | Canonical origins/paths/exclusions, resolution/rebinding and actual-peer checks, explicit private-network policy, metadata denial | Loopback numeric peer/redirect/path/time checks tested; live policy planned |
| Typed tool/profile approval | Supported adapter/version, approved operation/templates/modules, bounded budgets and per-action risk approval | Contracts implemented and tested; external adapters disabled |
| OS execution isolation | Non-root isolation, restricted filesystem, enforced destination egress, CPU/memory/process/time bounds and tested cleanup | Dedicated bounded trusted HTTP process only; enforced isolation unavailable |
| Evidence/access | Organization checks, bounded outputs, secret redaction, integrity references, accurate status and audit events | Local records/reports exercised; external adapter parsers pending |
| Reproducible integration | Actual tool parsing/version fixtures, positive/negative cases, timeout/cancel/partial-failure and retest | Built-in HTTP/TLS tests pass; external suites pending |

Open handoff review: `entry-748e50da33f94638` in SESSION_LOG. Claude should reply with design and actual L1 fixture results before requesting execution flags. An installed executable must never set `execution_enabled=True` by itself. Metasploit catalog and approved auxiliary contracts are present, but no msfconsole, arbitrary exploit module, interactive shell or payload execution is exposed. Intrusive validation remains a separately approved future profile with its own acceptance tests. Reports must always show actual coverage and remaining limits.
