# Scanner isolation (L1) — macOS Seatbelt backend

`services/scanner_worker.run_isolated()` runs one reviewed argv inside `/usr/bin/sandbox-exec` with a deny-default profile. It is the only isolation backend on the development host (no Docker, Podman or bubblewrap is installed). It executes nothing by itself and enables no adapter: callers must pass scope, approval and policy gates first, and running a tool here is never authorization to assess a target. Several controls below exist because Codex's independent review reproduced a failure; the session log has each exchange.

## Enforced, with the test that shows it

All in `tests/integration/test_isolation.py`, against fixtures the test starts on loopback. Deliberately weakening each control makes its test fail (none skip).

| Control (name in `enforced`) | Observed behaviour |
| --- | --- |
| `exec_allowlist` | Only the executable and `exec_paths` (the tool's own runtime) can be exec'd. `read_paths` are data: readable, never executable. A tool in a data folder, a copy dropped into scratch, and `/usr/bin/true` under a `/usr/bin` read grant all fail with `EPERM`. |
| `filesystem_read_allowlist` | Reading outside declared paths and listing other directories fail with `EPERM`. |
| `scratch_only_writes`, `aggregate_scratch_quota` | By default nothing is writable: the tool's only output is stdout/stderr, each capped by `RLIMIT_FSIZE`, so total disk use is bounded. `allow_scratch_writes=True` opens the private scratch directory; each file is then capped but their total is not, and that run's result omits `aggregate_scratch_quota`. |
| `network_denied_by_default`, `loopback_port_egress`, `exact_loopback_address` | A grant is `tcp4 localhost:port` for the literal `127.0.0.1` or `tcp6 localhost:port` for `::1`; no other host string is accepted. With real listeners on both families at the same port, only the granted family connects. Another port, `127.0.0.2`, v4-mapped addresses, RFC 5737 space, UDP to the granted port, bind/listen and DNS all fail with `EPERM`. |
| `process_escape_containment`, `process_count_limit` | By default fork is denied: `fork`, `subprocess`, `posix_spawn` and `setsid` fail with `EPERM`, so the tool is one process that stays its own group leader and dies with the group `SIGKILL`. `allow_fork=True` gives both controls up for that run: a forked child can call `setsid()` and survive. |
| Deadline and cancellation | `SIGTERM` to the group, then `SIGKILL` after the grace period; a tool ignoring `SIGTERM` exits with `-9`. |
| Output | Exactly-at-budget output is complete; one byte more is reported truncated. |
| Limits under the worker | Limits are set by a single-threaded launcher that clamps to inherited hard caps (worker: `NOFILE` 128, `CPU` 300), so no `preexec_fn` and threaded callers are safe. |
| Cleanup | Scratch is removed even if the tool set mode 0 or the immutable flag on it; unlocking never follows a planted symlink. If removal still fails, `scratch_removed` is false and the run is `failed`, never `completed`. |
| Other | Fixed argv, no shell, absolute executable, rebuilt environment, refuses root, strict budget types. |

`attest()` runs a probe inside the sandbox and lists a control only if the probe saw the kernel refuse it. The probe uses the default (no fork, no scratch writes); `IsolatedResult.enforced` states what each individual run was configured with.

## Not enforced — blocks live execution and general third-party tools

- **`live_destination_egress`.** Seatbelt filters only `localhost:port` or `*:port`; it cannot allowlist one non-loopback address. Every non-loopback destination is rejected. Live targets need a network-namespace or container backend.
- **`memory_limit`.** macOS rejects `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS` at usable values (observed `EINVAL`). Only the deadline bounds memory.
- **`file_metadata_privacy`.** A tool can `stat` a path it already knows (pinned by a test); removing that rule stops processes from starting. It cannot read contents or list directories.
- **Forking or file-writing tools** (`escape_containment_for_forking_tools`, `scratch_quota_for_writing_tools`): Semgrep, ZAP and Metasploit need at least one of the two opt-ins and therefore lose the matching controls.
- Thread count is not limited. `sandbox-exec` is deprecated by Apple and cannot nest: inside another sandbox the tests skip, which is not a pass. Verified on macOS 26.6.2 only.

```sh
.venv/bin/python -m unittest tests.integration.test_isolation -v
```

## Nmap adapter (L2) — builder and parser only

`packages/scanner_adapters/integrations/nmap.py` is **planned, not implemented**: no nmap binary is installed and it has never run one. It contains one fixed TCP-connect command line (no version probes, no scripts, no DNS, approved ports/time/rate passed as typed arguments with no defaults), a strict XML parser that fails closed on anything outside the request and retains no banner text, and the path through the isolated runner, exercised with a stand-in executable. The XML sample in `tests/integration/test_nmap_adapter.py` is hand-written; its header was checked against nmap's `xml.cc` and the official book example, nothing more.
