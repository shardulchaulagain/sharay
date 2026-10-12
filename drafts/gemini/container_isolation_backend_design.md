# OCI Container Isolation Sandbox Architecture & Runner Seam (C5/L1)

Author: Gemini (Principal Architect, Debugger & Helper)  
Target: Codex (C5 Orchestration) & Claude (L1 Isolation / Egress)  
Status: Architectural Proposal and Reference Specification in `drafts/gemini/`  

---

## 1. Problem Statement

On macOS, native process sandboxing relies on Apple Seatbelt (`sandbox-exec`). While Seatbelt effectively confines lightweight, single-process, non-forking binaries that obey tight filesystem rules, third-party scanner tools present fundamental isolation challenges:
1. **Java & Ruby Runtimes (OWASP ZAP, Metasploit Framework)**:
   - Must fork background workers, thread pools, and child helper processes.
   - Demand write access to user home directories (`~/.ZAP/`, `~/.msf4/`) for configuration, session databases, and caches.
   - Granting home-directory write access or permitting process forks on macOS Seatbelt weakens process escape containment and filesystem integrity.
2. **Resource Exhaustion**:
   - macOS Seatbelt cannot enforce hard cgroup-style memory limits (`memory.max`), CPU limits, or process count caps (`pids.max`). A rogue tool or runaway scanner can consume host RAM and cause a kernel panic or host lockup.
3. **Network Egress Boundaries**:
   - Seatbelt network filters cannot inspect connection-time socket destinations or prevent DNS rebinding dynamically.

**Solution**: Provide an unprivileged, rootless OCI container runner backend (via Rootless Podman or Docker) that satisfies all 13 `REQUIRED_RUNNER_CONTROLS` from `packages/shared_schemas.py`.

---

## 2. Fulfillment of `REQUIRED_RUNNER_CONTROLS`

| Required Control | Seatbelt Limitation | OCI Container Enforcement (`podman run`) |
| :--- | :--- | :--- |
| `non_root` | Inherits host UID | `--user 65534:65534` (nobody) or rootless unmapped UID |
| `fixed_argv_without_shell` | Shell wrappers prone to injection | Direct CLI invocation with `--entrypoint` and array argv |
| `clean_environment` | Leaks host env vars unless scrubbed | `--env-file /dev/null`, zero host env passthrough |
| `exec_allowlist` | Host path dependent | Cryptographically pinned image digest (`image@sha256:...`) |
| `filesystem_read_allowlist` | Broad `/usr/lib`, `/System` access | `--read-only` rootfs (immutable container image) |
| `scratch_only_writes` | Difficult to constrain runtime caches | `--tmpfs /tmp:rw,noexec,nosuid,size=64m` + bounded scratch mount |
| `network_denied_by_default` | All-or-nothing TCP connect | `--network none` (default) or dedicated scoped veth |
| `deadline_and_cancellation_group_kill`| Relies on host process tree kill | `--timeout <sec>` + container cancellation cgroup teardown |
| `bounded_output` | Pipe buffer reading | Container log driver `--log-driver none` + host capped pipe |
| `process_escape_containment` | Forking breaks Seatbelt bounds | `--cap-drop ALL`, `--security-opt no-new-privileges` |
| `memory_limit` | Unsupported on macOS Seatbelt | `--memory 512m --memory-swap 512m` |
| `process_count_limit` | Unsupported on macOS Seatbelt | `--pids-limit 64` |
| `aggregate_scratch_quota` | Disk quota requires APFS volume | tmpfs scratch bound or sized volume mount |

---

## 3. OCI Container Command Construction Contract

The container runner constructs immutable execution arguments without invoking any shell interpreter:

```python
def build_container_run_argv(
    image_digest: str,
    scratch_dir: str,
    target_argv: list[str],
    network_enabled: bool = False,
    memory_limit_mb: int = 512,
    pids_limit: int = 64,
    timeout_seconds: int = 60,
) -> list[str]:
    """Build unprivileged OCI container runner invocation."""
    cmd = [
        "podman", "run",
        "--rm",                                     # Auto-remove container upon exit
        "--read-only",                              # Immutable root filesystem
        "--security-opt", "no-new-privileges",      # Prevent privilege escalation
        "--cap-drop", "ALL",                        # Drop all Linux capabilities
        "--user", "65534:65534",                    # Non-root unprivileged execution
        "--memory", f"{memory_limit_mb}m",          # Memory limit
        "--memory-swap", f"{memory_limit_mb}m",     # Disable swap expansion
        "--pids-limit", str(pids_limit),            # Fork-bomb protection
        "--timeout", str(timeout_seconds),          # Hard execution deadline
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",# Ephemeral in-memory tmp
        "--volume", f"{scratch_dir}:/scratch:rw",   # Bounded scratch mount
        "--network", "bridge" if network_enabled else "none",
        image_digest,
    ]
    cmd.extend(target_argv)
    return cmd
```

---

## 4. Integration Seam Architecture

```
                      +-----------------------------------+
                      |      Codex C5 Control Plane       |
                      |  (ExecutionReadiness Verification)|
                      +-----------------+-----------------+
                                        |
                   +--------------------+--------------------+
                   |                                         |
     (Host Local Tools: Semgrep)               (Heavy / Forking: ZAP, MSF, Nmap)
                   |                                         |
                   v                                         v
     +--------------------------+              +---------------------------+
     |   Seatbelt Runner (L1)   |              |  Container Runner (C5/L1) |
     |  - sandbox-exec profile  |              |  - Rootless Podman/Docker |
     |  - Host binary execution |              |  - Hard cgroup memory cap |
     |  - Non-forking tools only|              |  - Read-only rootfs       |
     +--------------------------+              +---------------------------+
```

### Transition & Fallback Contract:
1. **Runner Selection**: `runner.py` detects host runtime capability:
   - If `podman` or `docker` is available and running, container runner profile is attested with `"memory_limit"` and `"process_count_limit"`.
   - If container runtime is absent, forking tools report `dependency_state: "missing"` and `execution_enabled: False`, satisfying the safety contract without crashing.
2. **Preflight Attestation**: Preflight checks verify that image digests are locally present or pullable, and that rootless user namespaces function properly before allowing task dispatch.
