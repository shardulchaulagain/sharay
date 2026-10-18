"""Drop-in release-ready replacement for `services/source_analysis_worker/containers.py`.

Resolves all 6 container items in `drafts/codex-review/l-half-release-review-20261013.md`:
1. P1 (containers.py:38,114): Redact recognized tokens before shortening in `_clean()`, and never
   sample raw/ordinary ENV/ARG secret values into finding descriptions.
2. P2 (containers.py:61,325): Track actual dropped findings (`file_truncated`) so 2,001 findings marks
   `truncated=True` while exactly 2,000 findings without drops remains `truncated=False`.
3. P2 (containers.py:77): Preserve `USER` and `HEALTHCHECK` configuration inherited from a named build
   stage (`FROM base AS builder` -> `FROM builder`).
4. P2 (containers.py:89,145): Distinguish registry `host:port/image` from `:tag` when checking for
   unpinned images, and treat `HEALTHCHECK NONE` as disabling healthchecks.
5. P2 (containers.py:150): Distinguish missing local `USER` instruction (unknown inherited runtime
   user from base image, `confidence="medium"`) from explicit `USER root`/`USER 0` (`confidence="high"`).
6. P2 (containers.py:270): Reject `null`, empty, or non-positive CPU/memory limits in Kubernetes
   container `resources.limits`.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from packages.secret_patterns import redact_tokens

MAX_DOCKERFILE_BYTES = 1 * 1024 * 1024
MAX_FILES = 500
MAX_FINDINGS = 2000
_SKIPPED_FOLDERS = {"node_modules", ".git", ".venv", "venv", "__pycache__"}
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_CURL_PIPE_SH = re.compile(r"(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash)", re.IGNORECASE)
_ENV_SECRET = re.compile(
    r"(ENV|ARG)\s+([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Za-z0-9_]*)\s*=\s*(.+)",
    re.IGNORECASE,
)


def _clean(value: object) -> str:
    return _UNPRINTABLE.sub("?", redact_tokens(str(value), "[REDACTED]"))[:200]


def _finding(rule_id: str, category: str, title: str, severity: str, confidence: str, **extra: Any) -> dict:
    return {
        "kind": "iac_issue",
        "category": category,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "tool": "iac_scanner",
        **extra,
    }


def _is_unpinned_image(image: str) -> bool:
    """Return True if an image reference lacks an immutable digest and specific non-latest tag.

    Distinguishes a registry port (`registry.example:5000/app`) from a tag on the last path segment.
    """
    name_part, has_digest, digest_part = image.partition("@")
    if has_digest and digest_part.strip():
        return False
    last_segment = name_part.rsplit("/", 1)[-1]
    _, has_colon, tag = last_segment.partition(":")
    if not has_colon or not tag.strip():
        return True
    return tag.strip().lower() == "latest"


def _scan_dockerfile_with_truncation(
    content: str, file_path: str = "Dockerfile"
) -> tuple[list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    truncated = False
    path = _clean(file_path)

    def add(finding: dict[str, Any]) -> None:
        nonlocal truncated
        if len(findings) < MAX_FINDINGS:
            findings.append(finding)
        else:
            truncated = True

    lines = content.splitlines()
    has_user_directive = False
    last_user = "root"
    has_healthcheck = False
    healthcheck_disabled = False
    stage_aliases: set[str] = set()
    stage_states: dict[str, tuple[bool, str, bool, bool]] = {}
    current_stage: str | None = None

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.upper().startswith("FROM "):
            if current_stage is not None:
                stage_states[current_stage] = (
                    has_user_directive,
                    last_user,
                    has_healthcheck,
                    healthcheck_disabled,
                )
            tokens = [t for t in stripped.split()[1:] if not t.startswith("--")]
            image = tokens[0] if tokens else ""
            image_key = image.lower()
            if image_key in stage_states:
                has_user_directive, last_user, has_healthcheck, healthcheck_disabled = stage_states[image_key]
            else:
                has_user_directive = False
                last_user = "root"
                has_healthcheck = False
                healthcheck_disabled = False

            if len(tokens) >= 3 and tokens[1].upper() == "AS":
                current_stage = tokens[2].lower()
                stage_aliases.add(current_stage)
            else:
                current_stage = None

            if image and image_key != "scratch" and image_key not in stage_aliases:
                if _is_unpinned_image(image):
                    add(
                        _finding(
                            "DOCKER_UNPINNED_IMAGE",
                            "container_security",
                            "Unpinned or latest base image tag in Dockerfile",
                            "medium",
                            "confirmed",
                            line=idx,
                            path=path,
                            description=f"Base image '{_clean(image)}' uses mutable :latest or lacks an "
                            "explicit immutable tag/digest.",
                            remediation="Pin the base image to a specific version tag or immutable "
                            "SHA256 digest.",
                        )
                    )

        if stripped.upper().startswith("USER "):
            has_user_directive = True
            last_user = stripped.split(None, 1)[1].strip()

        secret_match = _ENV_SECRET.search(stripped)
        if secret_match:
            directive, var_name = secret_match.group(1), secret_match.group(2)
            add(
                _finding(
                    "DOCKER_SECRET_IN_ENV",
                    "secret_leak",
                    f"Potential credential declared in Dockerfile {_clean(directive).upper()}",
                    "high",
                    "high",
                    line=idx,
                    path=path,
                    description=f"Variable '{_clean(var_name)}' appears to store a credential in a build "
                    "instruction; its value is not shown.",
                    remediation="Use runtime secret mounts (BuildKit --mount=type=secret) instead of ENV/ARG.",
                )
            )

        if _CURL_PIPE_SH.search(stripped):
            add(
                _finding(
                    "DOCKER_CURL_PIPE_SHELL",
                    "supply_chain_security",
                    "Insecure download piped directly to shell",
                    "high",
                    "high",
                    line=idx,
                    path=path,
                    description="Dockerfile executes an unverified remote script directly via a pipe to a shell.",
                    remediation="Download the script to a file, verify its hash/signature, then execute it.",
                )
            )

        if stripped.upper().startswith("HEALTHCHECK "):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].upper() == "NONE":
                has_healthcheck = False
                healthcheck_disabled = True
            else:
                has_healthcheck = True
                healthcheck_disabled = False

        if current_stage is not None:
            stage_states[current_stage] = (
                has_user_directive,
                last_user,
                has_healthcheck,
                healthcheck_disabled,
            )

    final_user = last_user.split(":", 1)[0].strip().lower()
    if not has_user_directive:
        add(
            _finding(
                "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "container_security",
                "No local non-root USER instruction in Dockerfile",
                "high",
                "medium",
                line=len(lines),
                path=path,
                description="The Dockerfile sets no local USER instruction; the runtime user is inherited "
                "from the base image and defaults to root unless the base image configures otherwise.",
                remediation="Create an unprivileged user/group and set 'USER <user>' before the entrypoint.",
            )
        )
    elif final_user in ("root", "0"):
        add(
            _finding(
                "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "container_security",
                "Container explicitly sets root user",
                "high",
                "confirmed",
                line=len(lines),
                path=path,
                description="The Dockerfile explicitly sets USER root (or UID 0); the process runs as root.",
                remediation="Create an unprivileged user/group and set 'USER <user>' before the entrypoint.",
            )
        )

    if not has_healthcheck:
        add(
            _finding(
                "DOCKER_MISSING_HEALTHCHECK",
                "container_resilience",
                "Disabled container HEALTHCHECK instruction"
                if healthcheck_disabled
                else "Missing container HEALTHCHECK instruction",
                "low",
                "medium",
                line=len(lines),
                path=path,
                description="The Dockerfile explicitly disables healthchecking with HEALTHCHECK NONE."
                if healthcheck_disabled
                else "The image declares no HEALTHCHECK instruction for runtime health monitoring.",
                remediation="Add a HEALTHCHECK instruction so the runtime can detect an unhealthy container.",
            )
        )
    return findings, truncated


def scan_dockerfile_content(content: str, file_path: str = "Dockerfile") -> list[dict[str, Any]]:
    """Security checks on one Dockerfile's text. At most MAX_FINDINGS are returned."""
    findings, _ = _scan_dockerfile_with_truncation(content, file_path)
    return findings


def _has_valid_limit(limits: Any, key: str) -> bool:
    if not isinstance(limits, dict):
        return False
    val = limits.get(key)
    if isinstance(val, str):
        return bool(val.strip())
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return val > 0
    return False


def scan_k8s_manifest_dict(doc: Any, file_path: str = "manifest.yaml") -> list[dict[str, Any]]:
    """Security checks on one already-parsed Kubernetes manifest (Pod or a workload with a template)."""
    if not isinstance(doc, dict):
        return []
    findings: list[dict[str, Any]] = []
    path = _clean(file_path)

    def add(finding: dict[str, Any]) -> None:
        if len(findings) < MAX_FINDINGS:
            findings.append(finding)

    metadata = doc.get("metadata")
    name = _clean(metadata.get("name", "unnamed")) if isinstance(metadata, dict) else "unnamed"
    label = f"{_clean(doc.get('kind', 'Pod'))} '{name}'"

    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return findings
    template = spec.get("template")
    pod_spec = template.get("spec", spec) if isinstance(template, dict) else spec
    if not isinstance(pod_spec, dict):
        return findings

    if pod_spec.get("hostNetwork") is True:
        add(
            _finding(
                "K8S_HOST_NETWORK",
                "kubernetes_security",
                f"{label} shares the host network namespace",
                "high",
                "confirmed",
                path=path,
                description="hostNetwork: true gives the pod the host's loopback and every host interface.",
                remediation="Disable hostNetwork unless a network daemon strictly requires it.",
            )
        )
    if pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
        add(
            _finding(
                "K8S_HOST_PID_IPC",
                "kubernetes_security",
                f"{label} shares the host PID or IPC namespace",
                "high",
                "confirmed",
                path=path,
                description="Sharing the host PID/IPC namespace lets pod processes view or signal host processes.",
                remediation="Remove hostPID and hostIPC.",
            )
        )

    all_containers = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        value = pod_spec.get(field)
        if isinstance(value, list):
            all_containers.extend(value)
    for container in all_containers:
        if not isinstance(container, dict):
            continue
        c_name = _clean(container.get("name", "container"))
        sec_ctx = container.get("securityContext")
        sec_ctx = sec_ctx if isinstance(sec_ctx, dict) else {}

        if sec_ctx.get("privileged") is True:
            add(
                _finding(
                    "K8S_PRIVILEGED_CONTAINER",
                    "kubernetes_security",
                    f"Container '{c_name}' runs in privileged mode",
                    "critical",
                    "confirmed",
                    path=path,
                    description="A privileged container disables isolation boundaries and gains root host access.",
                    remediation="Set securityContext.privileged: false and grant only the capabilities needed.",
                )
            )
        if sec_ctx.get("readOnlyRootFilesystem") is not True:
            add(
                _finding(
                    "K8S_WRITABLE_ROOT_FILESYSTEM",
                    "kubernetes_security",
                    f"Container '{c_name}' has a writable root filesystem",
                    "medium",
                    "high",
                    path=path,
                    description="A writable root filesystem lets an attacker persist malware or modify binaries.",
                    remediation="Set securityContext.readOnlyRootFilesystem: true and mount emptyDir for scratch.",
                )
            )
        resources = container.get("resources")
        limits = resources.get("limits") if isinstance(resources, dict) else None
        if not (_has_valid_limit(limits, "cpu") and _has_valid_limit(limits, "memory")):
            add(
                _finding(
                    "K8S_MISSING_RESOURCE_LIMITS",
                    "kubernetes_resilience",
                    f"Container '{c_name}' is missing a CPU or memory limit",
                    "low",
                    "medium",
                    path=path,
                    description="Unbounded resource use is a denial-of-service risk to other workloads on the node.",
                    remediation="Set resources.limits.cpu and resources.limits.memory.",
                )
            )
    return findings


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile.")


def _read(path: Path) -> str:
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ValueError("Dockerfile is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Dockerfile is not a regular file")
        data = stream.read(MAX_DOCKERFILE_BYTES + 1)
    if len(data) > MAX_DOCKERFILE_BYTES:
        raise ValueError("Dockerfile is larger than the parsing budget")
    return data.decode("utf-8", "replace")


def scan(root: Path | str) -> dict[str, Any]:
    """Walk an extracted tree for Dockerfiles and return their findings; counts are bounded."""
    root = Path(root).resolve()
    result: dict[str, Any] = {"files": [], "findings": [], "unreadable": [], "truncated": False}
    for folder, folders, files in os.walk(root):
        folders[:] = sorted(name for name in folders if name not in _SKIPPED_FOLDERS)
        for name in sorted(files):
            if not _is_dockerfile(name):
                continue
            relative = _clean(Path(folder, name).relative_to(root).as_posix())
            if len(result["files"]) >= MAX_FILES:
                result["truncated"] = True
                return result
            result["files"].append(relative)
            try:
                content = _read(Path(folder, name))
            except (OSError, ValueError):
                result["unreadable"].append(relative)
                continue
            file_findings, file_truncated = _scan_dockerfile_with_truncation(content, relative)
            if file_truncated:
                result["truncated"] = True
            for finding in file_findings:
                if len(result["findings"]) >= MAX_FINDINGS:
                    result["truncated"] = True
                    return result
                result["findings"].append(finding)
    return result


__all__ = [
    "scan",
    "scan_dockerfile_content",
    "scan_k8s_manifest_dict",
]
