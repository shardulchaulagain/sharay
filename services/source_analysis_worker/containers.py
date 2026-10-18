"""Container and IaC configuration analysis in an extracted tree (L6): parse, never run.

Static inspection only. Dockerfiles are read from a staged tree and checked for well-known
container misconfigurations (root execution, unpinned base image, credentials baked into
ENV/ARG, remote-script-piped-to-shell, missing healthcheck). `scan_k8s_manifest_dict` applies
the same idea to an already-parsed Kubernetes PodSpec; Kubernetes manifests are YAML and no
YAML parser is a dependency here, so file discovery covers Dockerfiles only and the PodSpec
checker is reached by a caller that has already parsed the document.

Config text is untrusted and may hold credentials or unprintable bytes: every value taken from
a file passes through `_clean` (and secrets through `redact_tokens`) before it reaches a finding,
and the number of findings is bounded, exactly as the dependency and secret analyzers do.
Structure adapted from Gemini's reviewed draft.
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
    # Config text is untrusted and may hold a credential (an image name, path or K8s identity can
    # carry one): redact recognised tokens on the whole value first, then make it printable and
    # bound the length so shortening can never leave half a credential behind.
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


def scan_dockerfile_content(content: str, file_path: str = "Dockerfile") -> list[dict[str, Any]]:
    """Security checks on one Dockerfile's text. At most MAX_FINDINGS are returned."""
    findings: list[dict[str, Any]] = []
    path = _clean(file_path)

    def add(finding: dict[str, Any]) -> None:
        if len(findings) < MAX_FINDINGS:
            findings.append(finding)

    lines = content.splitlines()
    # Per-stage state; "healthcheck" is "absent" | "set" | "none" (last directive in a stage wins).
    state = {"has_user": False, "last_user": "root", "healthcheck": "absent"}
    stages: dict[str, dict] = {}  # finished stage alias -> its end state, for FROM-alias inheritance
    current_alias: str | None = None

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.upper().startswith("FROM "):
            # Save the stage that just ended so a later "FROM <alias>" can inherit its USER/HEALTHCHECK.
            if current_alias is not None:
                stages[current_alias] = dict(state)
            # Skip flags like --platform=... to reach the real image reference.
            tokens = [t for t in stripped.split()[1:] if not t.startswith("--")]
            image = tokens[0] if tokens else ""
            current_alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].upper() == "AS" else None
            # A stage based on a named earlier stage inherits its filesystem (USER, HEALTHCHECK);
            # a stage on an external image starts fresh with an unknown inherited user.
            if image.lower() in stages:
                state = dict(stages[image.lower()])
            else:
                state = {"has_user": False, "last_user": "root", "healthcheck": "absent"}
            if image and image.lower() != "scratch" and image.lower() not in stages:
                if _is_unpinned(image):
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
            state["has_user"] = True
            state["last_user"] = stripped.split(None, 1)[1].strip()

        secret_match = _ENV_SECRET.search(stripped)
        if secret_match:
            directive, var_name = secret_match.group(1), secret_match.group(2)
            # The variable name and location are the hint; the value is never sampled into the
            # finding, because an ordinary (unrecognised) secret would survive redaction otherwise.
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
            # Last HEALTHCHECK in the stage wins: NONE disables, anything else sets one.
            state["healthcheck"] = "none" if stripped.split(None, 1)[1].strip().upper() == "NONE" else "set"

    # Save the final stage too, then judge the final image (what ships).
    if current_alias is not None:
        stages[current_alias] = dict(state)
    # USER may be "user:group" (e.g. "root:root" or "0:0"); judge the user part alone.
    final_user = str(state["last_user"]).split(":", 1)[0].strip().lower()
    if state["has_user"] and final_user in ("root", "0"):
        # A local USER explicitly selects root: a definite claim.
        add(
            _finding(
                "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "container_security",
                "Container sets the root user explicitly",
                "high",
                "confirmed",
                line=len(lines),
                path=path,
                description="A USER instruction selects root, so the container runs as root.",
                remediation="Run as a dedicated unprivileged user instead of root.",
            )
        )
    elif not state["has_user"]:
        # No USER anywhere in the final stage's lineage: the effective user is inherited from the
        # base image and is unknown from the Dockerfile text alone, so this is a hint.
        add(
            _finding(
                "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "container_security",
                "No non-root USER is declared",
                "medium",
                "medium",
                line=len(lines),
                path=path,
                description="No USER instruction is declared; the effective user is inherited from the "
                "base image and may be root. The Dockerfile alone does not establish it.",
                remediation="Declare a dedicated unprivileged 'USER <user>' before the entrypoint.",
            )
        )
    if state["healthcheck"] == "none":
        add(
            _finding(
                "DOCKER_HEALTHCHECK_DISABLED",
                "container_resilience",
                "Container healthchecking is disabled (HEALTHCHECK NONE)",
                "low",
                "confirmed",
                line=len(lines),
                path=path,
                description="HEALTHCHECK NONE disables any healthcheck inherited from the base image.",
                remediation="Replace HEALTHCHECK NONE with a real healthcheck, or omit it to inherit one.",
            )
        )
    elif state["healthcheck"] == "absent":
        add(
            _finding(
                "DOCKER_MISSING_HEALTHCHECK",
                "container_resilience",
                "Missing container HEALTHCHECK instruction",
                "low",
                "medium",
                line=len(lines),
                path=path,
                description="The image declares no HEALTHCHECK instruction for runtime health monitoring.",
                remediation="Add a HEALTHCHECK instruction so the runtime can detect an unhealthy container.",
            )
        )
    return findings


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

    # initContainers and ephemeralContainers run with the same securityContext risks as containers.
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
        # A present-but-null/empty cpu or memory is not an effective limit, so treat it as missing.
        if not isinstance(limits, dict) or not limits.get("cpu") or not limits.get("memory"):
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


def _is_unpinned(image: str) -> bool:
    # Pin = a digest, or a tag on the final path component. A ':' in the registry host is a port,
    # not a tag, so only the last '/'-segment is inspected; a missing tag defaults to :latest.
    if "@" in image:
        return False
    name_part = image.rsplit("/", 1)[-1]
    tag = name_part.split(":", 1)[1] if ":" in name_part else ""
    return tag in ("", "latest")


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile.")


def _read(path: Path) -> str:
    # Regular file only; O_NOFOLLOW so a symlink is never read through; fstat checks what was opened.
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
    for folder, folders, files in os.walk(root):  # never follows directory symlinks
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
            file_findings = scan_dockerfile_content(content, relative)
            # A file that hit the per-file cap dropped findings of its own: say so truthfully.
            if len(file_findings) >= MAX_FINDINGS:
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
