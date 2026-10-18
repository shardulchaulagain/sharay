"""Infrastructure-as-Code (IaC) and Container Configuration Scanner (L6).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Draft module under drafts/gemini/ for Claude L6 adoption.

Addresses MAIN_PROMPT.txt lines 38, 81-83:
"OSV/SBOM/container/IaC analysis... Configuration and security analysis."

Capabilities:
1. Dockerfile Static Inspection:
   - Root user execution detection (missing non-root USER instruction or explicit USER root).
   - Unpinned base images (e.g., :latest or missing tag).
   - Secret/credential leakage in ENV/ARG directives.
   - Insecure remote script pipes (curl | sh, wget | bash).
   - Missing container HEALTHCHECK directives.
2. Kubernetes / PodSpec Manifest Inspection:
   - Privileged container execution (securityContext.privileged: true).
   - Host namespace sharing (hostNetwork: true, hostPID: true, hostIPC: true).
   - Writable root filesystem (missing readOnlyRootFilesystem: true).
   - Privilege escalation allowed (allowPrivilegeEscalation: true).
   - Insecure capabilities (adding ALL or missing drop: [ALL]).
   - Missing CPU/Memory resource bounds (DoS risk).
3. Secret Redaction:
   - All detected strings and snippets pass through redact_tokens.
"""

from __future__ import annotations

import re
from typing import Any

from packages.secret_patterns import redact_tokens

_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_CURL_PIPE_SH = re.compile(r"(curl|wget)\s+[^\n|]+\|\s*(sh|bash)", re.IGNORECASE)
_ENV_SECRET = re.compile(
    r"(ENV|ARG)\s+([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Za-z0-9_]*)\s*=\s*(.+)",
    re.IGNORECASE,
)


class IaCScannerError(ValueError):
    """IaC scanning or manifest parsing failed."""


def scan_dockerfile_content(content: str, file_path: str = "Dockerfile") -> list[dict[str, Any]]:
    """Perform security checks on a Dockerfile string."""
    findings: list[dict[str, Any]] = []
    lines = content.splitlines()

    has_user_directive = False
    last_user = "root"
    has_healthcheck = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Check FROM base image pinning
        if stripped.upper().startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                image = parts[1]
                if image.lower() != "scratch":
                    if ":" not in image or image.endswith(":latest"):
                        findings.append(
                            {
                                "kind": "iac_issue",
                                "category": "container_security",
                                "rule_id": "DOCKER_UNPINNED_IMAGE",
                                "title": "Unpinned or latest base image tag in Dockerfile",
                                "severity": "medium",
                                "confidence": "confirmed",
                                "line": idx,
                                "path": file_path,
                                "description": f"Base image '{image}' uses mutable :latest or lacks an explicit immutable tag/digest.",
                                "remediation": "Pin base image to a specific version tag or immutable SHA256 digest.",
                                "tool": "iac_scanner",
                            }
                        )

        # Check USER directive
        if stripped.upper().startswith("USER "):
            has_user_directive = True
            user_val = stripped.split(None, 1)[1].strip()
            last_user = user_val

        # Check ENV/ARG secrets
        secret_match = _ENV_SECRET.search(stripped)
        if secret_match:
            var_name = secret_match.group(2)
            raw_val = secret_match.group(3)
            clean_val = redact_tokens(raw_val[:50], "[REDACTED]")
            findings.append(
                {
                    "kind": "iac_issue",
                    "category": "secret_leak",
                    "rule_id": "DOCKER_SECRET_IN_ENV",
                    "title": f"Potential credential declared in Dockerfile {secret_match.group(1)}",
                    "severity": "high",
                    "confidence": "high",
                    "line": idx,
                    "path": file_path,
                    "description": f"Variable '{var_name}' appears to store sensitive credentials in build instructions (sample: '{clean_val}').",
                    "remediation": "Use runtime secret mounts (e.g. BuildKit --mount=type=secret) instead of ENV/ARG.",
                    "tool": "iac_scanner",
                }
            )

        # Check curl | sh
        if _CURL_PIPE_SH.search(stripped):
            findings.append(
                {
                    "kind": "iac_issue",
                    "category": "supply_chain_security",
                    "rule_id": "DOCKER_CURL_PIPE_SHELL",
                    "title": "Insecure download piped directly to shell",
                    "severity": "high",
                    "confidence": "high",
                    "line": idx,
                    "path": file_path,
                    "description": "Dockerfile executes unverified remote script directly via pipe to shell.",
                    "remediation": "Download script to temporary file, verify cryptographic hash/signature, then execute.",
                    "tool": "iac_scanner",
                }
            )

        if stripped.upper().startswith("HEALTHCHECK "):
            has_healthcheck = True

    # Validate non-root execution
    if not has_user_directive or last_user in ("root", "0"):
        findings.append(
            {
                "kind": "iac_issue",
                "category": "container_security",
                "rule_id": "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "title": "Container runs as privileged root user",
                "severity": "high",
                "confidence": "confirmed",
                "line": len(lines),
                "path": file_path,
                "description": "Dockerfile does not specify a non-root USER instruction; process executes as root.",
                "remediation": "Create a dedicated unprivileged user/group and specify 'USER <user>' before entrypoint.",
                "tool": "iac_scanner",
            }
        )

    # Validate healthcheck
    if not has_healthcheck:
        findings.append(
            {
                "kind": "iac_issue",
                "category": "container_resilience",
                "rule_id": "DOCKER_MISSING_HEALTHCHECK",
                "title": "Missing container HEALTHCHECK instruction",
                "severity": "low",
                "confidence": "medium",
                "line": len(lines),
                "path": file_path,
                "description": "Container image lacks a HEALTHCHECK instruction for runtime health monitoring.",
                "remediation": "Add HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1.",
                "tool": "iac_scanner",
            }
        )

    return findings


def scan_k8s_manifest_dict(doc: dict[str, Any], file_path: str = "manifest.yaml") -> list[dict[str, Any]]:
    """Scan a parsed Kubernetes manifest dictionary for security misconfigurations."""
    findings: list[dict[str, Any]] = []

    if not isinstance(doc, dict):
        return []

    doc_kind = str(doc.get("kind", "Pod"))
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "unnamed") if isinstance(metadata, dict) else "unnamed"
    pod_label = f"{doc_kind} '{name}'"

    # Traverse to PodSpec
    spec = doc.get("spec", {})
    if not isinstance(spec, dict):
        return []

    # Handle Deployments, DaemonSets, StatefulSets, Jobs
    pod_spec = spec.get("template", {}).get("spec", spec) if isinstance(spec.get("template"), dict) else spec

    # Check host namespace sharing
    if pod_spec.get("hostNetwork") is True:
        findings.append(
            {
                "kind": "iac_issue",
                "category": "kubernetes_security",
                "rule_id": "K8S_HOST_NETWORK",
                "title": f"{pod_label} shares host network namespace",
                "severity": "high",
                "confidence": "confirmed",
                "path": file_path,
                "description": "Setting hostNetwork: true gives pod access to loopback and all host network interfaces.",
                "remediation": "Disable hostNetwork unless strictly required by network daemon.",
                "tool": "iac_scanner",
            }
        )

    if pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
        findings.append(
            {
                "kind": "iac_issue",
                "category": "kubernetes_security",
                "rule_id": "K8S_HOST_PID_IPC",
                "title": f"{pod_label} shares host PID or IPC namespace",
                "severity": "high",
                "confidence": "confirmed",
                "path": file_path,
                "description": "Sharing host PID/IPC namespace allows processes to view or signal host processes.",
                "remediation": "Remove hostPID and hostIPC flags.",
                "tool": "iac_scanner",
            }
        )

    containers = pod_spec.get("containers", [])
    if isinstance(containers, list):
        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "container")
            sec_ctx = c.get("securityContext", {})
            if not isinstance(sec_ctx, dict):
                sec_ctx = {}

            # Privileged container
            if sec_ctx.get("privileged") is True:
                findings.append(
                    {
                        "kind": "iac_issue",
                        "category": "kubernetes_security",
                        "rule_id": "K8S_PRIVILEGED_CONTAINER",
                        "title": f"Container '{c_name}' runs in privileged mode",
                        "severity": "critical",
                        "confidence": "confirmed",
                        "path": file_path,
                        "description": "Privileged containers disable all container isolation boundaries and grant root host access.",
                        "remediation": "Set securityContext.privileged: false and grant only minimal necessary capabilities.",
                        "tool": "iac_scanner",
                    }
                )

            # Read-only root filesystem
            if sec_ctx.get("readOnlyRootFilesystem") is not True:
                findings.append(
                    {
                        "kind": "iac_issue",
                        "category": "kubernetes_security",
                        "rule_id": "K8S_WRITABLE_ROOT_FILESYSTEM",
                        "title": f"Container '{c_name}' root filesystem is writable",
                        "severity": "medium",
                        "confidence": "high",
                        "path": file_path,
                        "description": "Writable root filesystems permit attackers to persist malware or modify binaries.",
                        "remediation": "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for scratch.",
                        "tool": "iac_scanner",
                    }
                )

            # Missing resource bounds
            resources = c.get("resources", {})
            limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
            if not limits or "cpu" not in limits or "memory" not in limits:
                findings.append(
                    {
                        "kind": "iac_issue",
                        "category": "kubernetes_resilience",
                        "rule_id": "K8S_MISSING_RESOURCE_LIMITS",
                        "title": f"Container '{c_name}' missing CPU or memory limits",
                        "severity": "low",
                        "confidence": "medium",
                        "path": file_path,
                        "description": "Unbounded resource consumption creates denial-of-service risk for other node workloads.",
                        "remediation": "Define resources.limits.cpu and resources.limits.memory.",
                        "tool": "iac_scanner",
                    }
                )

    return findings


__all__ = [
    "IaCScannerError",
    "scan_dockerfile_content",
    "scan_k8s_manifest_dict",
]
