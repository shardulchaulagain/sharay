"""Context-aware adaptive scanning and intelligence synthesis engine.

Correlates findings across passive reconnaissance, TLS inspection, port discovery,
crawled endpoints, and HTTP posture to extract target technology fingerprinting
and dynamically tailor downstream active tests and scanner tags.
"""

from __future__ import annotations

from typing import Any


class TargetIntelligence:
    """Consolidated profile of a target gathered from passive and early stages."""

    def __init__(self) -> None:
        self.web_servers: set[str] = set()
        self.runtimes: set[str] = set()
        self.frameworks: set[str] = set()
        self.cdn_or_waf: set[str] = set()
        self.open_ports: set[int] = set()
        self.discovered_endpoints: set[str] = set()
        self.discovered_parameters: set[str] = set()
        self.os_family: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "web_servers": sorted(self.web_servers),
            "runtimes": sorted(self.runtimes),
            "frameworks": sorted(self.frameworks),
            "cdn_or_waf": sorted(self.cdn_or_waf),
            "open_ports": sorted(self.open_ports),
            "endpoints_count": len(self.discovered_endpoints),
            "parameters_count": len(self.discovered_parameters),
            "os_family": self.os_family or "unknown",
        }


def extract_intelligence(observations: list[dict[str, Any]]) -> TargetIntelligence:
    """Analyze all observations to date and extract verified technology facts."""
    intel = TargetIntelligence()

    for obs in observations:
        kind = obs.get("kind", "")
        cat = obs.get("category", "")

        # 1. Ports and Services
        if kind == "network_service" or cat == "network_inventory":
            port = obs.get("port")
            if isinstance(port, int):
                intel.open_ports.add(port)

        # 2. HTTP Server and Headers
        server_header = obs.get("server") or obs.get("software_indicators", {}).get("server")
        if isinstance(server_header, str):
            s_lower = server_header.lower()
            if "apache" in s_lower:
                intel.web_servers.add("apache")
            if "nginx" in s_lower:
                intel.web_servers.add("nginx")
            if "cloudflare" in s_lower:
                intel.cdn_or_waf.add("cloudflare")
            if "caddy" in s_lower:
                intel.web_servers.add("caddy")
            if "iis" in s_lower or "microsoft" in s_lower:
                intel.web_servers.add("iis")
                intel.os_family = "windows"
            if "litespeed" in s_lower:
                intel.web_servers.add("litespeed")

        x_powered = obs.get("x_powered_by") or obs.get("software_indicators", {}).get("x_powered_by")
        if isinstance(x_powered, str):
            xp_lower = x_powered.lower()
            if "php" in xp_lower:
                intel.runtimes.add("php")
            if "express" in xp_lower or "node" in xp_lower:
                intel.runtimes.add("node")
                intel.frameworks.add("express")
            if "asp.net" in xp_lower:
                intel.runtimes.add("dotnet")
                intel.os_family = "windows"

        # 3. Crawler Observations
        if kind == "crawler_summary":
            for ep in obs.get("endpoints", []):
                intel.discovered_endpoints.add(ep)
                ep_lower = ep.lower()
                if "wp-content" in ep_lower or "wp-includes" in ep_lower:
                    intel.frameworks.add("wordpress")
                    intel.runtimes.add("php")
                if "api" in ep_lower:
                    intel.frameworks.add("api")
            for param in obs.get("parameters", []):
                intel.discovered_parameters.add(param)

        # 4. Raw Headers Inspection if present
        headers = obs.get("headers")
        if isinstance(headers, dict):
            h_server = headers.get("server", "").lower()
            if "cloudflare" in h_server:
                intel.cdn_or_waf.add("cloudflare")
            if "apache" in h_server:
                intel.web_servers.add("apache")
            if "nginx" in h_server:
                intel.web_servers.add("nginx")

    return intel


def synthesize_adaptive_strategy(
    intel: TargetIntelligence,
    base_tags: str | None = None,
    mode: str = "adaptive",
) -> dict[str, Any]:
    """Synthesize custom tailored scanner tags and execution focus based on intelligence."""
    suggested_tags: set[str] = set()

    if base_tags:
        for t in base_tags.split(","):
            if t.strip():
                suggested_tags.add(t.strip())

    if mode in ("adaptive", "aggressive"):
        # Add server-specific tags
        for server in intel.web_servers:
            suggested_tags.add(server)

        # Add runtime-specific tags
        for rt in intel.runtimes:
            suggested_tags.add(rt)

        # Add framework-specific tags
        for fw in intel.frameworks:
            suggested_tags.add(fw)

        # If API endpoints are present, include API tags
        if "api" in intel.frameworks or any("/api" in ep for ep in intel.discovered_endpoints):
            suggested_tags.add("api")
            suggested_tags.add("exposure")

        # If standard web ports, ensure general cve and misconfiguration tags
        if any(p in intel.open_ports for p in (80, 443, 8080, 8443)):
            suggested_tags.add("cve")
            suggested_tags.add("misconfig")

        # If Windows is detected, prioritize windows; else avoid windows-specific spraying
        if intel.os_family == "windows":
            suggested_tags.add("windows")

    tailored_tag_string = ",".join(sorted(suggested_tags)) if suggested_tags else None

    return {
        "tailored_tags": tailored_tag_string,
        "intel": intel.to_dict(),
        "targeted_technologies": sorted(intel.web_servers | intel.runtimes | intel.frameworks),
        "mode": mode,
    }


__all__ = ["TargetIntelligence", "extract_intelligence", "synthesize_adaptive_strategy"]
