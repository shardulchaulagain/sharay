"""Reconnaissance asset inventory with provenance (L5): merge what recon revealed, keep the source.

Pure aggregation: given the asset rollups that the recon parsers already produce (TLS SANs from
`tls.parse_peer_certificate`, DNS assets from `dns.parse_records`, hosts from `nmap`), this unions
them into one deduplicated list of discovered assets, each tagged with every source that revealed
it. This is recon output for scoping and review, NOT the product's authorized-target inventory
(that is the control plane's); nothing here authorizes contact with any asset. Hostnames are
lowercased and IPs normalised before dedup so one asset is never counted twice.
"""

from __future__ import annotations

import ipaddress
from typing import Any

MAX_ASSETS = 20000


def collect_assets(observations: Any) -> dict[str, Any]:
    """Merge `[{"source": str, "hostnames": [...], "ips": [...]}]` into provenance-tagged assets."""
    if not isinstance(observations, list):
        raise ValueError("Recon observations must be a list.")
    # (kind, value) -> set of sources that revealed it.
    seen: dict[tuple[str, str], set[str]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("A recon observation is not an object.")
        source = observation.get("source")
        if not isinstance(source, str) or not source:
            raise ValueError("A recon observation has no source label.")
        for kind, field in (("hostname", "hostnames"), ("ip", "ips")):
            values = observation.get(field, [])
            if not isinstance(values, list):
                raise ValueError(f"Recon {field} must be a list.")
            for value in values:
                if not isinstance(value, str) or not value:
                    raise ValueError(f"A recon {kind} is not text.")
                if kind == "hostname":
                    normalised = value.rstrip(".").lower()
                else:
                    # Normalise the IP (e.g. expanded IPv6 -> canonical) so one address dedups once.
                    try:
                        normalised = str(ipaddress.ip_address(value))
                    except ValueError:
                        raise ValueError("A recon ip is not a valid address.") from None
                seen.setdefault((kind, normalised), set()).add(source)
    assets = [
        {"value": value, "kind": kind, "sources": sorted(sources)}
        for (kind, value), sources in sorted(seen.items())
    ]
    return {"assets": assets[:MAX_ASSETS], "truncated": len(assets) > MAX_ASSETS}


__all__ = ["collect_assets", "MAX_ASSETS"]
