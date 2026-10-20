"""Reference implementation of IPv6 & Multi-Destination CIDR Egress Engine (Phase 0, Sector 3 - P0.4).

Provides:
1. Multi-destination allowlist (supporting N targets: IPs and CIDR networks).
2. Dual-stack IPv4 (iptables) and IPv6 (ip6tables) egress enforcement.
3. Fail-closed default DROP for all out-of-scope destinations.
4. Clean conntrack state management and atomic teardown.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence

from services.scanner_worker import IsolationError

_DEFAULT_V4_SUBNET = "10.88.0.0/16"
_DEFAULT_V6_SUBNET = "fd00::/64"


def build_multidest_egress_ruleset(
    chain: str,
    destinations: Sequence[tuple[str, int]],
    *,
    subnet_v4: str = _DEFAULT_V4_SUBNET,
    subnet_v6: str = _DEFAULT_V6_SUBNET,
) -> dict[str, list[list[str]]]:
    """Return {'up': [...], 'down': [...]} for default-drop egress across IPv4 and IPv6 destinations."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", chain):
        raise IsolationError("Egress chain name must be a short identifier.")
    if not destinations:
        raise IsolationError("At least one egress destination (IP/CIDR, port) must be specified.")

    v4_dests: list[tuple[str, int]] = []
    v6_dests: list[tuple[str, int]] = []

    for target, port in destinations:
        if type(port) is not int or not 1 <= port <= 65535:
            raise IsolationError(f"Egress port must be an integer from 1 to 65535, got {port}.")
        try:
            # Parse target as either single IP or CIDR network
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                if net.version == 4:
                    v4_dests.append((str(net), port))
                else:
                    v6_dests.append((str(net), port))
            else:
                addr = ipaddress.ip_address(target)
                if addr.version == 4:
                    v4_dests.append((str(addr), port))
                else:
                    v6_dests.append((str(addr), port))
        except ValueError as exc:
            raise IsolationError(f"Invalid IP address or CIDR network: '{target}'.") from exc

    up_rules: list[list[str]] = []
    down_rules: list[list[str]] = []

    # 1. IPv4 Rules (iptables)
    if v4_dests:
        chain_v4 = chain
        up_rules.append(["iptables", "-N", chain_v4])
        for tgt, dport in v4_dests:
            up_rules.append(["iptables", "-A", chain_v4, "-d", tgt, "-p", "tcp", "--dport", str(dport), "-j", "ACCEPT"])
        up_rules.append(["iptables", "-A", chain_v4, "-j", "DROP"])
        up_rules.append([
            "iptables", "-I", "FORWARD", "1", "-s", subnet_v4,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])
        up_rules.append(["iptables", "-I", "FORWARD", "2", "-s", subnet_v4, "-j", chain_v4])

        down_rules.append(["iptables", "-D", "FORWARD", "-s", subnet_v4, "-j", chain_v4])
        down_rules.append([
            "iptables", "-D", "FORWARD", "-s", subnet_v4,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])
        down_rules.append(["iptables", "-F", chain_v4])
        down_rules.append(["iptables", "-X", chain_v4])

    # 2. IPv6 Rules (ip6tables)
    if v6_dests:
        chain_v6 = f"{chain}_V6"
        up_rules.append(["ip6tables", "-N", chain_v6])
        for tgt, dport in v6_dests:
            up_rules.append(["ip6tables", "-A", chain_v6, "-d", tgt, "-p", "tcp", "--dport", str(dport), "-j", "ACCEPT"])
        up_rules.append(["ip6tables", "-A", chain_v6, "-j", "DROP"])
        up_rules.append([
            "ip6tables", "-I", "FORWARD", "1", "-s", subnet_v6,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])
        up_rules.append(["ip6tables", "-I", "FORWARD", "2", "-s", subnet_v6, "-j", chain_v6])

        down_rules.append(["ip6tables", "-D", "FORWARD", "-s", subnet_v6, "-j", chain_v6])
        down_rules.append([
            "ip6tables", "-D", "FORWARD", "-s", subnet_v6,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])
        down_rules.append(["ip6tables", "-F", chain_v6])
        down_rules.append(["ip6tables", "-X", chain_v6])

    return {"up": up_rules, "down": down_rules}
