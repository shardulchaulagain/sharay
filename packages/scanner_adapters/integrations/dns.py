"""DNS reconnaissance record parser (L5): validated answers and the assets they reveal; no lookup.

Parser only: no resolver query is made here. The input is a list of already-collected answers in a
normalised form — `{"name", "type", "data", "ttl"}` — such as a resolver or a supplied zone dump
produces. Each record is validated by type (A->IPv4, AAAA->IPv6, CNAME/NS/PTR->hostname, MX->pref +
host, TXT/SOA/CAA->bounded text) and anything malformed or of an unknown type rejects the batch
rather than being guessed at. The result also rolls the records up into discovered `assets`
(hostnames and IPs) with the record type as their provenance. TXT data can hold SPF/DKIM tokens, so
all retained text is redacted and length-bounded.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from packages.scanner_adapters.integrations._parsing import fingerprint, shown

MAX_RECORDS = 5000
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}\.?$")
_HOSTNAME_TYPES = {"CNAME", "NS", "PTR"}
_TEXT_TYPES = {"TXT", "SOA", "CAA"}
_KNOWN_TYPES = {"A", "AAAA", "MX"} | _HOSTNAME_TYPES | _TEXT_TYPES


def _host(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{what} is not text.")  # never coerce None/bool/int into a 'none' host
    name = shown(value)
    if not _HOST.match(name):
        raise ValueError(f"{what} is not a valid hostname.")
    return name.rstrip(".").lower()


def _ip(value: str, version: int) -> str:
    addr = ipaddress.ip_address(shown(str(value)))
    if addr.version != version:
        raise ValueError("DNS address record data is the wrong IP version.")
    return str(addr)


def parse_records(answers: Any) -> dict[str, Any]:
    """Validate a list of normalised DNS answers into records plus the assets they reveal."""
    if not isinstance(answers, list):
        raise ValueError("DNS answers must be a list.")
    records: list[dict[str, Any]] = []
    hostnames: set[str] = set()
    ips: set[str] = set()
    for answer in answers[:MAX_RECORDS]:
        if not isinstance(answer, dict):
            raise ValueError("A DNS answer is not an object.")
        rtype = shown(str(answer.get("type", "")))
        if rtype not in _KNOWN_TYPES:
            raise ValueError("A DNS answer has an unknown record type.")
        name = _host(answer.get("name", ""), "DNS record name")
        hostnames.add(name)
        raw = answer.get("data", "")
        if rtype == "A":
            data: Any = _ip(raw, 4)
            ips.add(data)
        elif rtype == "AAAA":
            data = _ip(raw, 6)
            ips.add(data)
        elif rtype in _HOSTNAME_TYPES:
            data = _host(raw, f"DNS {rtype} target")
            hostnames.add(data)
        elif rtype == "MX":
            preference, _, host = shown(str(raw)).partition(" ")
            if not preference.isdigit() or not host:
                raise ValueError("A DNS MX record is not '<preference> <host>'.")
            host = _host(host, "DNS MX host")
            hostnames.add(host)
            data = f"{int(preference)} {host}"
        else:  # TXT / SOA / CAA: structured but not an asset; keep bounded and redacted
            data = (shown(str(raw)))[:500]
        records.append(
            {
                "name": name,
                "type": rtype,
                "data": data,
                "fingerprint": fingerprint("dns", name, rtype, str(data)),
            }
        )
    return {
        "records": records,
        "assets": {"hostnames": sorted(hostnames), "ips": sorted(ips)},
        "truncated": len(answers) > MAX_RECORDS,
    }


__all__ = ["parse_records"]
