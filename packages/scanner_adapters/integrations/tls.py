"""TLS peer-certificate reconnaissance parser (L5): what a supplied certificate declares; no probe.

Parser only: no TLS connection is made here. The input is the certificate dict Python's `ssl`
module produces for a peer (`ssl.getpeercert()`): `subject`/`issuer` as nested RDN tuples,
`subjectAltName` as `(type, value)` pairs, and `notBefore`/`notAfter` as the OpenSSL time strings.
It yields a bounded recon observation — the subject and issuer common names, the validated DNS and
IP subject-alternative names (which are discovered assets), validity window, and derived
self-signed / expired / not-yet-valid facts relative to a supplied clock. Certificate text is
untrusted, so every retained string is redacted and length-bounded; an unparseable field rejects
the certificate rather than being guessed at.
"""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import UTC, datetime
from typing import Any

from packages.scanner_adapters.integrations._parsing import fingerprint, label, shown

MAX_SANS = 1000
_HOST = re.compile(r"^(?=.{1,253}$)(?:\*\.)?(?:[A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$")


def _common_name(rdn_sequence: Any) -> str | None:
    """Pull the commonName out of ssl's nested RDN structure ((('commonName','x'),), ...)."""
    if not isinstance(rdn_sequence, (tuple, list)):
        return None
    for rdn in rdn_sequence:
        if not isinstance(rdn, (tuple, list)):
            continue
        for attribute in rdn:
            if isinstance(attribute, (tuple, list)) and len(attribute) == 2 and attribute[0] == "commonName":
                return label(attribute[1], 253)
    return None


def _epoch(value: Any, what: str) -> float:
    """Parse an OpenSSL time string ('Jun  1 00:00:00 2025 GMT') as UTC seconds."""
    if not isinstance(value, str):
        raise ValueError(f"{what} is not a certificate time string.")
    collapsed = " ".join(value.split())  # the day is space-padded ('Jun  1' -> 'Jun 1')
    head, _, tail = collapsed.rpartition(" ")
    body = head if tail.isalpha() else collapsed  # drop a trailing zone word (GMT/UTC)
    try:
        return datetime.strptime(body, "%b %d %H:%M:%S %Y").replace(tzinfo=UTC).timestamp()
    except ValueError:
        raise ValueError(f"{what} is not a certificate time string.") from None


def _sans(alt_names: Any) -> dict[str, list[str]]:
    """Validate subjectAltName entries into DNS names and IP addresses; reject anything malformed."""
    dns: list[str] = []
    ips: list[str] = []
    if alt_names in (None, ()):
        return {"dns": dns, "ip": ips}
    if not isinstance(alt_names, (tuple, list)):
        raise ValueError("subjectAltName is not a sequence.")
    for entry in alt_names[:MAX_SANS]:
        if not (isinstance(entry, (tuple, list)) and len(entry) == 2):
            raise ValueError("A subjectAltName entry is not a (type, value) pair.")
        kind, raw = entry
        if not isinstance(raw, str):
            raise ValueError("A subjectAltName value is not text.")  # never coerce None -> 'none'
        value = shown(raw)
        if kind == "DNS":
            if not _HOST.match(value):
                raise ValueError("A DNS subjectAltName is not a valid hostname.")
            dns.append(value.lower())
        elif kind == "IP Address":
            try:
                ips.append(str(ipaddress.ip_address(value)))
            except ValueError:
                raise ValueError("An IP subjectAltName is not a valid address.") from None
        # Other GeneralName types (email, URI, …) are not assets for this recon and are skipped.
    return {"dns": sorted(set(dns)), "ip": sorted(set(ips))}


def parse_peer_certificate(cert: dict[str, Any], *, now_epoch: float | None = None) -> dict[str, Any]:
    """Turn an `ssl.getpeercert()` dict into one bounded TLS recon observation."""
    if not isinstance(cert, dict):
        raise ValueError("Peer certificate is not an object.")
    subject_cn = _common_name(cert.get("subject"))
    issuer_cn = _common_name(cert.get("issuer"))
    not_before = _epoch(cert.get("notBefore"), "notBefore")
    not_after = _epoch(cert.get("notAfter"), "notAfter")
    if not_after < not_before:
        raise ValueError("Certificate notAfter precedes notBefore.")
    sans = _sans(cert.get("subjectAltName"))
    now = time.time() if now_epoch is None else now_epoch
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "self_signed": subject_cn is not None and subject_cn == issuer_cn,
        "not_yet_valid": now < not_before,
        "expired": now > not_after,
        "days_until_expiry": int((not_after - now) // 86400),
        "fingerprint": fingerprint("tls", subject_cn or "", issuer_cn or "", str(not_after)),
    }


__all__ = ["parse_peer_certificate"]
