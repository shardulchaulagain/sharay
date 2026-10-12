"""Shared pieces for parsers of third-party tool reports: bounded, strict, nothing echoed.

Tool output mixes the tool's own fields with text the scanned target controls. These
helpers validate the ORIGINAL value and reject what does not fit; they never repair a
value into something that looks valid, because two different inputs must not end up as
one stored identity. Errors are ValueError with fixed text.
"""

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from packages.reporting import redact

MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 5000
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def load_json(data: bytes, what: str) -> Any:
    if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
        raise ValueError(f"{what} is not bytes within the parsing budget.")
    try:
        # parse_constant: Python otherwise accepts NaN and Infinity, which are not JSON.
        return json.loads(data, parse_constant=_not_json)
    except (ValueError, RecursionError):  # invalid JSON, bad encoding, or nesting too deep
        # "from None": the decoder's error object holds the whole input document.
        raise ValueError(f"{what} is not valid JSON.") from None


def _not_json(_constant: str) -> None:
    raise ValueError("non-finite number")


def text(value: Any, what: str, limit: int = 150) -> str:
    """An identity field: printable text within the limit, returned exactly as given.

    Unicode letters are legitimate in file names and paths; control and other unprintable
    characters are rejected, never removed.
    """
    if not isinstance(value, str) or not 0 < len(value) <= limit or not value.isprintable():
        raise ValueError(f"{what} is missing, too long or not printable text.")
    return value


def relative_path(value: Any, what: str, source_root: str = "") -> str:
    """A location inside the scanned tree, checked on the original string.

    An absolute path is accepted only beneath `source_root` (a trusted value from the caller)
    and is then made relative; anything else absolute, any parent reference and any control
    character rejects the report.
    """
    path = text(value, what, 500).replace("\\", "/")
    # The trusted root gets the same separator normalization, or a Windows root never matches.
    root = source_root.replace("\\", "/").rstrip("/")
    if root and path.startswith(root + "/"):
        path = path[len(root) + 1 :]
    parts = path.split("/")
    if path.startswith("/") or ":" in parts[0] or any(part in ("", "..") for part in parts):
        raise ValueError(f"{what} is absolute, empty or leaves the scanned tree.")
    return "/".join(part for part in parts if part != ".") or "."


def port_suffix(value: int | None, what: str) -> str:
    if value is None:
        return ""
    if not 1 <= value <= 65535:
        raise ValueError(f"{what} has a port outside 1-65535.")
    return f":{value}"


def http_location(value: Any, what: str) -> str:
    """An http(s) URL rebuilt only from its parsed parts: no credentials, query or fragment."""
    raw = text(value, what, 1000)
    try:
        parsed = urlsplit(raw)
        host, port = parsed.hostname, parsed.port
    except ValueError:  # includes an out-of-range or non-numeric port
        raise ValueError(f"{what} is not a valid URL.") from None
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError(f"{what} is not an http or https URL.")
    authority = f"[{host}]" if ":" in host else host  # an IPv6 literal keeps its brackets
    return f"{parsed.scheme}://{authority}{port_suffix(port, what)}{parsed.path or '/'}"


def label(value: Any, limit: int = 200) -> str | None:
    """A display-only field: redacted, cleaned and then shortened; never used for identity.

    Redaction comes first, on the whole value, so cutting at the limit cannot leave part of
    a credential behind; it runs again after cleaning in case removed characters were
    splitting one.
    """
    if not isinstance(value, str):
        return None
    return redact(_UNPRINTABLE.sub("", redact(value)))[:limit] or None


def shown(value: str) -> str:
    """What is stored: recognised credential shapes are redacted even in a rule id or a path.

    Pattern-based, so an unrecognised secret format in such a field is not caught.
    """
    return redact(value)


def line_number(value: Any, what: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{what} is not a positive line number.")
    return value


def fingerprint(*parts: object) -> str:
    """Stable identity from the original values, hashed so no raw value is stored."""
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()[:16]
