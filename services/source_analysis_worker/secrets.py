"""Built-in secret-pattern detection over an extracted tree (L6): locate, never reveal.

A small set of high-precision formats (private key blocks and a few provider token
shapes). Each match is reported by rule, file and line with a fingerprint; the matched
text is never returned. A match is a PATTERN match, not a verified live credential, and
this is a baseline, not a replacement for an established scanner such as Gitleaks.
"""

import hashlib
import os
from pathlib import Path
from typing import Any

from packages.secret_patterns import RULES, redact_tokens
from services.source_analysis_worker.dependencies import _SKIPPED_FOLDERS, _clean, _read

MAX_FILES = 20000
MAX_MATCHES = 5000
MAX_MATCHES_PER_FILE = 100
BASIS = "pattern match in file content; not verified as a live credential"


# Published documentation examples, stored in two halves so this file reports nothing itself.
_DOCUMENTED = {b"AKIA" + b"IOSFODNN7EXAMPLE"}


def _placeholder(match: bytes) -> bool:
    # "ghp_xxxxxxxx..." and "AKIA0000..." are documentation fillers, not credentials.
    return len(set(match[-16:])) <= 3 or match in _DOCUMENTED


def _embedded(data: bytes, start: int, end: int) -> bool:
    # Joined to a longer identifier by an underscore (PREFIX_AKIA..._SUFFIX, sk_live_..._handler):
    # a name that merely looks like a token. Redaction still removes it; detection does not report it.
    return data[start - 1 : start] == b"_" or data[end : end + 1] == b"_"


def detect(root: Path | str) -> dict[str, Any]:
    """Return where secret-shaped text appears under root, and which files were not scanned."""
    root = Path(root).resolve()
    result: dict[str, Any] = {"basis": BASIS, "files_scanned": 0, "matches": [], "skipped": []}

    def skipped(name: str, reason: str) -> None:
        if len(result["skipped"]) < MAX_MATCHES:
            result["skipped"].append({"file": name, "reason": reason})

    for folder, folders, files in os.walk(root):  # never follows directory symlinks
        folders[:] = sorted(name for name in folders if name not in _SKIPPED_FOLDERS)
        for name in sorted(files):
            path = Path(folder, name)
            # A file can be NAMED after the secret it holds, so the name is redacted too.
            shown = redact_tokens(_clean(path.relative_to(root).as_posix()), "[REDACTED]")
            if result["files_scanned"] >= MAX_FILES or len(result["matches"]) >= MAX_MATCHES:
                skipped(shown, "scan budget reached; not read")
                continue
            try:
                data = _read(path)
            except (OSError, ValueError) as exc:
                reason = str(exc).replace("manifest", "file") if str(exc).startswith("manifest is ") else ""
                skipped(shown, reason or "file could not be read")
                continue
            result["files_scanned"] += 1
            hits = []
            for rule, pattern in RULES:
                kept = 0
                for match in pattern.finditer(data):
                    if rule != "private_key_block" and (
                        _placeholder(match.group()) or _embedded(data, match.start(), match.end())
                    ):
                        continue
                    hits.append((match.start(), rule, match.group()))
                    kept += 1
                    if kept >= MAX_MATCHES_PER_FILE:
                        break
            line, last = 1, 0
            # In file order, so line numbers come from one forward pass instead of a rescan per match.
            for start, rule, text in sorted(hits)[:MAX_MATCHES_PER_FILE]:
                if len(result["matches"]) >= MAX_MATCHES:
                    break
                line += data.count(b"\n", last, start)
                last = start
                # A key block's header is identical for every key, so hash into its body.
                material = data[start : start + 4096] if rule == "private_key_block" else text
                result["matches"].append(
                    {
                        "rule": rule,
                        "file": shown,
                        "line": line,
                        # Lets a retest tell "same secret still there" from "a different one".
                        "fingerprint": hashlib.sha256(material).hexdigest()[:16],
                    }
                )
    return result


__all__ = ["detect", "redact_tokens"]
