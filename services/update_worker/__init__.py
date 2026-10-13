"""Verified, staged updates (self-update core): decides and records; fetches nothing.

An update goes CHECK, FETCH, VERIFY, EVALUATE, ACTIVATE, with ROLLBACK behind it. This module
is the part with no network: it checks a file already on disk against the publisher's
SHA-256, decides whether that candidate may become active, and keeps the ledger of what is
active, what it replaced and what was withdrawn. An update replaces detection content only:
nothing here can read or change scope, targets or approvals.

Not built yet: checking for new versions, downloading, signature verification, running the
corpora against a candidate, installing the files, and any scheduler. Nuclei templates are
deliberately not a component: new templates can add intrusive requests and need their own
review step first.
"""

import hashlib
import hmac
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# The only things that can be updated, and the only place each may come from.
SOURCES = {
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/download/",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/",
    "semgrep": "https://files.pythonhosted.org/packages/",
}
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_LEDGER_BYTES = 1024 * 1024
# After the official prefix: plain path segments only, so no dot segment, encoding, query or host trick.
_REST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")
Version = Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$")]
Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]


class UpdateRefused(ValueError):
    """A candidate was not activated; the message is fixed text."""


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    component: Literal["gitleaks", "nuclei", "semgrep"]
    version: Version
    url: str = Field(strict=True, max_length=500)
    sha256: Digest  # as published by the source, obtained separately from the file
    size: int = Field(strict=True, ge=1, le=MAX_ARTIFACT_BYTES)


class Pin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Version
    url: str
    sha256: Digest
    activated_at: str


class Ledger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: dict[str, Pin] = {}
    previous: dict[str, Pin] = {}
    withdrawn: dict[str, list[str]] = {}  # versions rolled back; never re-activated automatically
    history: list[dict[str, str]] = []


def _order(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def regressions(baseline: dict, candidate: dict) -> list[str]:
    """Disagreements in a candidate's evaluation report that the baseline report did not have."""

    def disagreements(report: dict) -> set[str]:
        return {
            f"{case['id']}:{kind}:{check}"
            for case in report["cases"]
            for kind in ("unexpected", "missed")
            for check in case[kind]
        } | {f"{identifier}:incomplete" for identifier in report.get("incomplete_scans", [])}

    # A case the candidate's report no longer contains is a regression too: an update that makes
    # the tool report nothing must not look like an update that agrees with everything.
    missing = {case["id"] for case in baseline["cases"]} - {case["id"] for case in candidate["cases"]}
    return sorted(
        (disagreements(candidate) - disagreements(baseline)) | {f"{name}:missing" for name in missing}
    )


def verify_file(path: Path | str, sha256: str, size: int) -> None:
    """Refuse unless path is a regular file of exactly `size` bytes with that SHA-256."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise UpdateRefused("The update file could not be opened as a regular file.") from None
    try:
        # Checked on the open descriptor, before any read: a directory or pipe is never read from.
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size != size or size > MAX_ARTIFACT_BYTES:
            raise UpdateRefused("The update file is not a regular file of the published size.")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    if not hmac.compare_digest(digest.hexdigest(), sha256):
        raise UpdateRefused("The update file does not match the published SHA-256.")


def load(ledger_path: Path | str) -> Ledger:
    try:
        descriptor = os.open(ledger_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return Ledger()  # nothing has ever been activated
    except OSError:
        descriptor = -1
    try:
        # One open, then checks on that descriptor: the file read is the file that was checked.
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_LEDGER_BYTES:
            raise ValueError
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            return Ledger.model_validate_json(handle.read(MAX_LEDGER_BYTES + 1))
    except (OSError, ValueError):  # a pydantic ValidationError is a ValueError
        # Never guess what is active: a damaged ledger stops updates until a person looks.
        raise UpdateRefused("The update ledger is unreadable; nothing was changed.") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _save(ledger_path: Path | str, ledger: Ledger) -> None:
    path = Path(ledger_path)
    temporary = path.with_name(path.name + ".tmp")
    # shortcut: no lock, one updater process at a time; add a file lock when a scheduler exists.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(ledger.model_dump_json(indent=1))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _event(action: str, component: str, version: str, reason: str) -> dict[str, str]:
    at = datetime.now(UTC).isoformat(timespec="seconds")
    return {"at": at, "action": action, "component": component, "version": version, "reason": reason}


def parse_candidate(values: dict) -> Candidate:
    try:
        return Candidate.model_validate(values)
    except ValidationError:
        raise UpdateRefused("The update candidate is not valid.") from None


def activate(ledger_path: Path | str, candidate: Candidate, artifact: Path | str, evaluation: dict) -> Pin:
    """Make a verified, evaluated, newer candidate the active version; anything less is refused.

    `evaluation` is the evidence from running the gates and corpora against the candidate:
    {"gates_passed": True, "regressions": []}. It must come from that run, not from the source.
    """
    ledger = load(ledger_path)
    url, prefix = candidate.url, SOURCES[candidate.component]
    if not url.startswith(prefix) or not _REST.match(url[len(prefix) :]):
        raise UpdateRefused("The update does not come from this component's official source.")
    if candidate.version in ledger.withdrawn.get(candidate.component, []):
        raise UpdateRefused("This version was rolled back and needs a person to re-approve it.")
    current = ledger.active.get(candidate.component)
    if current and _order(candidate.version) <= _order(current.version):
        raise UpdateRefused("The update is not newer than the active version.")
    passed = isinstance(evaluation, dict) and evaluation.get("gates_passed") is True
    if not passed or evaluation.get("regressions") != []:
        raise UpdateRefused("The update has not passed the gates and corpora without regression.")
    verify_file(artifact, candidate.sha256, candidate.size)
    pin = Pin(
        version=candidate.version,
        url=url,
        sha256=candidate.sha256,
        activated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    if current:
        ledger.previous[candidate.component] = current
    ledger.active[candidate.component] = pin
    ledger.history.append(_event("activated", candidate.component, pin.version, "verified and evaluated"))
    _save(ledger_path, ledger)
    return pin


def rollback(ledger_path: Path | str, component: str, reason: str) -> Pin | None:
    """Return to the version this one replaced and withdraw the failed one; None if there was none."""
    ledger = load(ledger_path)
    failed = ledger.active.get(component)
    if (
        failed is None
        or not isinstance(reason, str)
        or not 0 < len(reason.strip()) <= 300
        or not reason.isprintable()
    ):
        raise UpdateRefused("There is no active version to roll back, or no short reason was given.")
    ledger.withdrawn.setdefault(component, []).append(failed.version)
    restored = ledger.previous.pop(component, None)
    if restored:
        ledger.active[component] = restored
    else:
        del ledger.active[component]
    ledger.history.append(_event("rolled_back", component, failed.version, reason))
    _save(ledger_path, ledger)
    return restored


__all__ = [
    "SOURCES",
    "Candidate",
    "Ledger",
    "Pin",
    "UpdateRefused",
    "activate",
    "load",
    "parse_candidate",
    "regressions",
    "rollback",
    "verify_file",
]
