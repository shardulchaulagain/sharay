"""CycloneDX SBOM component inventory (L6): parse a supplied bill of materials, never fetch.

Reads a CycloneDX JSON document and returns its components as DECLARED {ecosystem, name, version}
entries in the same shape the dependency inventory and the OSV matcher use, so a supplied SBOM is
an alternative source of the component list that `integrations.osv.match` can check against
advisories. The ecosystem, name and version come from each component's Package URL (`purl`), which
is canonical; a component without a usable purl, or in an ecosystem the matcher does not support
(only PyPI and npm), is listed in `unresolved` rather than guessed. SBOM text is untrusted and may
hold odd values, so unresolved entries are described, never echoed raw.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote

from packages.secret_patterns import redact_tokens
from services.source_analysis_worker.dependencies import _NAME, _NPM_NAME, _PEP440, _SEMVER

MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COMPONENTS = 20000
BASIS = "declared in a supplied SBOM; not verified against installed code or any advisory source"
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
# pkg:TYPE/NAMESPACE?/NAME@VERSION?qualifiers#subpath. Version excludes "/@" so a raw "@scope" in a
# malformed npm purl is not misread as a version; version and the trailing parts are optional.
_PURL = re.compile(r"^pkg:(?P<type>[a-z0-9.+-]+)/(?P<body>[^@?#]+?)(?:@(?P<version>[^/?#@]+))?(?:[?#].*)?$")
_PURL_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}
_PEP503 = re.compile(r"[-_.]+")  # PyPI name normalisation, matching dependencies.py and osv.py
_PYPI_NAME = re.compile(rf"^{_NAME}$")  # same PyPI name grammar the dependency inventory enforces


def _clean(value: object) -> str:
    # SBOM text is untrusted and may hold a credential: redact recognised tokens, then keep it
    # printable and short before it reaches a result.
    return _UNPRINTABLE.sub("?", redact_tokens(str(value), "[REDACTED]"))[:200]


def _strip_qualifiers(purl: str) -> str:
    # A purl's ?qualifiers / #subpath can carry a credentialled download URL; echo only the
    # canonical pkg:type/name@version part, never the query.
    return purl.split("?", 1)[0].split("#", 1)[0]


def _parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Return (ecosystem, name, version) for a PyPI/npm purl, or None if it is neither usable
    nor in a supported ecosystem."""
    match = _PURL.match(purl.strip())
    if not match:
        return None
    ecosystem = _PURL_ECOSYSTEM.get(match.group("type").lower())
    raw_version = match.group("version")
    if ecosystem is None or not raw_version:
        return None
    # purl components are percent-encoded; decode both. npm scopes arrive as "%40scope/name".
    name = unquote(match.group("body")).strip("/")
    version = unquote(raw_version).strip()
    # A decoded control character (e.g. %00) must never be silently mangled into a name/version:
    # treat it as unusable so the component is listed in unresolved instead.
    if not name or not version or _UNPRINTABLE.search(name) or _UNPRINTABLE.search(version):
        return None
    # A name/version that is itself a recognised credential is an unusable identity: never echo it
    # and never match advisories on it. It falls through to unresolved, where the purl is redacted.
    if redact_tokens(name, "") != name or redact_tokens(version, "") != version:
        return None
    # The name and version must fit the ecosystem's grammar (same checks as the dependency
    # inventory and osv matcher), or the component is unusable for matching -> unresolved.
    if ecosystem == "PyPI":
        if not _PYPI_NAME.match(name) or not _PEP440.match(version):
            return None
        name = _PEP503.sub("-", name).lower()  # so 'Requests' and 'requests' are one component
    elif not _NPM_NAME.match(name) or not _SEMVER.match(version):
        return None
    return ecosystem, name, version


def parse_cyclonedx(data: bytes) -> dict[str, Any]:
    """Return {"basis", "components", "unresolved", "truncated"} from a CycloneDX JSON SBOM."""
    if not isinstance(data, bytes) or len(data) > MAX_SBOM_BYTES:
        raise ValueError("SBOM is not bytes within the parsing budget.")
    try:
        document = json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError("SBOM is not valid JSON.") from None
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not a CycloneDX document.")
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise ValueError("SBOM components must be a list.")

    result: dict[str, Any] = {"basis": BASIS, "components": [], "unresolved": [], "truncated": False}
    seen: set[tuple[str, str, str]] = set()

    def unresolved(item: object, reason: str) -> None:
        if len(result["unresolved"]) < MAX_COMPONENTS:
            result["unresolved"].append({"component": _clean(item), "reason": reason})
        else:
            result["truncated"] = True

    for component in raw_components:
        if not isinstance(component, dict):
            unresolved(component, "component is not an object")
            continue
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl:
            unresolved(component.get("name", "component"), "no package URL to resolve an ecosystem")
            continue
        parsed = _parse_purl(purl)
        if parsed is None:
            # unquote first so a percent-encoded prefix (e.g. "%40") cannot glue a digit onto a
            # recognised token and hide it from the redactor inside _clean.
            unresolved(
                unquote(_strip_qualifiers(purl)),
                "package URL is unusable or not a supported ecosystem (PyPI/npm)",
            )
            continue
        ecosystem, name, version = parsed
        key = (ecosystem, name, version)
        if key in seen:
            continue
        seen.add(key)
        if len(result["components"]) >= MAX_COMPONENTS:
            result["truncated"] = True
            break
        result["components"].append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                # Strip ?qualifiers/#subpath here too: a resolved component's purl can carry a
                # credentialled vcs_url/download_url just like an unresolved one.
                "purl": _clean(_strip_qualifiers(purl)),
            }
        )
    return result


__all__ = ["parse_cyclonedx"]
