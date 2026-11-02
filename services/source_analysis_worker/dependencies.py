"""Dependency inventory from lockfiles in an extracted tree (L6): parse, never install.

Reads pinned `requirements*.txt` and npm `package-lock.json` (lockfile v2/v3). The result
is DECLARED data: what the manifests say, not what is installed and not checked against a
registry or any advisory source. A package is reported only with one valid exact version;
everything else is listed as unresolved rather than guessed. Manifest text is untrusted
and may hold credentials, so unresolved lines are described, never echoed.
"""

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 5 * 1024 * 1024
MAX_MANIFESTS = 200
MAX_PACKAGES = 20000
BASIS = "declared in manifests; not verified against installed code, a registry or any advisory source"
_SKIPPED_FOLDERS = {"node_modules", ".git", ".venv", "venv", "__pycache__"}
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_EXTRAS = r"(?:\[[A-Za-z0-9._, -]*\])?"
_PINNED = re.compile(rf"^({_NAME}){_EXTRAS}\s*==\s*([^\s;,]+)\s*(?:;.*)?$")
# A name with ordinary version specifiers and nothing else: safe to show as written.
_SPECIFIER = re.compile(
    rf"^{_NAME}{_EXTRAS}\s*(?:(?:~=|===?|!=|<=?|>=?)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)*(?:;.*)?$"
)
_OPTION = re.compile(r"^--?[A-Za-z][A-Za-z-]*")
# PEP 440's public version grammar (the PEP's Appendix B expression, without capture names).
_PEP440 = re.compile(
    r"^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?[0-9]*)?"
    r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
    re.IGNORECASE | re.ASCII,
)
# semver.org's recommended expression.
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$")
# A registry tarball: https, no credentials in the authority, ends in .tgz.
_REGISTRY_TARBALL = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]+)?/[^\s?#@]*\.tgz$")

Parsed = tuple[list[dict[str, str]], list[tuple[str, str]]]


def _clean(value: object) -> str:
    # Manifest text is untrusted: printable and short before it reaches a report.
    return _UNPRINTABLE.sub("?", str(value))[:200]


def _requirements(text: str) -> Parsed:
    packages: list[dict[str, str]] = []
    unresolved: list[tuple[str, str]] = []
    # Hash-pinned files continue a requirement over several lines.
    for line in text.replace("\r\n", "\n").replace("\\\n", " ").splitlines():
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        if not line:
            continue
        pinned = _PINNED.match(line)
        option = _OPTION.match(line)
        reference = re.match(rf"^({_NAME}){_EXTRAS}\s*@\s", line)
        if pinned and _PEP440.match(pinned.group(2)):
            # PEP 503 normalization, so one package has one name.
            name = re.sub(r"[-_.]+", "-", pinned.group(1)).lower()
            packages.append({"name": name, "version": pinned.group(2), "source": "undeclared"})
        elif pinned:
            unresolved.append((pinned.group(1), "pinned version is not a valid PEP 440 version"))
        elif option:
            # Only the option's name: index URLs and tokens often carry credentials.
            unresolved.append((option.group(0), "pip option or include was not followed"))
        elif reference or "://" in line or line.startswith((".", "/", "~")):
            item = reference.group(1) if reference else "direct reference"
            unresolved.append((item, "direct URL, VCS or path reference was not resolved"))
        elif _SPECIFIER.match(line):
            unresolved.append((line.split(";")[0].strip(), "not pinned to one exact version"))
        else:
            unresolved.append(("unrecognized line", "not a requirement this reader understands"))
    return packages, unresolved


def _package_lock(text: str) -> Parsed:
    document = json.loads(text)
    version = document.get("lockfileVersion") if isinstance(document, dict) else None
    entries = document.get("packages") if isinstance(document, dict) else None
    if type(version) is not int or version not in (2, 3) or not isinstance(entries, dict):
        return [], [("package-lock.json", "only lockfile versions 2 and 3 are supported")]
    packages: list[dict[str, str]] = []
    unresolved: list[tuple[str, str]] = []
    for path, entry in entries.items():
        if "node_modules/" not in path:
            continue  # the project itself or one of its own workspace folders
        installed_as = path.rsplit("node_modules/", 1)[-1]
        if not isinstance(entry, dict):
            unresolved.append((installed_as, "entry is not an object"))
            continue
        # An alias installs under one folder name but is a different registry package.
        name = entry.get("name", installed_as)
        release, resolved = entry.get("version"), entry.get("resolved")
        if entry.get("link") is True:
            unresolved.append((installed_as, "workspace link has no registry version"))
        elif not isinstance(name, str) or not _NPM_NAME.match(name):
            unresolved.append((installed_as, "package name is not a valid registry name"))
        elif not isinstance(release, str) or not _SEMVER.match(release):
            unresolved.append((name, "version is not one exact semantic version"))
        elif resolved is not None and not (isinstance(resolved, str) and _REGISTRY_TARBALL.match(resolved)):
            # A version on a git, file or other source does not identify a registry release.
            unresolved.append((name, "resolved from a source other than a registry tarball"))
        else:
            source = "registry" if resolved else "undeclared"
            packages.append({"name": name, "version": release, "source": source, "path": _clean(path)})
    return packages, unresolved


def _read(path: Path) -> bytes:
    # Regular files only. O_NONBLOCK so a FIFO named like a manifest cannot make the open wait;
    # O_NOFOLLOW so a symlink is never read through; fstat so the check is on what was opened.
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ValueError("manifest is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("manifest is not a regular file")
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest is larger than the parsing budget")
    return data


def inventory(root: Path | str) -> dict[str, Any]:
    """Return declared packages with exact versions, plus everything that could not be resolved."""
    root = Path(root).resolve()
    result: dict[str, Any] = {"basis": BASIS, "manifests": [], "packages": [], "unresolved": []}
    seen = set()

    def unresolved(manifest: str, item: object, reason: str) -> None:
        if len(result["unresolved"]) < MAX_PACKAGES:
            result["unresolved"].append({"manifest": manifest, "item": _clean(item), "reason": reason})

    for folder, folders, files in os.walk(root):  # never follows directory symlinks
        folders[:] = sorted(name for name in folders if name not in _SKIPPED_FOLDERS)
        for name in sorted(files):
            is_requirements = name.startswith("requirements") and name.endswith(".txt")
            if not is_requirements and name != "package-lock.json":
                continue
            path = Path(folder, name)
            manifest = _clean(path.relative_to(root).as_posix())
            if len(result["manifests"]) >= MAX_MANIFESTS:
                unresolved(manifest, "manifest", "manifest budget reached; not read")
                continue
            result["manifests"].append(manifest)
            try:
                parser = _requirements if is_requirements else _package_lock
                packages, problems = parser(_read(path).decode("utf-8"))
            except RecursionError:
                unresolved(manifest, "manifest", "manifest nesting is too deep to parse")
                continue
            except (OSError, ValueError) as exc:
                fixed = (
                    str(exc)
                    if str(exc).startswith("manifest is ")
                    else "manifest could not be read or parsed"
                )
                unresolved(manifest, "manifest", fixed)
                continue
            ecosystem = "PyPI" if is_requirements else "npm"
            for package in packages:
                key = (ecosystem, package["name"], package["version"], manifest, package.get("path"))
                if key not in seen and len(result["packages"]) < MAX_PACKAGES:
                    seen.add(key)
                    result["packages"].append({"ecosystem": ecosystem, **package, "manifest": manifest})
            for item, reason in problems:
                unresolved(manifest, item, reason)
    return result


__all__ = ["inventory"]
