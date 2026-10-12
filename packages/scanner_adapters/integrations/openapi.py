"""OpenAPI description ingestion (L3): endpoint inventory from a supplied file, no requests.

Reads one OpenAPI 3.0/3.1 JSON document and lists what it DECLARES: endpoints, parameters,
and which authentication each operation states. Nothing is sent anywhere and nothing is
checked against a running service, so every result is a statement about the document.
Descriptions, examples and URLs can hold secrets, so only structural facts are returned.

Limits: JSON only (no YAML parser is installed); Swagger 2.0 is reported, not converted;
only local `#/components/...` references are followed, one level deep.
"""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# The same bounded, regular-file-only reader and text cleaner the manifest inventory uses.
from services.source_analysis_worker.dependencies import _clean, _read

MAX_OPERATIONS = 20000
BASIS = "declared in the supplied API description; not verified against a running service"
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_LOCATIONS = {"path", "query", "header", "cookie"}


def _local(document: dict, node: Any) -> Any:
    """Follow one local `#/components/<kind>/<name>` reference; anything else stays unresolved."""
    reference = node.get("$ref") if isinstance(node, dict) else None
    if not isinstance(reference, str):
        return node
    parts = reference.split("/")
    if len(parts) != 4 or parts[:2] != ["#", "components"]:
        return None
    target = document.get("components")
    for part in parts[2:]:
        target = target.get(part) if isinstance(target, dict) else None
    # A reference to another reference is not chased: that is how cycles start.
    return target if isinstance(target, dict) and "$ref" not in target else None


def _requirements(value: Any) -> list[list[str]] | None:
    """Normalize a `security` value; None means the key is absent or malformed."""
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        return None
    return [sorted(_clean(name) for name in item) for item in value]


def ingest(path: Path | str) -> dict[str, Any]:
    """Return the declared endpoint inventory, observations about it, and what was not understood."""
    result: dict[str, Any] = {
        "basis": BASIS,
        "version": None,
        "servers": [],
        "security_schemes": [],
        "endpoints": [],
        "observations": [],
        "unresolved": [],
    }

    def unresolved(item: object, reason: str) -> None:
        if len(result["unresolved"]) < MAX_OPERATIONS:
            result["unresolved"].append({"item": _clean(item), "reason": reason})

    def observe(check: str, **facts: object) -> None:
        result["observations"].append({"check": check, **facts})

    try:
        document = json.loads(_read(Path(path)).decode("utf-8"))
    except RecursionError:
        unresolved("document", "nesting is too deep to parse")
        return result
    except (OSError, ValueError) as exc:
        fixed = str(exc).replace("manifest", "document") if str(exc).startswith("manifest is ") else ""
        unresolved("document", fixed or "could not be read or parsed as JSON")
        return result
    version = document.get("openapi") if isinstance(document, dict) else None
    if not isinstance(version, str) or not version.startswith(("3.0.", "3.1.")):
        unresolved("document", "only OpenAPI 3.0 and 3.1 JSON documents are supported")
        return result
    result["version"] = _clean(version)[:20]

    servers = document.get("servers")
    for server in servers if isinstance(servers, list) else []:
        url = server.get("url") if isinstance(server, dict) else None
        try:
            parsed = urlsplit(url) if isinstance(url, str) else None
            host = parsed.hostname if parsed else None
        except ValueError:
            host = None
        if not parsed or parsed.scheme not in ("http", "https") or not host or "{" in str(url):
            unresolved("server", "server URL is relative, templated or not HTTP(S)")
            continue
        # Scheme and host only: credentials, paths and query strings are never echoed.
        result["servers"].append({"scheme": parsed.scheme, "host": _clean(host)})
        if parsed.scheme == "http":
            observe("server_declared_over_plain_http", host=_clean(host))

    components = document.get("components")
    declared = components.get("securitySchemes") if isinstance(components, dict) else None
    schemes: dict[str, dict] = {}
    for name, raw in declared.items() if isinstance(declared, dict) else []:
        scheme = _local(document, raw)
        if not isinstance(scheme, dict) or not isinstance(scheme.get("type"), str):
            unresolved(name, "security scheme is not an object with a type")
            continue
        facts = {
            key: _clean(scheme[key]).lower()
            for key in ("type", "scheme", "in")
            if isinstance(scheme.get(key), str)
        }
        schemes[_clean(name)] = facts
        result["security_schemes"].append({"name": _clean(name), **facts})

    default = _requirements(document.get("security"))
    paths = document.get("paths")
    for template, raw_item in paths.items() if isinstance(paths, dict) else []:
        item = _local(document, raw_item)
        if (
            not isinstance(template, str)
            or not template.startswith("/")
            or "?" in template
            or "#" in template
            or not isinstance(item, dict)
        ):
            # The key itself is not echoed: a malformed one can carry a query-string token.
            unresolved("path", "path is not a plain /template with an object, or its reference was not local")
            continue
        shared: list = item["parameters"] if isinstance(item.get("parameters"), list) else []
        for method in METHODS:
            operation = item.get(method)
            if operation is None:
                continue
            if len(result["endpoints"]) >= MAX_OPERATIONS:
                unresolved("document", "operation budget reached; remaining operations not read")
                return result
            if not isinstance(operation, dict):
                unresolved(f"{method.upper()} {template}", "operation is not an object")
                continue
            parameters = {}
            own: list = operation["parameters"] if isinstance(operation.get("parameters"), list) else []
            for raw in [*shared, *own]:  # an operation's own parameter overrides the path's
                parameter = _local(document, raw)
                valid = isinstance(parameter, dict) and isinstance(parameter.get("name"), str)
                if not valid or parameter.get("in") not in _LOCATIONS:
                    unresolved(
                        f"{method.upper()} {template}", "a parameter is malformed or not a local reference"
                    )
                    continue
                key = (_clean(parameter["name"]), parameter["in"])
                parameters[key] = {
                    "name": key[0],
                    "in": key[1],
                    "required": parameter.get("required") is True,
                }
            # An operation's own `security` (even an empty list) replaces the document default.
            own_security = _requirements(operation.get("security"))
            malformed = "security" in operation and own_security is None
            if malformed:
                unresolved(f"{method.upper()} {template}", "security requirement is malformed")
            effective = own_security if "security" in operation else default
            where = {"method": method.upper(), "path": _clean(template)}
            names = sorted({name for requirement in effective or [] for name in requirement})
            if malformed:
                # Not understood is not the same as "declares none".
                state = "unknown"
            elif not effective:
                state = "none"
                observe("operation_declares_no_authentication", **where)
            elif any(not requirement for requirement in effective):
                state = "optional"
                observe("operation_declares_optional_authentication", **where)
            else:
                state = "required"
            for name in names:
                scheme = schemes.get(name)
                if scheme is None:
                    observe("operation_references_undefined_security_scheme", scheme=name, **where)
                elif scheme.get("type") == "apikey" and scheme.get("in") == "query":
                    observe("api_key_declared_in_query_string", scheme=name, **where)
                elif scheme.get("type") == "http" and scheme.get("scheme") == "basic":
                    observe("http_basic_authentication_declared", scheme=name, **where)
            operation_id = operation.get("operationId")
            result["endpoints"].append(
                {
                    **where,
                    "operation_id": _clean(operation_id) if isinstance(operation_id, str) else None,
                    "authentication": state,
                    "security_schemes": names,
                    "parameters": sorted(parameters.values(), key=lambda p: (p["in"], p["name"])),
                    "request_body": isinstance(operation.get("requestBody"), dict),
                    "deprecated": operation.get("deprecated") is True,
                }
            )
    return result


__all__ = ["ingest"]
