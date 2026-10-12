"""Generate evidence-backed reports from stored assessment records."""

import json
import re
from collections import Counter
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from packages.secret_patterns import redact_tokens

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?:^|[_\-\s])(?:password|passwd|passcode|secret|token|authorization|"
    r"cookie|credentials?|private[_\-\s]?key|api[_\-\s]?key|access[_\-\s]?key)"
    r"(?:$|[_\-\s])",
    re.I,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----.*?"
    r"-----END (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----",
    re.S,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:password|passwd|passcode|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|session[_-]?token|secret|token)\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
)
_SENSITIVE_HEADER = re.compile(r"(?im)\b(authorization|proxy-authorization|set-cookie|cookie)\s*:\s*[^\r\n]+")
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)

LIMITATIONS = [
    "Executable assessment scope is restricted to explicitly approved literal "
    "loopback laboratory destinations. Public and private-network targets are unavailable.",
    "The dedicated Python worker has application-level destination, response-size "
    "and time limits. It is not an OS sandbox; filesystem and network egress "
    "isolation are not OS-enforced.",
    "Coverage is limited to the checks actually recorded below. The built-in "
    "safe HTTP adapter does not establish complete application security.",
    "Authenticated target testing, external scanners, source analysis and "
    "AI investigations are unavailable in this increment. No LLM was used.",
    "A missing security header is a configuration observation with contextual "
    "risk, not proof of successful exploitation or business impact.",
    "A report with no confirmed findings does not establish that a target has no vulnerabilities.",
]


def _secret_key(key: str) -> bool:
    # Normalize common camelCase names without changing evidence hash keys.
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", key)
    return bool(_SECRET_KEY.search(normalized))


def _redact_url(match: re.Match[str]) -> str:
    try:
        parts = urlsplit(match.group())
        netloc = parts.netloc.rsplit("@", 1)[-1]
        if "@" in parts.netloc:
            netloc = REDACTED + "@" + netloc
        query = [
            (key, REDACTED if _secret_key(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        return REDACTED


def redact(value: Any) -> Any:
    """Return a recursively sanitized copy; recognized secret fields are write-only.

    This is defensive pattern redaction, not a guarantee that arbitrary unlabeled
    personal data or unknown secret formats have been identified.
    """
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            original = str(key)
            base = redact(original)
            sanitized = base
            suffix = 2
            # Redaction can give distinct keys the same label; keep every record.
            while sanitized in clean:
                sanitized = f"{base}#{suffix}"
                suffix += 1
            clean[sanitized] = (
                REDACTED
                if (_secret_key(original) or _secret_key(base)) and not _safe_fact(original, item)
                else redact(item)
            )
        return clean
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = _CONTROL.sub("", value)
        text = _PRIVATE_KEY.sub(REDACTED, text)
        text = _SENSITIVE_HEADER.sub(lambda m: m.group(1) + ": " + REDACTED, text)
        text = _AUTH_VALUE.sub(lambda m: m.group(1) + " " + REDACTED, text)
        text = _URL.sub(_redact_url, text)
        text = _SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + REDACTED, text)
        # Bare provider tokens (no "key=" label) in tool output or free text; one shared rule set.
        return redact_tokens(text, REDACTED)
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value))


def _safe_fact(key: str, value: Any) -> bool:
    """Preserve scanner booleans without permitting raw cookie values."""
    if key == "cors_credentials":
        return isinstance(value, bool)
    if key != "cookie_flags" or not isinstance(value, list):
        return False
    return all(
        isinstance(flags, dict)
        and all(
            (name in {"secure", "httponly", "parse_error"} and isinstance(item, bool))
            or (name == "samesite" and isinstance(item, str) and item in {"strict", "lax", "none", "unset"})
            for name, item in flags.items()
        )
        for flags in value
    )


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return (
        "Unavailable"
        if value is None or value == ""
        else (_json(value) if isinstance(value, (dict, list)) else str(value))
    )


def _evidence_hashes(value: Any) -> list[str]:
    hashes: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"evidence_hash", "sha256", "content_hash"} and isinstance(item, str):
                hashes.add(item)
            hashes.update(_evidence_hashes(item))
    elif isinstance(value, list):
        for item in value:
            hashes.update(_evidence_hashes(item))
    return sorted(hashes)


def _prepare(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Report data must be a dictionary")
    clean = redact(data)
    assessment = _mapping(clean.get("assessment"))
    scope = _mapping(clean.get("scope") or assessment.get("scope_snapshot"))
    if not clean.get("tools"):
        clean["tools"] = [
            {"name": detail["adapter"], "version": detail.get("version")}
            for event in _records(clean.get("events"))
            if (detail := _mapping(_mapping(event).get("detail"))).get("adapter")
        ]
    clean["report_metadata"] = {
        "schema_version": "aegis.report.v1",
        "assessment_id": assessment.get("id"),
        "generated_at": clean.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        "scope_version": scope.get("version", assessment.get("scope_version")),
        "assessment_mode": "authorized-loopback-laboratory",
        "synthetic": bool(clean.get("synthetic", False)),
        "evidence_hashes": _evidence_hashes(clean),
        "limitations": LIMITATIONS + _records(clean.get("limitations")),
        "redaction": "Pattern-based recursive secret redaction; not an exhaustive personal-data classifier.",
    }
    clean["scope"] = scope
    return clean


def _sections(data: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    assessment = _mapping(data.get("assessment"))
    metadata = data["report_metadata"]
    project = _mapping(data.get("project"))
    target = _mapping(data.get("target"))
    findings = [_mapping(item) for item in _records(data.get("findings"))]
    confirmed = [item for item in findings if str(item.get("status", "")).lower() == "confirmed"]
    summary = "No confirmed vulnerabilities are recorded. Review coverage and limitations."
    if confirmed:
        severity = Counter(str(item.get("severity", "unavailable")) for item in confirmed)
        summary = f"{len(confirmed)} confirmed finding(s). " + ", ".join(
            f"{key}: {value}" for key, value in sorted(severity.items())
        )
    sections = [
        (
            "Assessment",
            [
                (
                    "Report classification",
                    "Synthetic example" if metadata["synthetic"] else "Stored assessment data",
                ),
                ("Assessment ID", _text(assessment.get("id"))),
                ("Project", _text(project.get("name") or project.get("id") or data.get("project"))),
                ("Target", _text(target.get("url") or target.get("origin") or data.get("target"))),
                (
                    "Objective",
                    _text(
                        assessment.get("objective")
                        or "Review explicitly approved loopback target HTTP configuration."
                    ),
                ),
                ("Status", _text(assessment.get("status"))),
                ("Generated at", _text(metadata["generated_at"])),
                (
                    "Created / started / finished",
                    " / ".join(
                        _text(assessment.get(key)) for key in ("created_at", "started_at", "finished_at")
                    ),
                ),
                ("Profile", _text(assessment.get("profile"))),
                ("Scope version", _text(metadata["scope_version"])),
                ("Assessment error", _text(assessment.get("error"))),
            ],
        ),
        (
            "Summary",
            [
                ("Confirmed findings", summary),
                ("Total finding records", str(len(findings))),
                ("Observation records", str(len(_records(data.get("observations"))))),
                (
                    "Priorities",
                    "Review confirmed issues in the target's context. Apply the recorded remediation and retest; no deadlines or business impacts are inferred.",
                ),
            ],
        ),
        (
            "Authorized scope",
            [
                ("Approved scope snapshot", _json(data["scope"])),
                (
                    "Verification",
                    _text(
                        data["scope"].get("verification")
                        or data["scope"].get("verification_status")
                        or data["scope"].get("verification_method")
                    ),
                ),
                ("Approved at", _text(data["scope"].get("approved_at"))),
                ("Authorized by", _text(data["scope"].get("authorized_by"))),
                ("Included target", _text(data.get("target"))),
                ("Exclusions", _text(data["scope"].get("excluded_paths", data["scope"].get("exclusions")))),
            ],
        ),
        (
            "Methodology and coverage",
            [
                (
                    "Approach",
                    "Bounded safe HTTP GET requests through deterministic scope enforcement; findings derive from stored response evidence.",
                ),
                (
                    "Authenticated coverage",
                    "Unauthenticated target requests only; authenticated target testing is unavailable.",
                ),
                ("Checks completed, skipped or failed", _json(_records(data.get("checks")))),
                (
                    "Tool metadata",
                    _text(
                        data.get("tools")
                        or "Built-in safe HTTP adapter; version is recorded only when supplied by the assessment."
                    ),
                ),
                ("Unrecorded tests", "Tests without stored execution evidence are not treated as completed."),
            ],
        ),
    ]
    for index, finding in enumerate(findings, 1):
        sections.append(
            (
                f"Finding {index}: {_text(finding.get('title'))}",
                [
                    ("Identifier", _text(finding.get("id") or finding.get("fingerprint"))),
                    ("Category", _text(finding.get("category"))),
                    ("Technical severity", _text(finding.get("severity"))),
                    ("Evidence confidence", _text(finding.get("confidence"))),
                    ("Verification / retest status", _text(finding.get("status"))),
                    ("Affected asset", _text(finding.get("affected_url") or finding.get("affected_asset"))),
                    ("Description", _text(finding.get("description"))),
                    ("Technical impact", _text(finding.get("technical_impact"))),
                    ("Business impact", _text(finding.get("business_impact"))),
                    ("Reproduction", _text(finding.get("reproduction_steps") or finding.get("reproduction"))),
                    ("Evidence references and sanitized excerpts", _text(finding.get("evidence"))),
                    ("Remediation", _text(finding.get("remediation"))),
                    ("References", _text(finding.get("references"))),
                    (
                        "CVSS",
                        _text(
                            finding.get("cvss")
                            or finding.get("cvss_vector")
                            or "Not scored; insufficient contextual inputs."
                        ),
                    ),
                    (
                        "First / last seen",
                        " / ".join(_text(finding.get(key)) for key in ("first_seen", "last_seen")),
                    ),
                ],
            )
        )
    sections.extend(
        [
            (
                "Observations and evidence",
                [
                    ("Stored observations", _json(_records(data.get("observations")))),
                    ("Evidence integrity hashes", _json(metadata["evidence_hashes"])),
                    (
                        "Integrity boundary",
                        "Hashes identify stored sanitized evidence. They do not attest to unsanitized originals or protect against a privileged local user changing the database.",
                    ),
                ],
            ),
            ("Execution timeline", [("Events", _json(_records(data.get("events"))))]),
            (
                "Limitations",
                [(str(index), _text(item)) for index, item in enumerate(metadata["limitations"], 1)]
                + [("Redaction", metadata["redaction"])],
            ),
        ]
    )
    return sections


def _html(sections: list) -> bytes:
    content = []
    for title, rows in sections:
        cells = "".join(
            f"<dt>{escape(label)}</dt><dd><pre>{escape(value)}</pre></dd>" for label, value in rows
        )
        content.append(f"<section><h2>{escape(title)}</h2><dl>{cells}</dl></section>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>SHARAY assessment report</title><style>"
        "body{font:15px/1.6 system-ui,sans-serif;color:#142434;background:#f3f6fa;margin:0}"
        "main{max-width:960px;margin:auto;padding:40px 24px}h1{letter-spacing:.12em}"
        "h2{font-size:21px;color:#163a51}section{padding:20px 24px;margin:20px 0;background:white;border:1px solid #d2dce5;border-radius:8px}"
        "dl{margin:0}dt{font-weight:650;margin-top:14px}dd{margin:2px 0 14px}"
        "pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere;margin:0}"
        "@media print{body{background:white}main{padding:0}section{break-inside:auto}}"
        "</style></head><body><main><h1>SHARAY</h1><p>Security assessment report</p>"
        + "".join(content)
        + "</main></body></html>"
    ).encode("utf-8")


def _markdown(sections: list) -> bytes:
    def heading(value: str) -> str:
        value = escape(value).replace("\n", " ")
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)

    blocks = ["# SHARAY security assessment report"]
    for title, rows in sections:
        blocks.append("## " + heading(title))
        for label, value in rows:
            blocks.append(
                "**" + heading(label) + "**\n\n" + "\n".join("    " + line for line in value.splitlines())
            )
    return ("\n\n".join(blocks) + "\n").encode("utf-8")


def _pdf(sections: list) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "ReportBody",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#142434"),
            spaceAfter=7,
            wordWrap="CJK",
            alignment=TA_LEFT,
        )
    )
    styles["Heading2"].textColor = colors.HexColor("#163a51")
    styles["Heading2"].spaceBefore = 14
    styles["Heading2"].spaceAfter = 8
    styles["Heading2"].keepWithNext = True
    story = [
        Paragraph("SHARAY", styles["Title"]),
        Paragraph("Security assessment report", styles["Heading2"]),
        Spacer(1, 8),
    ]
    for title, rows in sections:
        safe_title = title.encode("cp1252", errors="backslashreplace").decode("cp1252")
        story.append(Paragraph(escape(safe_title), styles["Heading2"]))
        for label, value in rows:
            # Built-in PDF fonts are local. Unsupported glyphs are represented
            # explicitly instead of rendering unreadable black boxes.
            safe = value.encode("cp1252", errors="backslashreplace").decode("cp1252")
            story.append(
                Paragraph(
                    f"<b>{escape(label)}</b><br/>" + escape(safe).replace("\n", "<br/>"), styles["ReportBody"]
                )
            )

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526779"))
        canvas.drawString(0.7 * inch, 0.45 * inch, "SHARAY | Authorized loopback laboratory assessment")
        canvas.drawRightString(doc.pagesize[0] - 0.7 * inch, 0.45 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        output,
        pagesize=(595.28, 841.89),
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.7 * inch,
        title="SHARAY security assessment report",
        author="SHARAY",
        pageCompression=1,
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def render_report(data: dict, format: str) -> tuple[bytes, str]:
    """Render actual records to bytes and the matching media type."""
    format = format.lower()
    if format not in {"html", "json", "markdown", "md", "pdf"}:
        raise ValueError("Unsupported report format")
    clean = _prepare(data)
    if format == "json":
        return (_json(clean) + "\n").encode("utf-8"), "application/json"
    sections = _sections(clean)
    if format == "html":
        return _html(sections), "text/html; charset=utf-8"
    if format in {"markdown", "md"}:
        return _markdown(sections), "text/markdown; charset=utf-8"
    return _pdf(sections), "application/pdf"
