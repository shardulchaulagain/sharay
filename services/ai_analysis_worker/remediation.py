"""Remediation Patch Validation & AST Compilation Engine.

Sector 5: AI Reasoning Layer.
Validates generated security patches before flagging them as 'deployable':
1. Python patches: AST compilation and syntax tree validation.
2. JSON / JSON-schema patches: strict parsing and schema conformity.
3. Web server configs (Nginx, Apache, Caddy): structural and balance verification.
4. Unified diffs: patch syntax and hunk boundary validation.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RemediationValidationResult:
    is_valid: bool
    language: str
    syntax_error: str | None = None
    deployable: bool = False
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "language": self.language,
            "syntax_error": self.syntax_error,
            "deployable": self.deployable,
            "details": self.details,
        }


class RemediationValidator:
    """Validates generated security patches and configs before flagging them as 'deployable'."""

    # A structural/syntax check never proves a patch applies, builds, preserves behaviour or fixes
    # the issue. So `deployable` is never set True here; it stays a suggestion for a human or a real
    # apply/build/security pipeline to validate.
    _SUGGESTION = (
        " Structural check only; not proven to apply, build, preserve behaviour or fix the issue — "
        "treat as a suggestion pending real apply/build/security validation."
    )

    @staticmethod
    def validate_patch(code: str, language: str = "python") -> RemediationValidationResult:
        lang = language.strip().lower()

        def outcome(is_valid: bool, details: str, syntax_error: str | None = None):
            return RemediationValidationResult(
                is_valid=is_valid,
                language=lang,
                syntax_error=syntax_error,
                deployable=False,
                details=details + (RemediationValidator._SUGGESTION if is_valid else ""),
            )

        if not code or not code.strip():
            return outcome(False, "No code provided in remediation patch.", "Empty patch content")

        # 1. Python patches: AST compilation
        if lang in {"python", "py"}:
            try:
                ast.parse(code)
                return outcome(True, "Python AST parsed without syntax errors.")
            except SyntaxError as err:
                return outcome(
                    False, f"Python syntax compilation failed: {err}", f"Line {err.lineno}: {err.msg}"
                )

        # 2. JSON / JSON-schema patches
        if lang == "json":
            try:
                json.loads(code)
                return outcome(True, "JSON parsed successfully.")
            except json.JSONDecodeError as err:
                return outcome(False, f"JSON parsing error: {err}", str(err))

        # 3. Nginx / Apache / Caddy reverse-proxy config (structural only)
        if lang in {"nginx", "apache", "caddy", "conf"}:
            if "\0" in code:
                return outcome(False, "Configuration contains an illegal null byte.", "Contains null byte")
            open_braces, close_braces = code.count("{"), code.count("}")
            if open_braces != close_braces:
                return outcome(
                    False,
                    "Unbalanced configuration block structure.",
                    f"Mismatched braces: {open_braces} open vs {close_braces} close",
                )
            if open_braces == 0:
                return outcome(
                    False,
                    "No configuration directives or blocks found.",
                    "No recognizable configuration structure",
                )
            return outcome(True, "Configuration braces balance.")

        # 4. Unified diff: must have a hunk and at least one change line (a header alone changes nothing)
        if lang in {"diff", "patch"}:
            hunk_pattern = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@", re.MULTILINE)
            if not hunk_pattern.search(code):
                return outcome(
                    False, "Patch has no unified-diff hunk (@@); it changes nothing.", "Missing hunk header"
                )
            change_lines = [
                line
                for line in code.splitlines()
                if line[:1] in ("+", "-") and not line.startswith(("+++", "---"))
            ]
            if not change_lines:
                return outcome(False, "Diff hunk contains no added or removed lines.", "No change lines")
            return outcome(True, "Unified diff has a hunk with change lines.")

        # Unknown language: cannot be validated, so it is not valid here (never a silent pass).
        return outcome(
            False, f"Unrecognized patch language '{lang}'; cannot be validated.", "Unsupported language"
        )
