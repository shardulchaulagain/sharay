"""Secret-shaped text patterns shared by report/log redaction and source secret detection.

One rule set, so a token format added for detection is redacted from output as well.
Matching here is by shape only; it says nothing about whether a credential is live.
"""

import re

RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private_key_block", re.compile(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_access_key_id", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    (
        "github_token",
        re.compile(
            rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})(?![A-Za-z0-9_])"
        ),
    ),
    # A numeric id segment is required, so hyphenated prose starting "xoxb-" does not match.
    ("slack_token", re.compile(rb"(?<![A-Za-z0-9])xox[abprs]-[0-9]{8,}-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])")),
    ("anthropic_api_key", re.compile(rb"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")),
    ("openai_api_key", re.compile(rb"(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")),
    ("google_api_key", re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")),
    ("stripe_live_key", re.compile(rb"(?<![A-Za-z0-9_])[rs]k_live_[0-9A-Za-z]{24,}(?![A-Za-z0-9])")),
)


# The same token shapes as text patterns, for redacting free text in reports and logs.
# Key blocks are left to the caller, which removes the whole block rather than its header.
_TEXT_RULES = tuple(re.compile(p.pattern.decode()) for rule, p in RULES if rule != "private_key_block")


def redact_tokens(text: str, replacement: str) -> str:
    """Replace every provider-token-shaped match in free text."""
    for pattern in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    return text


__all__ = ["RULES", "redact_tokens"]
