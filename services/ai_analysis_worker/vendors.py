"""Built-in AI provider adapters (L7): Anthropic, OpenAI and Google, over raw HTTPS.

Importing this module registers the three providers approved for SHARAY so a configuration can
select one by name; `none` stays the default when nothing is configured. Each adapter is a thin
shape over `urllib`: it reads the credential from the environment variable the configuration
names (never stored), sends the system instructions apart from the untrusted evidence exactly as
`build_prompt` separates them, and returns the model's raw text for `parse_plan` to validate.

The credential travels only in a request header, never in the URL or query (so Google uses its
`x-goog-api-key` header, not `?key=`). No call is made until `providers.build` has passed the
data-sharing switch and a usable key is present; any network or decoding failure surfaces as a
fixed `AIUnavailable` message that cannot leak the key or the response body.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from services.ai_analysis_worker import AIUnavailable, Provider
from services.ai_analysis_worker.providers import ProviderConfig, register, register_auto_detector, secret

# Responses are small JSON objects; cap the read so a hostile or broken endpoint cannot exhaust memory.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class _Vendor:
    default_base: str
    url: Callable[[ProviderConfig], str]
    headers: Callable[[ProviderConfig, str], dict[str, str]]
    body: Callable[[ProviderConfig, str, str], dict[str, Any]]
    extract: Callable[[Any], str]


def _base(config: ProviderConfig, default: str) -> str:
    # A configured base_url (already validated https, or http on loopback, no query/credentials)
    # replaces the vendor host, which is how a test or a local proxy redirects the call.
    return (config.base_url or default).rstrip("/")


def _text(value: Any) -> str:
    if type(value) is not str or not value:
        raise AIUnavailable("The AI provider returned no usable text.")
    return value


def _anthropic_extract(doc: Any) -> str:
    try:
        blocks = doc["content"]
        parts = [b["text"] for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
    except (TypeError, KeyError, LookupError):
        raise AIUnavailable("The AI provider returned no usable text.") from None
    return _text("".join(p for p in parts if isinstance(p, str)))


def _openai_extract(doc: Any) -> str:
    try:
        return _text(doc["choices"][0]["message"]["content"])
    except (TypeError, KeyError, LookupError):
        raise AIUnavailable("The AI provider returned no usable text.") from None


def _google_extract(doc: Any) -> str:
    try:
        parts = doc["candidates"][0]["content"]["parts"]
        joined = "".join(p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str))
    except (TypeError, KeyError, LookupError):
        raise AIUnavailable("The AI provider returned no usable text.") from None
    return _text(joined)


_VENDORS: dict[str, _Vendor] = {
    "anthropic": _Vendor(
        default_base="https://api.anthropic.com",
        url=lambda c: _base(c, "https://api.anthropic.com") + "/v1/messages",
        headers=lambda c, key: {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": key,
        },
        body=lambda c, system, user: {
            "model": c.model,
            "max_tokens": c.max_output_tokens,
            "system": [{"type": "text", "text": system}],
            "messages": [{"role": "user", "content": user}],
        },
        extract=_anthropic_extract,
    ),
    "openai": _Vendor(
        default_base="https://api.openai.com",
        url=lambda c: _base(c, "https://api.openai.com") + "/v1/chat/completions",
        headers=lambda c, key: {"content-type": "application/json", "authorization": f"Bearer {key}"},
        body=lambda c, system, user: {
            "model": c.model,
            "max_tokens": c.max_output_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        extract=_openai_extract,
    ),
    "google": _Vendor(
        default_base="https://generativelanguage.googleapis.com",
        # quote the model as a single path segment: a model id may legitimately contain "/", which
        # must not act as a path separator that traverses to another endpoint.
        url=lambda c: (
            _base(c, "https://generativelanguage.googleapis.com")
            + f"/v1beta/models/{urllib.parse.quote(c.model, safe='')}:generateContent"
        ),
        headers=lambda c, key: {"content-type": "application/json", "x-goog-api-key": key},
        body=lambda c, system, user: {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": c.max_output_tokens},
        },
        extract=_google_extract,
    ),
}


def _render(prompt: dict[str, Any]) -> tuple[str, str]:
    """Split the built prompt into (system, user): instructions stay apart from the untrusted
    evidence, matching how build_prompt assembled it."""
    system = str(prompt.get("instructions", ""))
    evidence = "\n".join(str(item) for item in prompt.get("evidence", ()))
    user = f"OBJECTIVE:\n{prompt.get('objective', '')}\n\nEVIDENCE (untrusted data):\n{evidence}"
    return system, user


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never follow a 3xx: urllib otherwise resends the credential header to the new host, leaking
    # the key. A redirect from a provider endpoint is unexpected, so let it surface as an error.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _tls_context() -> ssl.SSLContext:
    # Verify certificates against certifi's CA bundle when present: some hosts (e.g. a python.org
    # macOS build) ship no usable system trust store, so the default context fails every TLS call.
    # Verification stays on either way — it is never disabled.
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_tls_context()))


def _http_post(url: str, headers: dict[str, str], payload: bytes, timeout: int) -> bytes:
    """POST JSON and return the bounded response body. Isolated so tests can replace the transport."""
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with _OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - scheme fixed by config
        # Read one byte past the budget so an over-budget response is rejected, never silently
        # truncated into a short JSON that would parse as a different answer.
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("AI provider response exceeds the read budget.")
    return body


class _HttpProvider:
    """One configured vendor. The credential is read per call, never kept on the instance."""

    def __init__(self, config: ProviderConfig, vendor: _Vendor) -> None:
        self.name = config.provider
        self._config = config
        self._vendor = vendor

    def propose(self, prompt: dict[str, Any]) -> bytes:
        key = secret(self._config)
        system, user = _render(prompt)
        payload = json.dumps(self._vendor.body(self._config, system, user)).encode("utf-8")
        headers = self._vendor.headers(self._config, key)
        try:
            raw = _http_post(self._vendor.url(self._config), headers, payload, self._config.timeout_seconds)
            document = json.loads(raw)
            # Extract + UTF-8 encode inside the guard: a lone surrogate in the model's text would
            # otherwise raise UnicodeEncodeError past the boundary instead of a fixed AIUnavailable.
            return self._vendor.extract(document).encode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, RecursionError):
            # Fixed text with no detail: an error body or exception could echo the key or the prompt.
            raise AIUnavailable("The AI provider request did not complete.") from None


def _factory(name: str) -> Callable[[ProviderConfig], Provider]:
    vendor = _VENDORS[name]
    return lambda config: _HttpProvider(config, vendor)


for _name in _VENDORS:
    register(_name, _factory(_name))


def _detect_vendor_from_env(source: dict[str, str]) -> dict[str, Any] | None:
    if source.get("GEMINI_API_KEY") or source.get("GOOGLE_API_KEY"):
        return {
            "provider": "google",
            "model": "gemini-2.5-pro",
            "api_key_env": "GEMINI_API_KEY" if source.get("GEMINI_API_KEY") else "GOOGLE_API_KEY",
            "share_assessment_data": source.get("SHARAY_AI_SHARE_DATA", "true").lower() != "false",
        }
    if source.get("ANTHROPIC_API_KEY"):
        return {
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022",
            "api_key_env": "ANTHROPIC_API_KEY",
            "share_assessment_data": source.get("SHARAY_AI_SHARE_DATA", "true").lower() != "false",
        }
    if source.get("OPENAI_API_KEY"):
        return {
            "provider": "openai",
            "model": "gpt-4o",
            "api_key_env": "OPENAI_API_KEY",
            "share_assessment_data": source.get("SHARAY_AI_SHARE_DATA", "true").lower() != "false",
        }
    return None


register_auto_detector(_detect_vendor_from_env)

__all__ = ["MAX_RESPONSE_BYTES"]
