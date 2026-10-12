"""Switchable AI providers (L7): choose provider and model by configuration, no code change.

A provider is one small adapter registered under a name. This file holds the registry, the
configuration and the switch; it contains no vendor code and makes no network call. With
nothing configured the provider is `none` and AI analysis is simply unavailable.

Configuration never holds a credential: `api_key_env` is the NAME of an environment
variable, read only at the moment an adapter needs it. Assessment data may go to a provider
only when `share_assessment_data` is switched on for that configuration.
"""

import os
import re
from collections.abc import Callable
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from packages.secret_patterns import redact_tokens
from services.ai_analysis_worker import AIUnavailable, NoProvider, Provider

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
Name = Annotated[str, Field(strict=True, pattern=r"^[a-z][a-z0-9_-]{0,31}$")]


class ProviderConfig(BaseModel):
    """Everything needed to pick a provider and a model; safe to store and to log."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Name = "none"
    model: str = Field(default="", strict=True, max_length=100)
    api_key_env: str | None = Field(default=None, strict=True, pattern=r"^[A-Z][A-Z0-9_]{1,63}$")
    base_url: str | None = Field(default=None, strict=True, max_length=300)
    share_assessment_data: bool = Field(default=False, strict=True)
    timeout_seconds: int = Field(default=60, strict=True, ge=1, le=300)
    max_output_tokens: int = Field(default=16000, strict=True, ge=1, le=128000)

    @field_validator("model")
    @classmethod
    def printable_model(cls, value: str) -> str:
        if value and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value):
            raise ValueError("Model identifiers are plain names.")
        if redact_tokens(value, "") != value:
            raise ValueError("A model identifier is not a credential.")
        return value

    @field_validator("base_url")
    @classmethod
    def safe_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = urlsplit(value)
        port = parsed.port  # read here: urlsplit only checks the port when it is asked for
        local = parsed.scheme == "http" and parsed.hostname in _LOOPBACK
        # "@" covers user, password and the empty-user form (https://:secret@host).
        if not (parsed.scheme == "https" or local) or not parsed.hostname or "@" in parsed.netloc:
            raise ValueError("A base URL is https, or http on loopback, without credentials.")
        if parsed.query or parsed.fragment or not value.isprintable() or " " in value:
            raise ValueError("A base URL carries no query, fragment or unprintable text.")
        if port == 0 or parsed.netloc.endswith(":") or redact_tokens(value, "") != value:
            raise ValueError("A base URL has a usable port and holds no credential.")
        return value

    @model_validator(mode="after")
    def coherent(self):
        if self.provider != "none" and not self.model:
            raise ValueError("A provider needs a model.")
        return self


Factory = Callable[[ProviderConfig], Provider]
# Adapters add themselves here; "none" is always present so the product runs without AI.
REGISTRY: dict[str, Factory] = {"none": lambda _config: NoProvider()}


def register(name: str, factory: Factory) -> None:
    """Make an adapter selectable by name. Adapters live in their own modules."""
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or name == "none":
        raise ValueError("Provider names are short lowercase identifiers other than 'none'.")
    REGISTRY[name] = factory


def parse_config(values: dict[str, Any]) -> ProviderConfig:
    try:
        return ProviderConfig.model_validate(values)
    except ValidationError:
        # Fixed text: a malformed value might be a pasted credential.
        raise AIUnavailable("The AI provider configuration is not valid.") from None


def config_from_environment(environment: dict[str, str] | None = None) -> ProviderConfig:
    """Read the switch from SHARAY_AI_* variables; unset means provider `none`."""
    source = os.environ if environment is None else environment
    values: dict[str, Any] = {}
    for field, variable in (
        ("provider", "SHARAY_AI_PROVIDER"),
        ("model", "SHARAY_AI_MODEL"),
        ("api_key_env", "SHARAY_AI_KEY_ENV"),
        ("base_url", "SHARAY_AI_BASE_URL"),
    ):
        if source.get(variable):
            values[field] = source[variable]
    # Only the exact word "true" switches data sharing on.
    values["share_assessment_data"] = source.get("SHARAY_AI_SHARE_DATA", "") == "true"
    return parse_config(values)


def build(config: ProviderConfig) -> Provider:
    """Return the configured provider, or say plainly why AI is unavailable."""
    factory = REGISTRY.get(config.provider)
    if factory is None:
        raise AIUnavailable("The configured AI provider has no adapter installed.")
    if config.provider != "none" and not config.share_assessment_data:
        raise AIUnavailable("Sending assessment data to this AI provider has not been switched on.")
    return factory(config)


def secret(config: ProviderConfig, environment: dict[str, str] | None = None) -> str:
    """The credential an adapter needs, read from the named variable at call time only."""
    source = os.environ if environment is None else environment
    value = source.get(config.api_key_env or "", "")
    # Whitespace or a line break in a key is a paste accident, and a line break would split an HTTP header.
    if not value or not value.isprintable() or " " in value:
        raise AIUnavailable("The AI provider's credential variable is not set to a usable value.")
    return value


__all__ = [
    "REGISTRY",
    "ProviderConfig",
    "build",
    "config_from_environment",
    "parse_config",
    "register",
    "secret",
]
