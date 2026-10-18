"""Interactive Workspace Route Implementation for aegis/api.py.

Provides /api/v1/workspace/probe for live operator command execution,
probe replays, and stdout extraction within approved target scopes.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field

from drafts.gemini.interactive_workspace import (
    InteractiveWorkspace,
    PolicyError,
    WorkspaceResult,
)


class WorkspaceProbeInput(BaseModel):
    """Input payload for interactive target probing and command replay."""

    target_id: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    output_prefix: str | None = None
    output_suffix: str | None = None
    timeout: float = 10.0


def handle_workspace_probe(
    data: WorkspaceProbeInput,
    target: Any,
    user: Any,
    audit_func: Any,
    db: Any,
) -> dict[str, Any]:
    """Execute and audit a live workspace probe against an owned target."""
    if target.verification_status not in {"verified_lab", "operator_authorized"} or not target.authorized_by:
        raise HTTPException(403, "Target must be approved by operator before interactive probing")

    workspace = InteractiveWorkspace(default_timeout=data.timeout)
    try:
        result: WorkspaceResult = workspace.execute_probe(
            scope=target.scope,
            target_url=data.url,
            method=data.method,
            headers=data.headers,
            query_params=data.query_params,
            body=data.body,
            output_prefix=data.output_prefix,
            output_suffix=data.output_suffix,
        )
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception as exc:
        raise HTTPException(502, f"Target probe failed: {exc}") from None

    audit_func(
        db,
        user.organization_id,
        user.id,
        "workspace.probe_executed",
        target.id,
        {
            "url": result.target_url,
            "method": result.method,
            "status_code": result.status_code,
            "duration_ms": result.duration_ms,
            "fingerprint": result.fingerprint,
        },
    )
    return result.to_dict()
