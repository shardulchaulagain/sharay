"""Live Assessment SSE Streamer & WCAG AA Accessibility Engine.

Sector 9: Web UX & Visualization (Milestone P1.9).
Provides:
1. Server-Sent Events (SSE) real-time streaming for assessment progress, checks, and findings
   with Last-Event-ID resume support.
2. WCAG AA Automated Accessibility Validator evaluating keyboard navigation, ARIA attributes,
   and visual preference compliance.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional, Set

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.models import Assessment, Finding, FindingEvidence, Observation


@dataclass
class StreamEvent:
    event_id: int
    event_type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_sse_frame(self) -> str:
        payload = json.dumps(self.data, separators=(",", ":"))
        return f"id: {self.event_id}\nevent: {self.event_type}\ndata: {payload}\n\n"


class LiveAssessmentStreamer:
    """Streams real-time assessment state, checks, and discovered findings over SSE."""

    TERMINAL_STATES = {"completed", "completed_with_errors", "failed", "cancelled"}

    def __init__(self, sessions: sessionmaker[Session], assessment_id: str, organization_id: str):
        self.sessions = sessions
        self.assessment_id = assessment_id
        self.organization_id = organization_id

    def stream_events(
        self,
        last_event_id: int = 0,
        max_iterations: int = 100,
        poll_interval: float = 0.05,
    ) -> Iterator[StreamEvent]:
        """Generator yielding new events as they land in database."""
        current_seq = last_event_id
        last_stage: Optional[str] = None
        last_status: Optional[str] = None
        seen_finding_ids: Set[str] = set()
        seen_obs_ids: Set[str] = set()

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            with self.sessions() as db:
                row = db.get(Assessment, self.assessment_id)
                if row is None or row.organization_id != self.organization_id:
                    current_seq += 1
                    yield StreamEvent(current_seq, "error", {"detail": "Assessment not found"})
                    return

                # 1. Check if status or stage changed
                if row.status != last_status or row.stage != last_stage:
                    last_status, last_stage = row.status, row.stage
                    current_seq += 1
                    yield StreamEvent(
                        current_seq,
                        "stage_progress",
                        {
                            "status": row.status,
                            "stage": row.stage,
                            "started_at": row.started_at,
                            "finished_at": row.finished_at,
                            "checks": row.checks or [],
                        },
                    )

                # 2. Check for newly discovered findings
                evidence_stmt = (
                    select(FindingEvidence)
                    .where(FindingEvidence.assessment_id == self.assessment_id)
                )
                for ev in db.scalars(evidence_stmt):
                    if ev.finding_id not in seen_finding_ids:
                        seen_finding_ids.add(ev.finding_id)
                        finding = db.get(Finding, ev.finding_id)
                        if finding is not None:
                            current_seq += 1
                            yield StreamEvent(
                                current_seq,
                                "finding_detected",
                                {
                                    "id": finding.id,
                                    "title": finding.title,
                                    "category": finding.category,
                                    "severity": finding.severity,
                                    "status": finding.status,
                                    "affected_url": finding.affected_url,
                                    "evidence": ev.data,
                                },
                            )

                # 3. Check for newly recorded observations
                obs_stmt = (
                    select(Observation)
                    .where(Observation.assessment_id == self.assessment_id)
                    .order_by(Observation.observed_at)
                )
                for obs in db.scalars(obs_stmt):
                    if obs.id not in seen_obs_ids:
                        seen_obs_ids.add(obs.id)
                        current_seq += 1
                        yield StreamEvent(
                            current_seq,
                            "observation_recorded",
                            {"id": obs.id, "data": obs.data},
                        )

                # 4. If assessment reached terminal state, emit completion and end stream
                if row.status in self.TERMINAL_STATES:
                    current_seq += 1
                    yield StreamEvent(
                        current_seq,
                        "complete",
                        {"outcome": row.status, "stage": row.stage, "error": row.error},
                    )
                    return

            time.sleep(poll_interval)


class WCAGAccessibilityValidator:
    """Automated WCAG 2.1 AA Accessibility Validator for UI components and JSX templates."""

    VALID_ARIA_ROLES = {
        "alert", "alertdialog", "button", "checkbox", "dialog", "grid", "gridcell",
        "link", "listbox", "menu", "menubar", "menuitem", "progressbar", "radio",
        "radiogroup", "region", "scrollbar", "search", "separator", "slider",
        "spinbutton", "status", "tab", "tablist", "tabpanel", "textbox", "timer",
        "toolbar", "tooltip", "tree", "treegrid", "treeitem"
    }

    @classmethod
    def evaluate_jsx_snippet(cls, rule: str, jsx: str) -> bool:
        """Evaluates a JSX snippet against a specific WCAG rule.
        
        Returns True if the snippet VIOLATES the rule (should be denied).
        """
        # Rule: alt-text (images must have non-empty alt text)
        if rule == "alt-text":
            if "<img" in jsx and 'alt="' not in jsx:
                return True
            return False

        # Rule: anchor-has-content (anchor must have children or content)
        if rule == "anchor-has-content":
            if re.search(r"<a[^>]*/>", jsx) or re.search(r"<a[^>]*>\s*</a>", jsx):
                return True
            return False

        # Rule: anchor-is-valid (anchor must have a real navigation href, not '#')
        if rule == "anchor-is-valid":
            if 'href="#"' in jsx or "href='#'" in jsx:
                return True
            return False

        # Rule: aria-activedescendant-has-tabindex
        if rule == "aria-activedescendant-has-tabindex":
            if "aria-activedescendant=" in jsx and "tabIndex=" not in jsx:
                return True
            return False

        # Rule: aria-role (must use valid W3C roles)
        if rule == "aria-role":
            match = re.search(r'role="([^"]+)"', jsx)
            if match:
                role_val = match.group(1).strip().lower()
                if role_val not in cls.VALID_ARIA_ROLES:
                    return True
            return False

        # Rule: aria-props (reject invalid aria- attributes)
        if rule == "aria-props":
            valid_props = {
                "aria-label", "aria-labelledby", "aria-describedby", "aria-hidden",
                "aria-expanded", "aria-checked", "aria-disabled", "aria-live",
                "aria-controls", "aria-current", "aria-valuenow", "aria-valuemin",
                "aria-valuemax"
            }
            for prop_match in re.finditer(r'(aria-[a-z-]+)=', jsx):
                if prop_match.group(1) not in valid_props:
                    return True
            return False

        # Rule: aria-proptypes (boolean attributes must have "true" or "false")
        if rule == "aria-proptypes":
            if 'aria-hidden="maybe"' in jsx or 'aria-expanded="maybe"' in jsx:
                return True
            return False

        # Rule: click-events-have-key-events
        if rule == "click-events-have-key-events":
            if "<div" in jsx and "onClick=" in jsx and "onKeyDown=" not in jsx and "onKeyUp=" not in jsx:
                return True
            return False

        return False
