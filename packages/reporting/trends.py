"""Differential Trend Reporting, MTTR Analytics & Posture Trajectory.

Sector 6: Reporting & Evidence.
Provides:
1. Multi-assessment differential analytics: new, resolved, reopened, and persistent findings.
2. Mean-Time-To-Remediation (MTTR) calculation and posture score trajectory.
3. Executive dashboard generator (severity mix, coverage map, risk rating).
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class FindingRecord:
    finding_id: str
    vuln_type: str
    target_origin: str
    endpoint: str
    parameter: Optional[str]
    severity: str
    cvss_score: float
    description: str
    first_detected_at: float
    last_detected_at: float
    lifecycle_state: str = "REPRODUCED"  # REPRODUCED, REMEDIATED, DEMOTED

    @property
    def fingerprint(self) -> str:
        param = self.parameter or "none"
        raw = f"{self.target_origin}:{self.vuln_type}:{self.endpoint}:{param}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_dict(cls, data: Dict[str, Any], default_origin: str = "https://target.local") -> FindingRecord:
        finding_id = str(data.get("id") or data.get("finding_id") or "FINDING-GENERIC")
        vuln_type = str(data.get("category") or data.get("vuln_type") or "security_finding")
        affected_url = str(data.get("affected_url") or default_origin)
        endpoint = data.get("endpoint") or (affected_url.split("/", 3)[-1] if "/" in affected_url else "/")
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        target_origin = str(
            data.get("target_origin")
            or (
                affected_url.split("://")[0] + "://" + affected_url.split("://")[-1].split("/")[0]
                if "://" in affected_url
                else default_origin
            )
        )
        parameter = data.get("parameter")
        severity = str(data.get("severity") or "medium").upper()
        cvss = float(data.get("cvss_score") or data.get("cvss") or 5.0)
        desc = str(data.get("description") or data.get("title") or "")
        first_at = float(data.get("first_detected_at") or data.get("created_at") or 0.0)
        last_at = float(data.get("last_detected_at") or data.get("updated_at") or first_at)
        lifecycle = str(data.get("lifecycle_state") or "REPRODUCED")

        return cls(
            finding_id=finding_id,
            vuln_type=vuln_type,
            target_origin=target_origin,
            endpoint=endpoint,
            parameter=parameter,
            severity=severity,
            cvss_score=cvss,
            description=desc,
            first_detected_at=first_at,
            last_detected_at=last_at,
            lifecycle_state=lifecycle,
        )


@dataclasses.dataclass
class DifferentialReport:
    previous_assessment_id: str
    current_assessment_id: str
    new_findings: List[FindingRecord]
    resolved_findings: List[FindingRecord]
    reopened_findings: List[FindingRecord]
    persistent_findings: List[FindingRecord]
    mttr_seconds: Optional[float]
    posture_score_previous: float
    posture_score_current: float
    posture_delta: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_assessment_id": self.previous_assessment_id,
            "current_assessment_id": self.current_assessment_id,
            "counts": {
                "new": len(self.new_findings),
                "resolved": len(self.resolved_findings),
                "reopened": len(self.reopened_findings),
                "persistent": len(self.persistent_findings),
            },
            "new_findings": [dataclasses.asdict(f) for f in self.new_findings],
            "resolved_findings": [dataclasses.asdict(f) for f in self.resolved_findings],
            "reopened_findings": [dataclasses.asdict(f) for f in self.reopened_findings],
            "persistent_findings": [dataclasses.asdict(f) for f in self.persistent_findings],
            "mttr_seconds": self.mttr_seconds,
            "posture_score_previous": self.posture_score_previous,
            "posture_score_current": self.posture_score_current,
            "posture_delta": self.posture_delta,
        }


class AssessmentTrendEngine:
    """Analyzes differences between assessments, tracks finding lifecycles, and computes MTTR."""

    @staticmethod
    def calculate_posture_score(findings: List[FindingRecord]) -> float:
        """Calculates 0-100 posture score where 100 is pristine security."""
        deductions = {
            "CRITICAL": 25.0,
            "HIGH": 15.0,
            "MEDIUM": 8.0,
            "LOW": 3.0,
            "INFO": 0.5,
        }
        total_deduction = 0.0
        for f in findings:
            total_deduction += deductions.get(f.severity.upper(), 5.0)
        return max(0.0, round(100.0 - total_deduction, 1))

    @classmethod
    def compute_differential(
        cls,
        prev_assessment_id: str,
        prev_findings: List[FindingRecord],
        curr_assessment_id: str,
        curr_findings: List[FindingRecord],
        historical_resolved_fingerprints: Optional[Set[str]] = None,
        now: Optional[float] = None,
    ) -> DifferentialReport:
        ts = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
        resolved_history = historical_resolved_fingerprints or set()

        prev_map = {f.fingerprint: f for f in prev_findings}
        curr_map = {f.fingerprint: f for f in curr_findings}

        new_list: List[FindingRecord] = []
        reopened_list: List[FindingRecord] = []
        persistent_list: List[FindingRecord] = []
        resolved_list: List[FindingRecord] = []

        # Categorize current findings
        for fp, curr_f in curr_map.items():
            if fp not in prev_map:
                if fp in resolved_history:
                    reopened_list.append(curr_f)
                else:
                    new_list.append(curr_f)
            else:
                persistent_list.append(curr_f)

        # Categorize resolved findings
        remediation_durations: List[float] = []
        for fp, prev_f in prev_map.items():
            if fp not in curr_map:
                resolved_list.append(prev_f)
                duration = ts - prev_f.first_detected_at
                if duration > 0:
                    remediation_durations.append(duration)

        mttr = sum(remediation_durations) / len(remediation_durations) if remediation_durations else None

        prev_score = cls.calculate_posture_score(prev_findings)
        curr_score = cls.calculate_posture_score(curr_findings)
        delta = round(curr_score - prev_score, 1)

        return DifferentialReport(
            previous_assessment_id=prev_assessment_id,
            current_assessment_id=curr_assessment_id,
            new_findings=new_list,
            resolved_findings=resolved_list,
            reopened_findings=reopened_list,
            persistent_findings=persistent_list,
            mttr_seconds=mttr,
            posture_score_previous=prev_score,
            posture_score_current=curr_score,
            posture_delta=delta,
        )


class ExecutiveDashboardGenerator:
    """Generates high-level executive metrics, severity distribution, and risk ratings."""

    @staticmethod
    def generate_dashboard(
        findings: List[FindingRecord],
        total_endpoints_discovered: int,
        total_endpoints_tested: int,
        target_name: str = "Production Target",
    ) -> Dict[str, Any]:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        coverage_ratio = (
            round((total_endpoints_tested / total_endpoints_discovered) * 100.0, 1)
            if total_endpoints_discovered > 0
            else 100.0
        )

        posture_score = AssessmentTrendEngine.calculate_posture_score(findings)
        if posture_score >= 90.0:
            risk_rating = "LOW"
        elif posture_score >= 70.0:
            risk_rating = "MODERATE"
        elif posture_score >= 50.0:
            risk_rating = "ELEVATED"
        else:
            risk_rating = "CRITICAL"

        return {
            "target_name": target_name,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "posture_score": posture_score,
            "risk_rating": risk_rating,
            "severity_distribution": severity_counts,
            "attack_surface": {
                "discovered": total_endpoints_discovered,
                "tested": total_endpoints_tested,
                "coverage_percent": coverage_ratio,
            },
            "total_open_findings": len(findings),
            "executive_summary": (
                f"{target_name} posture score is {posture_score}/100 ({risk_rating} risk). "
                f"Assessed {total_endpoints_tested}/{total_endpoints_discovered} endpoints "
                f"({coverage_ratio}% coverage). Detected {severity_counts['CRITICAL']} critical and "
                f"{severity_counts['HIGH']} high findings requiring prioritized remediation."
            ),
        }
