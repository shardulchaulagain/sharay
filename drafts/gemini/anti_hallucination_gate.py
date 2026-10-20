"""Anti-Hallucination Grounding Gate (Phase 0, Sector 5: AI Reasoning Layer).

Grounds AI/LLM narrative outputs strictly in verified findings, observed crawl endpoints,
and cryptographic evidence hashes. Detects and rejects phantom vulnerabilities, fabricated
endpoints, severity inflation, and ungrounded CVE/CWE identifiers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class ClaimType(str, Enum):
    VULNERABILITY = "vulnerability"
    ENDPOINT = "endpoint"
    SEVERITY = "severity"
    IDENTIFIER = "identifier"


@dataclass(frozen=True)
class ExtractedClaim:
    """An individual assertion or entity extracted from candidate narrative text."""

    claim_type: ClaimType
    claim_text: str
    context_sentence: str
    start_char: int
    end_char: int


@dataclass(frozen=True)
class ClaimVerification:
    """The grounding verdict and cryptographic provenance backing an individual claim."""

    claim: ExtractedClaim
    grounded: bool
    matched_entity: str | None = None
    evidence_sha256: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.claim.claim_type.value,
            "text": self.claim.claim_text,
            "grounded": self.grounded,
            "matched_entity": self.matched_entity,
            "evidence_sha256": self.evidence_sha256,
            "reason": self.reason,
            "context": self.claim.context_sentence,
        }


@dataclass
class GroundingVerdict:
    """The aggregate gate verdict on an AI-generated narrative."""

    is_grounded: bool
    grounding_ratio: float
    total_claims: int
    verified_claims: list[ClaimVerification] = field(default_factory=list)
    hallucinated_claims: list[ClaimVerification] = field(default_factory=list)
    cited_fingerprints: list[str] = field(default_factory=list)
    cited_evidence_hashes: list[str] = field(default_factory=list)
    rejection_reason: str | None = None
    sanitized_narrative: str = ""
    provenance_manifest: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_grounded": self.is_grounded,
            "grounding_ratio": round(self.grounding_ratio, 3),
            "total_claims": self.total_claims,
            "verified_count": len(self.verified_claims),
            "hallucination_count": len(self.hallucinated_claims),
            "cited_fingerprints": self.cited_fingerprints,
            "cited_evidence_hashes": self.cited_evidence_hashes,
            "rejection_reason": self.rejection_reason,
            "verified_claims": [c.to_dict() for c in self.verified_claims],
            "hallucinated_claims": [c.to_dict() for c in self.hallucinated_claims],
            "provenance_manifest": self.provenance_manifest,
        }


class GroundingCorpusIndex:
    """Index of known verified assessment findings, crawled endpoints, and evidence hashes."""

    def __init__(
        self,
        findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        target_url: str = "",
    ) -> None:
        self.target_url = target_url
        self.findings = findings
        self.observations = observations

        # Indexed lookups
        self.endpoints: set[str] = set()
        self.fingerprints: dict[str, dict[str, Any]] = {}
        self.cwe_set: set[str] = set()
        self.cve_set: set[str] = set()
        self.vuln_term_map: dict[str, list[dict[str, Any]]] = {}
        self.evidence_hashes: dict[str, str] = {}  # sha256 -> label/source
        self.severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        self._build_index()

    def _normalize_path(self, path_or_url: str) -> str:
        if not path_or_url:
            return "/"
        if "://" in path_or_url:
            parsed = urlparse(path_or_url)
            path = parsed.path or "/"
        else:
            path = path_or_url.split("?")[0].split("#")[0]
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/") or "/"

    def _build_index(self) -> None:
        if self.target_url:
            parsed_tgt = urlparse(self.target_url)
            if parsed_tgt.path:
                self.endpoints.add(self._normalize_path(parsed_tgt.path))
            else:
                self.endpoints.add("/")

        # Ingest observations
        for obs in self.observations:
            kind = obs.get("kind", "")
            # Endpoints from crawler
            if kind == "crawler_summary":
                for ep in obs.get("endpoints", []):
                    self.endpoints.add(self._normalize_path(ep))
            elif "endpoint" in obs:
                self.endpoints.add(self._normalize_path(obs["endpoint"]))

            # Evidence hashes from observations
            obs_id = str(obs.get("observation_id", obs.get("id", "")))
            ev_hash = obs.get("evidence_sha256")
            if not ev_hash:
                # Deterministic fallback hash from payload
                dumped = str(sorted(obs.items())).encode("utf-8")
                ev_hash = hashlib.sha256(dumped).hexdigest()
            self.evidence_hashes[ev_hash] = obs_id or kind

        # Ingest verified findings
        for f in self.findings:
            fp = str(f.get("fingerprint", ""))
            if fp:
                self.fingerprints[fp] = f

            title = str(f.get("title", ""))
            cat = str(f.get("category", "")).lower()
            sev = str(f.get("severity", "medium")).lower()
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

            cwe = str(f.get("cwe_id", "")).upper()
            if cwe:
                self.cwe_set.add(cwe)

            aff_url = str(f.get("affected_url", ""))
            if aff_url:
                self.endpoints.add(self._normalize_path(aff_url))

            # Evidence hashes from finding
            f_ev_hash = f.get("evidence_sha256")
            if not f_ev_hash:
                ev_list = f.get("evidence", [])
                if ev_list and isinstance(ev_list[-1], dict):
                    ev_data = str(ev_list[-1].get("data", "")).encode("utf-8")
                    f_ev_hash = hashlib.sha256(ev_data).hexdigest()
                else:
                    f_ev_hash = hashlib.sha256(f"{fp}:{title}:{aff_url}".encode("utf-8")).hexdigest()
            self.evidence_hashes[f_ev_hash] = fp or title

            # Extract keywords from title and category
            terms = set()
            terms.add(cat)
            for word in re.findall(r"[A-Za-z0-9_\-]+", title.lower()):
                if len(word) >= 3:
                    terms.add(word)

            # Common cybersecurity synonyms mapping
            if "sql" in title.lower() or "injection" in title.lower() or cat == "injection":
                terms.update(["sqli", "sql injection", "injection"])
            if "actuator" in title.lower() or "rce" in cat:
                terms.update(["rce", "remote code execution", "actuator"])
            if "xss" in title.lower() or "scripting" in title.lower():
                terms.update(["xss", "cross-site scripting"])
            if "header" in title.lower() or "frame" in title.lower() or "nosniff" in title.lower():
                terms.update(["security header", "security headers", "clickjacking", "mime", "nosniff", "x-frame-options"])
            if "subdomain" in title.lower() or "dns" in title.lower():
                terms.update(["subdomain", "subdomain takeover", "dangling dns"])
            if "disclosure" in title.lower() or "dotfile" in title.lower() or ".git" in title.lower():
                terms.update(["information disclosure", "sensitive file", "dotfile", "source leak"])
            if "idor" in title.lower() or "bola" in title.lower() or "access control" in title.lower():
                terms.update(["idor", "bola", "broken access control", "authorization bypass"])
            if "ssrf" in title.lower():
                terms.update(["ssrf", "server-side request forgery"])

            for t in terms:
                self.vuln_term_map.setdefault(t, []).append(f)

            # Look for CVE identifiers in title or description
            for cve in re.findall(r"CVE-\d{4}-\d+", title + " " + str(f.get("description", "")), re.IGNORECASE):
                self.cve_set.add(cve.upper())


class AntiHallucinationGate:
    """Anti-hallucination validation gate enforcing evidence grounding on AI outputs."""

    # Well-known critical vulnerability terms that should never be hallucinated
    SENSITIVE_VULN_PATTERNS = [
        (r"\b(remote\s+code\s+execution|rce)\b", "remote code execution"),
        (r"\b(sql\s+injection|sqli)\b", "sql injection"),
        (r"\b(cross-site\s+scripting|xss)\b", "cross-site scripting"),
        (r"\b(server-side\s+request\s+forgery|ssrf)\b", "server-side request forgery"),
        (r"\b(insecure\s+direct\s+object\s+reference|idor|bola)\b", "idor"),
        (r"\b(path\s+traversal|directory\s+traversal|local\s+file\s+inclusion|lfi)\b", "path traversal"),
        (r"\b(command\s+injection|os\s+command\s+injection)\b", "command injection"),
        (r"\b(xml\s+external\s+entity|xxe)\b", "xxe"),
        (r"\b(subdomain\s+takeover)\b", "subdomain takeover"),
        (r"\b(privilege\s+escalation)\b", "privilege escalation"),
        (r"\b(authentication\s+bypass)\b", "authentication bypass"),
        (r"\b(sensitive\s+data\s+exposure|information\s+disclosure)\b", "information disclosure"),
        (r"\b(security\s+headers?|missing\s+headers?|clickjacking|nosniff)\b", "security headers"),
    ]

    def __init__(self, strict_mode: bool = True) -> None:
        self.strict_mode = strict_mode

    def extract_claims(self, text: str) -> list[ExtractedClaim]:
        """Extract testable assertions (vulnerabilities, endpoints, severities, CVEs) from text."""
        claims: list[ExtractedClaim] = []
        sentences = re.split(r"(?<=[.!?])\s+", text)

        for sent in sentences:
            sent_clean = sent.strip()
            if not sent_clean:
                continue

            # 1. Vulnerability Claims
            for pattern, canonical_name in self.SENSITIVE_VULN_PATTERNS:
                for match in re.finditer(pattern, sent_clean, re.IGNORECASE):
                    claims.append(
                        ExtractedClaim(
                            claim_type=ClaimType.VULNERABILITY,
                            claim_text=canonical_name,
                            context_sentence=sent_clean,
                            start_char=match.start(),
                            end_char=match.end(),
                        )
                    )

            # 2. Endpoint / Path Claims (e.g. /api/v1/..., /admin, /users)
            # Match paths like /something, but ignore common English punctuation or markdown slashes
            for match in re.finditer(r"(?<![A-Za-z0-9_])(/[a-zA-Z0-9_\-\./]+)", sent_clean):
                path = match.group(1).rstrip(".,;:!?)'\"`")
                # Filter out pure slash, markdown tags, or file extensions like /.
                if len(path) > 1 and not path.startswith("//") and not path.endswith(".."):
                    claims.append(
                        ExtractedClaim(
                            claim_type=ClaimType.ENDPOINT,
                            claim_text=path,
                            context_sentence=sent_clean,
                            start_char=match.start(),
                            end_char=match.end(),
                        )
                    )

            # 3. Severity Inflation Claims (e.g. "critical vulnerability", "critical issue")
            if re.search(r"\bcritical(\s+(vulnerabilit\w+|finding\s*|flaw\s*|risk|exploit|threat))\b", sent_clean, re.IGNORECASE):
                claims.append(
                    ExtractedClaim(
                        claim_type=ClaimType.SEVERITY,
                        claim_text="critical",
                        context_sentence=sent_clean,
                        start_char=0,
                        end_char=len(sent_clean),
                    )
                )

            # 4. Standard Identifiers (CVE-YYYY-NNNN, CWE-NNN)
            for match in re.finditer(r"\b(CVE-\d{4}-\d+|CWE-\d+)\b", sent_clean, re.IGNORECASE):
                claims.append(
                    ExtractedClaim(
                        claim_type=ClaimType.IDENTIFIER,
                        claim_text=match.group(1).upper(),
                        context_sentence=sent_clean,
                        start_char=match.start(),
                        end_char=match.end(),
                    )
                )

        return claims

    def verify_narrative(
        self,
        narrative: str,
        corpus: GroundingCorpusIndex,
        fallback_narrative: str = "",
    ) -> GroundingVerdict:
        """Verify candidate LLM text against the GroundingCorpusIndex."""
        if not narrative or not narrative.strip():
            return GroundingVerdict(
                is_grounded=True,
                grounding_ratio=1.0,
                total_claims=0,
                sanitized_narrative=fallback_narrative,
            )

        claims = self.extract_claims(narrative)
        if not claims:
            # Narrative made no specific vulnerability, endpoint, or severity assertions
            manifest = self._generate_manifest(corpus, narrative, [], [])
            return GroundingVerdict(
                is_grounded=True,
                grounding_ratio=1.0,
                total_claims=0,
                sanitized_narrative=narrative,
                provenance_manifest=manifest,
            )

        verified: list[ClaimVerification] = []
        hallucinated: list[ClaimVerification] = []
        cited_fps: set[str] = set()
        cited_hashes: set[str] = set()

        for c in claims:
            # Check 1: Vulnerability claims
            if c.claim_type == ClaimType.VULNERABILITY:
                matched_findings = corpus.vuln_term_map.get(c.claim_text.lower(), [])
                if matched_findings:
                    f = matched_findings[0]
                    fp = f.get("fingerprint", "")
                    ev_hash = f.get("evidence_sha256")
                    if not ev_hash and corpus.evidence_hashes:
                        ev_hash = next(iter(corpus.evidence_hashes.keys()))
                    if fp:
                        cited_fps.add(fp)
                    if ev_hash:
                        cited_hashes.add(ev_hash)
                    verified.append(
                        ClaimVerification(
                            claim=c,
                            grounded=True,
                            matched_entity=fp or f.get("title", ""),
                            evidence_sha256=ev_hash,
                            reason=f"Corroborated by verified finding: {f.get('title')}",
                        )
                    )
                else:
                    hallucinated.append(
                        ClaimVerification(
                            claim=c,
                            grounded=False,
                            reason=f"No verified assessment finding matches vulnerability class '{c.claim_text}'",
                        )
                    )

            # Check 2: Endpoint / Path claims
            elif c.claim_type == ClaimType.ENDPOINT:
                norm_path = corpus._normalize_path(c.claim_text)
                if norm_path in corpus.endpoints:
                    verified.append(
                        ClaimVerification(
                            claim=c,
                            grounded=True,
                            matched_entity=norm_path,
                            reason=f"Endpoint '{norm_path}' was observed in crawl or finding scope",
                        )
                    )
                else:
                    hallucinated.append(
                        ClaimVerification(
                            claim=c,
                            grounded=False,
                            reason=f"Path '{c.claim_text}' was never crawled or verified in assessment scope",
                        )
                    )

            # Check 3: Severity inflation
            elif c.claim_type == ClaimType.SEVERITY:
                if c.claim_text == "critical" and corpus.severity_counts["critical"] > 0:
                    verified.append(
                        ClaimVerification(
                            claim=c,
                            grounded=True,
                            matched_entity="critical_findings_present",
                            reason=f"Corroborated: {corpus.severity_counts['critical']} critical finding(s) verified",
                        )
                    )
                elif c.claim_text == "critical" and corpus.severity_counts["critical"] == 0:
                    hallucinated.append(
                        ClaimVerification(
                            claim=c,
                            grounded=False,
                            reason="Narrative asserted 'critical' severity, but 0 critical findings exist in assessment",
                        )
                    )
                else:
                    verified.append(ClaimVerification(claim=c, grounded=True, reason="Severity corroborated"))

            # Check 4: Identifiers (CVE, CWE)
            elif c.claim_type == ClaimType.IDENTIFIER:
                ident = c.claim_text.upper()
                if ident.startswith("CWE-") and ident in corpus.cwe_set:
                    verified.append(
                        ClaimVerification(
                            claim=c,
                            grounded=True,
                            matched_entity=ident,
                            reason=f"Corroborated by verified finding with {ident}",
                        )
                    )
                elif ident.startswith("CVE-") and ident in corpus.cve_set:
                    verified.append(
                        ClaimVerification(
                            claim=c,
                            grounded=True,
                            matched_entity=ident,
                            reason=f"Corroborated by verified finding with {ident}",
                        )
                    )
                else:
                    hallucinated.append(
                        ClaimVerification(
                            claim=c,
                            grounded=False,
                            reason=f"Identifier '{c.claim_text}' is not associated with any verified finding in this assessment",
                        )
                    )

        total = len(claims)
        ratio = len(verified) / total if total > 0 else 1.0

        # Strict mode: ANY ungrounded vulnerability, fabricated endpoint, or severity inflation fails the gate
        is_grounded = len(hallucinated) == 0

        rejection_reason = None
        if not is_grounded:
            rejection_reason = (
                f"Anti-Hallucination Gate rejected narrative: {len(hallucinated)} ungrounded claim(s) detected. "
                + "; ".join(f"[{h.claim.claim_type.value}] {h.reason}" for h in hallucinated[:3])
            )
            sanitized = fallback_narrative or (
                f"[GROUNDING REJECTION: LLM generated {len(hallucinated)} unverified assertion(s). "
                "Defaulting to verified deterministic findings summary.]"
            )
        else:
            sanitized = narrative

        # Build provenance manifest if grounded
        manifest = {}
        if is_grounded:
            manifest = self._generate_manifest(
                corpus=corpus,
                narrative=sanitized,
                cited_fps=sorted(cited_fps),
                cited_hashes=sorted(cited_hashes),
            )

        return GroundingVerdict(
            is_grounded=is_grounded,
            grounding_ratio=ratio,
            total_claims=total,
            verified_claims=verified,
            hallucinated_claims=hallucinated,
            cited_fingerprints=sorted(cited_fps),
            cited_evidence_hashes=sorted(cited_hashes),
            rejection_reason=rejection_reason,
            sanitized_narrative=sanitized,
            provenance_manifest=manifest,
        )

    def _generate_manifest(
        self,
        corpus: GroundingCorpusIndex,
        narrative: str,
        cited_fps: list[str],
        cited_hashes: list[str],
    ) -> dict[str, Any]:
        """Construct a cryptographic evidence seal connecting narrative text to observation hashes."""
        text_sha = hashlib.sha256(narrative.encode("utf-8")).hexdigest()
        combined = f"{text_sha}:" + ":".join(cited_hashes) + ":" + ":".join(cited_fps)
        seal_sha = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        return {
            "target_url": corpus.target_url,
            "narrative_sha256": text_sha,
            "evidence_hashes": cited_hashes or list(corpus.evidence_hashes.keys())[:5],
            "verified_fingerprints": cited_fps or list(corpus.fingerprints.keys()),
            "merkle_seal_sha256": seal_sha,
            "status": "cryptographically_grounded",
        }
