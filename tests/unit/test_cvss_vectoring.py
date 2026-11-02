"""Unit tests for FIRST.org CVSS v3.1 calculation engine and vector parser.

Verifies:
- Base, Temporal, and Environmental metrics calculation according to FIRST.org specification.
- Score boundaries: 0.0 (None) to 10.0 (Critical).
- Standard CVE reference vectors (Log4Shell, BlueKeep, Heartbleed, Reflected XSS).
- Vector string generation (short and verbose metric syntax, canonical ordering).
- Round-trip vector parsing, validation, and scoring.
- Appendix A floating-point Roundup behavior.
"""

from __future__ import annotations

import pytest

from packages.reporting.cvss import (
    compute_cvss_score,
    cvss_roundup,
    generate_cvss_vector,
    parse_cvss_vector,
    score_to_severity,
    validate_cvss_vector,
)


class TestCVSSRoundup:
    """Tests for FIRST.org CVSS v3.1 Appendix A Roundup function."""

    def test_roundup_exact_decimal(self) -> None:
        assert cvss_roundup(4.0) == 4.0
        assert cvss_roundup(0.0) == 0.0
        assert cvss_roundup(10.0) == 10.0
        assert cvss_roundup(5.3) == 5.3

    def test_roundup_fractional_increment(self) -> None:
        assert cvss_roundup(4.02) == 4.1
        assert cvss_roundup(4.0001) == 4.1
        assert cvss_roundup(0.01) == 0.1
        assert cvss_roundup(9.91) == 10.0

    def test_roundup_negative_zero(self) -> None:
        assert cvss_roundup(-0.5) == 0.0


class TestCVSSBaseScoring:
    """Tests Base metric scores against FIRST.org standard vectors."""

    def test_minimum_base_score_is_zero(self) -> None:
        vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 0.0
        assert res["base_severity"] == "NONE"
        assert res["sub_scores"]["impact"] == 0.0

    def test_maximum_base_score_is_ten(self) -> None:
        # Scope Changed, all High impact
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 10.0
        assert res["base_severity"] == "CRITICAL"
        assert res["sub_scores"]["exploitability"] > 3.0

    def test_cve_2021_44228_log4shell(self) -> None:
        # Log4Shell: Network, Low AC, None PR, None UI, Changed Scope, High C/I/A
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 10.0
        assert res["base_severity"] == "CRITICAL"

    def test_cve_2019_0708_bluekeep(self) -> None:
        # BlueKeep: Scope Unchanged, High C/I/A
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 9.8
        assert res["base_severity"] == "CRITICAL"

    def test_cve_2014_0160_heartbleed(self) -> None:
        # Heartbleed: Network, Low AC, None PR, None UI, Unchanged Scope, High C, None I/A
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 7.5
        assert res["base_severity"] == "HIGH"

    def test_stored_xss_medium_score(self) -> None:
        # XSS: Network, Low AC, None PR, Required UI, Changed Scope, Low C/I, None A
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 6.1
        assert res["base_severity"] == "MEDIUM"

    def test_low_severity_vector(self) -> None:
        vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 1.6
        assert res["base_severity"] == "LOW"

    def test_privileges_required_scope_dependency(self) -> None:
        # Scope Unchanged: PR:L = 0.62, PR:H = 0.27
        v_unchanged = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        res_u = compute_cvss_score(v_unchanged)

        # Scope Changed: PR:L = 0.68, PR:H = 0.50
        v_changed = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"
        res_c = compute_cvss_score(v_changed)

        assert res_u["base_score"] == 6.5
        assert res_c["base_score"] == 7.7


class TestCVSSTemporalScoring:
    """Tests Temporal metrics modifier on CVSS Base scores."""

    def test_temporal_official_fix_and_poc(self) -> None:
        # Base 7.5; E:P (0.94), RL:O (0.95), RC:C (1.0)
        # 7.5 * 0.94 * 0.95 = 6.6975 -> Roundup = 6.7
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 7.5
        assert res["temporal_score"] == 6.7
        assert res["temporal_severity"] == "MEDIUM"
        assert res["overall_score"] == 6.7
        assert res["overall_severity"] == "MEDIUM"

    def test_temporal_unproven_and_workaround(self) -> None:
        # Base 9.8; E:U (0.91), RL:W (0.97), RC:U (0.92)
        # 9.8 * 0.91 * 0.97 * 0.92 = 7.957 -> Roundup = 8.0
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:W/RC:U"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 9.8
        assert res["temporal_score"] == 8.0
        assert res["temporal_severity"] == "HIGH"
        assert res["overall_score"] == 8.0

    def test_temporal_defaults_when_omitted(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        res = compute_cvss_score(vector)
        assert res["temporal_score"] is None
        assert res["temporal_severity"] is None
        assert res["overall_score"] == 7.5


class TestCVSSEnvironmentalScoring:
    """Tests Environmental metrics customization according to FIRST.org specification."""

    def test_environmental_security_requirements_and_modified_av(self) -> None:
        # Base 7.5; CR:H (1.5), IR:L (0.5), AR:L (0.5), MAV:A (0.62)
        # Temporal: E:P (0.94), RL:O (0.95), RC:C (1.0)
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C/CR:H/IR:L/AR:L/MAV:A"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 7.5
        assert res["temporal_score"] == 6.7
        assert res["environmental_score"] == 7.5
        assert res["environmental_severity"] == "HIGH"
        assert res["overall_score"] == 7.5
        assert res["sub_scores"]["miss"] is not None

    def test_environmental_modified_scope_changed(self) -> None:
        # Base Scope Unchanged, Modified Scope Changed (MS:C)
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MS:C"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 9.8
        assert res["environmental_score"] == 10.0
        assert res["environmental_severity"] == "CRITICAL"
        assert res["overall_score"] == 10.0

    def test_environmental_modified_impact_none_yields_zero(self) -> None:
        # Modifying all impacts to None yields environmental score of 0.0
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N"
        res = compute_cvss_score(vector)
        assert res["base_score"] == 9.8
        assert res["environmental_score"] == 0.0
        assert res["environmental_severity"] == "NONE"
        assert res["overall_score"] == 0.0


class TestCVSSVectorGenerationAndParsing:
    """Tests round-trip vector synthesis, validation, and normalization."""

    def test_generate_vector_short_syntax(self) -> None:
        vec = generate_cvss_vector(
            av="N",
            ac="L",
            pr="N",
            ui="N",
            s="U",
            c="H",
            i="H",
            a="H",
        )
        assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_generate_vector_verbose_syntax(self) -> None:
        vec = generate_cvss_vector(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="REQUIRED",
            scope="CHANGED",
            confidentiality="LOW",
            integrity="LOW",
            availability="NONE",
            exploit_code_maturity="PROOF_OF_CONCEPT",
            remediation_level="OFFICIAL_FIX",
        )
        assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:O"

    def test_canonical_metric_order_preserved(self) -> None:
        # Pass metrics out of order
        vec = generate_cvss_vector(
            a="H",
            c="H",
            i="H",
            s="U",
            ui="N",
            pr="N",
            ac="L",
            av="N",
        )
        assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_roundtrip_vector_parsing_and_scoring(self) -> None:
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:O/RC:C"
        parsed = parse_cvss_vector(original)
        assert parsed["AV"] == "N"
        assert parsed["E"] == "P"
        assert parsed["RL"] == "O"

        regenerated = generate_cvss_vector(**parsed)
        assert regenerated == original

        scored = compute_cvss_score(regenerated)
        assert scored["base_score"] == 6.1
        assert scored["temporal_score"] == 5.5

    def test_missing_mandatory_base_metric_raises(self) -> None:
        with pytest.raises(ValueError, match="Missing mandatory base metrics"):
            generate_cvss_vector(av="N", ac="L", pr="N", ui="N", s="U", c="H")  # Missing I, A

        with pytest.raises(ValueError, match="Missing mandatory base metrics"):
            parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H")

    def test_invalid_vector_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="Vector string must start with 'CVSS:3.1/'"):
            parse_cvss_vector("INVALID/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        with pytest.raises(ValueError, match="CVSS 3.0 vector provided"):
            parse_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_duplicate_metric_key_raises(self) -> None:
        dup = "CVSS:3.1/AV:N/AC:L/AV:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        with pytest.raises(ValueError, match="Duplicate metric key"):
            parse_cvss_vector(dup)

    def test_invalid_metric_value_raises(self) -> None:
        bad_val = "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # AV cannot be X in base
        with pytest.raises(ValueError, match="Invalid value 'X' for metric 'AV'"):
            parse_cvss_vector(bad_val)

    def test_validate_cvss_vector_helper(self) -> None:
        valid_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ok, errors = validate_cvss_vector(valid_vec)
        assert ok is True
        assert len(errors) == 0

        invalid_vec = "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ok, errors = validate_cvss_vector(invalid_vec)
        assert ok is False
        assert len(errors) > 0


class TestQualitativeSeverityRatings:
    """Tests score_to_severity mapping according to FIRST specification thresholds."""

    def test_severity_thresholds(self) -> None:
        assert score_to_severity(0.0) == "NONE"
        assert score_to_severity(0.1) == "LOW"
        assert score_to_severity(3.9) == "LOW"
        assert score_to_severity(4.0) == "MEDIUM"
        assert score_to_severity(6.9) == "MEDIUM"
        assert score_to_severity(7.0) == "HIGH"
        assert score_to_severity(8.9) == "HIGH"
        assert score_to_severity(9.0) == "CRITICAL"
        assert score_to_severity(10.0) == "CRITICAL"

    def test_out_of_bounds_score_raises(self) -> None:
        with pytest.raises(ValueError, match="out of CVSS range"):
            score_to_severity(10.1)
        with pytest.raises(ValueError, match="out of CVSS range"):
            score_to_severity(-0.1)
