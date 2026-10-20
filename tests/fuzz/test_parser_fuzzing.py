"""Continuous Parser Fuzzing Test Suite (Sector 10: Testing, Benchmarks & QA).

Executes hundreds of malformed inputs across HTTP headers, Scope URLs, XML, and JSONL
to certify 100% crash resistance and strict fail-closed rejection.
"""

from __future__ import annotations

from packages.parser_fuzzer import (
    ParserFuzzerEngine,
    SafeParserHarness,
)


def test_http_header_parser_fuzzing():
    """Fuzz HTTP header parsing with 150 mutated seeds."""
    mutations = ParserFuzzerEngine.generate_http_header_mutations(count=150)
    crashes = 0
    handled = 0

    for m in mutations:
        try:
            valid, name, val = SafeParserHarness.parse_http_header_safe(m)
            handled += 1
        except Exception:
            crashes += 1
            continue

        if "\x00" in m or "BadHeaderNoColon" in m or len(m) > 8192:
            # Must be rejected fail-closed
            assert valid is False

    assert crashes == 0, f"Parser crashed on {crashes} inputs!"
    assert handled == 150


def test_scope_url_parser_fuzzing():
    """Fuzz scope URL parsing with 150 adversarial URL mutations."""
    mutations = ParserFuzzerEngine.generate_scope_url_mutations(count=150)
    crashes = 0
    handled = 0

    for m in mutations:
        try:
            valid, host = SafeParserHarness.parse_scope_url_safe(m, allowed_host="target.corp")
            handled += 1
            # Authority spoofing must be rejected
            if "@" in m or ":65536" in m or "javascript:" in m or "file://" in m:
                assert valid is False
        except Exception:
            crashes += 1

    assert crashes == 0, f"Scope URL parser crashed on {crashes} inputs!"
    assert handled == 150


def test_xml_parser_fuzzing_and_entity_bombs():
    """Fuzz XML parser with Billion Laughs and XXE entity expansions."""
    mutations = ParserFuzzerEngine.generate_xml_mutations(count=50)
    crashes = 0
    handled = 0

    for m in mutations:
        try:
            valid, tree = SafeParserHarness.parse_xml_safe(m)
            handled += 1
            # Billion laughs & XXE must be rejected
            if "<!ENTITY" in m or "<!DOCTYPE" in m or "\x00" in m:
                assert valid is False
        except Exception:
            crashes += 1

    assert crashes == 0, f"XML parser crashed on {crashes} inputs!"
    assert handled == 50


def test_jsonl_parser_fuzzing():
    """Fuzz JSONL parser with deep recursion, NaN, and corrupt lines."""
    mutations = ParserFuzzerEngine.generate_jsonl_mutations(count=100)
    crashes = 0
    handled = 0

    for m in mutations:
        try:
            valid, record = SafeParserHarness.parse_jsonl_safe(m)
            handled += 1
        except Exception:
            crashes += 1

    assert crashes == 0, f"JSONL parser crashed on {crashes} inputs!"
    assert handled == 100
