"""Acceptance tests for Context-Free Payload Forge & AST WAF Mutation Engine (E1–E5)."""

import unittest

from packages.scanner_adapters.integrations.payload_forge import (
    CFGPayloadGenerator,
    DeterministicPayloadForge,
    mutate_ast,
)


class PayloadForgeAcceptanceTests(unittest.TestCase):
    def test_cfg_grammar_generates_distinct_sqli_vectors(self):
        generator = CFGPayloadGenerator(seed=1337)
        vectors = generator.generate_sqli(count=50)

        # Assert at least 50 distinct vectors generated
        self.assertGreaterEqual(len(set(vectors)), 50)

        # Assert vectors contain core SQLi syntax elements
        self.assertTrue(any("UNION" in v or "union" in v.lower() for v in vectors))
        self.assertTrue(any("SELECT" in v or "select" in v.lower() for v in vectors))
        self.assertTrue(any("SLEEP" in v or "BENCHMARK" in v or "WAITFOR" in v for v in vectors))

    def test_ast_mutation_transforms_union_select(self):
        base_payload = "UNION SELECT 1, 2, 3"
        mutations = mutate_ast(base_payload, count=15, seed=42)

        # Assert at least 10 distinct equivalent obfuscations generated
        distinct = set(mutations)
        self.assertGreaterEqual(len(distinct), 10)

        # Assert presence of comment splicing, case alternation, whitespace substitutions
        has_comment_splicing = any("/*" in m and "*/" in m for m in distinct)
        has_case_variation = any(m != base_payload and m.upper() == base_payload.upper() for m in distinct)
        has_whitespace_sub = any("%20" in m or "+" in m or "/**/" in m for m in distinct)

        self.assertTrue(has_comment_splicing, "Expected comment-spliced mutation")
        self.assertTrue(has_case_variation, "Expected case-varied mutation")
        self.assertTrue(has_whitespace_sub, "Expected whitespace-substituted mutation")

    def test_waf_fingerprint_selects_targeted_transforms(self):
        forge = DeterministicPayloadForge()

        # Cloudflare profile
        cf_profile = forge.get_transform_profile("Cloudflare")
        self.assertEqual(cf_profile.vendor, "Cloudflare")
        cf_payloads = cf_profile.transform("1 UNION SELECT null, null--")
        self.assertGreater(len(cf_payloads), 0)
        self.assertTrue(any("/*!" in p or "%00" in p or "/**/" in p for p in cf_payloads))

        # AWS WAF profile
        aws_profile = forge.get_transform_profile("AWS WAF")
        self.assertEqual(aws_profile.vendor, "AWS WAF")
        aws_payloads = aws_profile.transform("cat /etc/passwd")
        self.assertGreater(len(aws_payloads), 0)
        self.assertTrue(any("$" in p or "{" in p or "%2f" in p.lower() for p in aws_payloads))

        # ModSecurity profile
        modsec_profile = forge.get_transform_profile("ModSecurity")
        self.assertEqual(modsec_profile.vendor, "ModSecurity")

    def test_deterministic_prng_seed_reproducibility(self):
        forge1 = DeterministicPayloadForge(seed=98765)
        forge2 = DeterministicPayloadForge(seed=98765)
        forge3 = DeterministicPayloadForge(seed=12345)

        seq1 = forge1.generate_fuzzing_sequence(vuln_type="sqli", count=40)
        seq2 = forge2.generate_fuzzing_sequence(vuln_type="sqli", count=40)
        seq3 = forge3.generate_fuzzing_sequence(vuln_type="sqli", count=40)

        # Identical seeds must produce 100% byte-identical lists
        self.assertEqual(seq1, seq2)

        # Different seed must produce different ordering or mutations
        self.assertNotEqual(seq1, seq3)


if __name__ == "__main__":
    unittest.main()
