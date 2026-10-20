"""Continuous Parser Fuzzing Engine & Negative Robustness Harness.

Sector 10: Testing, Benchmarks & QA (Milestone P1.10).
Provides:
1. Mutational and grammar-based fuzz input generation for:
   - HTTP response headers (multiline folded, null bytes, oversized, RFC non-compliant).
   - Scope URLs (authority spoofing, hex/octal IPs, unicode homographs, port overflows).
   - XML payloads (Billion laughs, recursive entities, unclosed CDATA).
   - JSONL records (corrupt UTF-8, depth overflow, infinite floats).
2. Fail-closed parser wrappers guaranteeing graceful error handling without unhandled crashes.
"""

from __future__ import annotations

import json
import random
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FuzzResult:
    category: str
    total_mutations: int
    handled_cleanly: int
    crashes: int
    crash_samples: List[Tuple[Any, str]]


class ParserFuzzerEngine:
    """Generates aggressive adversarial and malformed inputs to stress SHARAY parsers."""

    @classmethod
    def generate_http_header_mutations(cls, count: int = 150) -> List[str]:
        mutations: List[str] = []
        for _ in range(count):
            choice = random.choice(
                [
                    # Null byte injection
                    "Content-Type: text/html\x00; charset=utf-8\r\n",
                    # Folded header (RFC obsolete)
                    "X-Custom-Header: value\r\n continuation-line\r\n",
                    # Giant header (10KB)
                    "X-Oversized: " + ("A" * 10240) + "\r\n",
                    # Missing colon
                    "BadHeaderNoColonValueHere\r\n",
                    # Multiline injection
                    "Header1: val\r\n\r\nHTTP/1.1 200 OK\r\nInjected: true\r\n",
                    # Control characters
                    "X-Ctrl: \x01\x02\x03\x1f\x7f\r\n",
                    # Unicode surrogate pair
                    "X-Unicode: \ud800\udc00\r\n",
                    # Empty header name
                    ": empty-name-val\r\n",
                    # Unicode RTL overrides
                    "X-Spoof: \u202eadmin\u202c\r\n",
                ]
            )
            mutations.append(choice)
        return mutations

    @classmethod
    def generate_scope_url_mutations(cls, count: int = 150) -> List[str]:
        mutations: List[str] = [
            # Authority spoofing / userinfo bypass
            "https://trusted.corp@attacker.com/path",
            "https://attacker.com#@trusted.corp",
            "https://trusted.corp:secret@127.0.0.1:8080",
            # IP representations
            "http://0177.0.0.1/",  # Octal
            "http://0x7f000001/",  # Hex
            "http://2130706433/",  # Dword integer
            "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6
            "http://[fe80::1%25eth0]:8080/",  # IPv6 scope-id percent encoded
            # Port boundary overflows
            "https://target.local:65536/",
            "https://target.local:999999/",
            "https://target.local:-1/",
            "https://target.local:0/",
            # Protocol relative & non-standard schemes
            "//target.local/path",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            # Hostname homoglyphs / IDN
            "https://t\u0430rget.corp/login",  # Cyrillic 'а'
            "https://target.corp\x00.evil.com",
            # Trailing dots and spaces
            "https://target.corp./",
            "https://target.corp   /index",
        ]
        while len(mutations) < count:
            base = "https://target.corp/" + "".join(
                random.choices(["%00", "%20", "%0d%0a", "%ff", "../", "..\\", "??", "##"], k=4)
            )
            mutations.append(base)
        return mutations

    @classmethod
    def generate_xml_mutations(cls, count: int = 50) -> List[str]:
        mutations: List[str] = [
            # Billion laughs entity bomb
            """<?xml version="1.0"?>
            <!DOCTYPE lolz [
             <!ENTITY lol "lol">
             <!ELEMENT lolz (#PCDATA)>
             <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
             <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
            ]>
            <lolz>&lol2;</lolz>""",
            # External entity reference
            """<?xml version="1.0"?>
            <!DOCTYPE data [
             <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <data>&xxe;</data>""",
            # Unclosed CDATA
            "<root><![CDATA[Unclosed content",
            # Unbalanced tags
            "<root><nested>Text</root>",
            # Nested tags exceeding reasonable depth
            ("<a>" * 500) + "deep" + ("</a>" * 500),
            # Null bytes in XML
            "<root>\x00<child>val</child></root>",
        ]
        while len(mutations) < count:
            mutations.append(f"<root>{random.choice(['<unclosed>', '<!ENTITY>', '<<<>>>'])}</root>")
        return mutations

    @classmethod
    def generate_jsonl_mutations(cls, count: int = 100) -> List[str]:
        mutations: List[str] = [
            '{"key": "value"}\n',
            '{"unclosed": "string\n',
            '{"nan": NaN, "inf": Infinity}\n',
            '{"nested": ' + ('{"a": ' * 200) + "1" + ("}" * 200) + "}\n",
            '{"key\x00null": "val"}\n',
            '{"unicode_surrogate": "\ud83d"}\n',
            '{"number_overflow": 1e99999999999999999999999999999999999}\n',
            "not a json line at all\n",
            '{"valid": true}\r\n{"corrupt": \x00}\n',
        ]
        while len(mutations) < count:
            mutations.append(
                json.dumps({"fuzz": "".join(chr(random.randint(0, 255)) for _ in range(20))}) + "\n"
            )
        return mutations


class SafeParserHarness:
    """Executes parser stress tests and certifies fail-closed negative robustness."""

    @staticmethod
    def parse_http_header_safe(raw_header_line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Parses an HTTP header line safely; returns (valid, name, value)."""
        try:
            if len(raw_header_line) > 8192:
                return False, None, None
            if "\0" in raw_header_line:
                return False, None, None
            if ":" not in raw_header_line:
                return False, None, None
            name, val = raw_header_line.split(":", 1)
            name = name.strip()
            val = val.strip()
            if not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
                return False, None, None
            return True, name, val
        except Exception:
            return False, None, None

    @staticmethod
    def parse_scope_url_safe(url_str: str, allowed_host: str = "target.corp") -> Tuple[bool, Optional[str]]:
        """Validates and parses a target URL under scope policy, rejecting spoofing."""
        try:
            parsed = urllib.parse.urlsplit(url_str.strip())
            if parsed.scheme.lower() not in {"http", "https"}:
                return False, None
            hostname = parsed.hostname
            if not hostname:
                return False, None

            if "@" in parsed.netloc:
                return False, None

            if parsed.port is not None and not (1 <= parsed.port <= 65535):
                return False, None

            clean_host = hostname.rstrip(".").lower()
            if clean_host != allowed_host.lower():
                return False, None

            return True, clean_host
        except Exception:
            return False, None

    @staticmethod
    def parse_xml_safe(xml_text: str) -> Tuple[bool, Optional[ET.Element]]:
        """Defensively parses XML, disabling external entities and entity expansion."""
        try:
            if "<!ENTITY" in xml_text or "<!DOCTYPE" in xml_text:
                return False, None
            if "\0" in xml_text:
                return False, None
            parser = ET.XMLParser()
            root = ET.fromstring(xml_text, parser=parser)
            return True, root
        except Exception:
            return False, None

    @staticmethod
    def parse_jsonl_safe(line: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Safely parses JSONL records without crashing on NaN or surrogate errors."""
        try:
            clean = line.strip()
            if not clean:
                return False, None
            data = json.loads(clean)
            if not isinstance(data, dict):
                return False, None
            return True, data
        except Exception:
            return False, None
