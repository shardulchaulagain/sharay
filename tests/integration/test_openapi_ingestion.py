"""OpenAPI ingestion: declared facts only, hostile documents bounded, nothing secret echoed."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packages.scanner_adapters.integrations.openapi import ingest

ROOT = Path(__file__).resolve().parents[2]
SECRET = "synthetic-secret-value"
DOCUMENT = {
    "openapi": "3.0.3",
    "info": {"title": "Synthetic API", "version": "1", "description": f"internal token {SECRET}"},
    "servers": [
        {"url": f"https://user:{SECRET}@api.example.invalid/v1?key={SECRET}"},
        {"url": "http://legacy.example.invalid"},
        {"url": "/relative"},
        {"url": "https://{tenant}.example.invalid"},
    ],
    "security": [{"bearer": []}],
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
            "legacyKey": {"type": "apiKey", "in": "query", "name": "api_key"},
            "basic": {"type": "http", "scheme": "Basic"},
            "broken": "not an object",
        },
        "parameters": {
            "Page": {"name": "page", "in": "query"},
            "Loop": {"$ref": "#/components/parameters/Loop"},
        },
    },
    "paths": {
        "/users/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True},
                {"$ref": "#/components/parameters/Page"},
            ],
            "get": {"operationId": "getUser", "description": f"example password {SECRET}"},
            "delete": {"security": [], "deprecated": True},
            "put": {"security": [{"bearer": []}, {}], "requestBody": {"content": {}}},
        },
        "/reports": {
            "get": {
                "security": [{"legacyKey": []}],
                "parameters": [
                    {"name": "page", "in": "query", "required": True},
                    {"$ref": "https://evil.example.invalid/params.json#/x"},
                    {"$ref": "#/components/parameters/Loop"},
                    {"name": "bad", "in": "body"},
                ],
            },
            "post": {"security": [{"basic": []}, {"missing": []}]},
            "patch": "not an object",
            "head": {"security": "not a list"},
        },
        "no-leading-slash": {"get": {}},
        "/external": {"$ref": "other.json#/paths/x"},
    },
}


class OpenApiIngestionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name).resolve()

    def write(self, document, name="api.json") -> Path:
        path = self.folder / name
        path.write_text(document if isinstance(document, str) else json.dumps(document))
        return path

    def test_endpoints_carry_their_effective_declared_authentication(self):
        result = ingest(self.write(DOCUMENT))
        self.assertIn("not verified", result["basis"])
        self.assertEqual(result["version"], "3.0.3")
        endpoints = {(e["method"], e["path"]): e for e in result["endpoints"]}
        self.assertEqual(
            {key: (e["authentication"], e["security_schemes"]) for key, e in endpoints.items()},
            {
                # Inherits the document default.
                ("GET", "/users/{id}"): ("required", ["bearer"]),
                # An explicit empty list switches authentication off for this operation.
                ("DELETE", "/users/{id}"): ("none", []),
                # An empty alternative makes authentication optional.
                ("PUT", "/users/{id}"): ("optional", ["bearer"]),
                ("GET", "/reports"): ("required", ["legacyKey"]),
                ("POST", "/reports"): ("required", ["basic", "missing"]),
                # A malformed requirement is neither the default nor "declares none".
                ("HEAD", "/reports"): ("unknown", []),
            },
        )
        user = endpoints[("GET", "/users/{id}")]
        self.assertEqual(
            (user["operation_id"], user["request_body"], user["deprecated"]), ("getUser", False, False)
        )
        self.assertEqual(
            user["parameters"],
            [
                {"name": "id", "in": "path", "required": True},
                {"name": "page", "in": "query", "required": False},
            ],
        )
        self.assertTrue(endpoints[("DELETE", "/users/{id}")]["deprecated"])
        self.assertTrue(endpoints[("PUT", "/users/{id}")]["request_body"])
        # The operation's own parameter overrides the shared one of the same name and place.
        self.assertEqual(
            endpoints[("GET", "/reports")]["parameters"], [{"name": "page", "in": "query", "required": True}]
        )

    def test_observations_are_declared_facts_tied_to_an_operation(self):
        result = ingest(self.write(DOCUMENT))
        observed = {
            (o["check"], o.get("method"), o.get("path"), o.get("scheme") or o.get("host"))
            for o in result["observations"]
        }
        self.assertEqual(
            observed,
            {
                ("server_declared_over_plain_http", None, None, "legacy.example.invalid"),
                ("operation_declares_no_authentication", "DELETE", "/users/{id}", None),
                ("operation_declares_optional_authentication", "PUT", "/users/{id}", None),
                ("api_key_declared_in_query_string", "GET", "/reports", "legacyKey"),
                ("http_basic_authentication_declared", "POST", "/reports", "basic"),
                ("operation_references_undefined_security_scheme", "POST", "/reports", "missing"),
            },
        )
        self.assertEqual(
            result["security_schemes"],
            [
                {"name": "bearer", "type": "http", "scheme": "bearer"},
                {"name": "legacyKey", "type": "apikey", "in": "query"},
                {"name": "basic", "type": "http", "scheme": "basic"},
            ],
        )

    def test_secrets_urls_and_free_text_never_reach_the_output(self):
        result = ingest(self.write(DOCUMENT))
        text = json.dumps(result)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("password", text)
        # Scheme and host only: no credentials, path or query string.
        self.assertEqual(
            result["servers"],
            [
                {"scheme": "https", "host": "api.example.invalid"},
                {"scheme": "http", "host": "legacy.example.invalid"},
            ],
        )

    def test_what_is_not_understood_is_listed_not_guessed(self):
        reasons = [(item["item"], item["reason"]) for item in ingest(self.write(DOCUMENT))["unresolved"]]
        self.assertEqual(
            sorted(reasons),
            sorted(
                [
                    ("server", "server URL is relative, templated or not HTTP(S)"),
                    ("server", "server URL is relative, templated or not HTTP(S)"),
                    ("broken", "security scheme is not an object with a type"),
                    # External, self-referencing and malformed parameters are not followed or invented.
                    ("GET /reports", "a parameter is malformed or not a local reference"),
                    ("GET /reports", "a parameter is malformed or not a local reference"),
                    ("GET /reports", "a parameter is malformed or not a local reference"),
                    ("PATCH /reports", "operation is not an object"),
                    ("HEAD /reports", "security requirement is malformed"),
                    ("path", "path is not a plain /template with an object, or its reference was not local"),
                    ("path", "path is not a plain /template with an object, or its reference was not local"),
                ]
            ),
        )

    def test_a_secret_in_a_path_key_is_never_echoed(self):
        document = {
            "openapi": "3.0.3",
            "paths": {
                f"/a?token={SECRET}": "not an object",
                f"/b?key={SECRET}": {"get": {}},
                f"/c#{SECRET}": {"get": {}},
            },
        }
        result = ingest(self.write(document, "keys.json"))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual((result["endpoints"], len(result["unresolved"])), ([], 3))

    def test_unsupported_and_hostile_documents_yield_no_endpoints(self):
        unsupported = "only OpenAPI 3.0 and 3.1 JSON documents are supported"
        unreadable = "could not be read or parsed as JSON"
        for label, document, reason in (
            ("swagger 2", {"swagger": "2.0", "paths": {"/a": {"get": {}}}}, unsupported),
            ("openapi 4", {"openapi": "4.0.0", "paths": {"/a": {"get": {}}}}, unsupported),
            ("version not text", {"openapi": 3.0, "paths": {"/a": {"get": {}}}}, unsupported),
            ("not an object", [1, 2, 3], unsupported),
            ("yaml", "openapi: 3.0.3\npaths: {}\n", unreadable),
            ("deep nesting", "[" * 100000, None),
            ("binary", "\udcff".encode("utf-8", "surrogateescape").decode("latin-1") + "\x00", unreadable),
        ):
            with self.subTest(label):
                result = ingest(self.write(document, f"{label.replace(' ', '-')}.json"))
                self.assertEqual((result["endpoints"], result["observations"]), ([], []))
                self.assertEqual(len(result["unresolved"]), 1)
                if reason:
                    self.assertEqual(result["unresolved"][0]["reason"], reason)
        missing = ingest(self.folder / "absent.json")
        self.assertEqual(missing["unresolved"][0]["reason"], unreadable)
        # Wrong shapes inside an otherwise valid document are skipped without raising.
        odd = {
            "openapi": "3.1.0",
            "servers": "x",
            "components": [],
            "security": {},
            "paths": {"/a": {"get": {"parameters": "x"}}},
        }
        result = ingest(self.write(odd, "odd.json"))
        self.assertEqual([(e["method"], e["authentication"]) for e in result["endpoints"]], [("GET", "none")])

    def test_a_fifo_or_oversized_document_is_refused_without_waiting(self):
        os.mkfifo(self.folder / "pipe.json")
        code = (
            "import json, sys\n"
            "from packages.scanner_adapters.integrations.openapi import ingest\n"
            "print(json.dumps(ingest(sys.argv[1])['unresolved']))\n"
        )
        child = subprocess.run(
            [sys.executable, "-c", code, str(self.folder / "pipe.json")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)[0]["reason"], "document is not a regular file")
        big = self.write(json.dumps({"openapi": "3.0.3", "x": "a" * (5 * 1024 * 1024)}), "big.json")
        self.assertEqual(ingest(big)["unresolved"][0]["reason"], "document is larger than the parsing budget")


if __name__ == "__main__":
    unittest.main()
