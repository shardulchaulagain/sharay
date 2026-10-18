"""Acceptance tests for Route Discovery, Schema Ingestion, and Schema Coverage (B4)."""

import json
import unittest
from unittest.mock import patch

from packages.scanner_adapters.integrations.crawler import (
    crawl,
    parse_graphql_introspection,
    parse_openapi_spec,
    parse_wsdl,
)
from packages.security_policies import Destination


class SchemaIngestionAcceptanceTests(unittest.TestCase):
    def test_parse_openapi_spec_extracts_routes_and_params(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/users": {
                    "get": {"parameters": [{"name": "limit", "in": "query"}]},
                    "post": {},
                },
                "/api/v1/users/{userId}": {
                    "get": {},
                    "delete": {},
                },
                "/api/v1/billing/invoices": {
                    "get": {},
                },
            },
        }
        endpoints, params = parse_openapi_spec(json.dumps(spec))
        self.assertEqual(len(endpoints), 3)
        self.assertIn("/api/v1/users", endpoints)
        self.assertIn("/api/v1/users/{userId}", endpoints)
        self.assertIn("/api/v1/billing/invoices", endpoints)
        self.assertIn("limit", params)

    def test_parse_graphql_introspection_extracts_operations(self):
        introspection = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "Query",
                            "fields": [
                                {"name": "currentUser"},
                                {"name": "getInvoice"},
                            ],
                        },
                        {
                            "name": "Mutation",
                            "fields": [
                                {"name": "updateProfile"},
                                {"name": "deleteAccount"},
                            ],
                        },
                    ]
                }
            }
        }
        endpoints, operations = parse_graphql_introspection(
            json.dumps(introspection), base_endpoint="/graphql"
        )
        self.assertIn("/graphql?query={currentUser}", endpoints)
        self.assertIn("/graphql?query={getInvoice}", endpoints)
        self.assertIn("updateProfile", operations)
        self.assertIn("deleteAccount", operations)

    def test_parse_wsdl_extracts_soap_operations(self):
        wsdl_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/" name="PaymentService">
            <portType name="PaymentPort">
                <operation name="ProcessPayment"/>
                <operation name="RefundTransaction"/>
                <operation name="QueryStatus"/>
            </portType>
        </definitions>
        """
        endpoints, operations = parse_wsdl(wsdl_xml, base_url="/soap")
        self.assertEqual(len(operations), 3)
        self.assertIn("ProcessPayment", operations)
        self.assertIn("RefundTransaction", operations)
        self.assertIn("QueryStatus", operations)
        self.assertIn("/soap#ProcessPayment", endpoints)

    @patch("packages.scanner_adapters.integrations.crawler._fetch_page")
    def test_crawl_computes_schema_vs_spider_coverage(self, mock_fetch):
        # Mock responses:
        # /robots.txt -> 404
        # /sitemap.xml -> 404
        # Sensitive files -> 404
        # /openapi.json -> 200 with 3 endpoints
        # / -> 200 with HTML linking to 2 of the 3 endpoints
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {
                    "/api/v1/covered1": {"get": {}},
                    "/api/v1/covered2": {"get": {}},
                    "/api/v1/uncovered_orphan": {"get": {}},
                },
            }
        )

        html_root = """
        <html><body>
            <a href="/api/v1/covered1">Covered 1</a>
            <a href="/api/v1/covered2">Covered 2</a>
        </body></html>
        """

        def mock_fetch_handler(url, *args, **kwargs):
            if "openapi.json" in url:
                return (200, {"content-type": "application/json"}, spec)
            elif url.rstrip("/") == "http://example.com":
                return (200, {"content-type": "text/html"}, html_root)
            elif "covered" in url:
                return (200, {"content-type": "text/html"}, "<html>Covered</html>")
            return (404, {}, "")

        mock_fetch.side_effect = mock_fetch_handler

        destination = Destination(
            url="http://example.com/",
            scheme="http",
            host="example.com",
            port=80,
            path="/",
            origin="http://example.com",
            ip="93.184.216.34",
        )
        crawl_result = crawl(destination, "93.184.216.34", max_depth=2, max_pages=10)

        schema_cov = crawl_result.get("schema_coverage", {})
        self.assertEqual(schema_cov.get("declared_count"), 3)
        self.assertGreaterEqual(schema_cov.get("covered_count", 0), 2)
        self.assertIn("/api/v1/uncovered_orphan", schema_cov.get("uncovered", []))
        self.assertGreaterEqual(schema_cov.get("coverage_ratio", 0), 0.6)


if __name__ == "__main__":
    unittest.main()
