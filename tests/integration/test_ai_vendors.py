"""Built-in AI vendor adapters: request shape, response extraction, and credential handling.

Mostly no network: the transport (_http_post) is replaced with canned vendor responses, so these
tests prove the adapter builds the right request and reads the right field without ever calling
out. The redirect test is the exception: it drives the real transport against a loopback server
to prove a 3xx never resends the credential.
"""

import http.server
import json
import os
import socketserver
import threading
import unittest
from unittest.mock import patch

from services.ai_analysis_worker import AIUnavailable
from services.ai_analysis_worker.providers import REGISTRY, build, parse_config
from services.ai_analysis_worker.vendors import _render

KEY = "test-" + "A1b2C3d4" * 4  # token-shaped; assembled so a secret scanner does not flag this file
KEY_ENV = "SHARAY_TEST_AI_KEY"

CANNED = {
    "anthropic": {"content": [{"type": "text", "text": "PLAN"}]},
    "openai": {"choices": [{"message": {"content": "PLAN"}}]},
    "google": {"candidates": [{"content": {"parts": [{"text": "PLAN"}]}}]},
}
KEY_HEADER = {"anthropic": "x-api-key", "openai": "authorization", "google": "x-goog-api-key"}


def _config(provider):
    return parse_config(
        {
            "provider": provider,
            "model": "model-x",
            "api_key_env": KEY_ENV,
            "share_assessment_data": True,
        }
    )


class VendorAdapterTests(unittest.TestCase):
    def test_the_three_approved_providers_register_on_import(self):
        self.assertLessEqual({"anthropic", "openai", "google"}, set(REGISTRY))
        self.assertIn("none", REGISTRY)

    def test_each_adapter_sends_the_key_in_a_header_not_the_url_and_reads_its_response(self):
        for provider, document in CANNED.items():
            sent = {}

            def capture(url, headers, payload, timeout, _doc=document):
                sent.update(url=url, headers=headers, payload=payload, timeout=timeout)
                return json.dumps(_doc).encode()

            with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
                with patch("services.ai_analysis_worker.vendors._http_post", capture):
                    result = build(_config(provider)).propose(
                        {"instructions": "RULES", "objective": "find it", "evidence": ['{"a":1}']}
                    )
            self.assertEqual(result, b"PLAN", provider)
            # The credential rides in the documented header and never in the URL.
            self.assertEqual(sent["headers"][KEY_HEADER[provider]].endswith(KEY), True, provider)
            self.assertNotIn(KEY, sent["url"], provider)
            # Body is valid JSON carrying the configured model, and evidence stays out of the URL.
            body = json.loads(sent["payload"])
            self.assertIn("model-x", json.dumps(body) + sent["url"], provider)
            self.assertNotIn("find it", sent["url"], provider)

    def test_missing_credential_fails_before_any_call(self):
        calls = []
        with patch.dict(os.environ, {}, clear=True):
            with patch("services.ai_analysis_worker.vendors._http_post", lambda *a: calls.append(a)):
                with self.assertRaises(AIUnavailable):
                    build(_config("openai")).propose({"instructions": "", "objective": "", "evidence": []})
        self.assertEqual(calls, [])

    def test_a_response_without_text_is_unavailable_not_a_crash(self):
        with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
            with patch("services.ai_analysis_worker.vendors._http_post", lambda *a: b"{}"):
                for provider in CANNED:
                    with self.assertRaises(AIUnavailable, msg=provider):
                        build(_config(provider)).propose(
                            {"instructions": "", "objective": "", "evidence": []}
                        )

    def test_sending_assessment_data_is_off_unless_switched_on(self):
        config = parse_config({"provider": "openai", "model": "model-x", "api_key_env": KEY_ENV})
        with self.assertRaises(AIUnavailable):
            build(config)

    def test_a_non_json_response_is_unavailable_not_a_crash(self):
        with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
            with patch("services.ai_analysis_worker.vendors._http_post", lambda *a: b"<html>oops</html>"):
                with self.assertRaises(AIUnavailable):
                    build(_config("openai")).propose({"instructions": "", "objective": "", "evidence": []})

    def test_a_deeply_nested_response_is_unavailable_not_a_recursionerror(self):
        deep = b"[" * 20000 + b"]" * 20000
        with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
            with patch("services.ai_analysis_worker.vendors._http_post", lambda *a: deep):
                with self.assertRaises(AIUnavailable):
                    build(_config("openai")).propose({"instructions": "", "objective": "", "evidence": []})

    def test_a_redirect_never_resends_the_credential(self):
        # Regression: urllib follows 3xx by default and resends auth headers to the new host, leaking
        # the key. The adapter must refuse the redirect instead. This drives the real transport.
        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()

            def do_GET(self):
                seen["authorization"] = self.headers.get("authorization")
                self.send_response(200)
                self.end_headers()

        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = parse_config(
                {
                    "provider": "openai",
                    "model": "model-x",
                    "api_key_env": KEY_ENV,
                    "share_assessment_data": True,
                    "base_url": f"http://127.0.0.1:{port}",
                }
            )
            with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
                with self.assertRaises(AIUnavailable):
                    build(config).propose({"instructions": "", "objective": "o", "evidence": []})
        finally:
            server.shutdown()
            server.server_close()
        self.assertIsNone(seen.get("authorization"))  # the redirect target was never reached with the key

    def test_a_slash_in_a_google_model_cannot_traverse_the_url_path(self):
        # Slashes are legitimate in some model ids, so they are encoded, not rejected: the model
        # must stay a single path segment and never reach another endpoint.
        from services.ai_analysis_worker.vendors import _VENDORS

        config = parse_config(
            {
                "provider": "google",
                "model": "x/../v1/evil",
                "api_key_env": KEY_ENV,
                "share_assessment_data": True,
            }
        )
        url = _VENDORS["google"].url(config)
        self.assertIn("/v1beta/models/", url)
        self.assertNotIn("/../", url)
        self.assertTrue(url.endswith(":generateContent"))

    def test_an_over_budget_response_is_rejected_not_truncated(self):
        # Hermetic: mock the opener's response so no real socket is bound (a proxy in the env would
        # otherwise hijack even a loopback request). A body past the cap must raise, not truncate.
        from unittest.mock import MagicMock

        from services.ai_analysis_worker import vendors

        response = MagicMock()
        response.__enter__.return_value = response
        response.read.side_effect = lambda n: (b"x" * 50)[:n]
        with patch.object(vendors, "MAX_RESPONSE_BYTES", 10):
            with patch.object(vendors._OPENER, "open", return_value=response):
                with self.assertRaises(ValueError):
                    vendors._http_post("https://api.example.com/v1/chat", {}, b"{}", 5)

    def test_the_tls_context_verifies_certificates(self):
        import ssl

        from services.ai_analysis_worker.vendors import _tls_context

        ctx = _tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_the_actual_opener_uses_a_verifying_https_context(self):
        # Not just the factory: the opener that really sends requests must carry a verifying context,
        # so a swapped-in CERT_NONE context on _OPENER is caught here.
        import ssl
        import urllib.request

        from services.ai_analysis_worker import vendors

        https = [h for h in vendors._OPENER.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertTrue(https, "the opener must have an HTTPS handler")
        ctx = https[0]._context
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_render_keeps_instructions_apart_from_untrusted_evidence(self):
        system, user = _render({"instructions": "RULES", "objective": "obj", "evidence": ["E1", "E2"]})
        self.assertEqual(system, "RULES")
        self.assertNotIn("RULES", user)
        self.assertIn("E1", user)
        self.assertIn("E2", user)


if __name__ == "__main__":
    unittest.main()


class LoneSurrogateResponseTest(unittest.TestCase):
    def test_lone_surrogate_in_response_text_is_unavailable_not_unicodeerror(self):
        # valid JSON whose decoded text holds a lone surrogate (\ud800) that cannot UTF-8 encode
        raw = b'{"candidates":[{"content":{"parts":[{"text":"\\ud800"}]}}]}'
        with patch.dict(os.environ, {KEY_ENV: KEY}, clear=False):
            with patch("services.ai_analysis_worker.vendors._http_post", lambda *a: raw):
                with self.assertRaises(AIUnavailable):
                    build(_config("google")).propose({"instructions": "", "objective": "", "evidence": []})
