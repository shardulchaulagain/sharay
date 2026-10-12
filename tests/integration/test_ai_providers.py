"""Switchable AI providers: chosen by configuration, off by default, never holding a credential."""

import unittest

from services.ai_analysis_worker import AIUnavailable, NoProvider, providers
from services.ai_analysis_worker.providers import (
    REGISTRY,
    ProviderConfig,
    build,
    config_from_environment,
    parse_config,
    register,
    secret,
)

KEY = "sk-" + "ant-api03-" + "A1b2C3d4" * 8  # credential-shaped, assembled so no scanner reports this file
ON = {"provider": "scripted", "model": "model-a", "share_assessment_data": True}


class Scripted:
    def __init__(self, config):
        self.name, self.config = config.provider, config

    def propose(self, prompt):
        return self.config.model.encode()


class SwitchTests(unittest.TestCase):
    def setUp(self):
        register("scripted", Scripted)
        self.addCleanup(REGISTRY.pop, "scripted", None)

    def test_nothing_configured_means_no_provider_and_a_clear_refusal(self):
        for config in (ProviderConfig(), config_from_environment({}), parse_config({})):
            provider = build(config)
            self.assertIsInstance(provider, NoProvider)
            with self.assertRaisesRegex(AIUnavailable, "No AI provider is configured"):
                provider.propose({})

    def test_provider_and_model_change_by_configuration_alone(self):
        register("other", Scripted)
        self.addCleanup(REGISTRY.pop, "other", None)
        seen = set()
        for name, model in (("scripted", "model-a"), ("scripted", "model-b"), ("other", "vendor/model:1")):
            environment = {
                "SHARAY_AI_PROVIDER": name,
                "SHARAY_AI_MODEL": model,
                "SHARAY_AI_SHARE_DATA": "true",
            }
            provider = build(config_from_environment(environment))
            seen.add((provider.name, provider.propose({})))
        self.assertEqual(
            seen, {("scripted", b"model-a"), ("scripted", b"model-b"), ("other", b"vendor/model:1")}
        )

    def test_assessment_data_goes_nowhere_until_sharing_is_switched_on(self):
        for value in ("", "false", "1", "yes", "True", "TRUE", " true"):
            environment = {
                "SHARAY_AI_PROVIDER": "scripted",
                "SHARAY_AI_MODEL": "m",
                "SHARAY_AI_SHARE_DATA": value,
            }
            with self.subTest(value=value), self.assertRaisesRegex(AIUnavailable, "has not been switched on"):
                build(config_from_environment(environment))
        with self.assertRaisesRegex(AIUnavailable, "not valid"):
            parse_config(ON | {"share_assessment_data": "true"})  # a string is not a decision

    def test_an_unknown_provider_is_unavailable_not_a_fallback(self):
        with self.assertRaisesRegex(AIUnavailable, "no adapter installed"):
            build(parse_config(ON | {"provider": "missing"}))

    def test_none_cannot_be_replaced_and_names_are_plain(self):
        for name in ("none", "Scripted", "a b", "", "x" * 33, "../x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                register(name, Scripted)
        self.assertIsInstance(REGISTRY["none"](ProviderConfig()), NoProvider)


class ConfigurationTests(unittest.TestCase):
    def test_malformed_configuration_is_refused_without_echoing_it(self):
        cases = {
            "provider without a model": {"provider": "scripted"},
            "unknown key": ON | {"api_key": KEY},
            "key pasted where the variable name goes": ON | {"api_key_env": KEY},
            "key pasted as the model": ON | {"model": KEY},
            "model with a space": ON | {"model": "model a"},
            "plain http to a remote host": ON | {"base_url": "http://example.test/v1"},
            "credentials in the base URL": ON | {"base_url": f"https://user:{KEY}@example.test"},
            "password-only credentials": ON | {"base_url": f"https://:{KEY}@example.test"},
            "query in the base URL": ON | {"base_url": f"https://example.test/?key={KEY}"},
            "fragment in the base URL": ON | {"base_url": f"https://example.test/#{KEY}"},
            "not a URL": ON | {"base_url": "example.test"},
            "broken IPv6": ON | {"base_url": "https://[::1"},
            "timeout as text": ON | {"timeout_seconds": "60"},
            "timeout as a boolean": ON | {"timeout_seconds": True},
            "timeout too long": ON | {"timeout_seconds": 301},
            "token budget of zero": ON | {"max_output_tokens": 0},
            "provider name as a path": ON | {"provider": "../x"},
            "not a mapping": [("provider", "scripted")],
        }
        for label, values in cases.items():
            with self.subTest(label), self.assertRaises(AIUnavailable) as caught:
                parse_config(values)
            self.assertEqual(str(caught.exception), "The AI provider configuration is not valid.")
            # "from None": the rejected value must not ride along in the traceback either.
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)

    def test_loopback_and_https_base_urls_are_accepted(self):
        for url in (
            "https://api.example.test/v1",
            "http://127.0.0.1:11434",
            "http://[::1]:8080/v1",
            "http://localhost:1234",
        ):
            self.assertEqual(parse_config(ON | {"base_url": url}).base_url, url)

    def test_configuration_is_frozen_and_never_contains_the_credential(self):
        environment = {
            "SHARAY_AI_PROVIDER": "scripted",
            "SHARAY_AI_MODEL": "m",
            "SHARAY_AI_KEY_ENV": "LAB_AI_KEY",
            "LAB_AI_KEY": KEY,
        }
        config = config_from_environment(environment)
        self.assertEqual(config.api_key_env, "LAB_AI_KEY")
        self.assertNotIn(KEY, repr(config) + config.model_dump_json())
        with self.assertRaises(Exception):
            config.share_assessment_data = True
        self.assertFalse(config.share_assessment_data)
        self.assertEqual(secret(config, environment), KEY)

    def test_a_missing_credential_is_unavailable_with_fixed_text(self):
        for config, environment in (
            (parse_config(ON), {"LAB_AI_KEY": KEY}),  # no variable named
            (parse_config(ON | {"api_key_env": "LAB_AI_KEY"}), {}),  # named, not set
            (parse_config(ON | {"api_key_env": "LAB_AI_KEY"}), {"LAB_AI_KEY": ""}),
        ):
            with self.assertRaises(AIUnavailable) as caught:
                secret(config, environment)
            self.assertEqual(str(caught.exception), "The AI provider's credential variable is not set.")

    def test_this_module_brings_in_no_vendor_code_and_no_network_client(self):
        source = open(providers.__file__).read()
        for word in ("anthropic", "openai", "httpx", "urllib.request", "socket", "requests"):
            self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()
