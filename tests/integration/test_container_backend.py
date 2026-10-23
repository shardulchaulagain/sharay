"""L1 rootless-container backend: locked-down request building, availability, fail-closed egress."""

import tempfile
import unittest
from unittest.mock import patch

from services.scanner_worker import IsolationError
from services.scanner_worker import container as cb


class ContainerBackendTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.input = self._dir.name

    def test_build_argv_is_locked_down(self):
        argv = cb.build_run_argv("podman", "alpine:3.19", ["echo", "hi"], input_dir=self.input)
        joined = " ".join(argv)
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(flag, argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertIn("type=bind,src=", joined)
        self.assertTrue(joined.endswith("alpine:3.19 echo hi"))

    def test_any_egress_destination_is_refused_fail_closed(self):
        with self.assertRaisesRegex(IsolationError, "not enforceable"):
            cb.build_run_argv(
                "podman", "alpine:3.19", ["echo"], input_dir=self.input, destinations=[("127.0.0.1", 8080)]
            )

    def test_malformed_requests_are_rejected(self):
        bad = [
            dict(image="Bad Image Name", tool_argv=["x"]),
            dict(image="alpine", tool_argv=[]),
            dict(image="alpine", tool_argv="echo hi"),  # shell string
            dict(image="alpine", tool_argv=["x\0y"]),  # NUL
            dict(image="alpine", tool_argv=["x"], memory_mb=4),  # too small
            dict(image="alpine", tool_argv=["x"], cpus=99),  # too many
            dict(image="alpine", tool_argv=["x"], max_seconds=0),
        ]
        for kw in bad:
            with self.assertRaises(IsolationError):
                cb.build_run_argv("podman", input_dir=self.input, **kw)
        with self.assertRaises(IsolationError):
            cb.build_run_argv("podman", "alpine", ["x"], input_dir="/no/such/dir-xyz")

    def test_runtime_probe_is_fail_closed(self):
        rt = cb.container_runtime()
        self.assertTrue(rt is None or isinstance(rt, str))  # never a false positive
        # With no runtime, run_contained must refuse rather than run unisolated.
        with patch.object(cb, "container_runtime", return_value=None):
            with self.assertRaisesRegex(IsolationError, "No container runtime"):
                cb.run_contained("alpine", ["echo"], input_dir=self.input)

    def test_attest_shape(self):
        a = cb.attest()
        self.assertEqual(a["backend"], "rootless-container")
        self.assertIn("no_network", a["enforced"])

    def test_egress_ruleset_is_default_drop_allow_one(self):
        rules = cb.build_egress_ruleset("SHARAY_EGRESS", "10.88.0.0/16", "203.0.113.5", 443)
        up = [" ".join(c) for c in rules["up"]]
        self.assertTrue(any("203.0.113.5 -p tcp --dport 443 -j ACCEPT" in r for r in up))
        self.assertTrue(any(r.endswith("-j DROP") for r in up))  # everything else dropped
        self.assertTrue(any("-j SHARAY_EGRESS" in r for r in up))
        # teardown undoes the FORWARD hooks and removes the chain
        down = [" ".join(c) for c in rules["down"]]
        self.assertTrue(any("-X SHARAY_EGRESS" in r for r in down))

    def test_run_with_egress_shell_quotes_argv_no_injection(self):
        import shlex
        from types import SimpleNamespace

        scripts = []

        def recorder(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", recorder):
                cb.run_with_egress("busybox", ["echo", "a; id #pwn"], allow_ip="203.0.113.5", allow_port=443)
        run_script = next(s for s in scripts if "podman run" in s)
        self.assertIn(shlex.quote("a; id #pwn"), run_script)  # payload stays one quoted argument
        self.assertNotIn("echo a; id", run_script)  # never an unquoted second command

    def test_run_with_egress_preserves_tool_args_that_look_like_setup_flags(self):
        import shlex
        from types import SimpleNamespace

        scripts = []
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(
                cb,
                "_machine_ssh",
                lambda s, timeout=60.0: scripts.append(s) or SimpleNamespace(returncode=0, stdout=""),
            ):
                cb.run_with_egress(
                    "busybox",
                    ["echo", "--workdir", "type=bind-x", "--network=none"],
                    allow_ip="203.0.113.5",
                    allow_port=443,
                )
        run_script = next(s for s in scripts if "podman run" in s)
        toks = shlex.split(run_script)
        # the whole tool_argv survives, in order, right after the image
        self.assertEqual(
            toks[toks.index("busybox") + 1 :][:4], ["echo", "--workdir", "type=bind-x", "--network=none"]
        )

    def test_run_with_egress_tears_down_even_when_setup_times_out(self):
        import subprocess
        from types import SimpleNamespace

        calls = []

        def ssh(script, timeout=60.0):
            calls.append(script)
            if len(calls) == 1:  # the egress-allowlist setup times out
                raise subprocess.TimeoutExpired(cmd=["podman", "machine", "ssh"], timeout=timeout)
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                with self.assertRaises(subprocess.TimeoutExpired):
                    cb.run_with_egress("busybox", ["echo"], allow_ip="203.0.113.5", allow_port=443)
        self.assertGreaterEqual(len(calls), 2)  # setup attempted, then teardown
        self.assertIn("SHARAY_EGRESS", calls[-1])  # the firewall chain is always removed

    def test_run_with_egress_runs_no_tool_when_setup_exhausts_budget(self):
        from types import SimpleNamespace

        scripts = []

        def ssh(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="")

        # Clock jumps past the budget during setup: started, remaining-calc, duration_ms.
        clock = iter([0.0, 100.0, 100.0, 100.0])
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                with patch.object(cb.time, "monotonic", lambda: next(clock)):
                    res = cb.run_with_egress(
                        "busybox", ["nmap"], allow_ip="203.0.113.5", allow_port=443, max_seconds=1
                    )
        self.assertEqual(res.outcome, "failed")
        self.assertEqual(res.exit_code, 124)
        self.assertFalse(any("podman run" in s for s in scripts))  # tool never dispatched on spent clock
        self.assertTrue(any("SHARAY_EGRESS" in s for s in scripts))  # allowlist still torn down

    def test_run_with_egress_nonzero_teardown_is_never_completed(self):
        from types import SimpleNamespace

        calls = []

        def ssh(script, timeout=60.0):
            calls.append(script)
            if len(calls) == 3:  # teardown (after setup, then tool) fails to remove the allowlist
                return SimpleNamespace(returncode=1, stdout="")
            return SimpleNamespace(returncode=0, stdout="scan output")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                res = cb.run_with_egress("busybox", ["nmap"], allow_ip="203.0.113.5", allow_port=443)
        self.assertEqual(res.outcome, "failed")  # cleanup failure demotes an otherwise-successful run
        self.assertFalse(res.scratch_removed)
        self.assertIn(b"teardown failed", res.stderr)

    def test_egress_ruleset_rejects_a_hostname_or_bad_port(self):
        with self.assertRaises(IsolationError):
            cb.build_egress_ruleset("c", "10.88.0.0/16", "example.com", 443)  # not a literal IP
        with self.assertRaises(IsolationError):
            cb.build_egress_ruleset("c", "10.88.0.0/16", "203.0.113.5", 0)

    def test_build_egress_ruleset_ipv6_single_destination(self):
        rules = cb.build_egress_ruleset("SHARAY_EGRESS", "fd00::/64", "2001:db8::1", 443)
        up = [" ".join(c) for c in rules["up"]]
        self.assertTrue(any("ip6tables -N SHARAY_EGRESS" in r for r in up))
        self.assertTrue(any("2001:db8::1 -p tcp --dport 443 -j ACCEPT" in r for r in up))
        self.assertTrue(any(r.endswith("-j DROP") for r in up))
        down = [" ".join(c) for c in rules["down"]]
        self.assertTrue(any("ip6tables -X SHARAY_EGRESS" in r for r in down))

    def test_build_multidest_egress_ruleset_ipv4_and_ipv6_cidrs(self):
        dests = [
            ("192.168.1.0/24", 80),
            ("10.0.0.5", 8080),
            ("2001:db8::/32", 443),
            ("2001:db8::1", 8443),
        ]
        rules = cb.build_multidest_egress_ruleset("MULTI_EGRESS", dests)
        up = [" ".join(c) for c in rules["up"]]
        # IPv4 checks
        self.assertTrue(any("iptables -N MULTI_EGRESS" in r for r in up))
        self.assertTrue(any("192.168.1.0/24 -p tcp --dport 80 -j ACCEPT" in r for r in up))
        self.assertTrue(any("10.0.0.5 -p tcp --dport 8080 -j ACCEPT" in r for r in up))
        # IPv6 checks
        self.assertTrue(any("ip6tables -N MULTI_EGRESS_V6" in r for r in up))
        self.assertTrue(any("2001:db8::/32 -p tcp --dport 443 -j ACCEPT" in r for r in up))
        self.assertTrue(any("2001:db8::1 -p tcp --dport 8443 -j ACCEPT" in r for r in up))
        # Teardown checks
        down = [" ".join(c) for c in rules["down"]]
        self.assertTrue(any("iptables -X MULTI_EGRESS" in r for r in down))
        self.assertTrue(any("ip6tables -X MULTI_EGRESS_V6" in r for r in down))

    def test_build_multidest_egress_ruleset_validation_fail_closed(self):
        # Empty destinations
        with self.assertRaisesRegex(IsolationError, "At least one egress destination"):
            cb.build_multidest_egress_ruleset("CHAIN", [])
        # Invalid port
        with self.assertRaisesRegex(IsolationError, "Egress port must be an integer from 1 to 65535"):
            cb.build_multidest_egress_ruleset("CHAIN", [("10.0.0.1", 70000)])
        # Domain name instead of literal IP
        with self.assertRaisesRegex(IsolationError, "Invalid IP address or CIDR"):
            cb.build_multidest_egress_ruleset("CHAIN", [("example.com", 80)])
        # Invalid chain identifier
        with self.assertRaisesRegex(IsolationError, "chain name must be a short identifier"):
            cb.build_multidest_egress_ruleset("INVALID;CHAIN", [("10.0.0.1", 80)])

    def test_build_nftables_egress_ruleset_generation(self):
        dests = [("192.168.2.0/24", 80), ("2001:db8:abcd::1", 443)]
        res = cb.build_nftables_egress_ruleset("test_nft", dests)
        self.assertEqual(res["engine"], cb.LinuxEgressEngine.NFTABLES)
        self.assertEqual(res["table_name"], "test_nft")
        self.assertEqual(res["v4_count"], 1)
        self.assertEqual(res["v6_count"], 1)
        cfg = res["nft_config"]
        self.assertIn("table inet test_nft", cfg)
        self.assertIn("ct state established,related accept", cfg)
        self.assertIn("ip daddr { 192.168.2.0/24 }", cfg)
        self.assertIn("ip6 daddr { 2001:db8:abcd::1 }", cfg)
        self.assertIn("drop", cfg)
        # Teardown command check
        self.assertEqual(res["down_commands"], [["nft", "delete", "table", "inet", "test_nft"]])

    def test_generate_scanner_seccomp_profile_blocks_dangerous_syscalls(self):
        profile = cb.generate_scanner_seccomp_profile()
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        kill_rules = next(r for r in profile["syscalls"] if r["action"] == "SCMP_ACT_KILL")
        for bad_syscall in ("ptrace", "bpf", "mount", "pivot_root", "setns", "userfaultfd", "keyctl"):
            self.assertIn(bad_syscall, kill_rules["names"])
        allow_rules = next(r for r in profile["syscalls"] if r["action"] == "SCMP_ACT_ALLOW")
        for good_syscall in ("read", "write", "socket", "connect", "epoll_wait"):
            self.assertIn(good_syscall, allow_rules["names"])

    def test_generate_scanner_apparmor_profile_confinement(self):
        prof = cb.generate_scanner_apparmor_profile("sharay_test_prof")
        self.assertIn("profile sharay_test_prof flags=(attach_disconnected,enforce)", prof)
        self.assertIn("/input/** r,", prof)
        self.assertIn("/tmp/** rw,", prof)
        self.assertIn("deny ptrace,", prof)
        self.assertIn("deny capability sys_admin,", prof)

    def test_image_pinning_engine_digest_and_cosign(self):
        pinned = (
            "docker.io/library/alpine@sha256:e2e430d8726191151f7470f37abe47f63b4893fa0e4e935102c112a828e10d40"
        )
        digest = cb.ImagePinningEngine.validate_image_digest_pinning(pinned, require_digest=True)
        self.assertEqual(digest, "e2e430d8726191151f7470f37abe47f63b4893fa0e4e935102c112a828e10d40")

        # Floating tags rejected
        with self.assertRaisesRegex(IsolationError, "violates immutability policy"):
            cb.ImagePinningEngine.validate_image_digest_pinning("alpine:latest", require_digest=True)

        # Cosign signature verification uses a real verifier callback; with one it reflects its
        # verdict, and with none it fails closed (never assumes a valid signature -- F12).
        self.assertTrue(
            cb.ImagePinningEngine.verify_cosign_signature(pinned, "cosign-pub-key-123", lambda ref, key: True)
        )
        self.assertFalse(
            cb.ImagePinningEngine.verify_cosign_signature(pinned, "cosign-pub-key-123", lambda ref, key: False)
        )
        with self.assertRaisesRegex(IsolationError, "No cosign verifier is configured"):
            cb.ImagePinningEngine.verify_cosign_signature(pinned, "cosign-pub-key-123")
        with self.assertRaisesRegex(IsolationError, "Trusted public key is required"):
            cb.ImagePinningEngine.verify_cosign_signature(pinned, "")

    def test_egress_attestation_logger_receipt_and_signature(self):
        # 1. Test asymmetric Ed25519 attestation (default)
        asym_logger = cb.EgressAttestationLogger()
        self.assertTrue(asym_logger.is_asymmetric)
        self.assertIsNotNone(asym_logger.public_key)
        rules = [["iptables", "-A", "TEST", "-d", "10.0.0.1", "-j", "ACCEPT"]]
        asym_receipt = asym_logger.record_ruleset_applied("assessment-asym-1", "target.com", rules)
        self.assertEqual(len(asym_receipt.signature_sha256), 128)
        self.assertTrue(asym_logger.verify_receipt(asym_receipt))
        # Tampered receipt verification fails
        asym_receipt.applied_ruleset_hash = "tampered_hash_value"
        self.assertFalse(asym_logger.verify_receipt(asym_receipt))

        # 2. Test symmetric legacy attestation
        logger = cb.EgressAttestationLogger(notary_secret="TEST_SECRET_KEY")
        self.assertFalse(logger.is_asymmetric)
        receipt = logger.record_ruleset_applied("assessment-123", "target.com", rules)
        self.assertEqual(receipt.assessment_id, "assessment-123")
        self.assertEqual(receipt.state, "APPLIED")
        self.assertTrue(len(receipt.signature_sha256) == 64)
        self.assertIsNone(receipt.teardown_timestamp_utc)
        self.assertTrue(logger.verify_receipt(receipt))

        td_receipt = logger.record_ruleset_teardown(receipt.attestation_id, clean=True)
        self.assertEqual(td_receipt.state, "TORN_DOWN")
        self.assertIsNotNone(td_receipt.teardown_timestamp_utc)
        self.assertTrue(logger.verify_receipt(td_receipt))

        with self.assertRaises(KeyError):
            logger.record_ruleset_teardown("non-existent-id")

    def test_run_with_egress_multi_destination_dual_stack(self):
        from types import SimpleNamespace

        scripts = []

        def recorder(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="scan output")

        dests = [("192.168.1.10", 80), ("2001:db8::10", 443)]
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", recorder):
                res = cb.run_with_egress("busybox", ["echo", "test"], destinations=dests)

        self.assertEqual(res.outcome, "completed")
        self.assertIn("egress_allowlist_multi_destination", res.enforced)
        self.assertIn("ipv6_egress", res.enforced)
        setup_script = next(s for s in scripts if "iptables" in s and "ip6tables" in s)
        self.assertIn("192.168.1.10", setup_script)
        self.assertIn("2001:db8::10", setup_script)

    def test_run_with_egress_security_profiles_and_image_pinning(self):
        from types import SimpleNamespace

        scripts = []

        def recorder(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="")

        pinned_image = "busybox@sha256:e2e430d8726191151f7470f37abe47f63b4893fa0e4e935102c112a828e10d40"
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", recorder):
                res = cb.run_with_egress(
                    pinned_image,
                    ["echo", "hi"],
                    allow_ip="203.0.113.5",
                    allow_port=443,
                    seccomp_profile="/etc/seccomp/default.json",
                    apparmor_profile="sharay_sandbox",
                    require_pinned_digest=True,
                )

        self.assertEqual(res.outcome, "completed")
        self.assertIn("image_digest_pinning", res.enforced)
        self.assertIn("seccomp_profile", res.enforced)
        self.assertIn("apparmor_profile", res.enforced)
        run_cmd = next(s for s in scripts if "podman run" in s)
        self.assertIn("--security-opt=seccomp=/etc/seccomp/default.json", run_cmd)
        self.assertIn("--security-opt=apparmor=sharay_sandbox", run_cmd)

    def test_run_with_egress_audit_events_logging(self):
        from types import SimpleNamespace

        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        from aegis.models import AuditEvent, Base, Organization

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        session = Session(engine)
        org = Organization(id="org-test", name="Test Org")
        session.add(org)
        session.commit()

        calls = []

        def recorder(script, timeout=60.0):
            calls.append(script)
            return SimpleNamespace(returncode=0, stdout="done")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", recorder):
                res = cb.run_with_egress(
                    "busybox",
                    ["echo", "ok"],
                    allow_ip="203.0.113.10",
                    allow_port=443,
                    audit_db=session,
                    assessment_id="asmt-456",
                    org_id="org-test",
                )

        self.assertEqual(res.outcome, "completed")
        events = session.query(AuditEvent).all()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].action, "egress.allowlist_applied")
        self.assertEqual(events[1].action, "egress.allowlist_teardown")
        self.assertIn("ruleset_hash", events[0].detail)
        self.assertTrue(events[1].detail["clean"])

    def test_attest_reports_multi_destination_and_sector3_capabilities(self):
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            a = cb.attest()
            self.assertEqual(a["backend"], "rootless-container")
            self.assertEqual(a["runtime"], "podman")
            self.assertTrue(a["available"])
            for cap in (
                "egress_allowlist_single_destination",
                "egress_allowlist_multi_destination",
                "ipv6_egress",
                "seccomp_profile",
                "apparmor_profile",
                "image_digest_pinning",
                "egress_attestation_audit",
            ):
                self.assertIn(cap, a["enforced"])


if __name__ == "__main__":
    unittest.main()
