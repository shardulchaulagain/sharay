"""Tests for Linux dual-stack and nftables egress isolation with fail-closed drop guarantees (Sector 3.1 & 3.2)."""

import shlex
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from services.scanner_worker.container import (
    LinuxEgressEngine,
    TargetDestination,
    _machine_ssh,
    build_nftables_egress_ruleset,
    container_runtime,
    generate_scanner_apparmor_profile,
    generate_scanner_seccomp_profile,
    run_with_egress,
)


class ContainerEgressDropTests(unittest.TestCase):
    """Test suite for live egress drop policies, nftables/iptables dual-stack, and fail-closed teardown."""

    def test_nftables_engine_integration_in_run_with_egress(self):
        """Sector 3.1: Verify run_with_egress supports LinuxEgressEngine.NFTABLES and generates atomic nft tables."""
        scripts_run: list[str] = []

        def mock_ssh(script: str, timeout: float = 60.0):
            scripts_run.append(script)
            return SimpleNamespace(returncode=0, stdout="scan completed successfully")

        with patch(
            "services.scanner_worker.container.container_runtime", return_value="/opt/homebrew/bin/podman"
        ):
            with patch("services.scanner_worker.container._machine_ssh", side_effect=mock_ssh):
                result = run_with_egress(
                    "bkimminich/juice-shop:latest",
                    ["node", "/app/lib/index.js"],
                    destinations=[("192.168.1.100", 80), ("10.0.0.50", 443)],
                    engine=LinuxEgressEngine.NFTABLES,
                    max_seconds=30,
                )

        self.assertEqual(result.outcome, "completed")
        self.assertIn("nftables_isolation", result.enforced)
        self.assertIn("egress_allowlist_multi_destination", result.enforced)

        # Check setup script
        up_script = scripts_run[0]
        self.assertIn("nft add table inet sharay_egress", up_script)
        self.assertIn("policy drop", up_script)
        self.assertIn("192.168.1.100", up_script)
        self.assertIn("10.0.0.50", up_script)

        # Check teardown script
        down_script = scripts_run[2]  # setup, podman run, teardown
        self.assertIn("nft delete table inet sharay_egress", down_script)

    def test_nftables_dual_stack_ruleset_structure(self):
        """Sector 3.1: Dual-stack ruleset correctly parses IPv4, IPv6, and formats port sets."""
        spec = build_nftables_egress_ruleset(
            "sharay_nft_test",
            destinations=[
                ("192.168.1.50", 80),
                ("2001:db8::1", [443, 8443]),
                TargetDestination("10.10.0.0/24", (8080,)),
            ],
        )

        self.assertEqual(spec["engine"], LinuxEgressEngine.NFTABLES)
        self.assertEqual(spec["table_name"], "sharay_nft_test")
        self.assertEqual(spec["v4_count"], 2)  # 192.168.1.50 and 10.10.0.0/24
        self.assertEqual(spec["v6_count"], 1)  # 2001:db8::1
        self.assertEqual(spec["allowed_ports"], [80, 443, 8080, 8443])

        # Verify raw config format
        config = spec["nft_config"]
        self.assertIn("table inet sharay_nft_test", config)
        self.assertIn("policy drop;", config)
        self.assertIn("ip daddr { 192.168.1.50, 10.10.0.0/24 }", config)
        self.assertIn("ip6 daddr { 2001:db8::1 }", config)
        self.assertIn("tcp dport { 80, 443, 8080, 8443 } accept", config)

    def test_live_vm_egress_fail_closed_drop(self):
        """Sector 3.2: Live test inside VM showing unauthorized destinations are dropped fail-closed."""
        rt = container_runtime()
        if rt is None:
            self.skipTest("No container runtime available for live VM egress test.")

        # Test whether podman VM is currently reachable
        try:
            probe = _machine_ssh("which nft iptables", timeout=5.0)
            if probe.returncode != 0:
                self.skipTest("Podman machine not reachable or missing nftables/iptables.")
        except Exception as exc:
            self.skipTest(f"Podman machine SSH failed: {exc}")

        table_name = "sharay_live_egress_test"
        # Permitted target is a dummy loopback or specific IP, blocked target is 198.51.100.254 (TEST-NET-2)
        permitted_ip = "192.168.127.2"
        blocked_ip = "198.51.100.254"

        # Apply nftables ruleset in VM
        spec = build_nftables_egress_ruleset(
            table_name,
            destinations=[(permitted_ip, 80)],
        )
        up = " && ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in spec["up_commands"])
        down = "; ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in spec["down_commands"])

        up_res = _machine_ssh(up, timeout=10.0)
        self.assertEqual(up_res.returncode, 0, f"Failed to apply live nftables rules: {up_res.stderr}")

        try:
            # Check that table exists in VM
            list_res = _machine_ssh(f"sudo nft list table inet {table_name}", timeout=5.0)
            self.assertEqual(list_res.returncode, 0)
            self.assertIn("policy drop", list_res.stdout)
            self.assertIn(permitted_ip, list_res.stdout)

            # Test drop simulation: python script in VM attempting to reach blocked destination with a short timeout
            probe_script = f"""python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(('{blocked_ip}', 80))
    print('CONNECTED_UNAUTHORIZED')
except socket.timeout:
    print('FAIL_CLOSED_TIMEOUT')
except OSError as e:
    print(f'FAIL_CLOSED_ERROR: {{e.errno}}')
finally:
    s.close()
"
"""
            probe_res = _machine_ssh(probe_script, timeout=10.0)
            self.assertEqual(probe_res.returncode, 0)
            output = probe_res.stdout.strip()
            self.assertNotIn("CONNECTED_UNAUTHORIZED", output)
            self.assertTrue(
                "FAIL_CLOSED_TIMEOUT" in output or "FAIL_CLOSED_ERROR" in output,
                f"Expected fail-closed timeout or error, got: {output}",
            )
        finally:
            down_res = _machine_ssh(down, timeout=10.0)
            self.assertEqual(down_res.returncode, 0)

            # Verify table was completely removed
            verify_res = _machine_ssh(f"sudo nft list table inet {table_name}", timeout=5.0)
            self.assertNotEqual(verify_res.returncode, 0)  # Table should no longer exist

    def test_seccomp_profile_blocks_kernel_escape_syscalls(self):
        """Sector 3.3: Verify seccomp profile kills dangerous container-escape syscalls."""
        profile = generate_scanner_seccomp_profile()
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")

        kill_group = next(g for g in profile["syscalls"] if g["action"] == "SCMP_ACT_KILL")
        denied = kill_group["names"]

        for dangerous_call in [
            "ptrace",
            "bpf",
            "mount",
            "umount2",
            "pivot_root",
            "setns",
            "userfaultfd",
            "keyctl",
            "chroot",
            "reboot",
        ]:
            self.assertIn(dangerous_call, denied)

        allow_group = next(g for g in profile["syscalls"] if g["action"] == "SCMP_ACT_ALLOW")
        allowed = allow_group["names"]
        for safe_call in ["read", "write", "socket", "connect", "epoll_wait", "getrandom"]:
            self.assertIn(safe_call, allowed)

    def test_apparmor_profile_generation(self):
        """Sector 3.3: AppArmor profile generation denies raw memory and kernel access."""
        profile = generate_scanner_apparmor_profile("sharay_ci_sandbox")
        self.assertIn("profile sharay_ci_sandbox", profile)
        self.assertIn("deny /dev/mem", profile)
        self.assertIn("deny /dev/kmem", profile)
        self.assertIn("deny ptrace", profile)
        self.assertIn("deny capability sys_admin", profile)


if __name__ == "__main__":
    unittest.main()
