"""Nmap adapter: fixed argv, strict parsing and runner plumbing.

No real nmap exists on this host. SAMPLE is hand-written to nmap's XML layout, and the
executable below is a stand-in that prints it, so these tests show the adapter's own
behaviour, not nmap's.
"""

import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

from packages.scanner_adapters.integrations.nmap import build_argv, inventory, parse_xml
from services.scanner_worker import attest

PYTHON = os.path.realpath(sys.executable)
SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="synthetic sample" start="1760000000" version="7.95" xmloutputversion="1.05">
<host starttime="1760000000" endtime="1760000001"><status state="up" reason="user-set"/>
<address addr="{address}" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="{open}"><state state="open" reason="syn-ack"/>
<service name="http" product="Base&#9;HTTPServer" version="0.6" method="probed" conf="10"/></port>
<port protocol="tcp" portid="{closed}"><state state="closed" reason="conn-refused"/>
<service name="unknown" method="table" conf="3"/></port>
</ports></host>
<runstats><finished time="1760000001" exit="success"/></runstats>
</nmaprun>
"""
STAND_IN = f"""#!{PYTHON} -I
import sys, time
arguments = sys.argv[1:]
assert arguments[:3] == ["-sT", "-Pn", "-n"] and not {{"-sV", "--script"}} & set(arguments), arguments
ports = arguments[arguments.index("-p") + 1].split(",")
if MODE == "sleep":
    time.sleep(60)
sys.stdout.write(SAMPLE.format(address=arguments[-1], open=ports[0], closed=ports[-1]))
"""


def sample(address="127.0.0.1", open=8906, closed=8907) -> bytes:
    return SAMPLE.format(address=address, open=open, closed=closed).encode()


class ArgvTests(unittest.TestCase):
    def test_argv_is_the_fixed_template(self):
        self.assertEqual(
            build_argv("/opt/nmap", "127.0.0.1", [8906, 8907], 30, 0.5),
            "/opt/nmap -sT -Pn -n --max-parallelism 1 --max-retries 1 --max-rate 0.5 --host-timeout 28s"
            " -p 8906,8907 -oX - 127.0.0.1".split(),
        )
        self.assertEqual(build_argv("/opt/nmap", "::1", [80], 30, 5)[-2:], ["-6", "::1"])

    def test_untyped_or_out_of_bounds_values_are_rejected(self):
        for address, ports, seconds, rate in (
            ("localhost", [80], 30, 1),
            ("127.0.0.0/24", [80], 30, 1),
            ("-iL", [80], 30, 1),
            ("127.0.0.1 --script=vuln", [80], 30, 1),
            ("127.000.0.1", [80], 30, 1),
            ("fe80::1%en0", [80], 30, 1),
            ("127.0.0.1", [], 30, 1),
            ("127.0.0.1", ["80"], 30, 1),
            ("127.0.0.1", [80, 80], 30, 1),
            ("127.0.0.1", [0], 30, 1),
            ("127.0.0.1", list(range(1, 102)), 30, 1),
            ("127.0.0.1", [80], 301, 1),
            ("127.0.0.1", [80], "30", 1),
            ("127.0.0.1", [80], 2, 1),
            ("127.0.0.1", [80], 30, 0),
            ("127.0.0.1", [80], 30, 5.5),
            ("127.0.0.1", [80], 30, True),
        ):
            with (
                self.subTest(address=address, ports=ports, seconds=seconds, rate=rate),
                self.assertRaises(ValueError),
            ):
                build_argv("/opt/nmap", address, ports, seconds, rate)


class ParserTests(unittest.TestCase):
    def test_sample_becomes_bounded_observations_without_findings(self):
        version, observations = parse_xml(sample(), "127.0.0.1", [8906, 8907])
        self.assertEqual(version, "7.95")
        self.assertEqual([(o["port"], o["state"]) for o in observations], [(8906, "open"), (8907, "closed")])
        first, second = observations
        # The sample carries a product banner; nothing of it may be retained.
        self.assertFalse({"product", "product_version"} & set(first))
        self.assertNotIn("HTTPServer", str(observations))
        self.assertEqual((first["service"], first["identification"]), ("http", "probed"))
        self.assertEqual(first["identification_confidence"], 10)
        self.assertEqual((second["identification"], second["identification_confidence"]), ("table", 3))
        self.assertEqual(first["captured_at"], "2025-10-09T08:53:20+00:00")
        # An absurd start time is dropped rather than crashing the parse.
        for absurd in (b"99999999999999999999", b"9" * 5000):
            late = sample().replace(b'start="1760000000"', b'start="' + absurd + b'"')
            self.assertIsNone(parse_xml(late, "127.0.0.1", [8906, 8907])[1][0]["captured_at"])
        # The official book's older header: no encoding attribute and no DOCTYPE line.
        older = sample().replace(b' encoding="UTF-8"', b"").replace(b"<!DOCTYPE nmaprun>\n", b"")
        self.assertEqual(len(parse_xml(older, "127.0.0.1", [8906, 8907])[1]), 2)

    def test_output_outside_the_request_or_unsafe_fails_closed(self):
        for label, data, ports in (
            ("other host", sample(address="127.0.0.2"), [8906, 8907]),
            ("extra port", sample(), [8906]),
            ("truncated", sample()[:-40], [8906, 8907]),
            ("unfinished", sample().replace(b'exit="success"', b'exit="error"'), [8906, 8907]),
            (
                "entity",
                sample().replace(b"<!DOCTYPE nmaprun>", b'<!DOCTYPE x [<!ENTITY a "b">]>'),
                [8906, 8907],
            ),
            (
                "internal subset",
                sample().replace(b"<!DOCTYPE nmaprun>", b"<!DOCTYPE nmaprun [ ]>"),
                [8906, 8907],
            ),
            ("second doctype", sample().replace(b"<nmaprun ", b"<!DOCTYPE nmaprun><nmaprun "), [8906, 8907]),
            ("oversized", sample() + b" " * 1048576, [8906, 8907]),
            ("utf-16", sample().decode().replace("UTF-8", "UTF-16").encode("utf-16"), [8906, 8907]),
            ("exotic codec", sample().decode().replace("UTF-8", "cp037").encode("cp037"), [8906, 8907]),
            ("no declaration", sample().split(b"\n", 1)[1], [8906, 8907]),
            ("not nmap", b'<?xml version="1.0"?><html/>', [8906, 8907]),
            (
                "repeated port",
                sample().replace(
                    b"</ports>", b'<port protocol="tcp" portid="8906"><state state="open"/></port></ports>'
                ),
                [8906, 8907],
            ),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                parse_xml(data, "127.0.0.1", ports)


class RunnerPlumbingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not attest()["available"]:
            raise unittest.SkipTest("Seatbelt sandbox cannot be applied in this environment.")

    def stand_in(self, mode: str) -> tuple[str, list[Path]]:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        tool = Path(folder.name).resolve() / "stand-in-nmap"
        tool.write_text(STAND_IN.replace("MODE", repr(mode)).replace("SAMPLE", repr(SAMPLE)))
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        # The stand-in needs an interpreter; a real nmap binary would need no exec path.
        return str(tool), [Path(sys.base_prefix)]

    def run_inventory(self, mode, cancelled=lambda: False, **options):
        tool, exec_paths = self.stand_in(mode)
        events = []
        result = inventory(
            "127.0.0.1",
            [8906, 8907],
            cancelled,
            events.append,
            executable=tool,
            exec_paths=exec_paths,
            max_seconds=30,
            max_rate=5,
            **options,
        )
        return result, events

    def test_completed_run_yields_observations_and_events(self):
        result, events = self.run_inventory("ok")
        self.assertEqual(result["outcome"], "completed", result["checks"])
        self.assertEqual((result["adapter"], result["version"], result["findings"]), ("nmap", "7.95", []))
        self.assertEqual([o["port"] for o in result["observations"]], [8906, 8907])
        self.assertEqual([e["type"] for e in events], ["observation", "observation", "check"])

    def test_cancellation_never_looks_complete(self):
        stop_at = time.monotonic() + 0.3
        result, _ = self.run_inventory("sleep", cancelled=lambda: time.monotonic() >= stop_at)
        self.assertEqual((result["outcome"], result["observations"]), ("cancelled", []))
        self.assertEqual(result["checks"][0]["status"], "cancelled")

    def test_missing_tool_and_non_loopback_target_are_reported_not_faked(self):
        missing = inventory(
            "127.0.0.1", [80], lambda: False, lambda _event: None, executable="", max_seconds=30, max_rate=5
        )
        if not missing["checks"][0]["detail"].startswith("nmap is not installed"):
            self.skipTest("A real nmap is installed; this case needs a host without it.")
        self.assertEqual((missing["outcome"], missing["observations"]), ("failed", []))
        tool, exec_paths = self.stand_in("ok")
        live = inventory(
            "192.0.2.10",
            [80],
            lambda: False,
            lambda _event: None,
            executable=tool,
            exec_paths=exec_paths,
            max_seconds=30,
            max_rate=5,
        )
        self.assertEqual((live["outcome"], live["observations"]), ("failed", []))
        self.assertIn("loopback", live["checks"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
