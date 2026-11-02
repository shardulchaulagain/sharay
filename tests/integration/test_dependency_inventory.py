"""Dependency inventory: declared exact versions only, hostile manifests bounded, nothing echoed."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from services.source_analysis_worker import dependencies
from services.source_analysis_worker.dependencies import _PEP440, _SEMVER, inventory

ROOT = Path(__file__).resolve().parents[2]
SECRET = "synthetic-secret-value"
REQUIREMENTS = f"""\
# pinned, with the usual decorations
Django==5.1.2
requests[socks,security] == 2.32.3 ; python_version >= "3.9"   # trailing comment
typing_extensions==4.12.2 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
Zope.Interface==7.0
epoch-pkg==2!1.0.post1+local.5
demo==not-a-version
wild==1.0.*
flask>=3.0,<4
numpy
-r other.txt
--index-url https://user:{SECRET}@example.invalid/simple
--extra-index-url=https://__token__:{SECRET}@example.invalid/simple
-e git+https://user:{SECRET}@example.invalid/repo.git#egg=thing
https://user:{SECRET}@example.invalid/pkg.whl
direct @ https://user:{SECRET}@example.invalid/direct.whl
./local/path
PIP_TOKEN={SECRET}
"""
REGISTRY = "https://registry.npmjs.org"
PACKAGE_LOCK = {
    "name": "demo",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "packages/own-workspace": {"version": "0.0.1"},
        "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": f"{REGISTRY}/left-pad/-/left-pad-1.3.0.tgz",
        },
        "node_modules/@scope/tool": {"version": "2.0.0-beta.1"},
        "node_modules/left-pad/node_modules/inner": {"version": "0.1.0"},
        "node_modules/alias": {"name": "real-package", "version": "4.5.6"},
        "node_modules/workspace-pkg": {"link": True, "resolved": "packages/workspace-pkg"},
        "node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@example.invalid/x.git#abc"},
        "node_modules/from-file": {"version": "1.0.0", "resolved": "file:../local"},
        "node_modules/private": {"version": "1.0.0", "resolved": f"https://u:{SECRET}@example.invalid/p.tgz"},
        "node_modules/empty-prerelease": {"version": "1.2.3-"},
        "node_modules/Bad Name": {"version": "1.0.0"},
        "node_modules/no-version": {},
        "node_modules/not-an-object": "1.0.0",
    },
}


class DependencyInventoryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve() / "tree"
        self.root.mkdir()

    def write(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def packages(self, result):
        return [(p["ecosystem"], p["name"], p["version"]) for p in result["packages"]]

    def unresolved(self, result):
        return {(item["item"], item["reason"]) for item in result["unresolved"]}

    def test_only_valid_exact_python_pins_become_packages_and_nothing_secret_is_echoed(self):
        self.write("requirements.txt", REQUIREMENTS)
        result = inventory(self.root)
        self.assertIn("not verified", result["basis"])
        self.assertEqual(
            self.packages(result),
            [
                ("PyPI", "django", "5.1.2"),
                ("PyPI", "requests", "2.32.3"),
                ("PyPI", "typing-extensions", "4.12.2"),
                ("PyPI", "zope-interface", "7.0"),
                ("PyPI", "epoch-pkg", "2!1.0.post1+local.5"),
            ],
        )
        self.assertEqual(
            self.unresolved(result),
            {
                ("demo", "pinned version is not a valid PEP 440 version"),
                ("wild", "pinned version is not a valid PEP 440 version"),
                ("flask>=3.0,<4", "not pinned to one exact version"),
                ("numpy", "not pinned to one exact version"),
                ("-r", "pip option or include was not followed"),
                ("--index-url", "pip option or include was not followed"),
                ("--extra-index-url", "pip option or include was not followed"),
                ("-e", "pip option or include was not followed"),
                ("direct reference", "direct URL, VCS or path reference was not resolved"),
                ("direct", "direct URL, VCS or path reference was not resolved"),
                ("unrecognized line", "not a requirement this reader understands"),
            },
        )
        # Credentials in index URLs, direct references and stray assignments never reach the output.
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn("example.invalid", json.dumps(result))

    def test_windows_line_endings_keep_hash_pinned_requirements(self):
        self.write("requirements.txt", "demo==1.0 \\\r\n    --hash=sha256:aaaa\r\nother==2.0\r\n")
        result = inventory(self.root)
        self.assertEqual(self.packages(result), [("PyPI", "demo", "1.0"), ("PyPI", "other", "2.0")])
        self.assertEqual(result["unresolved"], [])

    def test_npm_packages_use_registry_identity_and_reject_other_sources(self):
        self.write("web/package-lock.json", json.dumps(PACKAGE_LOCK))
        result = inventory(self.root)
        self.assertEqual(
            [(p["name"], p["version"], p["source"], p["path"]) for p in result["packages"]],
            [
                ("left-pad", "1.3.0", "registry", "node_modules/left-pad"),
                ("@scope/tool", "2.0.0-beta.1", "undeclared", "node_modules/@scope/tool"),
                ("inner", "0.1.0", "undeclared", "node_modules/left-pad/node_modules/inner"),
                # The alias folder is provenance; the package is the one the registry knows.
                ("real-package", "4.5.6", "undeclared", "node_modules/alias"),
            ],
        )
        self.assertEqual(
            self.unresolved(result),
            {
                ("workspace-pkg", "workspace link has no registry version"),
                ("from-git", "resolved from a source other than a registry tarball"),
                ("from-file", "resolved from a source other than a registry tarball"),
                ("private", "resolved from a source other than a registry tarball"),
                ("empty-prerelease", "version is not one exact semantic version"),
                ("Bad Name", "package name is not a valid registry name"),
                ("no-version", "version is not one exact semantic version"),
                ("not-an-object", "entry is not an object"),
            },
        )
        self.assertNotIn(SECRET, json.dumps(result))

    def test_version_grammars_match_the_published_rules(self):
        valid = [
            "1",
            "1.0",
            "1.0.0",
            "2!1.0",
            "1.0a1",
            "1.0.rc1",
            "1.0-1",
            "1.0.post2",
            "1.0.dev3",
            "1.0+abc.5",
            "v1.0",
        ]
        invalid = [
            "",
            "not-a-version",
            "1.0.*",
            "1..0",
            "1.0+",
            "1.0-",
            "abc",
            "1.0 beta",
            "1.0+a_b_",
            "==1.0",
        ]
        for text in valid:
            self.assertTrue(_PEP440.match(text), text)
        for text in invalid:
            self.assertFalse(_PEP440.match(text), text)
        try:
            from packaging.version import InvalidVersion, Version
        except ImportError:  # packaging is a development dependency only
            self.skipTest("packaging is not installed; the reference cross-check did not run")
        for text in valid + invalid:
            try:
                Version(text)
                reference = True
            except InvalidVersion:
                reference = False
            self.assertEqual(bool(_PEP440.match(text)), reference, text)
        for text, expected in (
            ("1.2.3", True),
            ("1.2.3-alpha.1+build.5", True),
            ("0.0.0-0", True),
            ("1.2.3-", False),
            ("1.2.3+", False),
            ("01.2.3", False),
            ("1.2", False),
            ("1.2.3-01", False),
            ("1.2.3 ", False),
        ):
            self.assertEqual(bool(_SEMVER.match(text)), expected, text)

    def test_unsupported_lockfiles_and_unparseable_manifests_are_reported_not_guessed(self):
        packages = {"node_modules/x": {"version": "1.0.0"}}
        self.write(
            "a/package-lock.json",
            json.dumps({"lockfileVersion": 1, "dependencies": {"x": {"version": "1.0.0"}}}),
        )
        self.write("b/package-lock.json", "{not json")
        self.write("c/package-lock.json", "[" * 100000)
        self.write("d/requirements.txt", "ok==1.0\n")
        (self.root / "d" / "requirements-binary.txt").write_bytes(b"\xff\xfe\x00bad")
        self.write("e/package-lock.json", json.dumps({"lockfileVersion": 99, "packages": packages}))
        self.write("f/package-lock.json", json.dumps({"lockfileVersion": True, "packages": packages}))
        self.write("g/package-lock.json", json.dumps({"packages": packages}))
        self.write("h/package-lock.json", json.dumps({"lockfileVersion": 2, "packages": packages}))
        result = inventory(self.root)
        self.assertEqual(self.packages(result), [("PyPI", "ok", "1.0"), ("npm", "x", "1.0.0")])
        reasons = {item["manifest"]: item["reason"] for item in result["unresolved"]}
        unsupported = "only lockfile versions 2 and 3 are supported"
        for folder in "aefg":
            self.assertEqual(reasons[f"{folder}/package-lock.json"], unsupported)
        self.assertEqual(reasons["b/package-lock.json"], "manifest could not be read or parsed")
        self.assertIn(
            reasons["c/package-lock.json"],
            {"manifest nesting is too deep to parse", "manifest could not be read or parsed"},
        )
        self.assertEqual(reasons["d/requirements-binary.txt"], "manifest could not be read or parsed")

    def test_budgets_symlinks_and_vendored_folders_are_respected(self):
        outside = self.write("../outside-requirements.txt", "stolen==9.9\n")  # beside the tree
        (self.root / "requirements-link.txt").symlink_to(outside)
        self.write("node_modules/dep/package-lock.json", json.dumps(PACKAGE_LOCK))
        self.write(".git/requirements.txt", "hidden==1.0\n")
        self.write("requirements.txt", "big==1.0\n" + "#" * 2000)
        original = dependencies.MAX_MANIFEST_BYTES
        dependencies.MAX_MANIFEST_BYTES = 1000
        self.addCleanup(setattr, dependencies, "MAX_MANIFEST_BYTES", original)
        result = inventory(self.root)
        self.assertEqual(result["packages"], [])
        self.assertEqual(sorted(result["manifests"]), ["requirements-link.txt", "requirements.txt"])
        reasons = {item["manifest"]: item["reason"] for item in result["unresolved"]}
        self.assertEqual(reasons["requirements.txt"], "manifest is larger than the parsing budget")
        self.assertEqual(reasons["requirements-link.txt"], "manifest is not a regular file")

    def test_a_fifo_named_like_a_manifest_is_rejected_without_waiting(self):
        os.mkfifo(self.root / "requirements.txt")
        self.write("web/requirements.txt", "ok==1.0\n")
        code = (
            "import json, sys\n"
            "from services.source_analysis_worker.dependencies import inventory\n"
            "print(json.dumps(inventory(sys.argv[1])))\n"
        )
        # A child with a deadline, so a regression blocks the child and fails here instead of hanging.
        child = subprocess.run(
            [sys.executable, "-c", code, str(self.root)], cwd=ROOT, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(self.packages(result), [("PyPI", "ok", "1.0")])
        self.assertEqual(self.unresolved(result), {("manifest", "manifest is not a regular file")})

    def test_untrusted_text_is_made_printable_and_short(self):
        self.write("requirements.txt", "evil\x1b[31m" + "A" * 500 + "\n")
        self.write("x" * 10 + "\x1b/requirements.txt", "ok==1.0\n")
        result = inventory(self.root)
        self.assertNotIn("\\u001b", json.dumps(result))
        self.assertTrue(all(len(item["item"]) <= 200 for item in result["unresolved"]))
        self.assertEqual(
            self.unresolved(result), {("unrecognized line", "not a requirement this reader understands")}
        )


if __name__ == "__main__":
    unittest.main()
