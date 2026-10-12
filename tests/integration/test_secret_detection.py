"""Secret-pattern detection on a labelled synthetic tree; matched text never leaves the detector.

Token-shaped strings are assembled at run time so this file itself contains none.
"""

import json
import os
import string
import tempfile
import unittest
from pathlib import Path

from services.source_analysis_worker import secrets
from services.source_analysis_worker.secrets import detect

ALNUM = (string.ascii_letters + string.digits) * 3
UPPER = (string.ascii_uppercase + string.digits) * 2
DASH = "-" * 5
# (file, rule expected or None, content): one labelled case per file.
POSITIVE = [
    (
        "keys/id_rsa",
        "private_key_block",
        f"{DASH}BEGIN RSA PRIVATE KEY{DASH}\nsynthetic-one\n{DASH}END RSA PRIVATE KEY{DASH}\n",
    ),
    ("keys/other.pem", "private_key_block", f"{DASH}BEGIN PRIVATE KEY{DASH}\nsynthetic-two\n"),
    ("keys/ssh", "private_key_block", f"{DASH}BEGIN OPENSSH PRIVATE KEY{DASH}\nsynthetic-three\n"),
    ("config/aws.ini", "aws_access_key_id", "\n\nkey = " + "AKIA" + UPPER[3:19] + "\n"),
    ("config/sts.env", "aws_access_key_id", "ID=" + "ASIA" + UPPER[7:23]),
    ("ci/deploy.yml", "github_token", "token: " + "ghp_" + ALNUM[5:41]),
    ("ci/app.txt", "github_token", "ghs_" + ALNUM[9:45] + " # server token"),
    ("chat/hook.py", "slack_token", 'T = "' + "xoxb-" + "1234567890-" + ALNUM[2:26] + '"'),
    ("maps/key.js", "google_api_key", "const k='" + "AIza" + ALNUM[11:46] + "';"),
    ("pay/live.rb", "stripe_live_key", "sk_" + "live_" + ALNUM[4:32]),
    ("ai/claude.env", "anthropic_api_key", "KEY=" + "sk-" + "ant-" + "api03-" + ALNUM[1:49]),
    ("ai/other.env", "openai_api_key", "KEY=" + "sk-" + "proj-" + ALNUM[6:54]),
]
NEGATIVE = [
    ("keys/public.pem", None, f"{DASH}BEGIN PUBLIC KEY{DASH}\nabc\n"),
    ("keys/cert.pem", None, f"{DASH}BEGIN CERTIFICATE{DASH}\nabc\n"),
    ("docs/aws.md", None, "Use a key like " + "AKIA" + "X" * 16 + " (placeholder)"),
    ("docs/short.md", None, "AKIA" + UPPER[3:18]),  # one character short
    ("docs/embedded.md", None, "X" + "AKIA" + UPPER[3:19] + "Z"),  # part of a longer word
    ("docs/github.md", None, "ghp_" + "x" * 36),
    ("docs/gh-short.md", None, "ghp_" + ALNUM[5:40]),
    ("pay/test.rb", None, "sk_" + "test_" + ALNUM[4:32]),
    ("docs/prose.md", None, "xoxb-" + "this-is-just-ordinary-hyphenated-text"),
    ("docs/sk.md", None, "sk-" + "ant-" + "short"),
    ("src/app.py", None, "password = input()\nAPI_KEY = os.environ['API_KEY']\n"),
    ("src/empty.txt", None, ""),
]


class SecretDetectionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve() / "tree"
        self.root.mkdir()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def test_labelled_tree_is_classified_exactly_and_no_secret_text_is_returned(self):
        for name, _rule, content in POSITIVE + NEGATIVE:
            self.write(name, content)
        result = detect(self.root)
        self.assertIn("not verified", result["basis"])
        self.assertEqual(result["files_scanned"], len(POSITIVE) + len(NEGATIVE))
        found = {(match["file"], match["rule"]) for match in result["matches"]}
        expected = {(name, rule) for name, rule, _content in POSITIVE}
        # Measured on this 20-file tree: every seeded secret found, no look-alike reported.
        self.assertEqual((sorted(expected - found), sorted(found - expected)), ([], []))
        self.assertEqual(len(result["matches"]), len(POSITIVE))
        text = json.dumps(result)
        for _name, _rule, content in POSITIVE:
            for word in content.split():
                if len(word) >= 16:
                    self.assertNotIn(word.strip("'\";"), text)
        by_file = {match["file"]: match for match in result["matches"]}
        self.assertEqual(by_file["config/aws.ini"]["line"], 3)
        # Different keys with the same header get different fingerprints; a fingerprint is stable.
        self.assertNotEqual(by_file["keys/id_rsa"]["fingerprint"], by_file["keys/other.pem"]["fingerprint"])
        self.assertEqual(result["matches"], detect(self.root)["matches"])

    def test_special_oversized_vendored_and_linked_files_are_not_read(self):
        token = "ghp_" + ALNUM[5:41]
        outside = self.write("../outside.txt", token)
        (self.root / "link.txt").symlink_to(outside)
        os.mkfifo(self.root / "pipe")
        self.write("node_modules/dep/leak.js", token)
        self.write(".git/config", token)
        self.write("big.bin", b"a" * (5 * 1024 * 1024 + 1) + token.encode())
        result = detect(self.root)
        self.assertEqual((result["matches"], result["files_scanned"]), ([], 0))
        self.assertEqual(
            {(item["file"], item["reason"]) for item in result["skipped"]},
            {
                ("link.txt", "file is not a regular file"),
                ("pipe", "file is not a regular file"),
                ("big.bin", "file is larger than the parsing budget"),
            },
        )

    def test_output_is_bounded_per_file_and_in_total(self):
        token = "ghp_" + ALNUM[5:41]
        self.write("many.txt", "\n".join(token[:-3] + f"{n:03d}" for n in range(150)))
        self.assertEqual(len(detect(self.root)["matches"]), secrets.MAX_MATCHES_PER_FILE)
        for index in range(5):
            self.write(f"f{index}.txt", token)
        original = secrets.MAX_FILES
        secrets.MAX_FILES = 2
        self.addCleanup(setattr, secrets, "MAX_FILES", original)
        limited = detect(self.root)
        self.assertEqual(limited["files_scanned"], 2)
        self.assertEqual({item["reason"] for item in limited["skipped"]}, {"scan budget reached; not read"})

    def test_report_and_log_redaction_removes_bare_tokens(self):
        from packages.reporting import redact

        tokens = [
            "AKIA" + UPPER[3:19],
            "ghp_" + ALNUM[5:41],
            "xoxb-" + "1234567890-" + ALNUM[2:26],
            "AIza" + ALNUM[11:46],
            "sk_" + "live_" + ALNUM[4:32],
        ]
        for token in tokens:
            with self.subTest(token[:6]):
                cleaned = redact({"stdout": f"tool printed {token} here", "items": [token]})
                self.assertNotIn(token, str(cleaned))
                self.assertIn("tool printed", cleaned["stdout"])
        ordinary = "Assessment of 127.0.0.1 completed with 5 findings; skipped 2 checks."
        self.assertEqual(redact(ordinary), ordinary)

    def test_a_secret_in_a_file_name_is_redacted_and_lines_follow_file_order(self):
        name_token = "AKIA" + UPPER[3:19]
        first, second = "ghp_" + ALNUM[5:41], "AKIA" + UPPER[9:25]
        # The AWS-shaped id comes later in the file but its rule runs earlier.
        self.write(f"backup_{name_token}.txt", f"\n{first}\n\n\n{second}\n")
        result = detect(self.root)
        self.assertNotIn(name_token, json.dumps(result))
        self.assertEqual(
            [(m["rule"], m["line"], m["file"]) for m in result["matches"]],
            [("github_token", 2, "backup_[REDACTED].txt"), ("aws_access_key_id", 5, "backup_[REDACTED].txt")],
        )

    def test_untrusted_file_names_are_made_printable(self):
        self.write("odd\x1b[31mname.txt", "ghp_" + ALNUM[5:41])
        (match,) = detect(self.root)["matches"]
        self.assertNotIn("\x1b", match["file"])


if __name__ == "__main__":
    unittest.main()
