"""Ask Gemini (through Google's Antigravity CLI, `agy`) and file its reply in the shared log.

Three kinds of request: `review` (architecture, efficiency, what to build next), `debug`
(diagnose a failure, optionally with a test's real output attached) and `help` (draft code,
tests or documents when an owner's workload is heavy). The wrapper saves the returned
reply under drafts/gemini/ and appends it to the log as writer `gemini`, addressed to the
owner, who verifies and applies it. CLI workspace permissions are not enforced by this
wrapper or verified by stand-in tests. No reply, no entry.

    python -m scripts.gemini_review --to claude --focus "services/scanner_worker design"
    python -m scripts.gemini_review --to codex --mode debug --test tests/product/test_x.py --focus "why it fails"
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from packages.reporting import redact
from scripts.session_log import DEFAULT_LOG, ENTRY_ID, ROOT, append_entry

MAX_LOGGED = 10500  # the log accepts 12000 characters per entry
MAX_ATTACHED = 20000
TASKS = {
    "review": "This is a REVIEW request.",
    "debug": "This is a DEBUG request: find the root cause and give the smallest fix as a diff.",
    "help": "This is a HELP request: write the requested draft in full, each file under its path.",
}


def _test_output(test: str) -> str:
    """Run one existing test target and return the end of its real output for Gemini to read."""
    target = (ROOT / test.split("::")[0]).resolve()
    if not target.is_relative_to(ROOT / "tests") or not target.exists() or test.startswith("-"):
        raise RuntimeError("--test must name an existing file or folder under tests/.")
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "--tb=long", "--", test],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=600,
    )
    # Redact before taking the tail so a cut cannot discard a credential's field label.
    return (
        f"Output of pytest {redact(test)} (exit {run.returncode}):\n"
        + redact(run.stdout + run.stderr)[-MAX_ATTACHED:]
    )


def review(
    focus: str,
    to: str,
    *,
    mode: str = "review",
    requester: str = "human",
    test: str = "",
    reply_to: str = "",
    model: str = "",
    effort: str = "high",
    minutes: int = 15,
    log_path: Path = DEFAULT_LOG,
    drafts: Path = ROOT / "drafts" / "gemini",
) -> str:
    """Return the id of the log entry holding Gemini's reply; raise RuntimeError if there is none."""
    if (
        type(mode) is not str
        or mode not in TASKS
        or type(focus) is not str
        or not focus.strip()
        or len(focus) > 4000
    ):
        raise RuntimeError("Give a known mode and a review focus of 1 to 4000 characters.")
    if any(
        type(value) is not str or value not in allowed
        for value, allowed in (
            (to, ("codex", "claude", "human")),
            (requester, ("codex", "claude", "human")),
            (effort, ("low", "medium", "high")),
        )
    ):
        raise RuntimeError("Give a known recipient, requester and reasoning effort.")
    if type(minutes) is not int or not 1 <= minutes <= 60:
        raise RuntimeError("Review time must be an integer from 1 to 60 minutes.")
    if type(reply_to) is not str or (reply_to and not ENTRY_ID.fullmatch(reply_to)):
        raise RuntimeError("Reply references must be entry identifiers.")
    if any(type(value) is not str or len(value) > 1000 for value in (test, model)) or model.startswith("-"):
        raise RuntimeError("Test and model must be bounded strings; model cannot be a CLI option.")
    focus = redact(focus.strip())
    executable = shutil.which("agy")
    if not executable:
        raise RuntimeError(
            "The Antigravity CLI (agy) is not installed; nothing was asked and nothing was logged."
        )
    prompt = (
        "Follow GEMINI.md exactly, including its hard limits and the output format for this kind of request.\n"
        f"{TASKS[mode]} Requested by: {requester}. Your reply will be filed for: {to}.\n"
        f"Focus: {focus.strip()}"
    )
    if test:
        prompt += "\n\n" + _test_output(test)
    # Omit permission-bypass flags; actual CLI permission behavior is not verified here.
    command = [executable, "--output-format", "json", "--effort", effort, "--print-timeout", f"{minutes}m"]
    command += (["--model", model] if model else []) + ["-p", prompt]
    try:
        run = subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=minutes * 60 + 60,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Gemini did not answer within {minutes} minutes; nothing was logged.") from exc
    try:
        envelope = json.loads(run.stdout)
        answer = str(envelope.get("response") or "").strip() if envelope.get("status") == "SUCCESS" else ""
    except (ValueError, AttributeError):
        answer = ""
    if run.returncode != 0 or not answer:
        raise RuntimeError(f"agy exited {run.returncode} without a successful reply; nothing was logged.")
    answer = redact(answer)
    drafts.mkdir(parents=True, exist_ok=True, mode=0o700)
    # tempfile creates a unique file with O_EXCL and mode 0600, even under a permissive umask.
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=drafts,
        prefix=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-",
        suffix=f"-{mode}.md",
        delete=False,
    ) as stream:
        saved = Path(stream.name)
        stream.write(f"Requested by {requester} for {to}. Mode: {mode}. Focus: {focus}\n\n{answer}\n")
    shown = answer if len(answer) <= MAX_LOGGED else answer[:MAX_LOGGED] + "\n[continues in the saved file]"
    try:
        location = saved.relative_to(ROOT)
    except ValueError:
        location = saved
    # A recommendation stays in the owner's inbox until answered; an answer closes a thread.
    return append_entry(
        "gemini",
        "answer" if reply_to else "recommendation",
        f"Gemini {mode} requested by {requester}. Focus: {focus.strip()[:300]}\nFull reply: {location}\n\n{shown}",
        to=to,
        reply_to=reply_to,
        log_path=log_path,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--to", choices=("codex", "claude", "human"), required=True, help="Who must answer")
    parser.add_argument("--focus", required=True, help="What to review, debug or draft, in plain words")
    parser.add_argument("--mode", choices=tuple(TASKS), default="review")
    parser.add_argument(
        "--test", default="", help="debug: a test file or id under tests/ whose output is attached"
    )
    parser.add_argument("--requester", choices=("codex", "claude", "human"), default="human")
    parser.add_argument("--reply-to", default="", help="Entry id of a question addressed to gemini")
    parser.add_argument(
        "--model", default="", help="Model slug from `agy models`; default is agy's own choice"
    )
    parser.add_argument("--effort", choices=("low", "medium", "high"), default="high")
    args = parser.parse_args(argv)
    try:
        print(
            review(
                args.focus,
                args.to,
                mode=args.mode,
                requester=args.requester,
                test=args.test,
                reply_to=args.reply_to,
                model=args.model,
                effort=args.effort,
            )
        )
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"gemini_review: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
