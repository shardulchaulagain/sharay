"""Append attributable coordination checkpoints with an interprocess file lock.

Also the two-way channel: addressed praise/critique/question entries and an inbox
of entries that still await a writer's reply.
"""

import argparse
import fcntl
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from packages.reporting import redact

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = ROOT / "docs" / "SESSION_LOG.md"
KINDS = (
    "claim",
    "checkpoint",
    "verification",
    "review-request",
    "review-response",
    "recommendation",
    "handoff",
    "praise",
    "critique",
    "question",
    "answer",
    "help-request",
)
# These kinds, and any entry carrying a recommendation, stay open until the addressee replies.
NEEDS_REPLY = {"review-request", "recommendation", "critique", "question", "help-request"}
# gemini is the read-only architect reviewer; its entries are filed by scripts/gemini_review.py.
WRITERS = ("codex", "claude", "gemini", "human")
HEADER = re.compile(rf"^## (entry-[0-9a-f]{{16}}) — ({'|'.join(WRITERS)}) — ([a-z-]+) — (\S+)$")
ENTRY_ID = re.compile(r"entry-[0-9a-f]{16}")


def _body(value: str) -> str:
    """Keep quoted content from becoming log routing or a forged entry."""
    markers = ("## entry-", "To: ", "Reply to: ", "Recommendation / review request: ")
    return "\n".join("> " + line if line.startswith(markers) else line for line in value.strip().splitlines())


def read_log(log_path: Path = DEFAULT_LOG) -> str:
    if log_path.is_symlink():
        raise ValueError("Coordination log must not be a symbolic link")
    try:
        with log_path.open(encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_SH)
            return stream.read()
    except FileNotFoundError:
        return ""


def append_entry(
    agent: str,
    kind: str,
    summary: str,
    *,
    paths=(),
    checks=(),
    next_task="",
    reply_to="",
    recommendation="",
    to="",
    log_path: Path = DEFAULT_LOG,
) -> str:
    if agent not in WRITERS or kind not in KINDS or to not in ("", *WRITERS):
        raise ValueError("Use an explicit writer and a supported entry kind")
    if not summary.strip() or len(summary) > 12000:
        raise ValueError("Summary must contain 1–12000 characters")
    if reply_to and not ENTRY_ID.fullmatch(reply_to):
        raise ValueError("Reply references must be entry identifiers")
    if any(isinstance(value, (str, bytes, bytearray)) for value in (paths, checks)):
        raise ValueError("Paths and checks must be collections, not bare text")
    values = redact(
        {
            "summary": summary,
            "paths": list(paths),
            "checks": list(checks),
            "next": next_task,
            "reply_to": reply_to,
            "recommendation": recommendation,
        }
    )
    entry_id = "entry-" + uuid.uuid4().hex[:16]
    recorded = datetime.now(ZoneInfo("America/Chicago")).isoformat(timespec="seconds")
    lines = [f"\n## {entry_id} — {agent} — {kind} — {recorded}\n"]
    if to:
        lines.append("\nTo: " + to + "\n")
    lines.append("\n" + _body(values["summary"]) + "\n")
    if values["reply_to"]:
        lines.append("\nReply to: " + values["reply_to"] + "\n")
    for label, key in (("Affected paths", "paths"), ("Actual checks / outcomes", "checks")):
        if values[key]:
            lines.append("\n" + label + ":\n\n")
            lines.extend("- " + str(value).replace("\n", " ") + "\n" for value in values[key])
    if values["recommendation"]:
        lines.append("\nRecommendation / review request: " + _body(values["recommendation"]) + "\n")
    if values["next"]:
        lines.append("\nNext / unfinished work: " + _body(values["next"]) + "\n")
    if log_path.is_symlink():
        raise ValueError("Coordination log must not be a symbolic link")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write("".join(lines))
        stream.flush()
        os.fsync(stream.fileno())
    return entry_id


def inbox(agent: str, log_path: Path = DEFAULT_LOG) -> list[dict]:
    """Entries from other writers that ask for something and lack this writer's reply."""
    if agent not in WRITERS:
        raise ValueError("Use an explicit writer")
    entries: list[dict] = []
    answered = set()
    for line in read_log(log_path).splitlines():
        header = HEADER.match(line)
        if header:
            entries.append(
                dict(zip(("id", "from", "kind", "at"), header.groups()), to="", asks=False, summary="")
            )
        elif not entries:
            continue
        elif line.startswith("To: "):
            entries[-1]["to"] = line[4:].strip()
        elif line.startswith("Reply to: "):
            if entries[-1]["from"] == agent:
                answered.add(line[10:].strip())
        elif line.startswith("Recommendation / review request: "):
            entries[-1]["asks"] = True
        elif line.strip() and not entries[-1]["summary"]:
            entries[-1]["summary"] = line.strip()
    # An entry without a To line is addressed to every other writer, except the advisory
    # reviewer, which is only ever asked explicitly.
    return [
        entry
        for entry in entries
        if (entry["asks"] or entry["kind"] in NEEDS_REPLY)
        and entry["from"] != agent
        and (entry["to"] == agent or (not entry["to"] and agent != "gemini"))
        and entry["id"] not in answered
    ]


def inbox_text(agent: str, log_path: Path = DEFAULT_LOG) -> str:
    waiting = inbox(agent, log_path)
    lines = [
        f"{entry['id']}  {entry['from']} {entry['kind']}  {entry['at']}  {entry['summary'][:160]}"
        for entry in waiting
    ]
    lines.append(f"{len(waiting)} entr{'y' if len(waiting) == 1 else 'ies'} awaiting a reply from {agent}.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", choices=WRITERS, required=True)
    parser.add_argument("--kind", choices=KINDS, default="checkpoint")
    parser.add_argument("--summary", default="")
    parser.add_argument("--to", choices=WRITERS, default="", help="Writer who should reply")
    parser.add_argument("--inbox", action="store_true", help="List entries awaiting --agent's reply")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--check", action="append", default=[])
    parser.add_argument("--next", dest="next_task", default="")
    parser.add_argument("--reply-to", default="")
    parser.add_argument("--recommendation", default="")
    args = parser.parse_args(argv)
    try:
        if args.inbox:
            print(inbox_text(args.agent))
            return 0
        print(
            append_entry(
                args.agent,
                args.kind,
                args.summary,
                paths=args.path,
                checks=args.check,
                next_task=args.next_task,
                reply_to=args.reply_to,
                recommendation=args.recommendation,
                to=args.to,
            )
        )
        waiting = inbox(args.agent)
        if waiting:
            print(
                f"{len(waiting)} open item(s) still await your reply: "
                + ", ".join(entry["id"] for entry in waiting),
                file=sys.stderr,
            )
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
