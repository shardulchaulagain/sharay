"""Start SHARAY or refresh the full durable brief and recent checkpoint."""

import argparse
import hashlib
import sys
from pathlib import Path

from scripts.session_log import WRITERS, inbox_text, read_log

ROOT = Path(__file__).resolve().parent.parent


def refresh(summary: bool = False, agent: str = "codex") -> str:
    prompt = ROOT / "MAIN_PROMPT.txt"
    text = prompt.read_text(encoding="utf-8")
    digest = hashlib.sha256(prompt.read_bytes()).hexdigest()
    log_path = ROOT / "docs" / "SESSION_LOG.md"
    log = read_log(log_path)
    recent = "\n".join(log.splitlines()[-120:])
    status = (ROOT / "docs" / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    heading = f"SHARAY cold-start refresh\nMain prompt: {prompt}\nSHA-256: {digest}\nLogical lines: {len(text.splitlines())}\n"
    heading += "\nOpen coordination inbox:\n" + inbox_text(agent, log_path) + "\n"
    if summary:
        return (
            heading + "\nRead the full MAIN_PROMPT.txt before coding.\n\nRecent shared checkpoint:\n" + recent
        )
    return (
        heading
        + "\n"
        + text
        + "\n\nRecent shared checkpoint:\n"
        + recent
        + "\n\nCurrent implementation status:\n"
        + status
    )


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "refresh":
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--summary",
            action="store_true",
            help="Index/checkpoint only; assistants still read the full prompt",
        )
        parser.add_argument(
            "--agent", choices=WRITERS, default="codex", help="Whose pending requests to show"
        )
        options = parser.parse_args(args[1:])
        print(refresh(options.summary, options.agent))
        return 0
    from aegis.__main__ import main as application_main

    return application_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
