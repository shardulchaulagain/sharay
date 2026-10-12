# Self-update core — verify, decide, record

The human's requirement (October 12, `MAIN_PROMPT.txt`): SHARAY keeps its scanners, rules and advisory data current automatically, each update verified, tested before activation, reversible, and never widening scope by itself.

**What exists:** `services/update_worker/__init__.py`, the part with no network. Tests: `tests/integration/test_update_core.py`. **Nothing is downloaded, installed or scheduled yet**, and nothing calls this module.

An update goes CHECK → FETCH → VERIFY → EVALUATE → ACTIVATE, with ROLLBACK behind it (the staging outline is from Gemini's research, `drafts/gemini/self-update-research.md`). Built so far:

| Step | Built | Rule |
| --- | --- | --- |
| CHECK, FETCH | no | — |
| VERIFY | `verify_file` | The file must be a regular file (never a link, directory or pipe) of exactly the published size whose SHA-256 equals the published one. |
| EVALUATE | `regressions(baseline, candidate)` only | Lists disagreements in a candidate's corpus report that the baseline did not have, including scans that did not complete. Running the corpora against a candidate is not built. |
| ACTIVATE | `activate` | Refused unless: the URL lies under the component's one official source; the version is strictly newer than the active one; it was not rolled back before; the evidence says gates passed and regressions are an empty list; and the file verifies. The replaced version is kept. |
| ROLLBACK | `rollback` | Restores the replaced version and withdraws the failed one, which then needs a person to come back. |

Components and their only accepted sources: Gitleaks and Nuclei (their GitHub release downloads), Semgrep (PyPI files). Nuclei *templates* are deliberately not a component: new templates can add intrusive requests, so they need their own review step before any automatic update. Nmap and advisory data are not components yet.

The ledger is one JSON file (mode 0600, replaced atomically) holding the active pin, the previous pin, withdrawn versions and a history. A damaged, oversized or linked ledger stops updates rather than being guessed at or replaced.

Limits, stated plainly:

- The published SHA-256 comes from the same publisher over HTTPS. That detects corruption and a swapped file, not a compromised publisher. Signature verification is not built; the signing details in Gemini's research are unverified.
- "Activation" changes the ledger only. Nothing yet installs a file or makes the runner refuse a binary whose hash is not pinned; that link is the next piece.
- One updater at a time: the ledger has no lock yet.
- An update changes detection content only. This module imports nothing that holds scope, targets or approvals (a test checks its imports).

Open decision for the human: automatic updates mean downloading without asking each time. Today every download is named and confirmed first; unattended updates need that changed for the listed official sources, or they stay "checked automatically, downloaded on confirmation".
