# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history; the log and ledger hold the evidence. Update the line you changed and its date.
Last full edit: 2026-10-12 14:30, Claude.

## Health
- Last full run: 241 passed, four gates passed — `suite @tree=e5139fe0bc60` (Claude, 14:18). Same hash and same environment: reuse it; otherwise rerun. Check no other suite is running first (`pgrep -fl "pytest|run_tests"`).
- Backup: git, private remote `github.com/shardulchaulagain/sharay` (first commit a005277, 14:25). Never make it public; never commit credentials, stored data or evidence.
- Nothing is deployed. No scanner binary is installed yet. No live target can be assessed.

## MAIN_PROMPT.txt
- SHA-256 `66784e99cd7aa7069661ca3e20b1e1bbc2d6bd7138236e8ff967e83a87d07f71` (changed 14:28: human decisions added). Reread it completely only if this differs from the hash you last read in full.
- Complete reads of this hash — Claude: yes. Codex: no. Gemini: no.

## Who is doing what
- **Codex (C1–C8):** reviewing the AI core; fixed redaction of dictionary keys; next: ownership verification (C3/C4), staging lifecycle (C5/C6).
- **Claude (L1–L8):** next: switchable AI providers (L7), scanner installs once the human confirms each download, self-update design.
- **Gemini (advisory):** drafts only, under `drafts/gemini/`; one named task at a time. Unrequested drafts are deferred, unreviewed.

## Built and tested, not connected to the product
Sandbox runner and staged extraction (`docs/integrations/ISOLATION.md`, `SOURCE_ANALYSIS.md`); report parsers for Nmap, Gitleaks, Semgrep, Nuclei (`TOOL_REPORTS.md`); archive extraction; dependency inventory; secret detection; OpenAPI inventory (`API_INGESTION.md`); AI investigation core without a model (`AI_INVESTIGATION.md`); two evaluation corpora (`EVALUATION.md`).

## Human decisions, 2026-10-12 14:20 (full text in MAIN_PROMPT.txt)
1. Install scanners: yes. 2. AI: must be switchable between providers and models by configuration. 3. Reread MAIN_PROMPT.txt only when it changes: yes. 4. Private backup: done. 5. New requirement: SHARAY keeps its tools, rules and advisory data up to date automatically, verified and tested before activation, never widening scope by itself.

## Blocked, and on what
- Product use of any third-party tool or upload: no memory cap or hard disk quota on macOS; live egress allowlist needs a container/VM backend.
- AI analysis: no provider configured yet; data-sharing is a per-provider setting the human must switch on.

## Working rules that save tokens (`entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Entries about 900 characters; evidence in `--check`; detail in a file named by path. Verify, then post, in separate steps.
- Record full runs as `suite @tree=<hash>`; iterate on affected test files only.
- Last entry read — Claude: entry-c7b8a322024445ad.
