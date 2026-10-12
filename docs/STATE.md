# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history. It supplements the required cold-start reads; the log and ledger hold the evidence.
Update the line you changed and its date. Last full edit: 2026-10-12 14:00, Claude.

## Health
- Last full run: 241 passed, four gates passed — `suite @tree=e5139fe0bc60` (Claude, 2026-10-12 14:18). Same hash and same environment: reuse it; otherwise rerun.
- Nothing is deployed. No scanner binary is installed. No live target can be assessed.

## Who is doing what
- **Codex (C1–C8):** handed off 13:58 (`entry-d923cf8eadb84a93`), nothing open; next: broader review of the AI core, verified live-target ownership (C3/C4), trusted staging and adoption (C5/C6).
- **Claude (L1–L8):** report parsers hardened through Codex's and Gemini's reviews; first L7 slice (plan validation, policy gate, hypothesis states; no model) posted for review; next: whatever those reviews find, Gemini's independent secret corpus adopted as v2 (first run 0.8/0.8, fixed); next: findings from Codex's AI-core review.
- **Gemini (advisory):** drafts only, under `drafts/gemini/`; no task open; its independent secret corpus was delivered and adopted. Several unrequested drafts are deferred, unreviewed.

## Built and tested, not connected to the product
Sandbox runner and staged extraction (`docs/integrations/ISOLATION.md`, `SOURCE_ANALYSIS.md`); Nmap builder/parser; Gitleaks, Semgrep and Nuclei report parsers; archive extraction; dependency inventory; secret detection; OpenAPI inventory (`API_INGESTION.md`); AI investigation core without a model (`AI_INVESTIGATION.md`); report parsers (`TOOL_REPORTS.md`); HTTP-check evaluation corpus (`EVALUATION.md`).

## Blocked, and on what
- Third-party scanners: not installed (human decision; draft plan in `drafts/gemini/scanner-install-plan.md`, unverified).
- Product use of any tool or ingestion: no memory cap or hard disk quota on macOS; live egress allowlist needs a container/VM backend.
- AI features: provider and data-sharing choice (human decision).

## Open decisions for the human
1. Install scanners? 2. Product AI provider? 3. May assistants reread `MAIN_PROMPT.txt` only when its hash changes (saves about 15k tokens per cold start)? Codex deferred this to you.

## Working rules that save tokens (agreed in `entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Entries about 900 characters; evidence in `--check`; detail in a file named by path.
- Record full runs as `suite @tree=<hash>` (`python -m scripts.log_view --tree`); iterate on affected test files only.
- Last entry read — Claude: entry-9189dff251da41fc.
