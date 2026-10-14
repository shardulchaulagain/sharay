# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history; the log and ledger hold the evidence. Update the line you changed and its date.
Last full edit: 2026-10-12 19:03, Codex.
Codex refresh: 2026-10-14; C4 broad registration64b9fa6/tree4af8a855 verified:393tests/3skips,4gates,18UItests/build and CI38550982099 all3jobs/steps pass. C7 history731294f CI38552251381 all3jobs/steps pass; C6 non-object evidence regression reproduced/fixed, exact export next. Live execution remains unavailable.

## Health
- Host: Apple Silicon Mac — arm64, macOS 26.6.2 (Darwin 25.6.0), Python 3.13.1 arm64. We build and run here, so every scanner/tool download and native dependency must be the **darwin-arm64** build (never x86_64); the isolation backend is macOS Seatbelt (`sandbox-exec`). (2026-10-13)
- Earlier Claude snapshot:241/four gates at e5139fe0bc60 (14:18); historical. Coordinate full suites; reuse only matching verified inputs/environment.
- Latest Codex full snapshot: published tree df62cc8cf20548127b511c6c307f387905549e40,384tests/3skips/0failures57.845s; Python3.13.1/Darwin. Initial CI38523088548 unit60.137s timeout, static/frontend passed. Older diagnostics failure/pass evidence retained; L working source excluded.
- CI:64b9fa6 run38550982099 all Python3.11/3.13/frontend jobs/steps succeeded, existing GitHub connector confirmed. Exact-export393tests/3skips61.238410s plus4gates/18UItests/build pass. Earlier60s failure retained; product budgets unchanged.
- C1 `af52761`: clean staged tree0a3103c7 passed23 tests/Ruff/format/Linux types; three watcher mutants caught. Remote run38348549805 all3jobs successful.
- Backup: git, private remote `github.com/shardulchaulagain/sharay` (first commit a005277, 14:25). Never make it public; never commit credentials, stored data or evidence.
- Nothing is deployed. No live target can be assessed. Scanner downloads: approved 19:15 for three named files; see the log for which are installed.

## MAIN_PROMPT.txt
- SHA-256 `1289a49d25babccd0b93d40749c55531753fe692f16364d0781a111a5fc97447` (October14 communication cadence/format update only). Reread completely if it differs from your last complete read.
- Complete reads of this hash — Codex: yes (1138 lines, including corrected hash-read guidance); Claude/Gemini: not confirmed for the new hash. Original requirements retained.

## Who is doing what
- **Codex (C1–C8):** C4 broad inventory/API/UI64b9fa6 verified/pushed; six Gemini cases, extra regressions/3mutants, actual browser registration/authorization/blockers and390px layout pass. C7 history fix731294f verified/pushed; C6 invalid JSON snapshot guard under verification. One worker; rate ceiling10, concurrency ceiling5, actual1.
- **Claude (L1–L8):** reports Podman VM no-network smoke passed, but rootful bridge allow/deny+literal-shell tests passed (owner); Codex caught/fixed quoting through owner review, tool-argv filtering requester test still fails3cases. Codex independently replayed UTF-8 provider fix offline; actual-opener mutation now caught and budget fixture hermetic; redirect proxy400 false-pass gap remains.
- **Gemini (senior technical lead):** directs priorities/architecture/review; Codex/Claude implement and independently verify. C4 review accepted; interactive draft gaps reproduced. Agreed bounded worker reuse; IDEA9 review pending in ideas channel. No draft or log grants assessment/deployment authority.

## Built and tested, not connected to the product
Separate parser/runner slices with attributed local checks: isolation/staged extraction, Nmap/Gitleaks/Semgrep/Nuclei/ZAP/Metasploit reports, TLS/DNS/assets/browser plans, source/dependency/secret/container/SBOM/OpenAPI readers, AI investigation/verifier/vendor adapters and evaluation corpora. Normalizer has eight sources per Claude/Gemini; root has not clean-export verified all new modules. Release defects remain queued. See `docs/integrations/` and `WIRING.md`; no external integration dispatch or provider call enabled.

## Human decisions, 2026-10-12 14:20 (full text in MAIN_PROMPT.txt)
1. Install scanners: yes. 2. AI: must be switchable between providers and models by configuration. 3. Reread MAIN_PROMPT.txt only when it changes: yes. 4. Private backup: done. 5. New requirement: SHARAY keeps its tools, rules and advisory data up to date automatically, verified and tested before activation, never widening scope by itself.

## Blocked, and on what
- Product tool/upload use: Rootful single-destination allow/deny is owner-attributed; argv preservation/output/readiness review remains. Live successor still unconnected. Broad inventory does not enable dispatch.
- AI analysis: Claude reports credential/TLS probe;503 is not completion/auth proof. Product provider/evidence-sharing/readiness adoption remains unconnected; root read no key.

## Working rules that save tokens (`entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Check about every5 minutes; one topic/2–4 short lines, summary ≤600 chars when practical. Evidence in `--check`, longer detail by path. Only changes, requests or answers; verify before posting.
- Record full runs as `suite @tree=<hash>`; iterate on affected test files only.
- Last entry read — Claude: entry-e9bcb2ee954741bf.
- Last entry read — Codex: entry-0af5caf8cf764d36; ideas681df51 answered, IDEA9 proposal ae1d443 pending counterpart ideas reply. C4 Gemini review512a02 accepted; provider/scanner milestones remain attributed where not independently replayed.
