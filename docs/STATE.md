# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history; the log and ledger hold the evidence. Update the line you changed and its date.
Last full edit: 2026-10-12 19:03, Codex.
Codex refresh: 2026-10-14; C4 origin pacing fixed locally, exact staged verification next. Communication first, five-minute cadence; C8-REFRESH/C4-PACING Gemini reviews received.

## Health
- Host: Apple Silicon Mac — arm64, macOS 26.6.2 (Darwin 25.6.0), Python 3.13.1 arm64. We build and run here, so every scanner/tool download and native dependency must be the **darwin-arm64** build (never x86_64); the isolation backend is macOS Seatbelt (`sandbox-exec`). (2026-10-13)
- Earlier Claude snapshot:241/four gates at e5139fe0bc60 (14:18); historical. Coordinate full suites; reuse only matching verified inputs/environment.
- Latest Codex snapshot: exact staged tree64894c350d7adcc8b0daf571600ef286f978032a,361 tests/3 skips/0 failures52.857095s, four gates passed; Python3.13.1/Darwin. Linux-target typing44 sources passed. Earlier mypy argv failure retained in `.engineering/reports/codex-diagnostics-staged/initial/`; final report under `final/`. Uncommitted L-half work excluded.
- CI: diagnostics0bf60e9 run38438591470 and C3 commit1205283 run38353376974 succeeded on Python3.11/3.13 and frontend, all recorded steps; confirmed via existing GitHub connector. Historical local snapshots remain separate.
- C1 `af52761`: clean staged tree0a3103c7 passed23 tests/Ruff/format/Linux types; three watcher mutants caught. Remote run38348549805 all3jobs successful.
- Backup: git, private remote `github.com/shardulchaulagain/sharay` (first commit a005277, 14:25). Never make it public; never commit credentials, stored data or evidence.
- Nothing is deployed. No live target can be assessed. Scanner downloads: approved 19:15 for three named files; see the log for which are installed.

## MAIN_PROMPT.txt
- SHA-256 `1289a49d25babccd0b93d40749c55531753fe692f16364d0781a111a5fc97447` (October14 communication cadence/format update only). Reread completely if it differs from your last complete read.
- Complete reads of this hash — Codex: yes (1138 lines, including corrected hash-read guidance); Claude/Gemini: not confirmed for the new hash. Original requirements retained.

## Who is doing what
- **Codex (C1–C8):** C3/diagnostics published1205283/0bf60e9; compact refresh published5d8b6b4, CI38516112555 all3jobs passed. C4 pacing10 requester tests pass; dropped-shared-state/GET-refresh mutants caught. C4 drafts unadopted; IDEA5/6/7 boundaries in ideas log. Exact C4 staged verification next.
- **Claude (L1–L8):** live October14; container stage inheritance/last-healthcheck fixed, root5 requester tests and4 scoped mutations verified. Metasploit four semantic fixes independently reviewed; catalog16 classes/269 tests remain owner-attributed. External integrations stay unwired; new modules require owner clean-export verification. Provider data-sharing stays explicit.
- **Gemini (advisory):** container/Metasploit drafts queued for owner review. DIAG-1 review received; bounded diagnostics checks agree with root evidence, not attestation. IDEA5/6 and new resilience draft remain advisory; trusted predicates and execution controls are unimplemented. No draft grants execution authority.

## Built and tested, not connected to the product
Separate parser/runner slices with attributed local checks: isolation/staged extraction, Nmap/Gitleaks/Semgrep/Nuclei/ZAP/Metasploit reports, TLS/DNS/assets/browser plans, source/dependency/secret/container/SBOM/OpenAPI readers, AI investigation/verifier/vendor adapters and evaluation corpora. Normalizer has eight sources per Claude/Gemini; root has not clean-export verified all new modules. Release defects remain queued. See `docs/integrations/` and `WIRING.md`; no external integration dispatch or provider call enabled.

## Human decisions, 2026-10-12 14:20 (full text in MAIN_PROMPT.txt)
1. Install scanners: yes. 2. AI: must be switchable between providers and models by configuration. 3. Reread MAIN_PROMPT.txt only when it changes: yes. 4. Private backup: done. 5. New requirement: SHARAY keeps its tools, rules and advisory data up to date automatically, verified and tested before activation, never widening scope by itself.

## Blocked, and on what
- Product use of any third-party tool or upload: no memory cap or hard disk quota on macOS; live egress allowlist needs a container/VM backend.
- AI analysis: no provider configured yet; data-sharing is a per-provider setting the human must switch on.

## Working rules that save tokens (`entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Check about every5 minutes; one topic/2–4 short lines, summary ≤600 chars when practical. Evidence in `--check`, longer detail by path. Only changes, requests or answers; verify before posting.
- Record full runs as `suite @tree=<hash>`; iterate on affected test files only.
- Last entry read — Claude: entry-e9bcb2ee954741bf.
- Last entry read — Codex: entry-7394b543f9b74251 (Gemini C4 review and Claude catalog note included).
