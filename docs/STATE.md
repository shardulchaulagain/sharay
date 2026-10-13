# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history; the log and ledger hold the evidence. Update the line you changed and its date.
Last full edit: 2026-10-12 19:03, Codex.
Codex refresh: 2026-10-13; C3 scope/API/UI1205283 and diagnostics/coordination0bf60e9 published with exact staged evidence and successful remote CI.

## Health
- Host: Apple Silicon Mac — arm64, macOS 26.6.2 (Darwin 25.6.0), Python 3.13.1 arm64. We build and run here, so every scanner/tool download and native dependency must be the **darwin-arm64** build (never x86_64); the isolation backend is macOS Seatbelt (`sandbox-exec`). (2026-10-13)
- Earlier Claude snapshot:241/four gates at e5139fe0bc60 (14:18); historical. Coordinate full suites; reuse only matching verified inputs/environment.
- Latest Codex snapshot: exact staged tree64894c350d7adcc8b0daf571600ef286f978032a,361 tests/3 skips/0 failures52.857095s, four gates passed; Python3.13.1/Darwin. Linux-target typing44 sources passed. Earlier mypy argv failure retained in `.engineering/reports/codex-diagnostics-staged/initial/`; final report under `final/`. Uncommitted L-half work excluded.
- CI: diagnostics0bf60e9 run38438591470 and C3 commit1205283 run38353376974 succeeded on Python3.11/3.13 and frontend, all recorded steps; confirmed via existing GitHub connector. Historical local snapshots remain separate.
- C1 `af52761`: clean staged tree0a3103c7 passed23 tests/Ruff/format/Linux types; three watcher mutants caught. Remote run38348549805 all3jobs successful.
- Backup: git, private remote `github.com/shardulchaulagain/sharay` (first commit a005277, 14:25). Never make it public; never commit credentials, stored data or evidence.
- Nothing is deployed. No live target can be assessed. Scanner downloads: approved 19:15 for three named files; see the log for which are installed.

## MAIN_PROMPT.txt
- SHA-256 `718376f5ef42e59b2c7581e1912ff7976f23cca8c508cc13a6da058415c83ac2` (changed 19:20: evening human decisions added). Reread it completely only if this differs from the hash you last read in full.
- Complete reads of this hash — Claude: yes (wrote the addition). Codex: yes (1138 lines). Gemini: not confirmed here. Only the evening decisions section changed from the prior complete-read hash.

## Who is doing what
- **Codex (C1–C8):** C3 published1205283;51 Python/15 frontend tests,5 mutants/native390px flow passed. Diagnostics0bf60e9 published;4 relevant mutants caught. SBOM privacy independently verified; current container privacy/completeness3tests/5subtests pass with2 caught mutants. Container semantics/Metasploit remain queued for owner review. C4 session draft unadopted; IDEA5 acceptance design and IDEA6 critique recorded.
- **Claude (L1–L8):** offline per human. Reported parser/AI/recon/update checks are attributed; unresolved release review prevents a blanket correctness claim. New integrations remain unwired. Metasploit is L4. Normalizer eight sources and arm64 activation are Claude/Gemini evidence, not root clean-export verification. READ runner max accepted per-stream cap10MiB, default65,536 bytes. Scanner/provider selection approvals are recorded in MAIN; provider data-sharing stays explicit. (2026-10-13)
- **Gemini (advisory):** container/Metasploit release drafts queued for Claude independent review. C3 recommendations reproduced/fixed. IDEA5 matrix answered; trusted predicates/cleanup remain unimplemented. IDEA6 catalog is advisory pending ambiguous-CWE and oracle/control fixes. No draft grants execution authority; DIAG-1 source review pending.

## Built and tested, not connected to the product
Separate parser/runner slices with attributed local checks: isolation/staged extraction, Nmap/Gitleaks/Semgrep/Nuclei/ZAP/Metasploit reports, TLS/DNS/assets/browser plans, source/dependency/secret/container/SBOM/OpenAPI readers, AI investigation/verifier/vendor adapters and evaluation corpora. Normalizer has eight sources per Claude/Gemini; root has not clean-export verified all new modules. Release defects remain queued. See `docs/integrations/` and `WIRING.md`; no external integration dispatch or provider call enabled.

## Human decisions, 2026-10-12 14:20 (full text in MAIN_PROMPT.txt)
1. Install scanners: yes. 2. AI: must be switchable between providers and models by configuration. 3. Reread MAIN_PROMPT.txt only when it changes: yes. 4. Private backup: done. 5. New requirement: SHARAY keeps its tools, rules and advisory data up to date automatically, verified and tested before activation, never widening scope by itself.

## Blocked, and on what
- Product use of any third-party tool or upload: no memory cap or hard disk quota on macOS; live egress allowlist needs a container/VM backend.
- AI analysis: no provider configured yet; data-sharing is a per-provider setting the human must switch on.

## Working rules that save tokens (`entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Entries about 900 characters; evidence in `--check`; detail in a file named by path. Verify, then post, in separate steps.
- Record full runs as `suite @tree=<hash>`; iterate on affected test files only.
- Last entry read — Claude: entry-e9bcb2ee954741bf.
