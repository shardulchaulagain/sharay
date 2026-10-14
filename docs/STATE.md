# SHARAY — current state (edit in place; keep under 50 lines)

A current index, not a history; the log and ledger hold the evidence. Update the line you changed and its date.
Last full edit: 2026-10-12 19:03, Codex.
Codex refresh: 2026-10-14; C4 durable228158a published after82 exact-export cases; full384/3skips pass57.845s locally. Initial CI60s timeout retained; unit-gate90s follow-up under verification.

## Health
- Host: Apple Silicon Mac — arm64, macOS 26.6.2 (Darwin 25.6.0), Python 3.13.1 arm64. We build and run here, so every scanner/tool download and native dependency must be the **darwin-arm64** build (never x86_64); the isolation backend is macOS Seatbelt (`sandbox-exec`). (2026-10-13)
- Earlier Claude snapshot:241/four gates at e5139fe0bc60 (14:18); historical. Coordinate full suites; reuse only matching verified inputs/environment.
- Latest Codex full snapshot: published tree df62cc8cf20548127b511c6c307f387905549e40,384tests/3skips/0failures57.845s; Python3.13.1/Darwin. Initial CI38523088548 unit60.137s timeout, static/frontend passed. Older diagnostics failure/pass evidence retained; L working source excluded.
- CI: C4 commit61fd266 run38519009997, refresh5d8b6b4 run38516112555, diagnostics0bf60e9 run38438591470 and C3 commit1205283 run38353376974 all succeeded on Python3.11/3.13 and frontend/all recorded steps; existing GitHub connector confirmed.
- C1 `af52761`: clean staged tree0a3103c7 passed23 tests/Ruff/format/Linux types; three watcher mutants caught. Remote run38348549805 all3jobs successful.
- Backup: git, private remote `github.com/shardulchaulagain/sharay` (first commit a005277, 14:25). Never make it public; never commit credentials, stored data or evidence.
- Nothing is deployed. No live target can be assessed. Scanner downloads: approved 19:15 for three named files; see the log for which are installed.

## MAIN_PROMPT.txt
- SHA-256 `1289a49d25babccd0b93d40749c55531753fe692f16364d0781a111a5fc97447` (October14 communication cadence/format update only). Reread completely if it differs from your last complete read.
- Complete reads of this hash — Codex: yes (1138 lines, including corrected hash-read guidance); Claude/Gemini: not confirmed for the new hash. Original requirements retained.

## Who is doing what
- **Codex (C1–C8):** C4 durable228158a/tree df62cc8c:82 exact-export cases/static pass,3 mutants caught. Initial CI timeout; unit90s/test typing follow-up next. One locked worker/database; workspaces/workers uncoordinated. C4 drafts unadopted; C3/C4/C5 live prerequisites still unbuilt.
- **Claude (L1–L8):** October14 reports Podman6.1.4/10GB VM initialized but unstarted; fail-closed container runner5cases owner-attributed, per-destination egress unimplemented. Usage-limit handoff retained. Container parser fixes independently checked; catalog/provider milestones remain attributed, not root live attestation.
- **Gemini (advisory):** container/Metasploit drafts queued for owner review. DIAG-1 review received; bounded diagnostics checks agree with root evidence, not attestation. IDEA5/6 and new resilience draft remain advisory; trusted predicates and execution controls are unimplemented. No draft grants execution authority.

## Built and tested, not connected to the product
Separate parser/runner slices with attributed local checks: isolation/staged extraction, Nmap/Gitleaks/Semgrep/Nuclei/ZAP/Metasploit reports, TLS/DNS/assets/browser plans, source/dependency/secret/container/SBOM/OpenAPI readers, AI investigation/verifier/vendor adapters and evaluation corpora. Normalizer has eight sources per Claude/Gemini; root has not clean-export verified all new modules. Release defects remain queued. See `docs/integrations/` and `WIRING.md`; no external integration dispatch or provider call enabled.

## Human decisions, 2026-10-12 14:20 (full text in MAIN_PROMPT.txt)
1. Install scanners: yes. 2. AI: must be switchable between providers and models by configuration. 3. Reread MAIN_PROMPT.txt only when it changes: yes. 4. Private backup: done. 5. New requirement: SHARAY keeps its tools, rules and advisory data up to date automatically, verified and tested before activation, never widening scope by itself.

## Blocked, and on what
- Product tool/upload use: Seatbelt lacks required memory/live egress bounds; Podman is now callable, VM/runtime controls and exact destination allowlist not attested. Product dispatch stays disabled.
- AI analysis: Claude reports credential/TLS probe;503 is not completion/auth proof. Product provider/evidence-sharing/readiness adoption remains unconnected; root read no key.

## Working rules that save tokens (`entry-ce26ecf918404a45`)
- Start with `python -m scripts.session_log --agent <you> --inbox`, then `python -m scripts.log_view --agent <you> --brief --since <last id you read>`.
- Check about every5 minutes; one topic/2–4 short lines, summary ≤600 chars when practical. Evidence in `--check`, longer detail by path. Only changes, requests or answers; verify before posting.
- Record full runs as `suite @tree=<hash>`; iterate on affected test files only.
- Last entry read — Claude: entry-e9bcb2ee954741bf.
- Last entry read — Codex: entry-d8588e1eec20472e; ideas entry-681df51b0305409f answered. Provider/scanner milestones remain owner-attributed; C4 owner/Gemini code reviews tracked in session log.
