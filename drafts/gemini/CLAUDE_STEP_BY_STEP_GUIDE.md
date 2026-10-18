# Step-by-Step Execution Guide for Claude (L3 / L6 / L7 / L8)

**From**: `gemini` (Principal Architect, Debugger & Helper)  
**To**: `claude` (Integrations Owner, L1–L8)  
**Human Architect Authorization**: `shardul`

Because we are co-working while Codex's session limit is paused, and I (`gemini`) am actively watching `docs/SESSION_LOG.md` and `docs/IDEAS_LOG.md` every 60 seconds to review and debug your code, here is the exact, bite-sized sequence of tasks in **your owned paths**. Do **one step at a time**, run the listed pytest/ruff/mypy command, and post to `docs/SESSION_LOG.md` so I can immediately verify and debug your changes:

---

## Step 1: Adopt & Test L6 Metasploit Parser + 10-Class Validation Catalog (`packages/scanner_adapters/integrations/metasploit.py`)
1. Read `drafts/gemini/metasploit_and_validation_catalog.py` and `drafts/gemini/test_metasploit_and_validation_catalog.py`.
2. It uses your exact helpers in `packages/scanner_adapters/integrations/_parsing.py` (`load_json`, `text`, `http_location`, `port_suffix`, `label`, `shown`, `fingerprint`, `MAX_FINDINGS`).
3. Copy/adapt it into `packages/scanner_adapters/integrations/metasploit.py` and `tests/integration/test_metasploit_adapter.py`.
4. Verify with:
   ```sh
   .venv/bin/ruff check packages/scanner_adapters/integrations/metasploit.py tests/integration/test_metasploit_adapter.py
   .venv/bin/mypy --platform linux --explicit-package-bases packages/scanner_adapters/integrations/metasploit.py tests/integration/test_metasploit_adapter.py
   .venv/bin/python -m pytest tests/integration/test_metasploit_adapter.py
   ```

---

## Step 2: Adopt & Test L3/L6-to-`Finding` Normalizer Bridge (`packages/scanner_adapters/integrations/normalize.py`)
1. Read `drafts/gemini/finding_normalizer.py` and `drafts/gemini/test_finding_normalizer.py`.
2. Copy/adapt it into `packages/scanner_adapters/integrations/normalize.py` and `tests/integration/test_finding_normalizer.py`.
3. Verify with:
   ```sh
   .venv/bin/ruff check packages/scanner_adapters/integrations/normalize.py tests/integration/test_finding_normalizer.py
   .venv/bin/mypy --platform linux --explicit-package-bases packages/scanner_adapters/integrations/normalize.py tests/integration/test_finding_normalizer.py
   .venv/bin/python -m pytest tests/integration/test_finding_normalizer.py
   ```

---

## Step 3: Adopt & Test L7 Deterministic Hypothesis Verifier & Adversarial Challenger (`services/ai_analysis_worker/verifier.py`)
1. Read `drafts/gemini/ai_verifier_and_adversarial_review.py` and `drafts/gemini/test_ai_verifier_and_adversarial_review.py`.
2. It implements the `verifier` role already declared in `services/ai_analysis_worker/__init__.py:_MOVES` (`verify_testing_outcome`, `parse_challenge_verdict`, `apply_adversarial_challenge`, `TokenUsageLedger`).
3. Copy/adapt it into `services/ai_analysis_worker/verifier.py` and `tests/integration/test_ai_verifier.py`.
4. Verify with:
   ```sh
   .venv/bin/ruff check services/ai_analysis_worker/verifier.py tests/integration/test_ai_verifier.py
   .venv/bin/mypy --platform linux --explicit-package-bases services/ai_analysis_worker/verifier.py tests/integration/test_ai_verifier.py
   .venv/bin/python -m pytest tests/integration/test_ai_verifier.py
   ```

---

## Step 4: Nuclei 3.11.1 & Semgrep 1.180.0 Real-Binary Verification (L3/L8)
1. Read `drafts/gemini/signing-verification.md` for the verified SHA-256 digests and Semgrep's PEP 740 PyPI Sigstore attestation bundle:
   - **Nuclei 3.11.1 (`nuclei_3.11.1_macOS_arm64.zip`)**: `d4591643da3f98ee309025792e0d41fb555de115d7134ed0229050abbe8a5aa9`
   - **Semgrep 1.180.0 (`semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl`)**: `9c61070eaa7de785a8318e1d00de6c9151efa660cc3e58c3e2ffd6f5e6180af7`
2. Add `build_argv` and `suppression_files(root)` (checking `.semgrepignore`) to `packages/scanner_adapters/integrations/semgrep.py` and `nuclei.py`, using a file inside the per-run scratch directory for report output (see `IDEA 4` in `docs/IDEAS_LOG.md`).
