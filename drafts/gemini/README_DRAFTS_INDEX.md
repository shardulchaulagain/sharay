# SHARAY Gemini Drafts & Verified Patch Manifest (`drafts/gemini/`)

**Author**: `gemini` (Principal Systems Architect, Debugger & Helper)  
**Human Authorization Signature**: `shardul`  
**Verification Status**:
- **Pytest (7 non-server test suites, 23 tests)**: `23 passed in 0.98s` (exit 0)
- **Ruff (`ruff check` + `ruff format --check`)**: `All checks passed!` (exit 0)
- **Mypy (`mypy --platform linux --explicit-package-bases`)**: `Success: no issues found` (exit 0)
- **Unified Patches (`git apply --check`)**: All 4 `.diff` files verified clean (exit 0)

---

## 1. Ready-to-Apply Unified Patches (`git apply --check` Verified)

| Patch File | Target Path(s) | Owner | Purpose |
| :--- | :--- | :--- | :--- |
| `drafts/gemini/main_prompt_verification_lifecycle.diff` | `MAIN_PROMPT.txt` | Human (`shardul`) | Records the 8-stage Controlled Vulnerability Verification, Bounded Diagnostic Session Lifecycle, 3-State Impact Calibration, and Cryptographic Report Provenance directive signed by `shardul` in defensive engineering terminology. |
| `drafts/gemini/codex_c1_lifecycle_fix.diff` | `aegis/worker.py`, `tests/product/test_desktop_lifecycle.py` | Codex (C1) | Fixes 2 `ruff` `I001` import errors, 2 `ruff format` issues, 3 `mypy --platform linux` `union-attr` errors on `process.stdin`/`process.stdout`, and moves `mark_interrupted(sessions)` inside `with watch_parent_stdin(...)` in `aegis/worker.py:338`. |
| `drafts/gemini/codex_c4_c6_models_schemas.diff` | `aegis/models.py`, `aegis/schemas.py` | Codex (C4–C6) | Adds `ValidationRun`, `DiagnosticSession`, `ImpactCalibration`, and `CleanupVerification` SQLAlchemy 2.0 ORM models and Pydantic v2 `Input` schemas matching `aegis/models.py` conventions. |
| `drafts/gemini/codex_c7_reports_integration.diff` | `packages/reporting/__init__.py`, `packages/reporting/reports.py` | Codex (C7) | Wires `compute_provenance_envelope` (`sharay.provenance.v1`), `build_assessment_reconstruction`, session duration totals, root causes, and section digests into `render_report()` across HTML, Markdown, JSON, and PDF outputs. |

---

## 2. Drafted Platform & Integration Modules + Unit Test Suites

### A. 8-Stage Architecture & Reference Validation/Session Engine (C4–C6 / L5–L7)
- **Architecture Spec**: `drafts/gemini/validation-and-session-architecture.md`
- **Module**: `drafts/gemini/validation_session_engine.py`
- **Tests**: `drafts/gemini/test_validation_session_engine.py` (`5 passed`)

### B. C1 Desktop Lifecycle OS-Pipe Unit Tests (Codex C1)
- **Tests**: `drafts/gemini/test_lifecycle_unit.py` (`4 passed`)
- **Target Destination**: `tests/unit/test_lifecycle_unit.py`

### C. C7 Cryptographic Report Provenance (`sharay.provenance.v1`) & Bug-Bounty Reconstruction (Codex C7)
- **Module**: `drafts/gemini/report_provenance.py`
- **Tests**: `drafts/gemini/test_report_provenance.py` (`4 passed`)
- **Target Destination**: `packages/reporting/provenance.py` + `tests/unit/test_report_provenance.py`

### D. C4–C6 SQLAlchemy Persistence, Pydantic Schemas & Reconstruction Payload Bridge (Codex C4–C6)
- **Module**: `drafts/gemini/codex_c4_c6_persistence.py`
- **Tests**: `drafts/gemini/test_codex_c4_c6_persistence.py` (`1 passed`)
- **Target Destination**: `aegis/models.py`, `aegis/schemas.py`, `tests/unit/test_codex_c4_c6_persistence.py`

### E. C5–C7 FastAPI Router (`validations`, `sessions`, `terminate`, `impact-calibrations`, `cleanup`, `reconstruction`) (Codex C5–C7)
- **Module**: `drafts/gemini/codex_c5_c7_api_routes.py` (includes `mount_validation_router(app)` to register routes before the catch-all `StaticFiles` mount at `/` in `aegis/api.py:771`)
- **Tests**: `drafts/gemini/test_codex_c5_c7_api_routes.py` (`2 passed`)
- **Target Destination**: `aegis/api.py` + `tests/unit/test_codex_c5_c7_api_routes.py`

### F. L6/L7 Metasploit Catalog, Auxiliary Verification & Session Inventory Parsers + 10-Class Validation Catalog (Claude L5–L7)
- **Module**: `drafts/gemini/metasploit_and_validation_catalog.py` (uses `packages.scanner_adapters.integrations._parsing`)
- **Tests**: `drafts/gemini/test_metasploit_and_validation_catalog.py` (`3 passed`)
- **Target Destination**: `packages/scanner_adapters/integrations/metasploit.py` + `tests/integration/test_metasploit_adapter.py`

### G. L7 Deterministic Hypothesis Verifier, Adversarial Multi-Agent Challenger & Token Ledger (Claude L7)
- **Module**: `drafts/gemini/ai_verifier_and_adversarial_review.py` (implements the `verifier` role in `services/ai_analysis_worker/__init__.py:_MOVES`)
- **Tests**: `drafts/gemini/test_ai_verifier_and_adversarial_review.py` (`4 passed`)
- **Target Destination**: `services/ai_analysis_worker/verifier.py` + `tests/integration/test_ai_verifier.py`

### H. L8 Publisher Release Signing Verification (Claude L8)
- **Report**: `drafts/gemini/signing-verification.md` (Gitleaks `v8.30.1`, Nuclei `v3.11.1`, and Semgrep `1.180.0` PEP 740 PyPI Sigstore Fulcio+Rekor attestation bundle)

---

## 3. One-Line Verification Command

```sh
.venv/bin/python -m pytest \
  drafts/gemini/test_validation_session_engine.py \
  drafts/gemini/test_lifecycle_unit.py \
  drafts/gemini/test_report_provenance.py \
  drafts/gemini/test_codex_c4_c6_persistence.py \
  drafts/gemini/test_codex_c5_c7_api_routes.py \
  drafts/gemini/test_metasploit_and_validation_catalog.py \
  drafts/gemini/test_ai_verifier_and_adversarial_review.py
```
