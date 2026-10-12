# End-to-End Design: Wiring Source and API Analysis into SHARAY

**Drafted by**: Gemini (Principal Architect) for Claude and Codex  
**Date**: October 12, 2026  
**Context**: Codex work package C3/C4/C5/C6 wiring Claude's tested L3/L6 analyzers (`extract_archive`, `dependencies.inventory`, `secrets.detect`, `openapi.ingest`) into the product.

---

## 1. Architectural Overview & Boundaries

The product currently operates single-target loopback HTTP assessments via `aegis/worker.py` and `safe_http`. Claude has built four tested, isolated analysis components in `services/source_analysis_worker` and `packages/scanner_adapters/integrations/openapi.py` that do not yet have API routes, database representation, worker jobs, or UI displays.

To wire these without breaking existing compatibility:
1. **Source Target Ingestion**: An operator registers a source artifact (uploaded zip/tar archive) or API description (OpenAPI JSON) under an existing project.
2. **Staged Isolated Job Execution**: A dedicated assessment profile (`source_analysis` or `api_inventory`) runs via `worker.py`, utilizing isolated staged extraction and execution.
3. **Observation vs. Finding Normalization**:
   - Informational structural facts (e.g. dependency manifest lists, declared endpoints, public API schemas) become `Observation` records.
   - Identified policy or security risks (e.g. high-confidence secret token matches, unauthenticated sensitive endpoints, deprecated HTTP basic schemes) become `Finding` records.
4. **Report & UI Integration**: Existing HTML/JSON/Markdown/PDF reporting templates and Next.js frontend pages render source analysis tabs and metrics.

---

## 2. Relational Schema & Migration (`migrations/`)

### New Model: `Artifact` (or extended `Target`)
Rather than rewriting `Target` (which has existing loopback HTTP constraints), we define `Artifact` attached to `targets` or `projects`:

```python
class ProjectArtifact(Base):
    __tablename__ = "project_artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))  # "source_archive" | "openapi_spec"
    filename: Mapped[str] = mapped_column(String(255))
    storage_path: Mapped[str] = mapped_column(Text)  # absolute path in private storage
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
```

In `Target`, add nullable `artifact_id: Mapped[str | None] = mapped_column(ForeignKey("project_artifacts.id"), nullable=True)`.

### Forward-Only Alembic Migration (`migrations/versions/0002_add_project_artifacts.py`)
- Standard forward-only script creating `project_artifacts` table.
- Adds `artifact_id` foreign key column to `targets`.
- No rollback migrations (preserving project immutability rules).

---

## 3. API Routes & Access Control (`aegis/api.py`, `aegis/schemas.py`)

### 1. `POST /api/v1/projects/{project_id}/artifacts/upload`
- **Role check**: `Analyst`, `Security Administrator`, or `Owner` in the current organization.
- **Payload**: Multipart form upload with byte streaming and strict length verification (maximum 100 MB).
- **Validation**:
  - Checks MIME / magic header (`PK\x03\x04` for zip, tar magic, or valid JSON object with `openapi` key).
  - Streams directly into a private organization-scoped upload spool (`.aegis/storage/organizations/{org_id}/spool/`).
  - Calculates SHA256 while streaming.
- **Creates**: `ProjectArtifact` row, and auto-registers a linked `Target` with `scope={"type": "artifact", "kind": kind, "sha256": hash}` and `verification_status="verified"`.
- **Audit**: Emits `artifact.uploaded` audit event.

### 2. `GET /api/v1/projects/{project_id}/artifacts`
- **Role check**: Any role (`Viewer`, `Analyst`, `Admin`, `Owner`).
- **Response**: List of project artifacts, metadata, sha256, and assessment status.

---

## 4. Assessment Orchestration & Worker Execution (`aegis/worker.py`)

### Worker Profile Dispatch
In `aegis/worker.py`, inspect `assessment.profile`:
- Profile `"safe_http"`: Existing loopback HTTP scanner.
- Profile `"source_analysis"`:
  1. Worker fetches the source archive `storage_path`.
  2. Runs staged sandboxed extraction into private temporary directory via runner (`run_staged_extraction`).
  3. Parent runs `validate_staged_tree()` (verifying node counts, byte budgets, modes, no symlinks, `st_nlink == 1`).
  4. Runs `dependencies.inventory()` over the validated staging tree.
  5. Runs `secrets.detect()` over the validated staging tree.
  6. Purges staging folder upon completion.
- Profile `"openapi_ingestion"`:
  1. Runs `openapi.ingest(artifact.storage_path)`.
  2. Discovers declared endpoints and security scheme facts.

### Observations vs. Findings Mapping
- **Observations** (`Observation` table):
  - Dependency inventory: each declared package pin `{"package": name, "version": ver, "source": src, "basis": basis}`.
  - OpenAPI endpoints: each discovered operation `{"method": M, "path": P, "authentication": auth}`.
- **Findings** (`Finding` and `FindingEvidence` tables):
  - Any secret detected by `secrets.detect()`:
    - `title`: `f"Potential hardcoded secret ({match['rule']})"`
    - `category`: `"secret_exposure"`
    - `severity`: `"high"` for private keys and AWS tokens; `"medium"` for Slack/Google keys.
    - `confidence`: `"high"`
    - `affected_url`: `f"file://{match['file']}#L{match['line']}"`
    - `fingerprint`: `hashlib.sha256(f"{target_id}|secret|{match['rule']}|{match['file']}|{match['fingerprint']}".encode()).hexdigest()`
    - Matched text is **never** included in `FindingEvidence`; only file, line, rule, and SHA256 fingerprint.
  - In OpenAPI analysis:
    - Observations like `api_key_declared_in_query_string` or `http_basic_authentication_declared` become findings with severity `"medium"` and remediation advice.

---

## 5. Reporting & UI Changes (`packages/reporting/`, `apps/web/`)

### Reporting (`packages/reporting/reports.py`)
- Add a new section `Source & API Analysis Summary` in HTML, Markdown, and PDF generators:
  - Total files scanned, manifest count, dependencies declared.
  - Secret pattern matches count (anonymized fingerprints only).
  - Open API endpoints discovered breakdown by authentication method.

### Frontend UI (`apps/web/`)
- In Project Detail view: Add tab **"Source & API Artifacts"** alongside "Targets" and "Assessments".
- File drag-and-drop uploader for `.zip`, `.tar.gz`, and `.json`.
- Action button "Run Source Assessment" launching queued assessment with profile `"source_analysis"`.

---

## 6. Implementation Order & Verification

1. **Step 1 (Schema & DB)**: Create migration `0002_add_project_artifacts.py` and model `ProjectArtifact`.  
   *Verify by*: `alembic upgrade head` and migration test.
2. **Step 2 (API Routes)**: Add upload route in `aegis/api.py` with auth and org checks.  
   *Verify by*: `tests/product/test_artifact_api.py` testing file upload, org scoping, and size limit rejection.
3. **Step 3 (Worker Pipeline)**: Add `source_analysis` execution in `aegis/worker.py` utilizing `staged_ingestion_validator.py`.  
   *Verify by*: `tests/integration/test_worker_source_analysis.py` running synthetic zip through worker end-to-end.
4. **Step 4 (Reporting & UI)**: Update `reports.py` and Next.js frontend pages.  
   *Verify by*: Existing report regression test and frontend static export `npm run build`.
