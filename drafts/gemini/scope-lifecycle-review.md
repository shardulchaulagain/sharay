Reviewed: aegis/api.py, aegis/schemas.py, aegis/models.py, aegis/serialization.py, aegis/audit.py, aegis/worker.py, packages/security_policies/__init__.py, packages/shared_schemas/__init__.py, tests/product/test_api_workflow.py, tests/product/test_policy_scanner.py, docs/SECURITY_CONTROLS.md, docs/IMPLEMENTATION_STATUS.md, MAIN_PROMPT.txt

Executed checks in this session:
- Ran `.venv/bin/python -m pytest tests/product/test_policy_scanner.py -k PolicyTests` -> exit 0, 7 passed in 0.12s.
- All findings and reproductions below are reasoned from reading the cited source lines and verified against the schema/handler logic without network calls, target scans, or product file edits.

1. Fix: Target approval bypasses archived-project checks, idempotency replay bypasses archive/expiry/version checks, and expired-scope launch rejections roll back without an audit event or status update.
   Evidence:
   - `aegis/api.py:419-435` (`approve`): loads `row = owned(db, Target, target_id, user)` and validates `row.scope`, but never loads `Project` or checks `project.archived` (unlike `create_target` at lines 394-396 and `launch` at lines 440, 451-452). Approving a target under an archived project succeeds (`200 OK`), mutates `verification_status` to `"verified_lab"`, and writes `scope.lab_approved`.
   - `aegis/api.py:441-457` (`launch`): returns `assessment_view(previous)` (`201 Created`) on `idempotency_key` match (lines 447-450) before checking `project.archived` (line 451), `target.verification_status` (line 453), `validate_scope(target.scope, target.url)` (line 457), or whether `previous.scope_version == target.scope_version`. Additionally, `active` queue counting (`aegis/api.py:458-466`) omits `Assessment.organization_id == user.organization_id`, letting one organization's 10 queued jobs return `429` for other organizations.
   - `aegis/api.py:453-457` & `aegis/serialization.py:45-56`: when `target.scope["expires_at"]` passes, `target_view` continues to report `verification_status: "verified_lab"`. Calling `launch` passes line 453 and raises `PolicyError("The assessment scope has expired.")` at line 457; `get_db` (`aegis/api.py:59-61`) rolls back the transaction and returns `422` without recording `assessment.authorization_rejected` / `assessment.scope_rejected` in `audit_events` (contrasting with lines 454-455, which explicitly commit the denial audit event).
   Benefit: Prevents state mutations on archived projects, prevents stale idempotency replays across scope versions or archived projects, isolates per-organization queue budgets, and guarantees tamper-evident audit logging + accurate status reporting when expired scopes are rejected.
   Proposal:
   - In `approve` (`aegis/api.py:421`), load `project = owned(db, Project, row.project_id, user)` and raise `HTTPException(409, "Restore the project before approving targets")` when `project.archived`.
   - In `launch` (`aegis/api.py:447-467`), require `previous.scope_version == target.scope_version` on idempotency replay; catch `PolicyError` around `validate_scope(target.scope, target.url)` to record `audit(db, user.organization_id, user.id, "assessment.authorization_rejected", target.id, {"reason": str(exc)})` and `db.commit()` before raising `HTTPException(403, str(exc))`; and filter or partition `active` queue limits by `Assessment.organization_id == user.organization_id`.
   - In `target_view` (`aegis/serialization.py:45-56`), report effective verification status as `"expired"` (or surface `scope_expired: True`) when `verification_status == "verified_lab"` and `datetime.now(UTC) >= ScopePolicy.model_validate(row.scope).expires_at`.
   Verify by: Pure local `TestClient` test in `tests/product/test_api_workflow.py` (no socket server required):
   ```python
   # 1. Archive project then attempt target approval -> expect 409
   client.patch(f"/api/v1/projects/{project_id}", json={"archived": True})
   assert client.post(f"/api/v1/targets/{target_id}/approve", json={"acknowledgement": ACK}).status_code == 409
   # 2. Expired scope launch -> expect 403 and committed audit event
   with sessions() as db:
       t = db.get(Target, target_id)
       t.verification_status, t.authorized_by = "verified_lab", owner_id
       t.scope = {
           **t.scope,
           "starts_at": (now - timedelta(hours=2)).isoformat(),
           "expires_at": (now - timedelta(minutes=1)).isoformat(),
       }
       db.commit()
   res = client.post("/api/v1/assessments", json={"target_id": target_id, "idempotency_key": "expired-key-1"})
   assert res.status_code == 403
   ```
   Owner: codex   Confidence: high

2. Fix: RFC 3986 path parameters (`;`) bypass `excluded_paths` and dot-segment traversal (`..;`) in `_path` / `_matches`, and `ScopePolicy.coherent` permits unreferenced `hosts` / `allowed_cidrs` broader than `allowed_origins`.
   Evidence:
   - `packages/security_policies/__init__.py:17-32` (`_path`): splits only on `"/"` when checking traversal (`any(part in {".", ".."} for part in decoded.split("/"))` at line 27) and marks `";"` as safe in `quote(decoded, safe="/-._~:@!$&'()*+,;=")` at line 32.
   - `packages/security_policies/__init__.py:197-198` (`_matches`): checks `prefix == "/" or path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")`.
   - Because `";"` is permitted in paths and not treated as a segment parameter boundary:
     (a) `check_url(scope, "http://127.0.0.1:8766/excluded;jsessionid=1")` passes when `excluded_paths=["/excluded"]` and `allowed_paths=["/"]`, because `"/excluded;jsessionid=1"` neither equals `"/excluded"` nor starts with `"/excluded/"`.
     (b) `check_url(scope, "http://127.0.0.1:8766/app/..;/excluded")` passes when `allowed_paths=["/app"]` and `excluded_paths=["/excluded"]`, because `decoded.split("/")` produces segment `"..;"` (not in `{".", ".."}`) and the path starts with `"/app/"`. Many HTTP frameworks (Tomcat, Jetty, Spring, matrix routers) resolve `/app/..;/excluded` to `/excluded`.
   - `packages/security_policies/__init__.py:176-183` (`ScopePolicy.coherent`): validates `origin -> hosts/allowed_cidrs` (every origin's host is in `hosts` and `allowed_cidrs`), but never validates the converse (`hosts/allowed_cidrs -> allowed_origins`). A scope with `allowed_origins=["http://127.0.0.1:8766"]`, `hosts=["127.0.0.1", "::1"]`, and `allowed_cidrs=["127.0.0.1/32", "::1/128"]` is accepted, persisting unreferenced `::1` host and `/128` CIDR grants in `scope_snapshot`.
   Benefit: Closes matrix/semicolon path-parameter traversal and exclusion bypasses on target/redirect URLs, and ensures `hosts` and `allowed_cidrs` in approved scopes cannot be broader than `allowed_origins`.
   Proposal:
   - In `_path` (`packages/security_policies/__init__.py:18`), reject `";"` alongside `"?"`, `"#"`, and `"\\"` (`if not value.startswith("/") or any(c in value for c in "?#\\;"):`) and remove `";"` from `safe` in `quote(...)` at line 32 (or strip `;` parameters per segment before checking `{".", ".."}` and matching prefixes).
   - In `ScopePolicy.coherent` (`packages/security_policies/__init__.py:176-183`), require exact set equality between declared `hosts`/`allowed_cidrs` and the hosts/CIDRs derived from `self.allowed_origins`:
     ```python
     origin_hosts = {urlsplit(origin).hostname for origin in self.allowed_origins}
     expected_cidrs = {f"{h}/{'32' if h == '127.0.0.1' else '128'}" for h in origin_hosts}
     if set(self.hosts) != origin_hosts or set(self.allowed_cidrs) != expected_cidrs:
         raise ValueError("Every origin, host and address range must match exactly.")
     ```
   Verify by: Pure synthetic unit assertions in `tests/product/test_policy_scanner.py` (`PolicyTests`):
   ```python
   for bad_path in ("/excluded; param=1", "/excluded;jsessionid=1", "/app/..;/excluded", "/..;/secret"):
       with self.assertRaises(PolicyError):
           check_url(
               self.scope | {"allowed_paths": ["/app"], "excluded_paths": ["/excluded"]}, self.origin + bad_path
           )
   with self.assertRaises(ValidationError):
       ScopePolicy.model_validate(
           self.scope | {"hosts": ["127.0.0.1", "::1"], "allowed_cidrs": ["127.0.0.1/32", "::1/128"]}
       )
   ```
   Owner: codex   Confidence: high

3. Add: Controlled C3/C4 scope-update lifecycle (`expected_scope_version` race guards, historical report snapshot isolation, and worker cancel-persist guard).
   Evidence:
   - `aegis/models.py:77` defines `Target.scope_version` (default `1`), and `aegis/api.py:419-503` has no scope-update endpoint and does not bind `ApprovalInput` or `AssessmentInput` to `expected_scope_version` (strict positive `int`), allowing an operator who reviewed `v1` to approve or launch after another operator replaced the scope with `v2`.
   - `aegis/api.py:662-667` (`report`) and `packages/reporting/reports.py:214, 259, 261`: `report()` passes live `target_view(target)` as `data["target"]`. In `reports.py`, line 214 renders `target.get("url")` and line 261 (`"Included target"`) dumps the entire live `data["target"]` dict (`url`, `scope`, `scope_version`, `verification_status`, `approved_at`). After a target scope edit to `v2`, exporting a historical `v1` report overwrites its displayed target URL, scope version, and verification state with live `v2` values. Also, `aegis/api.py:479` stores `target.approved_at` in `scope_snapshot` as a raw float epoch rather than an ISO-8601 timestamp string (`timestamp(target.approved_at)`).
   - `aegis/worker.py:114-191` (`run_one`): if a scope edit (or cancel request) sets `current.cancel_requested = True` after `scan()` returns its dict but before `worker.py:110` acquires `BEGIN IMMEDIATE`, line 116 sets `outcome = "cancelled"`, yet lines 128-191 still execute unconditionally—persisting `Observation`, `Finding` (`confirmed`/`reopened`), `FindingEvidence`, and `FindingHistory` rows for a `"cancelled"` assessment whose scope was revoked.
   - `aegis/api.py:382-390` (`update_project`): `PATCH /api/v1/projects/{project_id}` applies `setattr(row, key, value)` without checking `name.strip()`, allowing `{"name": "   "}` unlike `create_project` (`aegis/api.py:335-336`).
   Benefit: Prevents TOCTOU approval/launch races across scope edits, prevents future target edits from mutating historical assessment reports, prevents cancelled assessments from persisting/reopening findings after scope revocation, and enforces non-blank project names on update.
   Proposal:
   - Require `expected_scope_version: Annotated[int, Field(strict=True, ge=1)]` on `ApprovalInput`, `AssessmentInput`, and the new `TargetScopeUpdate` (`PATCH /api/v1/targets/{target_id}/scope`); return `409` on version mismatch. Compare normalized `(normalize_url(data.url), validate_scope(data.scope, data.url).model_dump(mode="json")) == (row.url, row.scope)` so exact no-ops preserve version and approval.
   - In `report()` (`aegis/api.py:662-667`) and `reports.py:214, 259, 261`, construct the report's target view from `row.scope_snapshot` (`target_url`, `row.scope_version`, `authorized_by`, `timestamp(approved_at)`) rather than live `target_view(target)`.
   - In `worker.py:128`, guard observation and finding persistence with `if outcome != "cancelled":` so a cancelled assessment records no new observations or finding state transitions.
   - In `update_project` (`aegis/api.py:386`), strip `data.name` and raise `ValueError("Project name is required")` when blank.
   Verify by: Pure local `TestClient` + `run_one` regression verifying (a) `v1` approval/launch after `v2` edit returns `409`, (b) historical `v1` report bytes are unchanged after `v2` scope/URL edit, and (c) setting `cancel_requested = True` before `run_one` commit leaves `observations` and `findings` empty.
   Owner: codex   Confidence: high

Not reviewed: Frontend UI components (`apps/web/`), Claude-owned scanner worker isolation (`services/`).
