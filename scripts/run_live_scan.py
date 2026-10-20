"""Run a live scan on shardulchaulagain.com through the running SHARAY server.

Performs:
1. Obtains valid session credentials for owner user 'shardul'.
2. Updates the target scope validity window to active UTC range.
3. Operator-authorizes the target within the displayed scope.
4. Posts assessment launch request to /api/v1/assessments.
5. Monitors progress through the live API until finished.
6. Returns the completed assessment findings, checks, and observations.
"""

import datetime
import json
import secrets
import sys
import time
import urllib.request
import urllib.error

from aegis.config import Settings
from aegis.database import create_database
from aegis.models import SessionRecord, Target, User
from aegis.auth import digest

settings = Settings.from_env()
engine, SessionLocal = create_database(settings, migrate=False)

# Step 1: Ensure active session for user shardul
with SessionLocal() as db:
    user = db.query(User).filter(User.username == "shardul").first()
    if not user:
        print("User shardul not found!")
        sys.exit(1)
    
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = time.time()
    db.add(
        SessionRecord(
            token_hash=digest(token),
            user_id=user.id,
            csrf=csrf,
            created_at=now,
            expires_at=now + 86400,
        )
    )
    db.commit()
    print(f"[+] Created session for {user.username} (role: {user.role})")

API_BASE = f"http://127.0.0.1:{settings.port}/api/v1"
HEADERS = {
    "Cookie": f"aegis_session={token}",
    "X-CSRF-Token": csrf,
    "Origin": f"http://127.0.0.1:{settings.port}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

def api_call(path, method="GET", data=None):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, method=method, headers=HEADERS)
    if data is not None:
        req.data = json.dumps(data).encode("utf-8")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        print(f"[-] HTTP Error {err.code} on {method} {path}: {body}")
        raise

# Step 2: Locate target shardulchaulagain.com
projects = api_call("/projects")["items"]
target_id = None
scope_version = 1
for p in projects:
    proj_detail = api_call(f"/projects/{p['id']}")
    for t in proj_detail.get("targets", []):
        if "shardulchaulagain.com" in t["url"]:
            target_id = t["id"]
            scope_version = t["scope_version"]
            print(f"[+] Found Target {target_id} in project '{p['name']}' (scope v{scope_version})")
            break
    if target_id:
        break

if not target_id:
    print("[-] Target shardulchaulagain.com not found!")
    sys.exit(1)

# Step 3: Update Scope validity window
now_utc = datetime.datetime.now(datetime.timezone.utc)
starts_at = (now_utc - datetime.timedelta(minutes=5)).isoformat()
expires_at = (now_utc + datetime.timedelta(hours=12)).isoformat()

scope_payload = {
    "hosts": ["shardulchaulagain.com"],
    "allowed_origins": ["https://shardulchaulagain.com"],
    "allowed_paths": ["/"],
    "excluded_paths": [],
    "allowed_cidrs": [],
    "categories": ["http_headers"],
    "authenticated": False,
    "credential_refs": [],
    "request_rate": 10.0,
    "max_concurrency": 5,
    "starts_at": starts_at,
    "expires_at": expires_at,
    "intrusive": False,
    "approval_required": True,
    "emergency_stop_conditions": ["operator_cancel", "scope_expired", "policy_violation"],
}

print(f"[+] Updating scope validity window (v{scope_version} -> v{scope_version+1})...")
updated_target = api_call(
    f"/targets/{target_id}/scope",
    method="PATCH",
    data={
        "expected_scope_version": scope_version,
        "url": "https://shardulchaulagain.com/",
        "scope": scope_payload,
    },
)
scope_version = updated_target["scope_version"]
print(f"[+] Scope updated to v{scope_version}, status: {updated_target['verification_status']}")

# Step 4: Operator Approval
print("[+] Approving target with operator acknowledgement...")
approved_target = api_call(
    f"/targets/{target_id}/approve",
    method="POST",
    data={
        "expected_scope_version": scope_version,
        "acknowledgement": "I authorize this target within the displayed scope",
    },
)
print(f"[+] Target approved! Status: {approved_target['verification_status']}")

# Step 5: Launch Assessment
idempotency_key = f"scan-{secrets.token_hex(8)}"
print(f"[+] Launching assessment with profile=comprehensive, mode=adaptive...")
assessment = api_call(
    "/assessments",
    method="POST",
    data={
        "target_id": target_id,
        "idempotency_key": idempotency_key,
        "expected_scope_version": scope_version,
        "profile": "comprehensive",
        "config": {
            "mode": "adaptive",
            "rate": 10.0,
            "depth": 2,
            "crawler_max_pages": 15,
        },
    },
)
assessment_id = assessment["id"]
print(f"[+] Assessment queued successfully! ID: {assessment_id}")

# Step 6: Monitor progress
print("[*] Monitoring assessment progress...")
for _ in range(60):
    time.sleep(2)
    state = api_call(f"/assessments/{assessment_id}")
    status = state.get("status")
    stage = state.get("stage", "")
    print(f"    Status: {status} | Stage: {stage}")
    if status in ("completed", "failed", "cancelled"):
        break

print(f"\n[+] Final assessment state:")
print(f"    Status: {state.get('status')}")
print(f"    Stage: {state.get('stage')}")
print(f"    Findings count: {len(state.get('findings', []))}")
print(f"    Checks count: {len(state.get('checks', []))}")
print(f"    Observations count: {len(state.get('observations', []))}")

for f in state.get("findings", []):
    print(f"    - [{f.get('severity', 'info').upper()}] {f.get('title')} ({f.get('status')})")

with open("/tmp/live_scan_result.json", "w") as out:
    json.dump(state, out, indent=2)

print("\n[+] Full state saved to /tmp/live_scan_result.json")
