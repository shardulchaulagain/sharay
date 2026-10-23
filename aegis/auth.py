"""Owner-controlled accounts, opaque sessions and role enforcement."""

import base64
import dataclasses
import enum
import hashlib
import hmac
import secrets
import struct
import time
from typing import Any
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from aegis.audit import audit
from aegis.models import LoginAttempt, Organization, RecoveryToken, SessionRecord, User

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
ROLES = {"owner", "security_administrator", "analyst", "viewer"}


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def validate_password(password: str) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password between 12 and 256 characters")
    return password


def add_user(db: Session, username: str, password: str, org: str, role: str) -> User:
    if role not in ROLES:
        raise ValueError("Unknown role")
    if not 3 <= len(username) <= 80 or not all(c.isalnum() or c in "._-" for c in username):
        raise ValueError("Username must contain 3–80 letters, numbers, dots, hyphens or underscores")
    if db.scalar(select(User).where(User.username == username.lower())):
        raise ValueError("Username unavailable")
    user = User(
        organization_id=org,
        username=username.lower(),
        role=role,
        password_hash=HASHER.hash(validate_password(password)),
    )
    db.add(user)
    db.flush()
    return user


def provision_owner(db: Session, username: str, password: str, name: str = "Local laboratory") -> User:
    if db.scalar(select(User).limit(1)):
        raise ValueError("Owner already provisioned; sign in or use the local recovery command")
    org = Organization(name=name)
    db.add(org)
    db.flush()
    user = add_user(db, username, password, org.id, "owner")
    audit(db, org.id, user.id, "owner.provisioned", user.id)
    return user


def sign_in(
    db: Session,
    username: str,
    password: str,
    client: str,
    session_seconds: int,
    code: str | None = None,
):
    now = time.time()
    # ponytail: one local client throttle; distributed per-identity counters for server deployment.
    key = digest(client)
    attempt = db.get(LoginAttempt, key)
    if attempt and now - attempt.window_started >= 300:
        attempt.failures, attempt.window_started = 0, now
    if attempt and attempt.failures >= 8:
        raise HTTPException(429, "Too many login attempts; wait five minutes")
    user = db.scalar(select(User).where(User.username == username.lower(), User.active.is_(True)))
    valid: bool
    try:
        valid = HASHER.verify(user.password_hash if user else DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid or not user:
        if not attempt:
            attempt = LoginAttempt(key=key, failures=0, window_started=now)
            db.add(attempt)
        attempt.failures += 1
        if user:
            audit(db, user.organization_id, user.id, "auth.login_rejected", user.id)
        db.commit()  # Persist denial counters even though the request raises.
        raise HTTPException(401, "Invalid credentials")
    # MFA gate: an account with TOTP enabled must present a valid TOTP or backup code. A bad or
    # missing code is a failed login (counts against the failure budget); it never issues a session.
    if user.totp_enabled:
        provided = (code or "").strip()
        ok = False
        if provided:
            ok, _ = TOTPEngine.verify_otp(user.totp_secret or "", provided)
            if not ok and isinstance(user.totp_backup_hashes, list):
                remaining = list(user.totp_backup_hashes)
                if TOTPEngine.redeem_backup_code(provided, remaining):
                    user.totp_backup_hashes = remaining  # consume the used backup code
                    ok = True
        if not ok:
            if not attempt:
                attempt = LoginAttempt(key=key, failures=0, window_started=now)
                db.add(attempt)
            attempt.failures += 1
            audit(db, user.organization_id, user.id, "auth.mfa_rejected", user.id)
            db.commit()
            raise HTTPException(401, "Invalid or missing MFA code")

    # A valid account must not reset the shared failure budget for guesses at other accounts.
    if HASHER.check_needs_rehash(user.password_hash):
        user.password_hash = HASHER.hash(password)
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(
        SessionRecord(
            token_hash=digest(token),
            user_id=user.id,
            csrf=csrf,
            created_at=now,
            expires_at=now + session_seconds,
        )
    )
    db.execute(delete(SessionRecord).where(SessionRecord.expires_at < now))
    audit(db, user.organization_id, user.id, "auth.login", user.id)
    return user, token, csrf


def authenticate(db: Session, token: str | None) -> tuple[User, SessionRecord]:
    session = db.get(SessionRecord, digest(token)) if token else None
    if not session or session.expires_at <= time.time():
        raise HTTPException(401, "Sign in to access the workspace")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(401, "Session is no longer valid")
    return user, session


def check_csrf(session: SessionRecord, token: str | None) -> None:
    if not token or not token.isascii() or not hmac.compare_digest(token, session.csrf):
        raise HTTPException(403, "Invalid CSRF token")


def require_role(user: User, *roles: str) -> None:
    if user.role not in roles:
        raise HTTPException(403, "Your role does not permit this action")


def issue_recovery(db: Session, username: str) -> str:
    user = db.scalar(select(User).where(User.username == username.lower()))
    if not user:
        raise ValueError("Unknown local user")
    db.execute(delete(RecoveryToken).where(RecoveryToken.user_id == user.id))
    token = secrets.token_urlsafe(32)
    db.add(RecoveryToken(token_hash=digest(token), user_id=user.id, expires_at=time.time() + 600, used=False))
    audit(db, user.organization_id, "local_cli", "auth.recovery_issued", user.id)
    return token


def consume_recovery(db: Session, token: str, password: str) -> None:
    record = db.get(RecoveryToken, digest(token))
    if not record or record.used or record.expires_at <= time.time():
        raise ValueError("Recovery token is expired or invalid")
    user = db.get(User, record.user_id)
    if user is None:
        raise ValueError("Unknown recovery user")
    user.password_hash = HASHER.hash(validate_password(password))
    record.used = True
    db.execute(delete(SessionRecord).where(SessionRecord.user_id == user.id))
    audit(db, user.organization_id, "local_cli", "auth.password_reset", user.id)


class TOTPEngine:
    """RFC 6238 Time-Based One-Time Password Engine."""

    TIME_STEP: int = 30
    DIGITS: int = 6

    @classmethod
    def generate_secret(cls) -> str:
        """Generate a cryptographically secure 160-bit Base32 secret."""
        raw_bytes = secrets.token_bytes(20)
        return base64.b32encode(raw_bytes).decode("ascii").replace("=", "")

    @classmethod
    def generate_provisioning_uri(cls, secret: str, username: str, issuer: str = "SHARAY") -> str:
        """Generate standard otpauth:// URI for QR code enrollment."""
        label = quote(f"{issuer}:{username}")
        clean_secret = secret.replace(" ", "").upper()
        return f"otpauth://totp/{label}?secret={clean_secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={cls.DIGITS}&period={cls.TIME_STEP}"

    @classmethod
    def generate_otp(cls, secret: str, timestamp: float | None = None) -> str:
        """Calculates current 6-digit TOTP code for the given secret."""
        t = timestamp if timestamp is not None else time.time()
        counter = int(t // cls.TIME_STEP)

        clean_secret = secret.replace(" ", "").upper()
        padding = (8 - len(clean_secret) % 8) % 8
        key_bytes = base64.b32decode(clean_secret + "=" * padding)

        msg = struct.pack(">Q", counter)
        h = hmac.new(key_bytes, msg, hashlib.sha1).digest()

        offset = h[-1] & 0x0F
        binary = (
            ((h[offset] & 0x7F) << 24)
            | ((h[offset + 1] & 0xFF) << 16)
            | ((h[offset + 2] & 0xFF) << 8)
            | (h[offset + 3] & 0xFF)
        )

        otp = binary % (10**cls.DIGITS)
        return str(otp).zfill(cls.DIGITS)

    @classmethod
    def verify_otp(
        cls,
        secret: str,
        code: str,
        timestamp: float | None = None,
        allowed_drift_windows: int = 1,
        used_counters: set[int] | None = None,
    ) -> tuple[bool, int | None]:
        """Verifies code against secret with +/- allowed_drift_windows skew tolerance.

        Returns (is_valid, counter_used). Prevents replay if used_counters set is passed.
        """
        clean_code = str(code).strip()
        if len(clean_code) != cls.DIGITS or not clean_code.isdigit():
            return False, None

        t = timestamp if timestamp is not None else time.time()
        curr_counter = int(t // cls.TIME_STEP)

        for offset in range(-allowed_drift_windows, allowed_drift_windows + 1):
            check_counter = curr_counter + offset
            if used_counters is not None and check_counter in used_counters:
                continue

            expected_otp = cls.generate_otp(secret, timestamp=check_counter * cls.TIME_STEP)
            if hmac.compare_digest(clean_code, expected_otp):
                if used_counters is not None:
                    used_counters.add(check_counter)
                return True, check_counter

        return False, None

    @classmethod
    def generate_backup_codes(cls, count: int = 8) -> tuple[list[str], list[str]]:
        """Generates single-use backup recovery codes and their salted hashes."""
        plain_codes = []
        hashed_codes = []
        for _ in range(count):
            raw = secrets.token_hex(4).upper()
            formatted = f"{raw[:4]}-{raw[4:]}"
            plain_codes.append(formatted)
            hashed_codes.append(hashlib.sha256(formatted.encode("ascii")).hexdigest())
        return plain_codes, hashed_codes

    @classmethod
    def redeem_backup_code(cls, code: str, hashed_codes: list[str]) -> bool:
        """Atomically checks and consumes a backup code from the list."""
        formatted = str(code).strip().upper()
        h = hashlib.sha256(formatted.encode("ascii")).hexdigest()
        for idx, stored_hash in enumerate(hashed_codes):
            if hmac.compare_digest(h, stored_hash):
                hashed_codes.pop(idx)
                return True
        return False


class ResourceAction(str, enum.Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE_SCAN = "EXECUTE_SCAN"
    EXPLOIT_VERIFY = "EXPLOIT_VERIFY"
    DELETE = "DELETE"
    MANAGE_MEMBERS = "MANAGE_MEMBERS"


class ProjectRole(str, enum.Enum):
    PROJECT_OWNER = "PROJECT_OWNER"
    SECURITY_LEAD = "SECURITY_LEAD"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR_READONLY = "AUDITOR_READONLY"


_ROLE_PERMISSIONS: dict[ProjectRole, set[ResourceAction]] = {
    ProjectRole.PROJECT_OWNER: {
        ResourceAction.READ,
        ResourceAction.WRITE,
        ResourceAction.EXECUTE_SCAN,
        ResourceAction.EXPLOIT_VERIFY,
        ResourceAction.DELETE,
        ResourceAction.MANAGE_MEMBERS,
    },
    ProjectRole.SECURITY_LEAD: {
        ResourceAction.READ,
        ResourceAction.WRITE,
        ResourceAction.EXECUTE_SCAN,
        ResourceAction.EXPLOIT_VERIFY,
    },
    ProjectRole.SECURITY_ANALYST: {
        ResourceAction.READ,
        ResourceAction.EXECUTE_SCAN,
        ResourceAction.EXPLOIT_VERIFY,
    },
    ProjectRole.AUDITOR_READONLY: {
        ResourceAction.READ,
    },
}


class PermissionDeniedError(Exception):
    """Raised when an actor lacks sufficient resource-scoped permissions."""


@dataclasses.dataclass
class ProjectMembership:
    user_id: str
    project_id: str
    role: ProjectRole
    assigned_at: float = dataclasses.field(default_factory=time.time)


class ProjectRBACEnforcer:
    """Enforces fine-grained resource and project-level authorization."""

    def __init__(self) -> None:
        self._memberships: dict[tuple[str, str], ProjectMembership] = {}
        self._project_orgs: dict[str, str] = {}
        self._resource_projects: dict[str, str] = {}
        self.auth_audit_log: list[dict[str, Any]] = []

    def register_project(self, project_id: str, org_id: str, owner_user_id: str) -> None:
        self._project_orgs[project_id] = org_id
        self.assign_role(owner_user_id, project_id, ProjectRole.PROJECT_OWNER)

    def assign_role(self, user_id: str, project_id: str, role: ProjectRole) -> None:
        self._memberships[(user_id, project_id)] = ProjectMembership(
            user_id=user_id,
            project_id=project_id,
            role=role,
        )

    def register_resource(self, resource_id: str, project_id: str) -> None:
        self._resource_projects[resource_id] = project_id

    def check_permission(
        self,
        user_id: str,
        project_id: str,
        action: ResourceAction,
        resource_id: str | None = None,
    ) -> bool:
        """Evaluates whether user has permission to perform action within project context."""
        if resource_id is not None:
            res_proj = self._resource_projects.get(resource_id)
            if res_proj != project_id:
                self._record_auth_decision(
                    user_id, project_id, action, resource_id, False, "Resource not in project"
                )
                return False

        membership = self._memberships.get((user_id, project_id))
        if not membership:
            self._record_auth_decision(
                user_id, project_id, action, resource_id, False, "No project membership"
            )
            return False

        allowed_actions = _ROLE_PERMISSIONS.get(membership.role, set())
        has_perm = action in allowed_actions
        reason = "Authorized" if has_perm else f"Role {membership.role.value} lacks action {action.value}"
        self._record_auth_decision(user_id, project_id, action, resource_id, has_perm, reason)
        return has_perm

    def enforce(
        self,
        user_id: str,
        project_id: str,
        action: ResourceAction,
        resource_id: str | None = None,
    ) -> None:
        if not self.check_permission(user_id, project_id, action, resource_id):
            raise PermissionDeniedError(
                f"User {user_id} denied {action.value} on project {project_id} (resource: {resource_id})"
            )

    def _record_auth_decision(
        self,
        user_id: str,
        project_id: str,
        action: ResourceAction,
        resource_id: str | None,
        granted: bool,
        reason: str,
    ) -> None:
        self.auth_audit_log.append(
            {
                "timestamp": time.time(),
                "user_id": user_id,
                "project_id": project_id,
                "action": action.value,
                "resource_id": resource_id,
                "granted": granted,
                "reason": reason,
            }
        )
