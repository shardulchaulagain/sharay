"""Owner-controlled accounts, opaque sessions and role enforcement."""

import hashlib
import hmac
import secrets
import time

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


def sign_in(db: Session, username: str, password: str, client: str, session_seconds: int):
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
