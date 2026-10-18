# Architecture & Design: Live-Target Ownership Verification (C3/C4)

**Author**: Gemini (Principal Architect) for Codex and Claude  
**Date**: October 12, 2026  
**Scope**: Work packages C3 (Target Inventory & Ownership Verification) and C4 (Deterministic Policy & SSRF Prevention).  
**Context**: Required by `MAIN_PROMPT.txt` and `docs/LIVE_SCOPE_PLAN.md` before any live assessment profile is enabled.

---

## 1. Challenge Protocols & Workflows

Never infer authorization merely because an operator knows a hostname or IP. Live targets must be verified through cryptographic proof of administrative control.

### Challenge Option A: DNS TXT Challenge (Recommended for Domains & Subdomains)
1. **Initiation**: Operator requests challenge for domain (e.g. `example.com`).
2. **Challenge Record Generation**: The server issues a challenge record name:
   `_sharay-challenge.<target-domain>`
   and an unpredictable challenge value:
   `sharay-verify=<token_hash>`
3. **Operator Action**: Operator provisions the DNS TXT record in their authoritative nameserver.
4. **Verification Execution**:
   - The verification worker queries authoritative DNS resolvers directly (or default trusted DNS over TLS/HTTPS).
   - Looks up TXT records on `_sharay-challenge.<target-domain>`.
   - Requires exact string match for `sharay-verify=<token_hash>`.
   - If matched, the target transitions to `verified`.

### Challenge Option B: HTTP Well-Known Challenge (For Specific Web Origins)
1. **Initiation**: Operator requests challenge for an HTTP/HTTPS origin (e.g. `https://example.com:8443`).
2. **Challenge Path Generation**:
   `/.well-known/sharay-challenge/<challenge_id>`
3. **Expected Content**: A single line containing `sharay-verify=<token_hash>` served with `Content-Type: text/plain`.
4. **Verification Execution**:
   - The verification worker executes an unredirected, SSRF-guarded HTTP request to that exact URL.
   - Response size is capped at 4096 bytes; must match expected token exactly.

---

## 2. State Machine & Relational Data Model

### States:
- `awaiting_challenge`: Target registered, challenge not yet initiated.
- `pending_verification`: Token issued, challenge active, waiting for operator confirmation.
- `verified`: Challenge successfully validated; scope is active.
- `expired`: Verification validity window has passed; re-verification required.
- `revoked`: Explicitly invalidated by operator or security administrator.

```
       [awaiting_challenge]
                │  (POST /challenges)
                ▼
       [pending_verification]
          │             │  (TTL 24h expires)
          │             ▼
          │         [expired]
          │ (Verify success)
          ▼
       [verified] ───────► [expired] (Post-verification expiry: 30 days)
          │
          ▼ (Manual revocation)
       [revoked]
```

### Relational Schema (`target_verifications` table):
```python
class TargetVerification(Base):
    __tablename__ = "target_verifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    challenge_type: Mapped[str] = mapped_column(String(20))  # "dns_txt" | "http_well_known"
    token_hash: Mapped[str] = mapped_column(String(64))  # SHA256 of raw secret token
    challenge_path: Mapped[str] = mapped_column(String(255))  # "_sharay-challenge..." or "/.well-known/..."
    status: Mapped[str] = mapped_column(String(30), default="pending_verification")
    initiated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    verified_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    expires_at: Mapped[float] = mapped_column(Float)  # 24h challenge TTL
    valid_until: Mapped[float | None] = mapped_column(Float)  # 30d verification validity
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
```

---

## 3. Token Format, Entropy & Lifetimes

- **Entropy**: Raw token is 32 cryptographically secure random bytes generated via `secrets.token_urlsafe(32)` (256 bits of entropy).
- **Storage**: The raw token is displayed to the user **once** in the initiation response. The database stores strictly `hashlib.sha256(raw_token.encode()).hexdigest()`.
- **Challenge Lifetime**: The challenge token has a **24-hour TTL**. If not verified within 24 hours, the record transitions to `expired`.
- **Single-Use Verification**: Once a challenge succeeds, that token cannot be re-used. Subsequent re-verifications require issuing a fresh challenge token.
- **Verification Validity Window**: Verified status lasts **30 days**. Retests and assessments beyond 30 days require re-verification.

---

## 4. SSRF Defense: Preventing the Verifier from Becoming an Attack Tool

The HTTP challenge verifier fetches a URL on the internet. Without rigorous guards, this becomes a high-risk Server-Side Request Forgery (SSRF) vector.

The verifier must enforce the following non-negotiable protections (reusing `packages/scanner_adapters` patterns):

1. **Resolution Pinning & DNS Rebinding Defense**:
   - Resolve DNS for the target hostname.
   - Check every resolved IP address against the denylist (see below).
   - Pin the exact selected numeric IP address (`Destination(ip=numeric_ip, port=port)`).
   - Re-check peer at connection time: `sock.getpeername()[0] == pinned_ip`.
2. **Strict IP Denylist (RFC 1918, CGNAT, Loopback, Cloud Metadata)**:
   - Loopback: `127.0.0.0/8`, `::1` (unless in an explicit lab profile).
   - Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
   - Link-local & Cloud Metadata: `169.254.0.0/16` (specifically `169.254.169.254` AWS/GCP/Azure metadata), `fe80::/10`.
   - Carrier-grade NAT: `100.64.0.0/10`.
   - Special & multicast: `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`.
3. **Zero Redirect Policy**:
   - `HTTPConnection` must **strictly refuse redirects** (301, 302, 307, 308). A challenge URL that responds with a redirect is immediately marked as failed. This prevents redirect-based bypasses into internal endpoints.
4. **Port Restrictions**:
   - HTTP challenge connects strictly to standard web ports: `80` (HTTP) or `443` (HTTPS). Arbitrary high ports (e.g. `22`, `6379`, `8080`) are forbidden.
5. **Bounded Response & Tight Deadline**:
   - Request timeout: 3 seconds.
   - Max response size: 4096 bytes. Response reading aborts if byte limit is exceeded.

---

## 5. Audit Logging & Non-Repudiation

Every step in the ownership lifecycle records immutable audit rows via `aegis/audit.py`:
- `target.challenge_initiated`: target_id, challenge_type, challenge_path, initiated_by.
- `target.verification_attempted`: target_id, attempt_number, peer_ip (redacted if sensitive).
- `target.verified`: target_id, verified_at, valid_until, challenge_type.
- `target.verification_failed`: target_id, error_class (fixed builtin class only, no untrusted target error strings).
- `target.revoked`: target_id, revoked_by, reason.

---

## 6. Negative & Regression Test Matrix (Acceptance Suite)

Before live verification is enabled, the following negative test cases must pass:

1. `test_dns_rebinding_rejected`: Hostname resolves to public IP on first check, but connection-time peer check sees private IP -> aborts immediately.
2. `test_cloud_metadata_refused`: Attempt to verify `http://169.254.169.254/` -> rejected by policy before socket open.
3. `test_private_rfc1918_refused`: Attempt to verify `http://192.168.1.1/` -> rejected by policy.
4. `test_redirect_fails_closed`: Challenge URL responds with `302 Found` pointing to internal service -> verification fails closed with 0 hops followed.
5. `test_oversized_challenge_response_truncated`: Response larger than 4 KiB -> fails closed.
6. `test_expired_token_rejected`: Challenge attempted 24h and 1 second after issuance -> rejected with expired challenge error.
7. `test_single_use_token_invalidated`: Token used successfully once cannot be re-used for a second target or re-verification.
8. `test_partial_token_prefix_rejected`: Challenge response containing partial substring `sharay-verify=abc` when expected token is `abcdef...` -> rejected.
