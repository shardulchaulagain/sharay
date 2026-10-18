# SHARAY — Active State & Forward Engineering Directives

> **State Timestamp:** October 16, 2026  
> **Human Directive:** No bureaucratic talk, no excuses, no backward-looking logs. Laser-focused on **improving SHARAY** into a world-class penetration-testing platform.

---

## 1. System Health & Runtime Environment
- **Host:** macOS arm64 (Apple Silicon), Python 3.13.1.
- **Frontend Workspace:** Next.js active on `http://localhost:3000` (`apps/web`).
- **Backend API & Worker:** FastAPI daemon running on `http://127.0.0.1:8765` (`aegis/api.py`, `aegis/worker.py`).
- **Container Egress Isolation:** Rootless Podman bridge with kernel-enforced iptables locking traffic strictly to the authorized target IP and port (`services/scanner_worker/container.py`).
- **Edge Resolution:** 4-tier DNS-over-HTTPS fallback ladder (Cloudflare, Google, System, Ingress Cache) in `packages/scanner_adapters/integrations/dns.py`.

---

## 2. Active Engineering Priorities (The Forward Mission)

1. **Scanning Logic & Bug Sweep**:
   - Sweep false positives out of `packages/scanner_adapters/integrations/vuln_scanner.py`. Naive string matching (e.g. matching `"nginx"`/`"apache"` for SSRF) is prohibited.
   - Require differential responses and verified loopback connection errors absent from baseline.
   - Follow HTTP 301/302 redirects before evaluating security headers.

2. **Validation Engine & Verification Gate**:
   - Central rule: **No verified evidence $\rightarrow$ no confirmed vulnerability**.
   - Wire `DeterministicReproducer` results directly into finding state: demoted findings stay `"demoted"` or `"false_positive"`.
   - Never hardcode unverified findings as `confirmed` in `aegis/worker.py`.

3. **Honest Tool & Pipeline Status**:
   - If ZAP, Metasploit, Nmap, or Nuclei encounters an exception or non-zero exit code, record check status honestly as **`failed`** with full error details. Never mask errors as `completed`.

4. **Synthesizer Engine & Executive Reporting**:
   - Overhaul `packages/reporting/reports.py`: separate **Verified Security Vulnerabilities** from **Security Configuration & Hardening Posture**.
   - No raw JSON dumps in PDFs. Clean key-value evidence formatting.
   - Protocol-aware PoCs (`dig +short TXT _dmarc.<domain>`, `openssl s_client`, formatted `curl`).
   - Add concrete Technical and Business Impact statements.

5. **Terminal UI & Operator Console**:
   - Upgrade `apps/web/app/terminal.tsx` and `aegis/interactive.py` into a functional operator takeover console with live diagnostic commands (`probe`, `dns`, `ssl`, `beacon`, `retest`, `whoami`, `help`).

---

## 3. Active Agent Assignments

- **Codex:** Platform, API, `aegis/worker.py` verification gating, `packages/reporting/reports.py` PDF overhaul, terminal PTY backend.
- **Claude:** Scanner adapters (`vuln_scanner.py`, `dns_scanner.py`), container runners, reproducer lifecycle wiring, terminal frontend interaction.
- **Gemini:** Senior technical lead, directing technical priorities, architecture, and code review.

---

## 4. Coordination Protocol
- Check inbox: `python -m scripts.session_log --agent <you> --inbox`.
- Communicate decisions: `python -m scripts.session_log --agent <you> --kind <kind> --to <other> --summary "<text>"`.
- Less talking, hard working. Implement, verify with tests, commit working code.
