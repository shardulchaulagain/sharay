# SHARAY Next-Generation Architecture & Research Blueprint
## From Passive Vulnerability Scanner to Stateful, Adversarial, and Verifiable Security Platform

**Author**: Gemini (Principal Systems Architect, Advanced Security Researcher & AI Lead)  
**Target Audience**: Codex (Platform Architect, C1–C8), Claude (Integrations Lead, L1–L8), Human Leadership  
**Date**: October 12, 2026  
**Status**: Strategic Research Specification & Architectural Evolution Proposal  

---

## 1. Executive Evaluation: Current Architectural Blind Spots

SHARAY currently possesses exceptional foundational security rigor:
- Immutable typed proposal boundaries (`packages/shared_schemas`).
- Deterministic, fail-closed policy evaluation (`evaluate_tool_action`).
- Rigorous secret redaction and un-tampered data normalization.
- Strict process boundaries preventing rogue execution.

However, a critical adversarial assessment reveals four fundamental **architectural limitations**:

### Blind Spot 1: The "Passivity Trap" vs. Stateful Exploitability Validation
Current scanner designs treat security assessment as a collection of independent, one-shot static inspections (Nmap port grab -> HTTP header check -> static AST grep). Real-world security research and bug hunting are **fundamentally stateful**:
- An authentication bypass in endpoint `/api/v1/auth` alters session state.
- That session state unlocks access to `/api/v1/user/export`.
- A parameter in `/api/v1/user/export` contains a secondary IDOR or SQL injection.
- Treating each observation in isolation prevents SHARAY from discovering multi-stage vulnerabilities and leaves developers manually doing 90% of the verification work.

### Blind Spot 2: Static Finding Silos vs. Attack-Path Graph Synthesis
Findings are currently stored as flat rows in SQLite/database tables. A critical vulnerability is rarely a single bug; it is an **exploit chain** (e.g., unpinned dependency CVE + exposed CORS header + reflected parameter = full session takeover). SHARAY lacks an explicit **State Transition Attack Graph (STAG)** to correlate observations across network, web, source, and identity domains.

### Blind Spot 3: AI as a Static Schema Formatter vs. Dialectical Multi-Agent Triangulation
Claude's recent `services/ai_analysis_worker` implementation correctly establishes a fail-closed schema and finite state table. However, relying on a single prompt/model generation creates a binary bottleneck:
- If the model hallucinates or misses a defense (e.g., DOMPurify or prepared statements), the hypothesis is either blindly pushed to testing or discarded.
- There is no **internal adversarial challenge** within the AI subsystem to stress-test reasoning before spending compute, tool execution budgets, or human review attention.

### Blind Spot 4: Unverifiable Assessment Outputs in Bug Bounty & Compliance
Currently, assessment reports are generated as local HTML/Markdown/PDF documents. While clean and escaped, they lack **cryptographic tamper-evidence**. In bug bounty triage and enterprise security audits, reports are routinely doubted: Did the tool actually observe this payload? Was the HTTP response edited? What was the exact sequence of events?

---

## 2. Breakthrough Capabilities & Next-Gen Architecture

```
                                  +---------------------------------------+
                                  |     SHARAY AUTONOMY CONTROL DIAL      |
                                  | Level 0: Manual (CLI / PTY / API)     |
                                  | Level 1: AI-Assisted (Guided Steps)   |
                                  | Level 2: Supervised Bounded Autonomy  |
                                  | Level 3: Full Bounded Autonomous Loop |
                                  +-------------------+-------------------+
                                                      |
                   +----------------------------------+----------------------------------+
                   |                                                                     |
                   v                                                                     v
+------------------------------------+                                +------------------------------------+
|  DIALECTICAL MULTI-AGENT ENGINE    |                                |  STATE TRANSITION ATTACK GRAPH     |
|  - Agent 1: Red Teamer (Synthesizer|                                |  - Entity Graph (Host/App/Code)    |
|  - Agent 2: Blue Skeptic (Auditor) |                                |  - Multi-Stage Exploit Chains      |
|  - Agent 3: Verifier (Canary Echo) |                                |  - Impact Reachability Analysis    |
+------------------+-----------------+                                +------------------+-----------------+
                   |                                                                     |
                   +----------------------------------+----------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   STATEFUL FLIGHT RECORDER & FORENSICS|
                                  |   - eBPF / PTY Real-Time Syscall Log  |
                                  |   - Time-Travel Assessment Timeline   |
                                  |   - Bounded Ephemeral Access Sessions |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   CRYPTOGRAPHIC PROVENANCE ENGINE     |
                                  |   - Merkle Tree of Raw I/O Artifacts  |
                                  |   - Ed25519 Assessment Digital Seal   |
                                  |   - Reproducible Bug Bounty Proofs    |
                                  +---------------------------------------+
```

---

## 3. Deep Dive: Five Novel Architectural Pillars

### Pillar I: Dialectical Multi-Agent Verification Framework (DMAVF)
Instead of a single AI prompt generating an `InvestigationPlan`, SHARAY implements a **three-agent adversarial consensus protocol**:

1. **Agent 1: Red Hypothesis Generator** (Specialized in Offensive Patterns):
   - Ingests observations (e.g., Semgrep source finding + Nmap open port).
   - Synthesizes a concrete, non-destructive validation plan (e.g. "Send benign mathematical canary `id=1+0` vs `id=1` to observe semantic equivalence without damaging database integrity").
2. **Agent 2: Blue Skeptic & Defense Auditor** (Specialized in Defensive Architecture):
   - Evaluates the Red plan adversarially:
     - "Are prepared statements used downstream?"
     - "Is there an intervening WAF or input sanitizer?"
     - "Does this test violate the request rate budget or risk service disruption?"
   - Forces Agent 1 to refine the proposal or discard it before human review.
3. **Agent 3: Deterministic Verifier** (Code-Enforced, Non-LLM):
   - Dispatches only the approved minimal non-destructive probe.
   - Evaluates mathematical differential response (e.g., byte length, latency distribution, canary reflection).
   - Only findings verified by Canary Reflection or Mathematical Equivalence are marked `CONFIRMED`.

### Pillar II: Stateful Session Flight Recorder & Digital Forensics Engine
Security assessments require accurate, step-by-step reconstruction of what transpired:
- **Interactive Terminal & Command Flight Recorder**:
  - Developers need full manual terminal access within bounded sandboxes.
  - Every interactive PTY keystroke, subshell execution, and raw socket transaction is logged into an immutable time-series flight recorder (`.sharay-rec` format, pairing timestamped terminal I/O with process tree lineage).
- **Time-Travel Forensic Replay**:
  - Operators can scrub a visual timeline (T+00:00 to T+45:12) to inspect:
    - Target system state at each phase.
    - Exact HTTP headers and body bytes exchanged.
    - System resources consumed.
    - When authenticated access was established and when session termination occurred.
- **Strict Ephemeral Session Rollback**:
  - Enforces automatic session cleanup: all created test accounts, canary records, and temp files are tracked in a `DisposalManifest` and automatically purged at assessment close.

### Pillar III: Cryptographic Provenance & Tamper-Evident Assessment Seal
In modern bug bounty and regulatory compliance, proof of authenticity is paramount:
- **The SHARAY Merkle Tree**:
  - Every raw tool output, HTTP request/response hash, and audit ledger entry forms a leaf in an assessment Merkle Tree.
  - The root hash ($H_{root}$) is calculated at assessment completion.
- **Ed25519 Cryptographic Assessment Seal**:
  - SHARAY signs $(H_{root}, \text{ScopeDigest}, \text{Timestamp}, \text{OperatorID})$ using an operator-approved local Ed25519 key.
  - Reports export with an embedded **Cryptographic Verification Proof Block**:
    ```json
    {
      "sharay_version": "2.0.0",
      "assessment_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "scope_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "merkle_root": "a4b8...c129",
      "timestamp_utc": "2026-10-12T14:00:00Z",
      "operator_public_key": "ed25519_pk_...",
      "signature": "3045022100...c8e"
    }
    ```
  - Triagers, clients, and bug bounty platforms verify the authenticity and integrity of findings with an open-source standalone verification utility:
    `sharay-verify report.pdf` -> Validates digital signature and confirms that evidence was recorded live and untouched.

### Pillar IV: State Transition Attack Graph (STAG)
Replaces flat finding lists with an interconnected graph database/model:
- **Graph Entities**: `Host` -> `Port` -> `Service` -> `Endpoint` -> `Parameter` -> `SourceFile` -> `Credential`.
- **Graph Edges**: `exposes`, `consumes`, `authenticates_with`, `injects_into`.
- **Attack Path Synthesis**:
  - Automatically correlates:
    - *Discovery*: Gitleaks detects JWT signing secret in `backend/config.js`.
    - *Network*: Nmap shows Port 443 open with Express.js server.
    - *Web*: ZAP identifies unauthenticated endpoint `/api/verify`.
  - The STAG engine identifies the complete exploit path: Attacker can forge arbitrary JWTs and execute administrative actions on `/api/verify`.
  - Severity escalates to **Critical P0** with automatic remediation guidance across both code and configuration.

### Pillar V: Developer Freedom: The "Autonomy Dial" (0 to 3)
Automation must never disempower the human engineer:
- **Level 0 (Full Manual)**: Direct PTY, manual scanner execution, raw HTTP request builder (repeater/intruder mode). SHARAY acts solely as an immutable flight recorder and evidence collector.
- **Level 1 (AI-Assisted)**: Operator drives assessment; AI suggests hypotheses, draft test cases, and correlation insights inline.
- **Level 2 (Supervised Bounded Autonomy)**: AI drafts and sequences multi-step validation plans; requires single-click operator approval before each phase transition.
- **Level 3 (Autonomous within Approved Scope)**: Autonomous multi-tool execution and canary validation strictly bounded by the immutable scope object, with automatic emergency stop on error threshold.

---

## 4. Technical Feasibility & Implementation Matrix

| Novel Capability | Technical Feasibility | Core Dependencies | Architectural Owner | Failure Mode & Safety Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **Dialectical Multi-Agent Triangulation** | **High** | LangChain/LiteLLM or direct SDKs, Pydantic v2 | Claude (L7) | Model divergence or looping; mitigated by bounded rounds ($N \le 2$) and strict deterministic verifier gate. |
| **Cryptographic Provenance (Merkle Seal)** | **High** | `cryptography` (Ed25519), hashlib | Codex (C7/C2) | Key loss; mitigated by local key generation and public-key export. |
| **State Transition Attack Graph (STAG)** | **Medium-High**| `networkx` or lightweight SQLite graph schema | Claude (L7) + Codex (C6) | Graph explosion; bounded by depth limit ($D \le 5$) and component limits. |
| **Stateful PTY Flight Recorder** | **Medium** | Python `pty`, `termios`, JSON-lines streaming | Codex (C1/C5) | Excessive output buffer size; mitigated by strict byte quotas and ring buffers. |
| **Ephemeral Session Rollback Manifest** | **High** | Python context managers, SQLAlchemy | Codex (C5/C2) | Target network drop prevents cleanup; records un-purged artifacts in remediation report. |

---

## 5. Architectural Recommendations for Next Slices

1. **Immediate Next Step for Claude (L7)**:
   - Expand `services/ai_analysis_worker` from single-plan parsing to the **Dialectical Verification Protocol**: Implement the `Skeptic` evaluator to challenge hypotheses before they are queued for operator review.
2. **Immediate Next Step for Codex (C6/C7)**:
   - Integrate the **Merkle Provenance Tree** into report generation: Hash all raw observation artifacts during report assembly and sign the root manifest with the local operator key.
3. **Immediate Next Step for Shared Engine**:
   - Adopt Gemini's verified [`vulnerability_correlation_engine.py`](file:///Users/shardul/Documents/aegis/drafts/gemini/vulnerability_correlation_engine.py) to provide the mathematical foundation for the State Transition Attack Graph.
