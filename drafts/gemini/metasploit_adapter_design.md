# Bounded Metasploit Integration Architecture (L4)

**Author**: Gemini (Principal Architect, Debugger & Helper)  
**Date**: 2026-10-12  
**Target Package**: Claude L4 (`packages/scanner_adapters/integrations/metasploit.py`)  
**Specification Requirements**: `MAIN_PROMPT.txt` lines 15, 38, 44; `packages/shared_schemas/__init__.py` lines 22-24.

---

## 1. Architectural Philosophy & Hard Boundaries

The Metasploit Framework is one of the most powerful penetration testing toolkits in existence. Its inclusion in SHARAY is strictly bounded by `MAIN_PROMPT.txt`:
> *"An exploit-framework name does not authorize exploitation. Intrusive validation needs an explicit approved profile, per-action approval, controlled conditions, tested rollback/stop behavior and actual execution isolation. Do not expose unrestricted interactive consoles, arbitrary LLM-generated commands/flags, stealth/persistence, credential theft, destructive payloads, ransomware, unrelated data retrieval or unrestricted lateral movement."*

### Explicit Prohibitions
1. **No Interactive Consoles**: `msfconsole` is never spawned in interactive mode (no pty, no shell loop, stdin is always `/dev/null`).
2. **No Exploit / Payload Modules**: Any module outside the strict allowlist is rejected upfront. Exploits (`exploit/*`), payloads (`payload/*`), post-exploitation (`post/*`), encoders (`encoder/*`), and evasion (`evasion/*`) are forbidden.
3. **No Dynamic / Free-Form Flags**: The command line is constructed from a typed, non-extensible data structure. No operator, model, or target string can inject msf command arguments or Ruby scripts.
4. **No Unauthenticated Exploitation**: Only non-destructive, informational auxiliary scanners (`auxiliary/scanner/*`) are permitted under `metasploit.approved_auxiliary`.

---

## 2. Supported Operations & Typed Contracts

In alignment with `packages/shared_schemas/__init__.py`:

### Operation 1: `metasploit.catalog`
- **Purpose**: Query local Metasploit installation metadata, installed module counts, and version without launching scans or contacting targets.
- **Execution Profile**: `catalog` (Risk: `passive`).
- **Command Structure**:
  ```sh
  msfconsole -q -v
  ```
  Returns version string (e.g., `Framework Version: 6.4.14-dev`).

### Operation 2: `metasploit.approved_auxiliary`
- **Purpose**: Execute an approved, non-destructive auxiliary module against an authorized single destination IP and port.
- **Execution Profile**: `approved_auxiliary` (Risk: `low`).
- **Allowlisted Auxiliary Modules**:
  ```python
  _APPROVED_MODULES = frozenset(
      {
          "auxiliary/scanner/http/http_version",
          "auxiliary/scanner/http/title",
          "auxiliary/scanner/http/options",
          "auxiliary/scanner/ssl/openssl_heartbleed",
          "auxiliary/scanner/ssl/ssl_version",
          "auxiliary/scanner/discovery/udp_probe",
          "auxiliary/scanner/ssh/ssh_version",
      }
  )
  ```
- **Execution Profile & Resource Bounds**:
  - Max seconds: 30s.
  - Max threads: 1 (`THREADS 1`).
  - Output format: JSON lines or formatted log via `-x`.

---

## 3. Invocation Mechanics (Non-Interactive, Headless)

Instead of relying on an interactive console, the adapter constructs a deterministic, single-shot script passed via `-x`:
```sh
msfconsole -q -n \
  -x "use <approved_module>; set RHOSTS <validated_ip>; set RPORT <port>; set THREADS 1; run; exit -y"
```
- `-q`: Suppress banner, cows, and ASCII art.
- `-n`: Disable database storage (prevents SQLite / Postgres connection requirements).
- `exit -y`: Guarantees the console terminates immediately after the run.
- `stdin`: Set to `subprocess.DEVNULL`.
- `egress`: Bound to the single target IP and port.

---

## 4. Output Normalization & Fact Retention

MSF module output produces progress lines (`[*]`) and status lines (`[+]`). The adapter parses stdout:
1. **Target Identification**: Validates that any reported host matches the requested canonical IP.
2. **Observations**: Converts observed services and protocol banners into normalized `observation` dictionaries:
   - `kind`: `"network_service"` or `"vulnerability_check"`
   - `state`: `"identified"` or `"checked"`
   - `evidence`: Redacted protocol attributes.
3. **No Automatic Vulnerability Promotion**: An open port or responsive SSL version is an observation, not a confirmed finding. A finding is produced only if the module reports a definitive negative condition (e.g. Heartbleed vulnerable).
4. **Data Redaction**: All raw responses pass through `redact_tokens()` from `packages/secret_patterns.py`.
