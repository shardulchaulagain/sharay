# Safe Scanner Installation Plan for Apple Silicon macOS

**Author**: Gemini (Principal Architect)  
**Date**: October 12, 2026  
**Host Context**: macOS on Apple Silicon (arm64), no Homebrew, loopback-fixture-only testing.  
**Policy**: No scanner is downloaded or executed until human review and approval.

---

## 1. Scanner Inventory & Specifications

### 1. Gitleaks
- **Role**: High-speed secret pattern analysis in git repositories and extracted filesystem trees.
- **Official Source**: `https://github.com/gitleaks/gitleaks/releases`
- **Target Release**: `v8.30.1` (`gitleaks_8.30.1_darwin_arm64.tar.gz`)
  *(Version verified via Google Search API in this session on October 12, 2026)*
- **License**: MIT License (`https://github.com/gitleaks/gitleaks/blob/master/LICENSE`)
- **Verification**:
  - Download `gitleaks_8.30.1_checksums.txt` and `gitleaks_8.30.1_darwin_arm64.tar.gz`.
  - Verification Command:
    ```bash
    shasum -a 256 -c gitleaks_8.30.1_checksums.txt --ignore-missing
    ```
- **Non-root Installation Path**: Single standalone binary placed in `tools/bin/gitleaks` (mode `0o755`).
- **Runtime Dependencies**: Self-contained Go static binary; zero external dependencies, no network required (`--no-git` flag operates over plain directory trees).

---

### 2. Semgrep (Core OSS CLI)
- **Role**: AST-based static source-code analysis for pattern-based vulnerabilities.
- **Official Source**: `https://github.com/semgrep/semgrep/releases` and PyPI `https://pypi.org/project/semgrep/`
- **Target Release**: `1.108.0`
  *(Note: Release series 1.x verified from official repo; exact pin 1.108.0 is a planned baseline subject to wheel hash check during pip installation)*
- **License**: LGPL 2.1 (core analysis engine: `https://github.com/semgrep/semgrep/blob/main/LICENSE`)
- **Verification**:
  - Pinned wheel hash verification via pip:
    ```bash
    .venv/bin/pip install --require-hashes -r tools/requirements-semgrep.txt
    ```
- **Non-root Installation Path**: `.venv/bin/semgrep`
- **Runtime Dependencies**: Python runtime (already in `.venv`); offline rules passed via `--config <path_to_rules.yaml>`; no network connection required (`--metrics=off` and `--disable-version-check`).

---

### 3. Nuclei
- **Role**: Template-driven vulnerability validation and HTTP checks against known exposures.
- **Official Source**: `https://github.com/projectdiscovery/nuclei/releases`
- **Target Release**: `v3.11.0` (`nuclei_3.11.0_macOS_arm64.zip`)
  *(Version verified via Google Search API in this session on October 12, 2026)*
- **License**: MIT License (`https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md`)
- **Verification**:
  - Download `checksums.txt` from release assets and verify:
    ```bash
    shasum -a 256 -c checksums.txt --ignore-missing
    ```
- **Non-root Installation Path**: `tools/bin/nuclei` (mode `0o755`).
- **Runtime Dependencies**: Self-contained Go static binary.
- **Strict Flags Required**: Offline mode (`-duc -ut=false` to prevent automatic template downloading) and explicit offline template path (`-t tools/templates/local/`).

---

### 4. Nmap
- **Role**: Authorized service discovery and TCP port inventory.
- **Official Source**: `https://nmap.org/dist/`
- **Target Release**: `7.95` (`nmap-7.95.tar.bz2`)
  *(Version verified from nmap.org official distribution directory)*
- **License**: Nmap Public Source License (NPSL, `https://nmap.org/npsl/`)
- **Verification**:
  - PGP signature verification against Fyodor's public key (Key fingerprint `43FC 68D2 3E73 01E8 2E01 71E7 AC45 083E 5D85 DC22`):
    ```bash
    gpg --verify nmap-7.95.tar.bz2.asc nmap-7.95.tar.bz2
    ```
- **Non-root Installation Path**: Extracted/built into `tools/nmap` (using `--prefix`).
- **Runtime Dependencies**: `nmap-services`, `nmap-os-db`, `nmap-payloads` data directory in `tools/nmap/share/nmap/`.
- **Privilege Boundary**: Must run strictly as unprivileged user with `-sT` (TCP Connect scan), never `-sS` (SYN stealth scan which requires raw socket root privileges).

---

### 5. OWASP ZAP (ZAP Core / CLI)
- **Role**: Web application proxy, automated spidering, and active/passive HTTP security checks.
- **Official Source**: `https://github.com/zaproxy/zaproxy/releases`
- **Target Release**: `2.16.0` (`ZAP_2.16.0_Core.tar.gz`)
  *(Version series verified from zaproxy/zaproxy releases page)*
- **License**: Apache 2.0 (`https://github.com/zaproxy/zaproxy/blob/main/LICENSE`)
- **Verification**:
  - SHA256 verification against published release checksum:
    ```bash
    shasum -a 256 -c ZAP_2.16.0_Core.tar.gz.sha256
    ```
- **Non-root Installation Path**: `tools/zap/`
- **Runtime Dependencies**: Requires **Java Runtime Environment (JRE 17+ or Temurin JRE)**. JRE is not pre-installed on this host, requiring an unprivileged headless OpenJDK tarball in `tools/jre/`.

---

## 2. Risk vs. Product Value Ranking (Loopback Fixture Setup)

| Priority | Tool | Product Value | Operational Risk | Rationale |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Gitleaks** | **High** | **Lowest** | Single Go binary, zero network calls, operates purely on local files, deterministically verifiable via SHA256 checksums, unprivileged. |
| **2** | **Semgrep** | **High** | **Low** | Python/C++ wheel running inside existing `.venv`, offline rule sets, strictly non-root, highly complementary to source analysis. |
| **3** | **Nuclei** | **Medium-High** | **Low-Medium** | Single Go binary, but requires strict command flags (`-duc -ut=false`) to disable background template updates and network phoning. |
| **4** | **Nmap** | **Medium** | **Medium** | Service discovery value is bounded in loopback fixture testing; must enforce unprivileged `-sT` flag to avoid raw socket requirements. |
| **5** | **OWASP ZAP** | **High** | **Highest** | Heavyweight dependency (requires JRE 17+ JVM), multi-process overhead, long startup time (~5-10s), complex headless daemon configuration. |
