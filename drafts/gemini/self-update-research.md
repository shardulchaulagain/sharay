# Self-Updating Detection Content & Scanner Research

This research document evaluates the automated self-updating requirements for SHARAY as established on October 12, 2026 (`MAIN_PROMPT.txt`, Self-Updating Requirement).

SHARAY requires maintaining current scanner binaries, detection rules, vulnerability templates, and advisory feeds without human intervention, while strictly enforcing cryptographic integrity, automated regression validation, non-intrusive safety bounds, and rollback guarantees.

---

## 1. Scanner & Advisory Research Dossiers

### 1.1 Gitleaks

- **Official Machine-Readable Source for Latest Version & Content**:
  - Latest version metadata: GitHub Releases API at `https://api.github.com/repos/gitleaks/gitleaks/releases/latest` (parses `tag_name`, e.g., `v8.30.1`, and published assets).
  - Download binary artifact: `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz` (and `gitleaks_8.30.1_linux_amd64.tar.gz`).
  - Checksums manifest: `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt`.
- **Signing, Checksumming & Exact Verification Step**:
  - Gitleaks uses GoReleaser with keyless Sigstore / Cosign signing in GitHub Actions.
  - Signature bundle: `gitleaks_<version>_checksums.txt.sigstore.json` (or `.sig` and `.pem`).
  - Verification sequence:
    1. Verify `checksums.txt` integrity via Cosign:
       ```sh
       cosign verify-blob \
         --bundle gitleaks_<version>_checksums.txt.sigstore.json \
         --certificate-identity-regexp "^https://github.com/gitleaks/gitleaks/\.github/workflows/.*" \
         --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
         gitleaks_<version>_checksums.txt
       ```
    2. Verify downloaded binary archive against verified checksums:
       ```sh
       shasum -a 256 -c --ignore-missing gitleaks_<version>_checksums.txt
       ```
- **Change Cadence**:
  - Bi-weekly to monthly (typically 1–3 patch/minor releases per month as new token formats or performance patches land).
- **Licence Terms for Redistribution**:
  - **MIT License**: Core CLI tool (`gitleaks`) is permissive open source. Redistribution and commercial execution are permitted with copyright attribution.
  - *Note*: `gitleaks-action` (the GitHub Action wrapper) has a proprietary commercial license for organizations, but the underlying CLI engine is 100% MIT.
- **What Breaks if Updated Blindly**:
  - **Rule IDs and Definitions**: Default embedded `gitleaks.toml` frequently renames rule identifiers, tunes Shannon entropy cutoffs, or modifies regular expression boundary groups (`(?![A-Za-z0-9])` vs word boundaries).
  - **Report JSON Schema Shifts**: Alterations to keys (`Match`, `Secret`, `StartLine`, `Fingerprint`) break downstream adapter normalization in `packages/scanner_adapters/integrations/`.
  - **Single Biggest Risk**: **Adapter ingestion parser crashes and finding fingerprint instability caused by silent rule ID renames and JSON structure alterations.**

---

### 1.2 Semgrep

- **Official Machine-Readable Source for Latest Version & Content**:
  - PyPI JSON API: `https://pypi.org/pypi/semgrep/json` (`info.version` -> `1.180.0`, `releases["1.180.0"]` provides wheel/sdist artifact URLs and SHA-256 digests).
  - GitHub Releases API: `https://api.github.com/repos/semgrep/semgrep/releases/latest`.
  - Direct Wheel Download: `https://files.pythonhosted.org/packages/.../semgrep-1.180.0-cp313-cp313-macosx_...whl`.
- **Signing, Checksumming & Exact Verification Step**:
  - PyPI generates authoritative SHA-256 hashes recorded in PyPI API metadata and publishes PEP 740 Sigstore digital attestations.
  - Verification sequence:
    1. Fetch `digests.sha256` from HTTPS PyPI JSON API for target wheel.
    2. Compute SHA-256 of downloaded wheel:
       ```sh
       shasum -a 256 semgrep-<version>-<platform>.whl
       ```
    3. Assert exact match before pip installation into isolated virtual environment.
- **Change Cadence**:
  - Weekly (rapid release cadence; typically 1–2 releases per week).
- **Licence Terms for Redistribution**:
  - **Hybrid / Dual Licensing**:
    - **Semgrep Core Engine (CLI)**: **LGPL-2.1** (open source; permitted for internal execution, modification requires sharing engine source under LGPL).
    - **Semgrep Rules Registry (`semgrep-rules`)**: Governed by the **Semgrep Rules License v1.0 (Source-Available / Restricted)**! This explicitly **prohibits third parties from commercializing, bundling, or serving Semgrep-maintained rules in competing products or SaaS offerings**.
    - **Semgrep Pro/Extensions**: Proprietary commercial software.
- **What Breaks if Updated Blindly**:
  - **CLI Flags Deprecation**: Flags frequently change or deprecate between releases (e.g., changes to `--json`, `--config`, `--legacy`).
  - **Rule Syntax Parsing**: Changes in pattern operators or AST syntax can cause older custom rules to fail validation and abort scans.
  - **Licence Violation**: Blindly syncing rules from the public Semgrep Registry risks commercial license infringement under Semgrep Rules License v1.0.
  - **Single Biggest Risk**: **Licence infringement from automatically pulling Semgrep Registry rules into a redistributed platform, combined with CLI invocation flag breakages.**

---

### 1.3 Nuclei and Nuclei-Templates

- **Official Machine-Readable Source for Latest Version & Content**:
  - Nuclei Engine API: `https://api.github.com/repos/projectdiscovery/nuclei/releases/latest` (`tag_name` -> `v3.11.1`).
  - Nuclei Engine Archive & Checksum: `https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_macOS_arm64.zip` and `checksums.txt`.
  - Nuclei Templates API: `https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest`.
  - Templates Source Tarball: `https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v<version>.tar.gz` (or git tracking of `https://github.com/projectdiscovery/nuclei-templates.git`).
- **Signing, Checksumming & Exact Verification Step**:
  - **Engine**: Release assets include `checksums.txt`.
    ```sh
    shasum -a 256 -c --ignore-missing checksums.txt
    ```
  - **Templates**: ProjectDiscovery embeds an **ECDSA Digital Signature** in every template file (`# digest: <signature>` comment). The Nuclei engine contains ProjectDiscovery's public key and verifies template authenticity during parsing.
    Verification step: Run template verification via the engine:
    ```sh
    nuclei -validate -t <templates_directory>
    ```
- **Change Cadence**:
  - Engine: Every 2–4 weeks.
  - Templates: **Daily to multiple times per day** (continuous feed of community and ProjectDiscovery CVE templates).
- **Licence Terms for Redistribution**:
  - Both Nuclei Engine and Nuclei-Templates are licensed under the **MIT License** (permissive open source, distribution permitted with attribution).
- **What Breaks if Updated Blindly**:
  - **Scope & Intrusiveness Breach**: Community templates frequently add intrusive exploit probes (remote code execution payloads, destructive write requests, or out-of-band network calls to Interactsh/OOB servers). If ingested without filtering, these violate SHARAY's non-intrusive safety policy and lab authorization bounds!
  - **Template Syntax Evolution**: Nuclei engine updates introduce new protocol requirements (`code`, `javascript`, flow templates) that older engines cannot run, or deprecate older DSL helpers.
  - **Template Signature Invalidation**: Local modifications to templates invalidate embedded ECDSA digests, causing Nuclei to reject them unless explicitly bypassed.
  - **Single Biggest Risk**: **Scope and safety violations: new untriaged templates executing intrusive exploits or external OOB callbacks on targets without explicit operator approval.**

---

### 1.4 Nmap

- **Official Machine-Readable Source for Latest Version & Content**:
  - Official Distribution Directory: `https://nmap.org/dist/` (contains source tarballs, RPMs, and GPG detached signatures).
  - GitHub Mirror Tags: `https://api.github.com/repos/nmap/nmap/tags` (for tracking commits/tags).
  - Source Archive URL: `https://nmap.org/dist/nmap-7.991.tar.bz2` (or `.tar.gz`).
  - GPG Signature URL: `https://nmap.org/dist/sigs/nmap-7.991.tar.bz2.asc`.
  - Checksums: `https://nmap.org/dist/sigs/` (SHA-256 digests).
- **Signing, Checksumming & Exact Verification Step**:
  - Releases are signed with Fyodor's Nmap Project Signing Key (GPG Key ID: `43EA64BA50F688B8` / `BB613316F75DE443`).
  - Verification sequence:
    1. Import Nmap project public key from official sources:
       ```sh
       gpg --recv-keys 43EA64BA50F688B8
       ```
    2. Verify detached OpenPGP signature:
       ```sh
       gpg --verify nmap-7.991.tar.bz2.asc nmap-7.991.tar.bz2
       ```
    3. Verify SHA-256 digest:
       ```sh
       shasum -a 256 -c nmap-7.991.tar.bz2.sha256
       ```
- **Change Cadence**:
  - Low / Infrequent (typically 1–2 releases per year; long stability cycles).
- **Licence Terms for Redistribution**:
  - **NPSL (Nmap Public Source License v0.92+)**: A custom license derived from GPLv2 with strict proprietary software restrictions.
  - Specifically **forbids embedding or redistributing Nmap within commercial products or appliances without an Nmap OEM commercial license agreement**.
- **What Breaks if Updated Blindly**:
  - **Host OS & Privilege Assumptions**: Changes to socket mechanisms, raw packet captures, or NSE script execution requirements (requiring `root` vs unprivileged `-sT` connect scans).
  - **NSE Script Deprecations**: Renamed or removed Lua scripts breaking `--script` arguments.
  - **Machine-Readable XML Output (`-oX`)**: Changes to XML element hierarchy or service fingerprint attributes breaking downstream parsing.
  - **Compilation Failures**: On macOS, updates require compiling source against specific versions of `libpcap`, `openssl`, and `liblua`.
  - **Single Biggest Risk**: **NPSL commercial license restriction, coupled with host compilation failures and privilege/sandbox requirement changes breaking unprivileged execution.**

---

### 1.5 OSV (Open Source Vulnerabilities) Advisory Data

- **Official Machine-Readable Source for Latest Version & Content**:
  - Ecosystems Manifest: `https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt` (lists all supported package ecosystems).
  - Bulk Database Download (Full): `https://storage.googleapis.com/osv-vulnerabilities/all.zip`.
  - Per-Ecosystem Bulk Download: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` (e.g., `PyPI/all.zip`, `npm/all.zip`, `Go/all.zip`).
  - Incremental Manifest: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/modified_id.csv` (contains advisory ID and modification timestamps).
  - REST Query API: `https://api.osv.dev/v1/query` and `https://api.osv.dev/v1/vulns/<ID>`.
- **Signing, Checksumming & Exact Verification Step**:
  - Google Cloud Storage serves HTTP response headers:
    - `x-goog-hash`: Contains `crc32c=<base64>` and `md5=<base64>`.
    - `ETag`: GCS object MD5/generation hash.
  - Verification sequence:
    1. Query GCS object metadata via HTTP `HEAD` request to capture `x-goog-hash`.
    2. Download target archive into temporary staging directory.
    3. Compute local MD5 / CRC32C over downloaded file and verify against header.
    4. Unpack in memory/disk and validate extracted JSON records against OpenSSF OSV Schema v1.6.0 specification.
- **Change Cadence**:
  - **Continuous / Hourly**: Upstream advisory databases (GHSA, PyPA, RustSec, Debian SecDB) are continuously aggregated and exported multiple times daily.
- **Licence Terms for Redistribution**:
  - **Multi-Licensed Aggregation**:
    - OSV aggregates disparate feeds; each advisory retains its upstream source license:
      - GitHub Security Advisories: **CC-BY 4.0**
      - PyPI Advisory DB / Go Vuln DB: **CC-BY 4.0**
      - RustSec / GSD: **CC0 1.0 (Public Domain)**
    - Redistribution is permitted with appropriate attribution (as required by CC-BY 4.0).
- **What Breaks if Updated Blindly**:
  - **Disk / Memory Exhaustion**: `all.zip` contains hundreds of thousands of individual JSON files; unpacking the entire archive without ecosystem filters consumes gigabytes of storage and inodes.
  - **Upstream Schema Deviations**: Invalid version strings or unparseable SemVer ranges in community advisories crashing version comparison algorithms.
  - **Withdrawn Advisories**: Retracted advisories (`withdrawn` timestamp present) causing false alarms or zombie findings if not correctly handled as revocations.
  - **Single Biggest Risk**: **Resource exhaustion (gigabyte unpacks / inode exhaustion) and crashes caused by malformed version ranges in unvalidated upstream records.**

---

## 2. Proposed Seven-Stage Self-Updating Pipeline

To fulfill the October 12 engineering mandate without risking product stability, authorization breaches, or scope creep, SHARAY must implement a strict seven-stage pipeline:

```
[1. CHECK] ──> [2. FETCH] ──> [3. VERIFY] ──> [4. STAGE]
                                                    │
[7. ROLLBACK] <── [6. ACTIVATE] <── [5. EVALUATE] <─┘
```

### Stage 1: CHECK (Manifest & Version Polling)
- Query the publisher's official machine-readable metadata endpoint (GitHub Releases API, PyPI JSON API, GCS `modified_id.csv`).
- Compare reported remote version and ETag/hash against the locally pinned active version recorded in `config/versions.json`.
- If identical, terminate cleanly. If newer, record candidate version.

### Stage 2: FETCH (Atomic Staged Download)
- Download artifact exclusively over HTTPS to an isolated temporary scratch directory (`.cache/updates/staging/<tool>/<version>`).
- Enforce strict size and timeout quotas (e.g., maximum 500 MB, 120s timeout) to prevent disk exhaustion attacks.
- Never write directly to production executable paths.

### Stage 3: VERIFY (Cryptographic Signatures & Checksums)
- Perform cryptographic verification before unpacking or executing:
  - For Gitleaks: Cosign certificate identity verification on `checksums.txt`, then SHA-256 match.
  - For Semgrep: PyPI SHA-256 digest match.
  - For Nuclei Engine: `checksums.txt` SHA-256 match.
  - For Nuclei Templates: ProjectDiscovery ECDSA digest signature check (`nuclei -validate`).
  - For Nmap: Detached GPG signature verification against Fyodor's public key (`43EA64BA50F688B8`), then SHA-256 match.
  - For OSV: GCS `x-goog-hash` MD5/CRC32C verification and JSON schema conformance.
- Any signature or checksum failure immediately aborts the update, deletes staged files, and logs an alert.

### Stage 4: STAGE (Isolated Sandboxed Extraction)
- Extract the verified archive into a version-isolated directory:
  `tools/bin/<tool>-<version>/` or `data/<advisory>-<version>/`.
- Mark executable binaries read-only (`chmod 0555`).
- For templates and rules, run automated safety filters:
  - Filter out templates requiring intrusive protocols, remote code execution flags, or Interactsh/OOB network callbacks unless authorized.

### Stage 5: EVALUATE (Corpora & Regression Gates)
- **Zero-Trust Validation**: The candidate version is never activated until it proves compatibility.
- Execute existing product integration tests and independent evaluation corpora against the staged version:
  - Run `tests.evaluation.secret_detection` against Gitleaks / secret rules.
  - Run `tests.evaluation.http_configuration` against HTTP checks.
  - Run tool report parser regression suites (`tests/integration/test_tool_report_parsers.py`).
  - Verify adapter outcome contracts, fingerprint stability, and error handling.
- If any test, gate, or evaluation score degrades below baseline (e.g., unexpected false positives or parser failures), the update is rejected.

### Stage 6: ACTIVATE (Atomic Symlink Swap & Ledger Pinning)
- If all regression tests and evaluation gates pass:
  - Perform an atomic directory symlink swap (`tools/bin/<tool>/current` -> `tools/bin/<tool>-<version>/`).
  - Update `config/versions.json` recording:
    - Tool name and newly activated version string
    - Cryptographic SHA-256 hash of the binary/content
    - Verification timestamp and publisher signature identifier
    - Evaluation gate exit codes and test results
  - Retain the immediate previous version directory (`tools/bin/<tool>-<previous>/`) for instant rollback.

### Stage 7: ROLLBACK (Instant Fallback)
- If runtime errors, unexpected crashes, or operational defects are detected post-activation:
  - Atomic symlink rollback to the retained previous version.
  - Record the rollback event and reason in the audit ledger.
  - Blacklist the failing candidate version from automatic re-installation until human intervention.

---

## 3. URLs Examined in this Session

- Gitleaks Repository & Releases: `https://github.com/gitleaks/gitleaks/releases`
- Semgrep GitHub Releases: `https://github.com/semgrep/semgrep/releases`
- Semgrep PyPI Metadata: `https://pypi.org/pypi/semgrep/json`
- Semgrep Licensing Documentation: `https://semgrep.dev/docs/licensing/`
- ProjectDiscovery Nuclei Releases: `https://github.com/projectdiscovery/nuclei/releases`
- ProjectDiscovery Nuclei-Templates: `https://github.com/projectdiscovery/nuclei-templates`
- ProjectDiscovery Template Signing: `https://docs.projectdiscovery.io/templates/introduction#template-signing`
- Nmap Official Distribution Directory: `https://nmap.org/dist/`
- Nmap GPG Signatures Directory: `https://nmap.org/dist/sigs/`
- Nmap Public Source License (NPSL): `https://nmap.org/npsl/`
- OSV Storage Bucket Documentation: `https://ossf.github.io/osv-schema/`
- OSV Cloud Storage Endpoint: `https://storage.googleapis.com/osv-vulnerabilities/`
