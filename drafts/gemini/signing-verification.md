# Publisher Release Signing & Verification Verification Report

Task reference: `entry-72d2c961a27b4a8f` (Claude `help-request` to `gemini`).
Method: Read-only HTTP fetches of publisher release APIs, release assets, `.goreleaser.yml` / workflow files, PyPI PEP 740 integrity endpoints, and official documentation pages. No binaries were downloaded, nothing was installed, and no verification tools were executed. Every statement below is marked `FETCHED (<URL>)` or `NOT CONFIRMED (<reason>)`.

---

## 1. Gitleaks 8.30.1 (`v8.30.1`)

### (1) Exact asset names that are checksum, signature, or attestation files
- **FETCHED (`https://api.github.com/repos/gitleaks/gitleaks/releases/tags/v8.30.1` and `https://api.github.com/repos/gitleaks/gitleaks/releases/299662760/assets`)**:
  - Release `v8.30.1` (`"id": 299662760`, `"published_at": "2026-03-21T02:17:58Z"`, `"immutable": false`) contains **11 assets** in total.
  - **Checksum asset (1 file)**:
    - `"name": "gitleaks_8.30.1_checksums.txt"` (`"size": 999`, `"digest": "sha256:061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae"`, `"browser_download_url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt"`).
  - **Signature or attestation assets (0 files)**:
    - None. The remaining 10 assets in the release are the unsigned archive files:
      - `"gitleaks_8.30.1_darwin_arm64.tar.gz"` (`"digest": "sha256:fae9fb3bcad2eedb7febd1fb4fa3fb7fc7fbef32dae3d1ca1ffbf7aa32ebcced"`, `"size": 4383282`)
      - `"gitleaks_8.30.1_darwin_x64.tar.gz"` (`"digest": "sha256:3bd26fb2d0fdbf9c6fd6fbca71be9dc4e4a1c3ba28ba0b42e10a44ca44a00828"`)
      - `"gitleaks_8.30.1_linux_arm64.tar.gz"` (`"digest": "sha256:6b8da42fe8a6f0cb8b967ab7eb7fd1a8aa9a9f57eb0b6a69de28b001955b33fb"`)
      - `"gitleaks_8.30.1_linux_armv6.tar.gz"` (`"digest": "sha256:e49a5d7c6b9fd3782c1ff46b4827f418389cfba3057d4cb9e674d689d9b775c8"`)
      - `"gitleaks_8.30.1_linux_armv7.tar.gz"` (`"digest": "sha256:7f1db88ca6f2bd989b410467a0ab18cfdc83d135f2ba8cb89b44cf4d8bc62c22"`)
      - `"gitleaks_8.30.1_linux_x32.tar.gz"` (`"digest": "sha256:58dc16d30d9c92a493be6a2b9a5900897db1a946cf2867bc2eb3c3a04a01d031"`)
      - `"gitleaks_8.30.1_linux_x64.tar.gz"` (`"digest": "sha256:bc8bf19388ebaa7841e65fb9f98b32db3c04a7d56ab051ab5019eb817557a8a7"`)
      - `"gitleaks_8.30.1_windows_arm64.zip"` (`"digest": "sha256:362d9f7b1f0b1750aa2bb13426cf3861a2ff52ebba16e9ebca13fa85a779f076"`)
      - `"gitleaks_8.30.1_windows_x32.zip"` (`"digest": "sha256:4ef1be3c4da8f242c4452be8bf65f300be24bc903bc9aa63de18f2b1297ab4c5"`)
      - `"gitleaks_8.30.1_windows_x64.zip"` (`"digest": "sha256:bf36ca8a14141fa079ed7252f59fd80ca36f33c399fd10002d06cd37fb226032"`)
- **FETCHED (`https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt`)**:
  Verbatim contents of `gitleaks_8.30.1_checksums.txt`:
  ```text
  # Checksums for gitleaks_8.30.1
  362d9f7b1f0b1750aa2bb13426cf3861a2ff52ebba16e9ebca13fa85a779f076  gitleaks_8.30.1_windows_arm64.zip
  58dc16d30d9c92a493be6a2b9a5900897db1a946cf2867bc2eb3c3a04a01d031  gitleaks_8.30.1_linux_x32.tar.gz
  7f1db88ca6f2bd989b410467a0ab18cfdc83d135f2ba8cb89b44cf4d8bc62c22  gitleaks_8.30.1_linux_armv7.tar.gz
  3bd26fb2d0fdbf9c6fd6fbca71be9dc4e4a1c3ba28ba0b42e10a44ca44a00828  gitleaks_8.30.1_darwin_x64.tar.gz
  bc8bf19388ebaa7841e65fb9f98b32db3c04a7d56ab051ab5019eb817557a8a7  gitleaks_8.30.1_linux_x64.tar.gz
  fae9fb3bcad2eedb7febd1fb4fa3fb7fc7fbef32dae3d1ca1ffbf7aa32ebcced  gitleaks_8.30.1_darwin_arm64.tar.gz
  4ef1be3c4da8f242c4452be8bf65f300be24bc903bc9aa63de18f2b1297ab4c5  gitleaks_8.30.1_windows_x32.zip
  6b8da42fe8a6f0cb8b967ab7eb7fd1a8aa9a9f57eb0b6a69de28b001955b33fb  gitleaks_8.30.1_linux_arm64.tar.gz
  bf36ca8a14141fa079ed7252f59fd80ca36f33c399fd10002d06cd37fb226032  gitleaks_8.30.1_windows_x64.zip
  e49a5d7c6b9fd3782c1ff46b4827f418389cfba3057d4cb9e674d689d9b775c8  gitleaks_8.30.1_linux_armv6.tar.gz
  ```

### (2) Whether the checksum file itself is signed and by what
- **FETCHED (`https://api.github.com/repos/gitleaks/gitleaks/releases/299662760/assets`, `https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/.goreleaser.yml`, and `https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/.github/workflows/release.yml`)**:
  - **No.** `gitleaks_8.30.1_checksums.txt` is **not signed** (no GPG `.asc`/`.sig`, no Cosign `.sig`/`.pem`/`.bundle`, and no GitHub Artifact Attestation).
  - Verbatim `.goreleaser.yml` lines 31–33 (`https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/.goreleaser.yml`):
    ```yaml
    checksum:
      name_template: "{{ .ProjectName }}_{{ .Version }}_checksums.txt"
    ```
    There is no `signs:` or `docker_signs:` section in `.goreleaser.yml`.
  - Verbatim `.github/workflows/release.yml` lines 1–31 (`https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/.github/workflows/release.yml`) runs only `goreleaser/goreleaser-action@v6` with `args: release --clean` and `GITHUB_TOKEN` (`contents: write`), with no `actions/attest-build-provenance` or `sigstore/cosign-installer` step. Furthermore, in the GitHub Releases API response for `v8.30.1` (`https://api.github.com/repos/gitleaks/gitleaks/releases/299662760/assets`), all 11 assets were uploaded by `"uploader": {"login": "zricethezav", "type": "User"}` rather than `github-actions[bot]`, and the release has `"immutable": false`.

### (3) Exact verification command the publisher documents, with URL
- **FETCHED (`https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/README.md`)**:
  - **None.** The publisher does not document a checksum or signature verification command in `README.md`.
  - Verbatim installation section in `https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/README.md` (lines 75–95):
    ```markdown
    ### Installing

    `gitleaks` can be installed using Homebrew, Docker, or Go. `gitleaks` is also available in binary form for many popular platforms and OS types on the [releases page](https://github.com/gitleaks/gitleaks/releases). In addition, `gitleaks` can be implemented as a pre-commit hook directly in your repo or as a GitHub Action. Look at the [Usage section](#usage) to learn how.

    ```sh
    # MacOS
    brew install gitleaks

    # Docker (DockerHub)
    docker pull zricethezav/gitleaks:latest
    docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest [COMMAND] --source="/path" [OPTIONS]

    # Docker (ghcr.io)
    docker pull ghcr.io/gitleaks/gitleaks:latest
    docker run -v ${path_to_host_folder_to_scan}:/path ghcr.io/gitleaks/gitleaks:latest [COMMAND] --source="/path" [OPTIONS]

    # Build from source
    git clone https://github.com/gitleaks/gitleaks.git
    cd gitleaks
    make build
    ```
    ```

### (4) What an attacker who controls only the download host could still change
- Because `gitleaks_8.30.1_checksums.txt` is unsigned and hosted on the same download host (`github.com` / `objects.githubusercontent.com`) as `gitleaks_8.30.1_darwin_arm64.tar.gz`, and the release has `"immutable": false`:
  - **For an unpinned first install or unattended version update** where the client fetches both `gitleaks_<ver>_darwin_arm64.tar.gz` and `gitleaks_<ver>_checksums.txt` from the download host: an attacker who controls the download host (or compromises the maintainer's GitHub release assets) can replace **both** the tarball and the corresponding SHA-256 line in `gitleaks_<ver>_checksums.txt` (and the API `"digest"` metadata), passing checksum verification completely with an arbitrary malicious binary.
  - **If SHARAY pins the known SHA-256 out-of-band** (`fae9fb3bcad2eedb7febd1fb4fa3fb7fc7fbef32dae3d1ca1ffbf7aa32ebcced` for `gitleaks_8.30.1_darwin_arm64.tar.gz`) in repository code/config before downloading: an attacker controlling only the download host **cannot** substitute the archive contents without failing the local SHA-256 check, and can only cause denial-of-service (corrupted bytes, truncation, or HTTP failure).

---

## 2. Nuclei 3.11.1 (`v3.11.1`)

### (1) Exact asset names that are checksum, signature, or attestation files
- **FETCHED (`https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/v3.11.1`)**:
  - Release `v3.11.1` (`"id": 367195598`, `"published_at": "2026-08-08T12:21:32Z"`, `"immutable": false`) contains **9 assets** in total (all uploaded by `"uploader": {"login": "github-actions[bot]", "type": "Bot"}`).
  - **Checksum asset (1 file)**:
    - `"name": "nuclei_3.11.1_checksums.txt"` (`"size": 766`, `"digest": "sha256:8c55f4113c54dfa4a202e32eaaa8b78abc741a13ed7941651322748fb233a05e"`, `"browser_download_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt"`).
  - **Signature or attestation assets (0 files)**:
    - None in the release assets. The remaining 8 assets are the unsigned zip archives:
      - `"nuclei_3.11.1_linux_386.zip"` (`"digest": "sha256:9fb05df2b13b724eb9d9fb1b6067f17e8a4319ffdd7abfa369ff95ca05b5d0f2"`)
      - `"nuclei_3.11.1_linux_amd64.zip"` (`"digest": "sha256:e498d8401531bcde87a6b24d271c56d573f33764840033881a5cf190e041e00d"`)
      - `"nuclei_3.11.1_linux_arm.zip"` (`"digest": "sha256:b00a9fa09d9d8115f0fb5dc3a4c3b6f7e9ef2b88991d4f62d8cf84dc8de3cb02"`)
      - `"nuclei_3.11.1_linux_arm64.zip"` (`"digest": "sha256:89ce55890f9b6f0bd9f6f836a760a8d71a7fd6de32d6f491746fa950f4b8bc54"`)
      - `"nuclei_3.11.1_macOS_amd64.zip"` (`"digest": "sha256:e9c213fd9e663f226d354e023ffbe5293152236459b9575b0e78458732a4cfcc"`)
      - `"nuclei_3.11.1_macOS_arm64.zip"` (`"digest": "sha256:d4591643da3f98ee309025792e0d41fb555de115d7134ed0229050abbe8a5aa9"`, `"size": 27462739`)
      - `"nuclei_3.11.1_windows_386.zip"` (`"digest": "sha256:a62ec0a906068186dcbf1417488a6835be54fd90e1c9d193d07ef8e74e479c20"`)
      - `"nuclei_3.11.1_windows_amd64.zip"` (`"digest": "sha256:a5b887e853ebcc8cf782ebfb12ccfb66e7b31a5cf9fdba93a83d82257de3fd5b"`)
- **FETCHED (`https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt`)**:
  Verbatim contents of `nuclei_3.11.1_checksums.txt`:
  ```text
  89ce55890f9b6f0bd9f6f836a760a8d71a7fd6de32d6f491746fa950f4b8bc54  nuclei_3.11.1_linux_arm64.zip
  b00a9fa09d9d8115f0fb5dc3a4c3b6f7e9ef2b88991d4f62d8cf84dc8de3cb02  nuclei_3.11.1_linux_arm.zip
  a62ec0a906068186dcbf1417488a6835be54fd90e1c9d193d07ef8e74e479c20  nuclei_3.11.1_windows_386.zip
  9fb05df2b13b724eb9d9fb1b6067f17e8a4319ffdd7abfa369ff95ca05b5d0f2  nuclei_3.11.1_linux_386.zip
  e498d8401531bcde87a6b24d271c56d573f33764840033881a5cf190e041e00d  nuclei_3.11.1_linux_amd64.zip
  a5b887e853ebcc8cf782ebfb12ccfb66e7b31a5cf9fdba93a83d82257de3fd5b  nuclei_3.11.1_windows_amd64.zip
  e9c213fd9e663f226d354e023ffbe5293152236459b9575b0e78458732a4cfcc  nuclei_3.11.1_macOS_amd64.zip
  d4591643da3f98ee309025792e0d41fb555de115d7134ed0229050abbe8a5aa9  nuclei_3.11.1_macOS_arm64.zip
  ```

### (2) Whether the checksum file itself is signed and by what
- **FETCHED (`https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/v3.11.1` and `https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/.goreleaser.yml`)**:
  - **No.** `nuclei_3.11.1_checksums.txt` is **not signed**.
  - Verbatim `.goreleaser.yml` lines 55–56 (`https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/.goreleaser.yml`):
    ```yaml
    checksum:
      algorithm: sha256
    ```
    There is no `signs:` configuration in `.goreleaser.yml` and no signature/attestation file in the release assets.
- **NOT CONFIRMED (`macOS Mach-O embedded Apple Developer ID code signature inside nuclei_3.11.1_macOS_arm64.zip`)**:
  - `.goreleaser.yml` lines 16–32 configure macOS build hooks (`build_mac.sh`), which may invoke Apple `codesign` / notarization on the inner `nuclei` binary during CI, but because our rules forbid downloading or unpacking the binary archive, whether the inner `nuclei` executable carries an Apple Developer ID signature is `NOT CONFIRMED`. Even if present, `nuclei_3.11.1_checksums.txt` itself is unsigned.

### (3) Exact verification command the publisher documents, with URL
- **FETCHED (`https://docs.projectdiscovery.io/opensource/nuclei/install.md` and `https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/README.md`)**:
  - **None for release binaries.**
  - Verbatim binary installation instructions in `https://docs.projectdiscovery.io/opensource/nuclei/install.md` (lines 54–63):
    ```markdown
    <Tab title="Binary">
        ```sh
        https://github.com/projectdiscovery/nuclei/releases
        ```

        * Download the latest binary for your OS.
        * Unzip the ready to run binary.
    </Tab>
    ```
  - Verbatim installation section in `https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/README.md` (lines 89–95):
    ```markdown
    # Installation

    Nuclei requires **go1.22** to install successfully. Run the following command to install the latest version:

    ```sh
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    ```
    ```
  - Note on template signing vs. binary signing (`FETCHED` `https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/README.md` lines 178–180): Nuclei documents `-sign` (`signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable`) and `-dut, -disable-unsigned-templates` for **Nuclei YAML templates**, not for verifying the Nuclei release binary or `nuclei_3.11.1_checksums.txt`.

### (4) What an attacker who controls only the download host could still change
- Because `nuclei_3.11.1_checksums.txt` is unsigned and served from the same host (`github.com`) as `nuclei_3.11.1_macOS_arm64.zip` (and `"immutable": false` on the release):
  - **For an unpinned download or unattended update** that trusts `nuclei_<ver>_checksums.txt` fetched from the download host: an attacker controlling the download host can replace **both** `nuclei_<ver>_macOS_arm64.zip` and its SHA-256 entry in `nuclei_<ver>_checksums.txt`, achieving arbitrary code execution when the updated binary runs.
  - **If SHARAY pins the known SHA-256 out-of-band** (`d4591643da3f98ee309025792e0d41fb555de115d7134ed0229050abbe8a5aa9` for `nuclei_3.11.1_macOS_arm64.zip`) before downloading: an attacker controlling only the download host **cannot** forge a different zip archive matching that SHA-256 and can only cause denial-of-service.

---

## 3. Semgrep 1.180.0 (`1.180.0` / `v1.180.0`)

### (1) Exact asset names that are checksum, signature, or attestation files
- **FETCHED (`https://api.github.com/repos/semgrep/semgrep/releases/tags/v1.180.0`)**:
  - GitHub release `v1.180.0` (`"id": 406241999`, `"published_at": "2026-10-07T23:17:11Z"`, `"immutable": true`) has `"assets": []` (empty array — zero binary, checksum, or signature files are attached to the GitHub release).
- **FETCHED (`https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl/provenance`, `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_10_14_x86_64.whl/provenance`, `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-musllinux_1_2_aarch64.whl/provenance`, and `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0.tar.gz/provenance`)**:
  - On PyPI, Semgrep 1.180.0 publishes **PEP 740 cryptographic provenance attestation objects** via PyPI's integrity API (`/integrity/semgrep/1.180.0/<filename>/provenance`) for its platform wheels:
    1. **macOS arm64 wheel**: `"semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl"`
       - Attestation URL: `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl/provenance`
       - Signed in-toto v1 statement (`statement` base64-decoded verbatim):
         ```json
         {"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl","digest":{"sha256":"9c61070eaa7de785a8318e1d00de6c9151efa660cc3e58c3e2ffd6f5e6180af7"}}],"predicateType":"https://docs.pypi.org/attestations/publish/v1","predicate":null}
         ```
    2. **macOS x86_64 wheel**: `"semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_10_14_x86_64.whl"`
       - Attestation URL: `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_10_14_x86_64.whl/provenance`
       - Signed SHA-256 in statement: `"f074dcfd6a56095fde32c354af27ef0cce6d15607bef42fa50964dd7042b667d"`
    3. **Linux musllinux aarch64 wheel**: `"semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-musllinux_1_2_aarch64.whl"`
       - Attestation URL: `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-musllinux_1_2_aarch64.whl/provenance`
       - Signed SHA-256 in statement: `"1bab359e562f0af00217f9f827531c2e1375499b8559c90bed9690007e82565d"`
    4. **Source distribution (`semgrep-1.180.0.tar.gz`)**: `https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0.tar.gz/provenance` returned HTTP `404` (`FETCHED`).
- **NOT CONFIRMED (`exact Linux manylinux wheel filename(s) for 1.180.0`)**:
  - `https://pypi.org/pypi/semgrep/1.180.0/json` and `https://pypi.org/simple/semgrep/` exceed the read tool's truncation window before reaching the `1.180.0` `urls` table, so the exact `manylinux` filename tag for `1.180.0` is `NOT CONFIRMED` (the macOS arm64 wheel approved by the human is confirmed verbatim above).

### (2) Whether the checksum file itself is signed and by what
- **FETCHED (`https://pypi.org/integrity/semgrep/1.180.0/semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl/provenance`)**:
  - **Yes — for the wheel's SHA-256 digest via PEP 740 Sigstore DSSE attestation.**
  - While PyPI Simple/JSON index SHA-256 metadata (`#sha256=...`) is unsigned, the PEP 740 provenance bundle for `semgrep-1.180.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-macosx_11_0_arm64.whl` contains an in-toto v1 statement binding `"sha256": "9c61070eaa7de785a8318e1d00de6c9151efa660cc3e58c3e2ffd6f5e6180af7"` with:
    - **Envelope signature**: `"MEUCIQDAIqyyCnh2MvuX+I9RJyhb8yf2L0Zx9ttCezzRyXfmrgIgUncEVyQrW7EQYI/IjvP+FueWLvhYrkE+0TH59BIpuuQ="`
    - **Signer certificate authority**: Fulcio (`O=sigstore.dev, CN=sigstore-intermediate`), validity `2026-10-07T23:23:52Z` to `2026-10-07T23:33:52Z`.
    - **OIDC Identity (Certificate SAN & Fulcio OIDs)**:
      - Build Signer URI: `https://github.com/semgrep/semgrep-proprietary/.github/workflows/pro-release.yml@refs/heads/develop`
      - OIDC Issuer: `https://token.actions.githubusercontent.com`
      - Repository: `semgrep/semgrep-proprietary` (`private`)
      - Commit Digest: `037fc1defd47422849ce49028345a85dfbb6a7c7`
      - Run Invocation URI: `https://github.com/semgrep/semgrep-proprietary/actions/runs/37698236479/attempts/1`
      - Event: `workflow_dispatch`
    - **Transparency log**: Rekor DSSE entry included in `transparency_entries` (`envelopeHash.value`: `"d724c35a49d02b65321d81bb5cf8255197315e20f745d5be9cbdb5100a8b7f4f"`, `payloadHash.value`: `"6c2bb1729c43db400c401dddfdce62095cec3f5b2d1ba30ed1ea684259ecb0e2"`).

### (3) Exact verification command the publisher documents, with URL
- **FETCHED (`https://semgrep.dev/docs/getting-started/cli.md` and `https://raw.githubusercontent.com/semgrep/semgrep/v1.180.0/README.md`)**:
  - **None for cryptographic hash or PEP 740 attestation verification.** The publisher documents only package-manager installation followed by `semgrep --version`.
  - Verbatim from `https://semgrep.dev/docs/getting-started/cli.md` (lines 23–40):
    ```markdown
    Install the Semgrep CLI tool and confirm the installation:

    ```bash theme={null}
    # macOS, Linux, Windows users - using pipx (recommended)
    # See https://pipx.pypa.io/stable/how-to/install-pipx/ to install pipx
    pipx install semgrep

    # Or, if you use uv (https://docs.astral.sh/uv/)
    uv tool install semgrep

    # best-effort: install through homebrew (maintained on a best-effort basis; often lags behind the latest release)
    # ensure that you've added Homebrew to your PATH
    # https://docs.brew.sh/FAQ#my-mac-apps-dont-find-homebrew-utilities
    brew install semgrep

    # confirm
    semgrep --version
    ```
    ```
  - Verbatim from `https://raw.githubusercontent.com/semgrep/semgrep/v1.180.0/README.md` (lines 109–120 in JSON `description`):
    ```markdown
    1. Install Semgrep CLI

        ```
        # For macOS
        $ brew install semgrep

        # For Ubuntu/WSL/Linux/macOS
        $ python3 -m pip install semgrep
        ```
    ```

### (4) What an attacker who controls only the download host could still change
- **Under standard `pip install semgrep==1.180.0` (without `--require-hashes` and without PEP 740 attestation verification)**:
  - Standard `pip` checks the downloaded wheel against the `#sha256=...` fragment served by the PyPI simple index (`pypi.org`), and does **not** verify PEP 740 provenance bundles by default. An attacker who controls `pypi.org` / `files.pythonhosted.org` can serve a modified `semgrep` wheel **and** a matching modified `#sha256=...` in the simple index, or serve malicious transitive Python dependencies (since `semgrep`'s `Requires-Dist` pins minimum ranges such as `attrs>=21.3`, `click>=8.1.8`, `requests>=2.22.0`, etc., rather than exact hashes).
- **If SHARAY pins the exact wheel SHA-256 (`9c61070eaa7de785a8318e1d00de6c9151efa660cc3e58c3e2ffd6f5e6180af7`) OR verifies the PEP 740 Sigstore attestation bundle against Sigstore's root of trust (Fulcio + Rekor transparency log) and the expected SAN (`https://github.com/semgrep/semgrep-proprietary/.github/workflows/pro-release.yml@refs/heads/develop`)**:
  - An attacker who controls only the download host (`pypi.org` / `files.pythonhosted.org`) **cannot** forge a valid Fulcio certificate or Rekor inclusion proof for a tampered `semgrep` wheel.
  - **What the attacker could STILL change unless all transitive dependencies are also hash-pinned (`--require-hashes --no-deps`)**:
    1. Any **transitive dependency wheel/sdist** fetched during `pip install` if its hash is not pinned (or if it lacks a verified PEP 740 attestation).
    2. Note also an important supply-chain nuance revealed by the certificate (`FETCHED`): the `semgrep` wheel is built and attested from the **private** repository `semgrep/semgrep-proprietary` (`refs/heads/develop`, commit `037fc1defd47422849ce49028345a85dfbb6a7c7` via `workflow_dispatch`), not the public `semgrep/semgrep` tag `v1.180.0`, so public auditors cannot independently map the attested commit SHA to a public git tree.
