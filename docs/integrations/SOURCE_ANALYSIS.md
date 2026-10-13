# Source analysis (L6) — archive extraction and dependency inventory

Two tested parser slices in `services/source_analysis_worker`. **Neither is connected to the product**: there is no upload endpoint, no dispatch and no vulnerability lookup. Both parse hostile bytes with the Python standard library in the caller's process, so their budgets bound bytes and files, not the parser's own memory or time. Codex and Claude agreed (session log) that product use waits for an isolated, staged ingestion job designed together.

## `extract_archive(archive, destination, ...)`

Zip and tar (gzip, bzip2, xz) only. Tests are in `tests/integration/test_archive_ingestion.py`; every rejection asserts its reason, and each archive is built by the test.

| Behaviour | Detail |
| --- | --- |
| What is written | Regular files (mode 0600, created exclusively, never through a link) and directories, inside a directory the function creates itself. No execute or setuid bit survives. |
| What is skipped and reported | Symlinks, hard links, FIFOs, devices and sparse tar members. Their names are still validated first. |
| What rejects the whole archive | Absolute paths, `..`, backslash or drive-style names, paths deeper than 32 components or longer than 1024 bytes, a file entry with no name, duplicate or conflicting names, corrupt or encrypted data, anything over budget. Everything already written is removed; if removal fails, the error says so. |
| Budgets (strict integers, checked first) | `max_archive_bytes` for the input file; `max_files` for the archive's entries and for files plus folders actually created, implied parents included; `max_file_bytes` and `max_total_bytes` for bytes written as files. |
| Tar stream budget | Tar is decompressed here and read as one counted forward stream, so headers, extended metadata and the payload of skipped entries count as well. Zip entries that are skipped are never decompressed. |

Known limits: names differing only by case collide on a case-insensitive filesystem and reject the archive; nested archives stay as inert files; a zip's central directory is parsed by the standard library before the entry budget can apply (bounded only by `max_archive_bytes`).

## Staged extraction: `run_staged_extraction` and `staging.validate_staged_tree`

How a hostile archive is meant to be extracted, agreed with Codex and Gemini in the session log. It is still **not connected to the product**; Codex owns the staging lifecycle, adoption of the result and provenance.

1. The trusted parent creates an empty output folder inside a directory the child cannot write.
2. `services.scanner_worker.run_staged_extraction(archive, output, ...)` runs `extract_archive` in the sandbox: it can read the one archive and this project's `services` source, write only inside the output folder, and has no network and no fork. This is the only runner entry point whose files survive the run; the general `run_isolated` rejects any such option.
3. The child's printed summary is a claim. The parent then calls `staging.validate_staged_tree(output, ...)`, which inspects every entry with `lstat` before changing anything, accepts only real directories and singly linked regular files, clamps modes, recounts nodes and bytes against the same budgets, and on any problem deletes the folder and raises with `removed` set.
4. Removal (`remove_tree`, shared with the runner's scratch cleanup) survives mode 0 and immutable entries, unlinks a symbolic link instead of following it, and leaves a multiply linked file's mode and flags alone.

Tests: `tests/integration/test_staged_extraction.py`. Limits on this backend: no memory cap, and total disk use is detected by the recount after the fact, not prevented. Product ingestion stays unavailable until those are enforced.

## `dependencies.inventory(root)`

Reads `requirements*.txt` and `package-lock.json` (lockfile version 2 or 3) under a tree, without following symlinks and skipping `node_modules`, `.git` and virtualenv folders. Tests are in `tests/integration/test_dependency_inventory.py`.

- The result is **declared data** and says so in its `basis` field: what manifests state, not what is installed, and not checked against a registry or advisory source.
- A package is listed only with one valid exact version: PEP 440 for PyPI, semantic versioning for npm. Ranges, wildcards, bare names, editable installs, URL/VCS/path references, workspace links and non-registry sources are listed under `unresolved` with a reason.
- npm entries report the registry package name (so an alias folder reports the real package), the install `path`, and `source`: `registry` only for an https tarball URL without credentials, otherwise `undeclared`.
- Manifest lines can contain credentials, so unresolved lines are described, not echoed: an option shows only its name, a URL or path shows `direct reference`. A test plants one synthetic credential in six forms and asserts it never appears in the output.
- Only regular files are read; a FIFO, device or symlink named like a manifest is reported and not opened in a way that can block. Manifests over 5 MiB, invalid or deeply nested JSON and undecodable text are reported, not parsed.

Known limit: a line that is syntactically a pin (`word==1.0`) is reported as a package whatever it really is.

## `secrets.detect(root)`

A built-in baseline for secret-shaped text in an extracted tree: private key blocks and a few provider token formats (AWS access key IDs, GitHub, Slack, Google API, Stripe live, Anthropic and OpenAI project keys). The same rules drive redaction of bare tokens in reports and the session log. Tests are in `tests/integration/test_secret_detection.py`.

- Each match is reported by rule, file, line and a fingerprint. **The matched text is never returned**; the fingerprint lets a retest tell "the same secret is still there" from "a different one".
- A match is a pattern match, not a verified live credential, and the result's `basis` field says so. Obvious documentation fillers (`ghp_xxxx…`) are ignored.
- On the test's labelled 24-file tree it finds all 12 seeded secrets and reports none of the 12 look-alikes (public keys, certificates, test-mode keys, strings one character short or embedded in a longer word). That is a small synthetic tree, not a general accuracy claim.
- Only regular files up to 5 MiB are read; symlinks, FIFOs and oversized files are listed under `skipped`; `node_modules`, `.git` and virtualenv folders are not searched; output is capped per file and in total.

A secret that appears in a file's own name is redacted from the reported path. Known limits: eight formats only; no entropy analysis, no generic `password = "..."` detection, no decoding of base64 or archives, and nothing in git history. It is a baseline until an established scanner such as Gitleaks is installed and integrated, not a replacement for one.

```sh
.venv/bin/python -m unittest tests.integration.test_archive_ingestion tests.integration.test_dependency_inventory tests.integration.test_secret_detection -v
```

## Advisory matching (OSV)

`packages/scanner_adapters/integrations/osv.py` answers one question: which declared packages (from the dependency inventory above) fall inside the affected ranges of OSV advisory records the caller supplies. Tests: `tests/integration/test_osv_matching.py`. **No advisory data is bundled or downloaded and nothing calls this yet**, so today it reports nothing in the product; data arrives with the self-update work (`SELF_UPDATE.md`).

- Ranges are evaluated as the OSV schema defines: events sorted, every introduced/fixed window counted, `last_affected` inclusive, `limit` honoured. PyPI versions are ordered by PEP 440 (the `packaging` library), npm by SemVer 2.0.0. PyPI names are compared in normalised form, npm names exactly; ecosystems never cross.
- A match means a **declared** version lies in a **published** range. It does not show the vulnerable code is reachable or even installed.
- Severity is the advisory database's own word or `unknown`; a CVSS vector is never turned into a word. Withdrawn advisories report nothing.
- What cannot be evaluated for a declared package is listed in `not_evaluated` with a fixed reason: a commit-only (GIT) range, a malformed range or bound, a declared version that cannot be ordered. An advisory about a package that is not declared is ignored, however odd it is. A feed that is not OSV records at all is rejected.
- Written by Gemini against acceptance tests Claude wrote first; it passed all twelve. Review then found defects the tests had not covered, each reproduced before the fix: one unorderable declared version crashed the whole run; a legacy string in an advisory's version list, or a commit range beside a version range, suppressed a finding the version range plainly supported; an unevaluable entry hid the next package in the same advisory; `1.0` did not equal a listed `1.0.0`; two entries for one package produced two findings; one malformed alias anywhere rejected the entire feed.
- Limits: PyPI and npm only; input is at most 10 MiB per call, so a real database must be fed in pieces; `packaging` is installed through the test tools but is not yet a declared runtime dependency (asked of Codex).

