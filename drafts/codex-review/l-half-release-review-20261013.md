# L-half release review — October 13, 2026

Repository-source-only review. No L-half source edited, integrated or executed against a target.
SBOM package-name privacy was fixed and independently verified in `entry-966a933d7f7f416d`.
Container output privacy/completeness (`entry-8897c36a868a4fdd`) has a passing independent
follow-up (`entry-700a81a08dcc4eef`): source `a923f66f8fe060455bb43f7a77f76e1a4875d95cc857560a93c15311722883c0`,
unchanged requester acceptance3 tests/5subtests pass; removing identity redaction catches3
failures and dropping the per-file incomplete flag catches1 failure in in-memory mutants.
Items1–2 below are retained as the original before-fix evidence. Semantic and Metasploit
findings remain queued; Gemini drafts await owner review. No L-half source was adopted.

## Evidence and boundaries

- RAN independent reviewer: two Metasploit/normalizer modules, 6 tests passed in 0.26s.
- RAN independent reviewer: container module, 13 tests passed. Symlink/oversized-file
  refusal and file-count truncation worked.
- RAN root: every primary probe below reproduced using synthetic bytes/dicts and temporary
  Dockerfile text. Only booleans, rule IDs, counts and exception types were printed.
- READ root: affected parser functions, container scanner, worker persistence and Docker's
  original documentation. No Docker/Kubernetes/Metasploit execution, scanner, provider or
  live network assessment. Runtime security and universal parser accuracy are NOT CHECKED.
- Reviewed source hashes: metasploit `b89bea3f388072a078ae5b4b2dbdb92d302a802c0581cf5fd2cc0cf97fb5e498`,
  normalizer `4ef8a230ef9c25457fc7645ef19b4fd220bc8cbe17f26ba130d68ca62d225e2b`,
  containers `5ce4d16f0d67de3b2f91bc2ea477cff0d8ea782947535ccb182cf81599245010`.
  Subsequent source changes require focused rechecks.

## Container privacy and completeness

1. **P1 — containers.py:38,114.** An ordinary synthetic `ENV DB_PASSWORD` value appears
   in the result description; recognized provider tokens in image references and file paths
   also survive. The variable sample truncates before redaction. Expected: suppress
   credential-value samples and redact recognized tokens in all output-bearing fields
   before shortening. Root observed both ordinary-value and token/path retention.
2. **P2 — containers.py:61,325.** One Dockerfile containing 2,001 sensitive ENV instructions
   returns 2,000 findings with `truncated=False`. Expected: explicit incomplete coverage
   whenever the per-file finding cap drops data. Root repeated the count/flag mismatch.
3. **P2 — containers.py:77.** A stage with `USER app` and a healthcheck, then `FROM builder`,
   reports root execution and missing healthcheck. Expected: preserve configuration inherited
   from the named stage. Root saw both false-positive rule IDs.
4. **P2 — containers.py:89,145.** An untagged `registry.example:5000/app` with
   `HEALTHCHECK NONE` produces neither unpinned-image nor disabled-healthcheck hint.
   Expected: distinguish registry port from tag and recognize disabled healthchecking.
5. **P2 — containers.py:150.** An unknown base image with no local USER instruction yields
   a definitive root-execution claim. Expected: distinguish missing local configuration
   from unknown inherited runtime user; source text alone does not establish image metadata.
6. **P2 — containers.py:270.** CPU and memory limits whose values are null produce no
   missing-limit hint. Expected: reject invalid values or report absent effective declarations.

Docker's [FROM reference](https://docs.docker.com/reference/dockerfile/#from) explains
using a previous stage as the next base. Its [HEALTHCHECK reference](https://docs.docker.com/reference/dockerfile/#healthcheck)
describes NONE as disabling inherited healthchecking. The [image reference format](https://docs.docker.com/reference/cli/docker/image/tag/)
separates host port and tag and defaults a missing tag to latest. These are documentation
oracles, not observations of a built image.

## Metasploit metadata and identity

1. **P2 — metasploit.py:325.** Session timestamp JSON `1e999` is accepted and gives
   nonfinite duration; a 401-digit integer produces raw `OverflowError`. Expected:
   bounded finite numbers or fixed `ValueError`. Root reproduced both.
2. **P2 — metasploit.py:206.** Clearing a returned technique's nested preconditions
   changes the global catalog and future callers. Expected: independent nested values.
   The root probe mutated only its own short-lived Python process.
3. **P2 — metasploit.py:301.** Same module and endpoint, with only outcome changed,
   receives a different normalized Finding fingerprint. Expected: stable finding identity;
   changed outcome belongs in evidence/history. Both parser claims remain suspected.
4. **P2 — metasploit.py:211.** Catalog name `auxiliary/../scanner/http/title` is accepted.
   Expected: reject dot segments rather than normalize them. This demonstrates metadata
   validation failure, not execution or path escape.

## Integration contract

Current `aegis.worker` gives deterministic built-in safe HTTP results confirmed status and
safe_http provenance. An external parser must not enter that loop unchanged. Preserve
parser status/source, trusted organization/target/assessment/snapshot linkage and evidence
provenance; a parsed claim does not authorize validation or an interactive session.
Gemini's draft bridge and validation-session engine remain unadopted pending requester
acceptance, independent source review, relevant mutation checks and host execution controls.
