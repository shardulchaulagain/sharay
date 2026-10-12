# Prioritized implementation roadmap

Current roadmap (October 12, 2026): the product is now SHARAY. Read `MAIN_PROMPT.txt`, `docs/TEAM_ASSIGNMENTS.md` and `docs/IMPLEMENTATION_STATUS.md` for live-system goals, Codex/Claude responsibilities and actual current results. The following October 11 foundation roadmap is preserved as historical baseline, not a claim that no product exists today.

Date: October 11, 2026. Initial state: Aegis was an empty directory with no Git repository or product functionality. The user approved preparing the engineering foundation first. This plan does not imply approval for future production changes or paid services.

| Priority | Work | Evidence / acceptance | State |
| --- | --- | --- | --- |
| P0 | Establish truthful baseline and tool inventory | Zero-file inventory, explicit gaps, sourced conditional choices | Audited |
| P0 | Add repository guidance, deterministic tests, evidence collection and local dashboard | Tests cover pass/fail/not-run/blocked/timeout, credential handling, hidden files and injection; dashboard interaction checked | Foundation implementation |
| P0 | Add specialized reusable skills to user scope | Six structurally validated skills, source review and installation equality check | Prepared; installation recorded in delivery evidence |
| P1 | Define product problem and acceptance criteria | Users, core flows, data sensitivity, integration targets, availability goals, cost budget | Needs product requirements |
| P1 | Choose product stack and data/access boundaries | Small ADR, appropriate existing tooling, explicit auth/authorization model | Needs P1 requirements |
| P1 | Connect an actual GitHub repository and enforce CI | Reviewed repository identity, successful remote checks, required status checks | No remote repository supplied |
| P1 | Verify and enable dedicated secret scanning | Official pinned Gitleaks CLI, redacted positive fixture detection and exit-policy check, files/history scope | Not installed/run |
| P2 | Add stack-native lint/types/unit/integration checks | Rules fit implemented code; tests cover real behavior and denied access | No product stack yet |
| P2 | Resolve and scan real dependencies | Lockfile, SBOM artifact identity and advisory DB age; choose Trivy or Syft+Grype | No product dependencies yet |
| P2 | Add one SAST workflow | Reviewed Semgrep rules or justified SonarQube service; findings triaged | No application code yet |
| P2 | Ship first tested product slice | End-to-end acceptance, safe persistence and authenticated access if needed | Needs requirements and stack |
| P3 | Browser/accessibility regressions | Playwright Test on real user flows; keyboard, labels, focus, contrast evidence | Foundation dashboard checked manually; product unavailable |
| P3 | Measure product performance and memory | Representative workload, repeated baseline, percentile/error threshold and environment record | No product workload yet |
| P3 | Add instrumentation and chosen monitoring services | Real emitted traces/metrics/logs, redaction and retention checks | No running product services |
| P4 | Production preparation and approved release | Threat model, recovery/rollback test, deployment review, explicit human approval | Not authorized/provisioned |
| P4 | AI/ML experiments | Reproducible dataset/model/code/seed, bounded compute and observed cost | Await actual research hypothesis |

## Selection rules

Use the existing Context7 and GitHub connectors before another MCP. Verify the configured Chrome DevTools server can launch and expose tools before depending on it. Playwright MCP is optional for agent exploration; Playwright Test is for reproducible regression checks. Install tools only after provenance and applicability are established. Do not stack competing scanners without a specific coverage gap. Choose native/standard-library mechanisms when they meet the measured need.

## Change acceptance protocol

For each substantial improvement, record the requested outcome, affected code, baseline command and environment, implementation, actual check command/exit and observations. Benchmarks require comparable repeated measurements; a new feature is not a speed improvement. A blocked or unexecuted check stays visible. Preserve approved scope, and prepare concrete consequential changes for human approval before performing them.

## Pending product input

The next architecture decision requires the purpose of Aegis, primary users, first user workflow, data/integrations and deployment constraints. A framework cannot be selected from the word “advanced.” No existing business functionality was available to preserve or benchmark.
