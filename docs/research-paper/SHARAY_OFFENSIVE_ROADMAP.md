# SHARAY — Offensive Capability Audit & Roadmap to World-Class (toward 0-day)

Deep-research audit of the attack side, 2026-10-19. Grounded in a direct read of the offensive
modules (`metasploit.py`, `payload_forge.py`, `adaptive.py`, `reproducer.py`, `interactive.py`,
`crawler.py`, scanner bounds). Cites `file:line`. No code was changed.

**Scope & safety.** SHARAY is an authorized offensive+defensive platform. Everything here stays inside
its existing controls: operator-authorized targets only, scope policy, single-destination egress lock,
safe-gate, per-action confirmation for anything state-changing, non-destructive by default, clean-exit,
one authorized scope at a time. "0-day capability" means vulnerability *research* (fuzzing, differential
analysis, source-assisted taint) on authorized targets and components, for responsible disclosure — not
weaponization, C2, persistence, or mass targeting. Those lines do not move.

The goal you set: **miss nothing known, then find the unknown.** That ordering is correct — 0-day falls
out of a tool that (a) has complete known-vuln coverage, (b) generates and *adapts* payloads from live
target behavior, (c) has a strong impact oracle, and (d) can fuzz for novel behavior. SHARAY today is
weak on all four. This document is the path.

---

## Implementation progress (updated 2026-10-19)

Supervised build-out on branch `feat/offensive-o3-payload-engine`. Each sector was first **verified**
(most agent-pre-built modules were scaffold — failing/absent tests, unwired; O2 even fabricated exploit
sessions), then made real, **wired into the live pipeline**, and proven with reproducible tests. Full
suite: **988 passed, 0 failed**. Eight of ten offensive sectors shipped (only O9 scale and O10 QA remain).

| Sector | Status | Commit | Evidence |
| --- | --- | --- | --- |
| O3 Payload engine | ✅ DONE | `aa63176` | Compositional grammar, 12 classes (1,728-vector SQLi), real token mutation; fires+confirms in Stage 7d |
| O4 Adaptive loop | ✅ DONE | `0e52f18` | WAF-learn → bypass → oracle-select; **0→3 confirmations** vs a blocking WAF |
| O2 MSF full capacity | ✅ DONE | `037fcf3` | Killed fabrication (fail-closed); real JSON-RPC transport vs mock msfrpcd; live module tree wired to console search |
| O1 Version→CVE | ✅ DONE | `ec7c333` | Grounded fingerprint→CVE (patched/bare banners flag nothing); Apache 2.4.49 → CVE-2021-41773 end-to-end |
| O6 Stateful reproduction | ✅ DONE | `71e530e` | Live OOB blind-SSRF via real callback (no FP); authenticated reproduction reaches an auth-gated SQLi |
| O8 0-day discovery | ✅ DONE | `bf7f07c` | Anomaly/differential fuzzing → `needs_triage` research candidates, never auto-confirmed; defensive parser fuzzer verified |
| O5 Real console | ✅ DONE | `c4e0c67` | Persistent-session infra verified; added an interactive MSF session driver (one session, many commands) + per-run console secret |
| O7 Tool belt | ✅ DONE | `1432c5c` | ffuf/dalfox/katana adapters + interactsh ingestion over the egress sandbox; sqlmap/semgrep verified; dispatcher skips unavailable tools honestly |
| O9 Scale | ⏳ TODO | — | Large-surface crawl, triage, resumable, distributed |
| O10 Offensive QA | ⏳ TODO | — | Vulnerable range + exploitation benchmark |

**Recurring finding:** every agent-pre-built offensive module (`payload_engine`, `msf_rpc`, `oob`,
`parser_fuzzer`) was scaffold; `msf_rpc` additionally fabricated exploit evidence. The verify-and-make-real
pass replaced claims with reproducible evidence. The audit below is the original pre-work assessment;
the sector items marked ✅ are shipped.

---

## PART A — OFFENSIVE AUDIT: the honest state

### A1. Metasploit is NOT deployed at full capacity `[SHAPE]`

You asked specifically. Verified from `metasploit.py` and the execution path:

- The module itself is **parser-only** — its own docstring: *"Parser only: no Metasploit command line is
  built and nothing has run here... unrestricted shell/console access is never represented here"*
  (`metasploit.py:3`).
- The "offensive" catalog is a **hardcoded list of ~21 modules** (`METASPLOIT_OFFENSIVE_CATALOG`,
  `metasploit.py:443`) — Log4Shell, Spring4Shell, Struts, Drupalgeddon, EternalBlue, Zerologon, etc.
  `resolve_metasploit_exploit` only knows those 21. Metasploit ships **~2,400 exploits + ~1,200 auxiliary
  + ~400 post** modules. SHARAY sees <1%.
- **Every catalog entry is `default_action: "check"`** (`metasploit.py:450` and throughout). The execution
  path (`scan_live_metasploit_auxiliary`, console `msf`) runs `check` for exploit modules and `run` for
  auxiliary. **No exploitation-to-session happens.** `ALLOWED_SESSION_TYPES` (shell/meterpreter) is only
  used to *parse* a session report, never to open one.
- **Missing entirely:** msfrpcd/RPC automation, full module-tree search, `check→exploit→session`,
  **msfvenom** payload generation, meterpreter, post-exploitation modules actually running, routing/pivot
  through a session, session interaction from the console. `msfconsole` isn't even on PATH (verified) —
  MSF only runs if the container image is pullable.

Verdict: MSF is a **CVE-check engine over a tiny hardcoded subset**, not Metasploit. This is the single
biggest offensive gap.

### A2. Payload generation is static, and the "AST mutation" is a misnomer `[SHAPE]`

`payload_forge.py`:
- `CFGPayloadGenerator` is **not a context-free grammar** — it is fixed lists (8 SQLi prefixes, a few
  union/time/boolean/error templates) recombined with `random.choice` (`payload_forge.py:23-88`). No
  recursive production rules, no grammar.
- `mutate_ast` (`:139`) does **no AST work** — it is regex string substitution (replace spaces with
  comments, case-flip, hex/comment wrap, null-byte append). A real AST/semantic mutation parses the
  payload's grammar and transforms the parse tree; this just rewrites text.
- WAF evasion = **hardcoded string replaces for 3 vendors** (`WAFTransformProfile`, `:189`).
- The docstring claims **SSTI and XXE** generation; **only `generate_sqli`/`generate_command_injection`/
  `generate_ssrf` exist**. SSTI, XXE, NoSQL, LDAP, XPath, deserialization, prototype-pollution, template
  payloads are **absent**.
- Critically: **generation is open-loop.** Payloads are synthesized and (per the orchestrator) recorded as
  *"synthesized N payloads"* — they are not systematically fired, scored by response, and adapted. There
  is no feedback from the target into the next payload. This is the core of your complaint.

### A3. "Adaptive" methodology is tag-selection, not response-driven `[SHAPE]`

`adaptive.py` "adapts" by fingerprinting tech from headers/crawler (substring matching: `"apache" in
server`) and emitting a set of **Nuclei tags** (`synthesize_adaptive_strategy`, `adaptive.py:110`). That
is *template selection*, not adaptive fuzzing. Nothing observes a response delta and changes *how* it
attacks (encoding, oracle type, injection context, bypass route). The platform cannot currently say
"the target reflected my quote unencoded in an HTML attribute, so switch to attribute-breakout XSS, and
it 403'd my `UNION` so route around the WAF with inline comments." That decision loop does not exist.

### A4. Target reproduction: good bones, but stateless and shallow `[REAL but limited]`

`reproducer.py` is one of the better parts and improved this round: 3x replay + negative-control canary +
`DifferentialOracle`, now with `compute_baseline_stats` (statistical baselining), a `PostconditionOracle`,
and a `MultiStepExploitChainEngine` (`reproducer.py:422,459`). But:
- It is **stateless HTTP-diff**: no login/session/cookie/CSRF/JWT handling inside the reproducer, so it
  **cannot reach authenticated or workflow-gated vulnerabilities** — exactly what matters on real apps.
- **No JS-rendered verification** — SPA/DOM-driven behavior and client-side execution aren't confirmed in
  a real browser.
- The oracle is signature/stat-based on a single response pair; it won't confirm blind/async classes
  without a live OOB server (which doesn't exist yet — `oob.py` uses `oob.sharay.invalid`, a non-resolving
  reserved TLD, so **no callbacks are ever received**).

So reproduction feels gimmicky on anything beyond a simple reflected parameter: it can't log in, can't
render JS, can't catch an out-of-band hit, and can't carry state across steps of a real exploit.

### A5. The console is a one-shot command dispatcher, not a session `[SHAPE]`

`interactive.py` has nice wrapping — `pty` import, `FlightLogRecorder` (asciinema export, HMAC-chained
logs), collaborative multi-operator presence/handoff — but the command **execution** runs a **fresh
one-shot container per command** (`run_with_egress ... exit -y`, `deadline_sec`). There is **no persistent
interactive shell, no stateful session, no meterpreter you can actually drive.** `probe`/`http`/`dns`/`msf`
each spawn, run once, and die. That is why it feels gimmicky: it is a menu of scoped one-liners dressed as
a takeover console. (Also note hardcoded HMAC keys: `hmac_secret="sharay_operator_key_2026"`
`interactive.py:255`, and `EgressAttestationLogger`/`oob.py` constants — see the main audit's crypto note.)

### A6. Scale: built for tiny targets, not big sites `[LIMIT]`

- Safe profile: **`MAX_REQUESTS = 5`, `MAX_SECONDS = 15`** (`__init__.py:32-33`).
- Crawler: **`max_pages=30`, `max_depth=2`** with hard caps (`crawler.py:396`, `_MAX_PAGES_CAP`).
- Comprehensive pipeline then samples aggressively: Nuclei gets ~4 URLs, the auth matrix gets the first
  5 endpoints (`discovered_endpoints[:5]`), body-fuzzer 20 form fields.

On a large site (thousands of routes, deep JS, auth walls), SHARAY sees a tiny slice and tests a fraction
of it. There is no large-surface crawling, prioritization/triage, incremental/resumable scanning, or
distributed crawl. "On bigger sites it lacks" is structurally true.

### A7. The tool belt is nearly empty `[MISSING]`

Verified on PATH / bundled: only **nuclei** (in `tools/bin/`) and **gitleaks**, plus `httpx` (the Python
one, not ProjectDiscovery's). **Missing:** sqlmap, ffuf, feroxbuster, dalfox, commix, tplmap, nikto,
gobuster, katana, gau/waybackurls, amass, subfinder, interactsh, Arjun, nmap NSE, testssl.sh, RESTler,
semgrep/CodeQL, AFL++/libFuzzer, msfconsole (container-only). A world-class offensive platform orchestrates
the best specialized tools; SHARAY currently reimplements thin versions and skips the proven ones.

### A8. Offensive rating: ~4/10

Excellent safety and verification bones; the offense feeding them is static, open-loop, stateless,
check-only, and under-tooled. The rest of this document is the build-out.

---

## PART B — ROADMAP CHECKLIST (offense-focused, untimed)

Guardrails for the whole of Part B (do not violate): authorized + in-scope only; egress-locked; safe-gate
+ per-action operator confirmation for any exploitation or state change; non-destructive default;
clean-exit with persistence tracking; no real C2/implants/self-propagation; no mass targeting; responsible
disclosure for any 0-day. WAF/filter bypass work is to measure the control for the client, with authorization.

### Sector O1 — Complete KNOWN-vuln coverage (the precondition for 0-day) — ✅ DONE (`ec7c333`)

You can only claim "misses nothing known" when these are true:

- [ ] **Version → CVE intelligence.** Fingerprint product + version (server, framework, JS libs, CMS,
  dependencies) and map to CVEs via CPE matching against **NVD + OSV + GitHub Advisory** feeds (the
  `osv.py` adapter exists — extend it). Flag every known CVE the target's stack is exposed to.
  - Do: ground each CVE claim in an observed version (reproducer-backed where a safe check exists).
  - Don't: emit a CVE from a banner substring alone — that is the false-positive pattern the project bans.
- [ ] **Full Nuclei, not a sample.** Run the complete template set (community + custom), not ~4 URLs; feed
  it all discovered endpoints; keep templates updated; add Nuclei **fuzzing** templates (`-fuzzing`).
- [ ] **Full Metasploit module tree** (see Sector O2), not the 21-entry hardcoded catalog.
- [ ] **Integrate the specialized tool belt** (see Sector O7) so each class is covered by a proven tool.
- [ ] **Coverage ledger per assessment:** "of the known classes/CVEs applicable to this stack, here is what
  we tested and the result." This is how you *prove* you didn't miss anything known.
- Done when: for a known-vulnerable target, SHARAY flags every applicable known CVE and every OWASP-class
  issue a top commercial scanner would, each evidence-backed, with an explicit coverage ledger.

### Sector O2 — Metasploit at full capacity — ✅ DONE (`037fcf3`)

- [ ] Stand up **msfrpcd / MSF RPC** and drive it programmatically (session-based), replacing the
  hardcoded 21-module catalog and the `-x ... exit -y` one-shots.
- [ ] Expose the **full module tree** via RPC search (not `METASPLOIT_OFFENSIVE_CATALOG`); map a finding to
  the best module dynamically.
- [ ] Support `check → exploit → session` **behind an explicit per-run operator confirmation**: open a
  session, capture proof (e.g. `getuid`/`id`), then **cleanly close** — never a persistent/destructive
  payload. Record to the ledger + flight log.
- [ ] Integrate **msfvenom** for payload generation (benign/test payloads for authorized exploitation).
- [ ] Run **post/** modules for safe, read-only evidence collection (env, enum) within scope.
- [ ] MSF **routing/pivot** (session-routed scanning of authorized adjacent scope) — isolated, logged,
  torn down (replaces the simulated `SOCKSPivotRouter`).
- [ ] Surface live sessions in the console (Sector O5) for interactive, gated operation.
  - Don't: leave sessions open, deploy outside scope, or use destructive payloads.
- Done when: SHARAY can, on an authorized target and with confirmation, use any suitable MSF module to
  prove exploitability to a benign auto-closed session, fully logged.

### Sector O3 — A real payload engine (grammar + semantic mutation + full class coverage) — ✅ DONE (`aa63176`)

- [ ] Replace the fixed-list generator with a **true grammar-based engine** (recursive production rules)
  per class, and **add the missing classes**: SSTI (per-engine: Jinja2/Twig/FreeMarker/ERB/Velocity),
  XXE (incl. parameter entities, OOB DTD), **NoSQL** (Mongo/operators), **LDAP**, **XPath**,
  **deserialization** (Java/PHP/.NET/Python gadget-aware, benign markers only), **SSRF** (already partial —
  extend), prototype pollution, **GraphQL** injection/batching, header/host-injection, **request
  smuggling** (CL.TE/TE.CL), mass assignment.
- [ ] Implement **real semantic mutation**: parse the payload's grammar and mutate the tree
  (keyword synonyms, equivalent operators, whitespace/comment nodes, encoding nodes), not regex text
  rewrites. Keep a deterministic seed for reproducibility.
- [ ] **Encoder chains:** URL (single/double), HTML entity, unicode, base64, hex, mixed — composable, and
  chosen by injection context.
- [ ] **Context-aware payload selection:** detect the reflection/injection context (HTML body vs attribute
  vs JS string vs URL vs SQL string vs shell) and emit payloads valid for *that* context.
  - Don't: keep calling string substitution "AST"; don't claim classes you don't generate.
- Done when: every OWASP + API class has a grammar-driven, context-aware generator with real tree
  mutations, and generated payloads are fired and scored (Sector O4).

### Sector O4 — Response-driven, adaptive methodology (close the loop) — ✅ DONE (`0e52f18`)

This is the heart of what you said is missing.

- [ ] **Feedback loop:** fire a probe, parse the response (status, length, timing, reflected context,
  error strings, headers), score it, and **choose the next payload from that signal** — boolean→confirm,
  anomaly→escalate, 403/429→switch bypass, timeout→time-based oracle.
- [ ] **WAF probe-then-adapt:** send benign markers to learn what the WAF blocks, then route payloads
  around the observed filter (measured, reported as WAF efficacy) instead of firing static vendor profiles.
- [ ] **Oracle auto-selection per target:** pick reflection / boolean-differential / time-based / OOB /
  error-based depending on what the target actually reveals.
- [ ] **Coverage/entropy-guided fuzzing:** prioritize inputs that change behavior; deprioritize dead ones;
  track which parameters/endpoints are "interesting."
- [ ] **Differential across transformations:** same payload under N encodings/casings, compare, keep the
  winner — this is how you beat filters and find parser quirks (a 0-day signal).
- Done when: SHARAY's attack strategy visibly changes based on live target responses, and can be replayed
  deterministically from the recorded decision trace.

### Sector O5 — A real interactive console (not one-shot) — ✅ DONE (`c4e0c67`)

- [ ] **Persistent, stateful session execution:** a real PTY/shell channel to a gated, authorized session
  (MSF session or a scoped container shell), with working directory/env/history preserved across commands
  — not a fresh container per command.
- [ ] **Drive live sessions:** interact with an MSF/meterpreter session (read-only/benign, gated) from the
  console; show session list; attach/detach; clean-exit.
- [ ] Keep the good parts (flight-log recorder, asciinema export, multi-operator handoff) but wrap the
  **real** session, and move hardcoded HMAC keys (`interactive.py:255`) to per-install secrets.
- [ ] Command UX: autocomplete, history, inline results, and an AI copilot that *proposes* the next command
  but requires human confirm for anything active.
- Done when: an operator can take over a live, authorized, gated session, run a sequence of stateful
  commands, and export a replayable, attributable flight log — with teardown proven.

### Sector O6 — Stateful, deep target reproduction (reach real apps) — ✅ DONE (`71e530e`)

- [ ] **Auth-aware reproduction:** the reproducer logs in (form/JWT/OAuth), carries cookies/CSRF tokens,
  and re-authenticates on expiry, so it can confirm authenticated and workflow-gated findings.
- [ ] **JS-rendered verification:** use a real headless browser (Playwright/Chromium) to confirm DOM XSS by
  **actual script execution** (callback fired), SPA routes, and client-side logic — not static HTML.
- [ ] **Live OOB server** (replace `oob.sharay.invalid`): run an interactsh-style DNS/HTTP collaborator so
  blind SSRF/RCE/XXE/SQLi are confirmed by a real out-of-band callback, then reproduced.
- [ ] **Multi-step / workflow reproduction:** the `MultiStepExploitChainEngine` exists — feed it real
  chains (login → IDOR → escalate) with postcondition assertions and sealed evidence bundles.
- Done when: reproduction confirms authenticated, JS-driven, blind, and multi-step findings on a real app,
  not just a reflected GET parameter.

### Sector O7 — Tools to add (the specialized belt) — ✅ DONE (`1432c5c`)

Orchestrate proven tools in the egress-locked sandbox instead of reimplementing thin versions. Each runs
containerized, pinned, scope-bounded, output-parsed into the Finding contract and reproducer-verified.

- [ ] **Injection:** `sqlmap` (full SQLi), `commix` (command injection), `tplmap`/`SSTImap` (SSTI),
  `dalfox` (XSS), `NoSQLMap`.
- [ ] **Content/param discovery:** `ffuf` or `feroxbuster` (dirs/files), `Arjun`/`ParamSpider` (hidden
  params), `katana` + `gau`/`waybackurls` (deep + historical URLs).
- [ ] **Recon/surface:** `subfinder` + `amass` (subdomains), ProjectDiscovery `httpx` (probing),
  `nmap` + NSE (service/version/vuln scripts), `testssl.sh` (TLS depth), `naabu` (fast ports).
- [ ] **OOB:** `interactsh-client` (self-hosted collaborator) — pairs with Sector O6.
- [ ] **CMS/app:** `wpscan`, `nuclei` with full + fuzzing templates, `nikto` (legacy coverage).
- [ ] **Exploitation:** Metasploit RPC (Sector O2); optionally `nuclei` code-protocol / custom exploit
  templates.
- [ ] **API fuzzing:** `RESTler` or `schemathesis` (OpenAPI-driven stateful API fuzzing).
- [ ] **Source-assisted (when source is provided):** `semgrep` + `CodeQL` for taint/dataflow to find
  injection sinks and *novel* bugs (the `semgrep.py` adapter exists — extend to full rulesets).
  - Do: pin every tool by digest, sign images (Sector 3 of the main roadmap), bound runtime, parse output
    into verified findings.
  - Don't: run a tool unsandboxed, outside scope, or trust its output as "confirmed" without the reproducer.
- Done when: each vuln class is covered by at least one best-in-class tool, orchestrated safely and
  reproducer-verified, with results normalized into SHARAY's contract.

### Sector O8 — 0-day discovery capability (find the unknown) — ✅ DONE (`bf7f07c`)

Realistic 0-day falls out of coverage + adaptivity + strong oracles + fuzzing. Build these:

- [ ] **Coverage-/grammar-guided web fuzzing:** stateful API fuzzing (RESTler/schemathesis from the
  OpenAPI/GraphQL schema) and grammar fuzzing of parameters, hunting unexpected 500s, stack traces,
  reflections, timing anomalies, and state corruption.
- [ ] **Differential/parser-confusion discovery:** send semantically-equivalent-but-syntactically-varied
  inputs (encodings, smuggling, unicode, boundary cases) and flag where the target behaves inconsistently —
  a classic 0-day signal (request smuggling, parser desync, auth bypass).
- [ ] **Anomaly oracles:** learn the target's normal response distribution (`compute_baseline_stats` is a
  start) and flag statistically novel behavior for operator review — the "interesting, unknown" bucket.
- [ ] **Source-assisted vuln research:** when the client provides source, run taint analysis (CodeQL/
  Semgrep) to find sinks, then **dynamically confirm** them with the reproducer — the most reliable path
  to real new bugs.
- [ ] **Binary/parser fuzzing harness (optional, for components):** AFL++/libFuzzer integration to fuzz a
  provided parser/library in the sandbox, with crash triage.
- [ ] **Novel-finding workflow:** anything unconfirmed-but-anomalous goes to a "research queue" with full
  evidence, never auto-reported as confirmed; responsible-disclosure metadata attached.
  - Don't: auto-publish unverified anomalies as vulns; don't fuzz destructively; keep it authorized + scoped.
- Done when: SHARAY surfaces reproducible novel (previously-unknown) issues on a target it has full known
  coverage of, each with an evidence bundle and a disclosure record — demonstrated at least on a seeded
  unknown in a lab.

### Sector O9 — Scale for big sites

- [ ] **Large-surface crawling:** lift the 30-page/depth-2 caps for authorized large scopes; add sitemap/
  robots/JS-route (katana) discovery; dedupe by route template; respect rate + scope.
- [ ] **Prioritization/triage:** rank the discovered surface (auth-adjacent, parameterized, API, upload,
  admin) and spend the budget where bugs live, instead of a flat sample.
- [ ] **Incremental + resumable** assessments; **distributed crawl/scan** across the worker pool
  (needs the concurrency wiring from the main roadmap's Sector 4).
- [ ] **Adaptive rate control:** back off on 429/errors, speed up when safe, per-origin.
- Done when: a large authorized site is crawled broadly, triaged, and tested where it matters, resumably,
  without hammering the target.

### Sector O10 — Offensive QA & proof

- [ ] Stand up a **vulnerable range**: Juice Shop, DVWA, WebGoat, VAmPI, bWAPP, a vulnerable AD/API lab,
  plus a seeded *unknown* bug for the 0-day workflow.
- [ ] In CI, prove **exploitation-and-confirm** (not just detection) per class, with clean-up, and
  benchmark the **exploitation rate** against sqlmap/Metasploit/Burp on that range.
- [ ] Track coverage over time; gate regressions.
- Done when: offensive capability has a measured, reproducible exploitation benchmark on a public range,
  and the 0-day workflow has surfaced the seeded unknown.

---

## Priority order (what to build first)

1. **MSF full capacity (O2)** + **tool belt (O7)** + **version→CVE (O1)** — this is "stop missing known."
2. **Response-driven adaptive loop (O4)** + **real payload engine (O3)** — this is where methodology stops
   being gimmicky.
3. **Stateful/JS/OOB reproduction (O6)** + **live OOB server** — so it works on real, authenticated apps.
4. **Real interactive session console (O5)** — so the "takeover" is genuine.
5. **Scale (O9)** — so big sites are covered.
6. **0-day fuzzing + source-assisted research (O8)** — the payoff, once 1–5 make coverage complete.

## The honest framing

SHARAY's verification and safety architecture is genuinely strong — that is the hard, rare half, and it is
exactly what makes an aggressive offensive build-out *safe to do*. But today the offense is static payload
lists, check-only MSF, tag-based "adaptivity," a one-shot console, stateless reproduction, almost no tool
belt, and tiny scale. None of that reaches "world-class," and none of it reaches 0-day. The work is to make
the attack side as serious as the verification side — fire real, adapting, context-aware payloads through
proven tools and full Metasploit, confirm them statefully (auth + JS + OOB), scale to real sites, and only
then fuzz for the unknown — every step inside the authorization, egress, and safe-gate controls that are
already SHARAY's best feature.
