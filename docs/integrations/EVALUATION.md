# Evaluation (L8) — measured results, narrowly scoped

Two corpora exist. Their numbers describe those corpora only and are not a general accuracy claim for SHARAY or any scanner.

## HTTP configuration corpus v1

`tests/evaluation/corpus/http_configuration.v1.json` holds 16 labelled HTTP responses. `tests/evaluation/http_configuration.py` serves each on a loopback fixture it starts, runs the built-in `safe_http` adapter through the normal scope policy, and compares the checks it reports with the labels. The report records the corpus hash and adapter version.

```sh
.venv/bin/python -m tests.evaluation.http_configuration
```

Measured October 12, 2026; all 16 scans completed in both runs:

| Adapter | Subset | Cases | Correct | False alarms | Missed | Precision | Recall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.0.0 | `clear`: protection plainly absent or plainly valid | 10 | 10 | 0 | 0 | 1.0 | 1.0 |
| 1.0.0 | `ineffective-value`: header present but gives no protection | 6 | 4 | 0 | 4 | 1.0 | 0.5 |
| 1.0.0 | All | 16 | 14 | 0 | 4 | 1.0 | 0.78 |
| 1.1.0 | `clear` | 10 | 10 | 0 | 0 | 1.0 | 1.0 |
| 1.1.0 | `ineffective-value` | 6 | 8 | 0 | 0 | 1.0 | 1.0 |
| 1.1.0 | All | 16 | 18 | 0 | 0 | 1.0 | 1.0 |

Version 1.0.0 missed four checks: an empty `Content-Security-Policy`, an undefined `X-Frame-Options` value, `frame-ancestors *`, and an unrecognised `Referrer-Policy` token, because three of its checks tested that a header was present, not that its value was effective (`entry-fc99b79d3abc44ee`). Version 1.1.0 checks effectiveness. That change was made by Claude in Codex's file while Codex was offline, at the human's instruction, and awaits Codex's review (`drafts/codex-review/header-checks.diff`). `tests/evaluation/test_http_configuration.py` now fails on any miss or false alarm. A perfect score on a 16-case corpus the fix was written against says the known gaps are closed, not that the checker is complete.

The labels are one reviewer's judgement of how browsers treat each value; each `ineffective-value` case carries its reason in a `basis` field and is open to challenge. HTTPS-only checks, redirects and every other scanner are not covered. No AI or third-party tool has been evaluated.

## Secret detection corpus v1

`tests/evaluation/corpus/secret_detection.v1.json` holds 24 one-file cases: 12 with one synthetic secret each (private key blocks and seven provider token formats) and 12 look-alikes that must not be reported (public keys, certificates, test-mode keys, placeholders, strings one character short or embedded in a longer word). Content is stored in short pieces and joined at run time, so the corpus file itself contains no token-shaped text; a test confirms the detector finds nothing in it. `tests/evaluation/secret_detection.py` writes the cases to a temporary tree, runs `secrets.detect` once and scores the rules reported per file.

```sh
.venv/bin/python -m tests.evaluation.secret_detection
```

Measured October 12, 2026: 24 of 24 files scanned; 12 of 12 seeded secrets found; none of the 12 look-alikes reported.

**How much v1 proves:** little. Its cases are the ones the detector's own tests were written against, by the same author.

## Secret detection corpus v2 — independent labels

`tests/evaluation/corpus/secret_detection.v2.json` holds 30 cases written by Gemini, at Claude's request, without reading the detection rules (`entry-bdbcc92ccb734412`, `entry-60e3fb41ed9a49aa`).

| Run | Correct | False alarms | Missed | Precision | Recall |
| --- | --- | --- | --- | --- | --- |
| First run, detector as it was | 12 | 3 | 3 | 0.8 | 0.8 |
| After corrections on both sides | 12 | 0 | 0 | 1.0 | 1.0 |

What changed between the runs:

- **Three false alarms were real detector faults, now fixed:** AWS's published documentation example key was reported; a key-shaped segment inside a longer identifier joined by underscores was reported; a Stripe-shaped name followed by an underscore was reported. Detection now ignores those; redaction still removes them.
- **Three misses were labelling errors**, withdrawn by their author: the synthetic values were one or two characters off the real format length, so they are now labelled look-alikes.

The second row is therefore not independent any more: the detector was changed to pass it. The honest figure for unseen cases is the first row. A fresh set from someone who has seen neither is the next step. Both corpora cover eight formats only, with no entropy-based or generic-password detection and no real-world repositories.
