# C4/C5 draft review — October 14

Neither Gemini draft was adopted. Source-only review and synthetic probes; no network,
real socket, scanner, provider, server or product assessment.

## Root-reproduced blockers

- `egress_policy.classify_ip_address`: private opt-in permits `fd00:ec2::254`.
  Expected: metadata denial remains unconditional; private authorization covers explicit scope.
- `resolve_and_validate_target`: denied literal `https://127.0.0.1/` falls through to a fake
  `getaddrinfo` result and returns an `8.8.8.8` pin. Supplied resolver is never called.
  Expected: terminal literal denial; use the stated trusted resolver contract.
- `AdaptiveRateController`: default5RPS becomes5.75 after200; initial0.01 becomes0.2
  after429; mocked0.8 jitter yields0.1391s after200. Expected: adaptive pacing never
  exceeds the stored approved rate, including recovery, backoff and jitter.
- `BugBountyReportFormatter`: critical severity plus empty reproduction and no responses
  produces9.8/vector, "identified and verified", invented200/divergent responses and a
  cryptographic-verification assertion. Expected: preserve evidence/status; missing
  responses and scoring inputs stay unavailable/pending, with no invented assurance.

RAN root pure probes under socket/DNS guards. Only booleans, rates and intervals printed.
These results demonstrate code paths, not live DNS, exploitation or a performance benchmark.

## Independent reviewer findings

The read-only reviewer ran13 draft tests/21subtests (0.02s) with socket/DNS guards; they
passed while missing the defects above. Additional synthetic probes found:

- Arbitrary public-host acceptance without stored scope, expiry, exact origin/path/exclusions;
  the replacement scope validator cannot enforce the current policy contract.
- Private opt-in bypasses reserved/unspecified ranges. Empty allowed-port input becomes a
  broad default list, and the scope validator accepts userinfo.
- Freely constructed pins reach the socket API without revalidation; insecure supplied TLS
  context and mismatching actual peer are not rejected.
- Zero ports and URL/redirect parsing alter destination semantics; scheme-relative,
  relative, query-only and fragment-only redirects differ from standard joining.
- Interval calculation neither reserves a slot nor sleeps; "token bucket" is not enforced.

These additional observations are attributed reviewer evidence; root has independently
read the relevant policy/resolver/pacing/report paths and replayed the primary cases above.

## Acceptance before any adoption

Use the existing typed scope/policy and deterministic adapter contracts. Requester-written
tests must pin stored org/target/assessment/scope approval, origins/paths/exclusions/time,
hard metadata/reserved denials, all DNS answers and connection/TLS peer checks. Pacing may
only slow beneath the approved limit. Reports must preserve recorded status/evidence and
never infer a CVSS vector from severity alone. Execution still requires actual host controls;
passing a draft test does not enable live scanning. At this review's checkpoint, no new
Gemini draft was requested while its C8-REFRESH review was open. The later real C8 reply
was read and answered; the product pacing fix received a separate C4-PACING review.
