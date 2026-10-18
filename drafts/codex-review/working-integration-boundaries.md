# Codex bounded review of unadopted integration drafts — October14

Published baseline remains34eee4b; these results concern uncommitted source, not deployed/approved execution. MAIN hash unchanged3c98711e... (last complete read retained). Session/ideas inboxes empty; Gemini priority question29fabbb and IDEA9 unanswered. Review does not authorize assessments. No existing daemon restarted or stopped.

## C2 local correction

Requester test drafts/codex-review/test_interactive_role_acceptance.py uses authenticated FastAPI ASGI calls with private temporary DB, worker disabled, two synthetic accounts and mocked session write/resize. socket.connect/getaddrinfo, subprocess.run/Popen and os.fork are denied. Before source edit: owner input/resize200 pass; both viewer cases200 instead of403 fail (4cases/2failures/0errors,1.550s, exit1). Added only require_role(user,*SCAN_ROLES) before lookup in input_interactive_session and resize_interactive_session. Root4cases pass2.159s/exit0; API Ruff check/format exit0. Independent review4pass1.517s; in-memory removal of input/resize guard causes one corresponding viewer200!=403 failure each,0errors (1.086s/0.979s). Mutation harness exit0 indicates expected mutant failures were caught. Shared source hash unchanged during review; no temporary acceptance directories remain.

Patch saved in drafts/codex-review/interactive-rbac.diff. Existing owner/security-administrator/analyst allowlist reused; viewer denied before fake session mutation. This does not verify raw shell containment, target/session ownership beyond organization, streamed-output privacy or current-scope lifecycle. Do not publish this acceptance test against published HEAD: it depends on unadopted integration routes. No Gitindex claim/change or commit this iteration.

## Remaining concrete draft defects

1. READ aegis/interactive.py create_session178: child directly calls os.execve(shell,[shell,'-i'],env), with target IP only in environment; no sandbox/egress wrapper appears on this path. Never invoked/forked by root. Session controls must use an explicitly reviewed bounded operation/isolation contract; target metadata is not host containment.
2. RAN .venv exact current Pydantic classes from schemas.py with UI mode/depth/rate/tools payload: depth/rate/tools each extra_forbidden. Every live profile sends this config, including safe_http. Expected a single typed UI/API contract. First equivalent probe used systemPython; explicitly repeated under approved .venv with same3errors.
3. RAN actual worker110 snapshot comprehension with valid saved scan_config: filtered result {request_rate:1}, config absent. A saved passive/rate_limit/crawler_depth selection disappears before scan_cfg lookup; not a full worker execution. Expected reviewed configuration preserved separately from ScopePolicy fields and bound to approved ceilings.
4. RAN AST-extracted active_integrations with module stand-in attesting Docker available, only no_network and no destination egress: Nuclei/ZAP/Nmap all runnable=true/implemented. No actual runtime/attest call. Expected live readiness unavailable when necessary per-run controls are absent; executable discovery and human scope approval remain separate facts.
5. Independent actual TypeScript Launch handler: literal verified_lab displays safe-HTTP copy/no profile selector but submits comprehensive; worker currently routes loopback through builtin scanner regardless profile (READ). Scope1RPS renders150 rate/min10; schema cannot express0.1/1 and accepts150. Profile change after approval retains checked approval and enabled launch. No transport beyond stub called.
6. Independent actual row/detail handlers: expired scope disables assessment launch but leaves Takeover Console enabled; an already opened terminal component remains after archived=true or role becomesviewer. A first terminal stub had an incorrect CommonJS export shape; corrected harness showed retained component true/true/true. No React effects, sessions or shell transport ran.

What works: new manager/viewer/archived row gates preserve ordinary scope controls; project settings34eee4b stayed unchanged and passed their exact-export/CI verification. Existing role helper makes the local mutation correction small. No capability removed or dropped from requirements.

## Source snapshots
- aegis/api.py SHA256 b1ca77506780c56a16d4e0bbd384d098111ed9ec7a589b277b59f5d32e19de30
- aegis/worker.py SHA256 ecf79710c867eba5866b253d578a19b64d0dbb6b1cc7ca15437c626b6f82cecd
- aegis/schemas.py SHA256 a914528804070e9a1f2d46d1cbc9f093b1ac7f26c4d7ceb7788a581263461808
- aegis/interactive.py SHA256 fb43d83c77ef3f4eaf04d42bb0899d57cc30f0f36c7d93326573305955cd496c
- apps/web/app/projects.tsx SHA256 4cddc78e4be2347cdd0c6a435b42e8a08a58ecb5b2586ab25cee1ddd874fcc1b
