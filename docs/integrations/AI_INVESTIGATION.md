# AI investigation core (L7) — no model attached

`services/ai_analysis_worker` holds the rules an AI assistant inside the product must obey, built and tested before any model is connected. **No provider exists**: `NoProvider` raises "No AI provider is configured", and scanning and reporting never import this module. Nothing here executes a tool. Tests: `tests/integration/test_ai_investigation.py`.

| Piece | What it guarantees |
| --- | --- |
| `parse_plan` | A model's output must be one JSON object matching `InvestigationPlan` exactly: objective, hypothesis, the observations it rests on, one typed `ProposedToolAction` from the shared contract, expected evidence, impact, preconditions, success criteria, stop conditions. Any extra field (a command, an argv, a scope), wrong type, non-JSON number or oversize refuses the whole proposal with fixed text; the model's words are never echoed. |
| `review` | Records the proposal as a hypothesis in state `proposed`, then applies Codex's deterministic `evaluate_tool_action` with metadata and readiness that must come from the trusted control plane. Allowed means `awaiting_approval`, never execution. Denied, or citing an observation that does not exist, means `rejected_by_policy` with the reason codes in its history. |
| `advance` | Fixed states (`proposed`, `awaiting_approval`, `approved`, `testing`, `supported`, `confirmed`, `inconclusive`, `disproved`, `rejected_by_policy`, `closed`) and a table of which actor may make each move. A model can make none. `supported`, `confirmed` and `disproved` require evidence references. Nothing leads out of `disproved` except `closed`. Each change returns a new object with one event appended; history cannot be edited. |
| `build_prompt` | Instructions and evidence travel in separate fields; evidence is included up to a byte budget and the number of omitted items is reported. |

A test feeds evidence containing injected instructions to a stand-in model that "obeys" them: the resulting proposal is rejected by policy, and the injected text is shown to have travelled only as data.

Not built: any real provider or model call, token and cost accounting, relevance-based evidence retrieval, storage of hypotheses, the operator approval screen, and the verification engine that would act as `verifier`. Choosing a provider, and what assessment data may be sent to it, is a decision for the human.
