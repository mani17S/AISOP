# ADR-016: Opt-In Hosted AI Provider for the Public Demo (Cloudflare Workers AI)

| Field | Value |
|---|---|
| **ID** | ADR-016 |
| **Status** | **PROPOSED**, implemented and offline-tested on 2026-11-23 on the project owner's instruction that the AI, RAG and pgvector are the core of the product and must be visible on the hosted demo. Owner confirmation of this record is still wanted. |
| **Date** | 2026-11-23 |
| **Relates to** | ADR-001 (direct lightweight LLM abstraction), ADR-002 (pgvector), ADR-008 (sufficiency gate), the local-first rule in `backend/app/modules/ai/llm/manager.py` |
| **Does not change** | The deterministic path, the sufficiency gate, claim verification, or the local-first default |

## Context
Until now AISOP refused any non-local model endpoint: evidence never left the machine. That is the right default for real security data and it stays. But the free hosting tier (512 MB, shared CPU, no GPU) cannot run any model or the embedding model, so the hosted demo showed the deterministic product only, and the AI, RAG and pgvector that make up the core of the project were invisible there. The hosting plan had set `LLM_ENABLED=false` for that reason.

## Decision
Add Cloudflare Workers AI as a second, **opt-in, external** provider for two things only: chat generation (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`, JSON-schema constrained, same prompts and validator as the local model) and embeddings (`@cf/baai/bge-base-en-v1.5`, 768 dimensions, so the existing pgvector column is unchanged).

Rules that keep it safe:
1. **Off by default.** It is built only when `LLM_PROVIDER` or `EMBEDDING_PROVIDER` names it **and** `LLM_ALLOW_EXTERNAL_PROVIDER=true` **and** an account id and token are set. Missing any one fails closed with a typed configuration error; nothing is inferred and nothing falls back to another provider.
2. **Synthetic data only.** The prompt, including evidence text, and RAG queries and knowledge-base text are sent to Cloudflare. Enable it for a demo database that holds synthetic data. The privacy page states this.
3. **The token is a secret.** Held as a `SecretStr`, sent only in the Authorization header, never in a body, log, error, health response or stored raw response. The hosted service must use a token limited to Workers AI, not the broad token used for deployment.
4. **A budget.** Workers AI's free allowance is 10,000 neurons a day. The provider counts the neurons each response reports and refuses further calls (without sending them) past `CLOUDFLARE_AI_DAILY_NEURON_LIMIT` (default 9,000), so a public demo cannot exhaust it. The refusal is a typed connection error, so the pipeline falls back to the deterministic result, as it does for any model failure.
5. **Nothing about trust changes.** An AI answer is still never evidence. Citations are still checked against the case's events, the model's own confidence and grounding values are still ignored, and the deterministic report is complete without it.

## Measured (2026-11-23, the real investigation prompt and schema, synthetic case)
Llama 3.3 70B returned valid JSON matching the schema in 14.3 s, with both claims citing real events, for about 211 neurons (about 45 such calls a day on the free allowance). Mistral Small 3.1 24B hit the output limit and returned truncated JSON, so it was not chosen. The 1.5B local model is faster but its summaries are weaker; this is a quality difference, not a safety one.

## Alternatives considered
- **Keep the hosted demo deterministic only.** Safest; hides the core of the project.
- **Tunnel the hosted API to the laptop's Ollama.** Breaks the local-first rule in a less controlled way, and depends on the laptop.
- **Paid GPU hosting.** Outside the project's zero-budget constraint.

## Consequences
- New code: `providers/cloudflare/provider.py`, `embeddings/cloudflare.py`, `get_embedder`, settings, tests (`test_cloudflare_ai.py`).
- A knowledge base embedded locally (nomic) cannot be searched with bge vectors: the hosted database is re-embedded with the hosted model, and the two are separate databases.
- A third party now sees demo evidence text when this is on. Real evidence must never be used with it.
- Residual risks: Cloudflare's terms and retention for Workers AI inputs were not reviewed in depth; the free allowance and model catalogue can change (a model used here was already deprecated on one route during testing); latency is higher than the local small model for multi-incident cases.

## What this ADR does not decide
Whether the real product should ever send data to a hosted model. The answer for real data remains no unless an operator takes that decision explicitly.
