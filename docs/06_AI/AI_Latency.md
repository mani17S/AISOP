# AI latency: measured breakdown and fixes

Scope: the optional AI step of the multi-source investigation (`POST /api/v1/cases/{id}/investigations/multisource` with `use_llm=true`) and any caller of `InvestigationPromptBuilder.build_request`. Deterministic analysis does not depend on the model and is unaffected.

## Setup (measured)

Case `3483d845-...` (10 events, 1 incident, sufficiency verdict `sufficient`), Ollama on `127.0.0.1:11434`, `qwen3:4b` (Q4_K_M), CPU host with about 3 GB free RAM, one model call per incident. Timings come from the fields Ollama returns in `/api/chat` (`load_duration`, `prompt_eval_duration`, `eval_duration`, `prompt_eval_count`, `eval_count`) and from wall clock around `run_workflow` (same Python path the API uses, loaded from the stored case evidence). The host was shared with a browser and other agents, so absolute seconds vary by roughly 10 to 20 percent.

## Where the 88 to 110 seconds went (measured, before)

| Part | Measured |
| --- | --- |
| Prompt size | 2050 tokens (14 056 characters, system 4 579 + user 9 477) |
| Prompt processing | 0.2 to 2.3 s (about 900 tokens/s, even with a unique prefix so no cache) |
| Model load | 0.01 s when warm; 11 to 14 s after the model was unloaded or the context size changed |
| Output | 854 to 919 tokens at about 8.5 tokens/s = 100 to 114 s |
| Python path (gate, correlation, parsing, claim verification, report) | well under 1 s (`total` minus call wall time was 0.03 s in run 1) |
| Retry | none in this path (`run_workflow` makes one call per sufficient incident) |

Conclusion: more than 97 percent of the time is output decoding. Trimming the prompt cannot help (prompt processing is about 1 percent), so context trimming was not done. The prompt asks for "1-2 claims, max 1 hypothesis, 1-2 actions" but nothing enforced it; the model produced 3-4 claims, 2 hypotheses and 5 actions.

## What changed

1. Bounded output schema (`prompt_builder/builder.py`, `_bound_output_schema`): `maxItems` claims 2, hypotheses 1, alternatives 1, actions 2, data gaps 3, `assertions` 3; `maxLength` on summary, claim text, reasoning and list items. This is the cardinality the prompt already requested; Ollama enforces it in constrained decoding.
2. Platform-owned fields removed from the schema the model sees: `claim.verification`, `claim.claim_id`, `hypothesis.taxonomy`, top-level `generated_at`. The model can no longer author them at all (they were already discarded or recomputed server-side), `investigation_id` and `model_identifier` stay pinned with `const`, and unreferenced `$defs` are pruned (the old schema was 10.9 KB; the new size was not measured).
3. Output ceiling for the multi-source call lowered from 2048 to 1024 tokens (`BOUNDED_MAX_TOKENS`, used only in `correlation/workflow.py`; `DEFAULT_MAX_TOKENS` stays 2048 because other call sites and existing tests pin it). A valid bounded answer uses 450 to 600 tokens; a truncated answer still falls back deterministically.
4. Optional `OLLAMA_NUM_CTX` (default unset = unchanged). Measured decoding at `num_ctx=3072` was about 10.5 tokens/s against 7.5 to 8.1 at Ollama's default 4096 (two runs each in a direct test, same schema). Risk: Ollama silently drops prompt tokens that do not fit, so the value must exceed the largest prompt plus 1024. The evidence budget is 8 750 characters, and this prompt measured 2050 tokens, but a worst-case incident is not proven to fit 3072, so it is opt-in and the provider logs a warning when a response uses 90 percent of the window.
5. The provider now logs `load_ms`, `prompt_eval_ms` and `eval_ms` per call.

Already in place and kept: `keep_alive` is sent on every request (`OLLAMA_KEEP_ALIVE`, default `5m`; setting `30m` avoids the 11 to 14 s reload after idle, not measured separately); the sufficiency gate runs before any model call and an insufficient incident never reaches the provider; incidents beyond `MAX_LLM_INCIDENTS` are skipped; claim verification, the validator and the deterministic fallback are unchanged. Not changed: no second call is made when the first answer is valid (the multi-source path has no retry at all).

## Before and after (same case, same model, three runs each, `run_workflow` wall seconds)

| Variant | Run 1 | Run 2 | Run 3 | Output tokens | Result |
| --- | --- | --- | --- | --- | --- |
| Before (2048 ceiling, unbounded schema) | 104.4 | 110.0 | 114.6 | 854 / 919 / 919 | validated, `is_valid=True`, decision `remediated` |
| After, schema + 1024 ceiling (default context) | 85.2 (incl. 11.7 s model load) | 1360.4 (queued, decode 57.8) | 55.9 | 562 / 485 / 485 | validated, `is_valid=True`, `remediated`, 0 claims in runs 2 and 3 |
| After, plus `OLLAMA_NUM_CTX=3072` | 67.0 (incl. 12.2 s model load) | 55.3 | 54.4 | 482 / 525 / 525 | validated, `is_valid=True`, decision `pass`, 2 claims |

Note: run 2 of the middle row took 1 360 s of wall time because the call waited about 1 300 s in Ollama's queue (prompt processing 1 301 s, decode 57.8 s); another process on the shared host was using Ollama. Its decode time (57.8 s) is the comparable figure. Warm runs: 104 to 115 s before, about 55 s after (roughly 50 percent less). Decode speed after was 9.7 to 10.9 tokens/s with `num_ctx=3072` and 7 to 8.6 without.

## Measured versus assumed

Measured: all numbers above, on this one case and model. Not measured: the HTTP endpoint after the change (the running backend was started before these edits and still runs the old code; a restart with `OLLAMA_NUM_CTX=3072` is needed to confirm end-to-end, expected to match the harness because the Python path adds well under 1 s); larger incidents (up to 8 750 characters of evidence); other models; a GPU host; the effect of `OLLAMA_KEEP_ALIVE=30m`. Assumed: that answer quality is not reduced by the caps. The runs without `OLLAMA_NUM_CTX` returned zero claims twice (the schema does not require `supporting_evidence_ids`, and the validator demotes uncited claims to unsupported); the claims-0 outputs are valid and safe but less useful, so a follow-up could make citations required at the cost of about 50 to 100 more output tokens per claim. Not changed here.

## Tests

`backend/tests/unit/test_ai_latency_schema.py` (bounds, platform-owned fields absent, pinned ids, no dangling `$defs`, one bounded call per sufficient incident, no call for insufficient evidence, deterministic fallback on provider timeout, incident cap) and `test_ai_latency_provider.py` (`num_ctx` and `keep_alive` in the payload, default payload unchanged, settings default).
