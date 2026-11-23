# Hosted AI for the public demo

Decision record: `docs/03_System_Design/ADR/ADR-016_Opt_In_Hosted_AI_Provider.md`. Local-first is unchanged and remains the default; this is an opt-in for a demo that holds synthetic data only.

## What runs where

| Part | Local stack (your laptop) | Hosted demo (Render API, Cloudflare Pages, Render PostgreSQL) |
|---|---|---|
| Deterministic ingestion, correlation, sufficiency gate, ATT&CK, reports | yes | yes |
| Vector search (pgvector 0.8.x) | yes, 35 chunks embedded with nomic-embed-text (Ollama) | yes, 51 chunks embedded with bge-base-en-v1.5 (Cloudflare) |
| RAG query embedding | Ollama | Cloudflare Workers AI |
| Language model | Ollama, qwen2.5:1.5b (fast) or qwen3:4b (slower, better) | Cloudflare Workers AI, Llama 3.3 70B |
| Claim validation, human approval gates | same code | same code |

Vectors from different embedding models are not comparable, so the two databases are separate and each is embedded with its own model.

## Settings (all off unless set)
`LLM_PROVIDER=cloudflare_workers_ai`, `LLM_ALLOW_EXTERNAL_PROVIDER=true`, `EMBEDDING_PROVIDER=cloudflare_workers_ai`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_AI_API_TOKEN` (secret; a token limited to Workers AI, never the deployment token), `CLOUDFLARE_AI_DAILY_NEURON_LIMIT` (default 9000 of the 10,000 free neurons a day). Missing any one fails closed with a typed configuration error and AI actions fall back to the deterministic result.

## Measured on 2026-11-23 (hosted-style backend, production mode, hosted database, one synthetic case with 2 incidents; the database round trip from this machine is about 0.5 s per query)

| Action | Time | Result |
|---|---|---|
| AI case synthesis with RAG | 33 s | decision remediated, 1 claim validated_reference (2 cited events), ATT&CK T1110.001, 5 knowledge chunks retrieved |
| AI report synthesis | 26 s | no fallback, grounding 1.0, model `@cf/meta/llama-3.3-70b-instruct-fp8-fast` |
| AI investigation (2 incidents, one model call each) | 59 s | incident 1 pass, grounding 1.0; incident 2 remediated, 0.5 (one claim needed analyst review) |
| Cost | about 210 to 260 neurons per call | about 40 calls a day inside the free allowance |

Compared with the local small model (about 5 s per call) the hosted model is slower and its output is better written. The retrieval step itself returned five chunks with similarity 0.70 to 0.86 for on-topic queries.

## What this does not show
- Quality across many cases: one case, one run each.
- Time on Render itself: from Render's own region the database part should be much faster; the model part will not change.
- Whether Render's free tier lets a 60 second request finish: unverified. The interface shows elapsed time and a Cancel button for long actions.
- Cloudflare's retention terms for Workers AI inputs were not reviewed in depth. Use synthetic data only.

## Operating notes
- The daily budget is shared process state (the application builds a provider per request, and a per-instance counter would restart every request; a test pins this).
- A model used during testing (`llama-3.1-8b`) was already deprecated on one route, so the model id is a setting, not a constant.
- To load the knowledge base into a hosted database: set `DATABASE_URL`, the three Cloudflare settings and `EMBEDDING_PROVIDER`, then run `backend/scripts/ingest_knowledge_base.py`.
