# Local setup: database, RAG, ATT&CK, threat intelligence and the local model

These steps were run and checked on 2026-11-20 on a Windows machine with 13.9 GB of memory.

## 1. Database
PostgreSQL 17 with pgvector, from `docker-compose.yml` (host port 5433). Create a database, enable the extension and migrate:

```
docker exec aisop-postgres psql -U <user> -d postgres -c "CREATE DATABASE <db>;"
docker exec aisop-postgres psql -U <user> -d <db> -c "CREATE EXTENSION IF NOT EXISTS vector;"
set DATABASE_URL=postgresql+psycopg://<user>:<password>@localhost:5433/<db>
.venv\Scripts\python.exe -m alembic upgrade head
```

## 2. Local model (Ollama)
Models are stored on D: so nothing is written to C:.

```
set OLLAMA_MODELS=D:\AISOP-External\ollama-models
ollama serve
ollama pull nomic-embed-text      # 768-dimension embeddings, about 270 MB (required for RAG)
ollama pull qwen2.5:1.5b          # chat model, about 1 GB
```

`qwen2.5:1.5b` is on the approved-model list because it fits a low-memory machine. It often fails the strict JSON output check; when it does, the report falls back to the deterministic version and says so (`fallback:ResponseParsingError`). The larger approved models (`qwen3:4b`, `llama3.1:8b`) give better results if the machine has the memory.

## 3. Knowledge base (RAG)
`knowledge_base/` holds playbooks, ATT&CK mapping notes, Sigma examples and an architecture summary. Ingest it with `KnowledgeIngestionService.ingest_directory` (35 chunks at the time of writing). Retrieval is cosine similarity over pgvector; a query about encoded PowerShell returned the matching playbook section at 0.76 similarity.

## 4. MITRE ATT&CK
The pinned Enterprise v20.1 file lives at `D:\AISOP-Reference-Data\MITRE-ATT&CK\Enterprise\v20.1\enterprise-attack-20.1.json`. Set `ATTACK_REFERENCE_PATH` to it. The loader checks the SHA-256 before parsing and refuses a changed file.

## 5. Threat intelligence
- **Local feeds (work offline, no key):** download `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` to `data/feeds/feodo_tracker.csv` and `https://check.torproject.org/torbulkexitlist` to `data/feeds/tor_exit_nodes.txt`. 1,304 indicators loaded; a Tor exit node returned `suspicious`, a public DNS server returned `not_found`.
- **AbuseIPDB (needs your own key):** the adapter exists and is tested with a mock transport only. Set `TI_EXTERNAL_ENABLED=true`, `TI_ENABLED_SOURCES=abuseipdb` and `ABUSEIPDB_API_KEY`. External lookups also need a per-query opt-in and pass the private-network shield first. The running API does not yet route investigations through external providers.
- OTX and MISP have no adapter. VirusTotal is deferred by the owner.

## 6. Run the backend
```
set API_AUTH_ENABLED=true
set LLM_ENABLED=true
set OLLAMA_MODEL=qwen2.5:1.5b
.venv\Scripts\python.exe backend\run_local.py
```
`run_local.py` selects the Windows selector event loop. Without it every database call fails with "Psycopg cannot use the 'ProactorEventLoop'".
