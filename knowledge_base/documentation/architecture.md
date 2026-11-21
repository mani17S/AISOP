# AISOP architecture summary

## Components
- **Frontend:** a React application that talks to the backend over HTTPS with an API key.
- **Backend:** a FastAPI service. Endpoints cover alert ingestion, evidence queries, cases, investigations and reports.
- **Database:** PostgreSQL with the pgvector extension. It stores raw evidence, normalized events, extracted entities, cases, analyst accounts and knowledge embeddings.
- **Knowledge base:** Markdown documents in `knowledge_base/`, split into chunks, embedded with a local embedding model (768 dimensions) and retrieved by cosine similarity.
- **ATT&CK reference:** a pinned local copy of the ATT&CK Enterprise collection, verified by SHA-256 before use.
- **Language model:** an optional local model served by Ollama. Output is checked against the evidence before it is shown.
- **Threat intelligence:** local feeds work offline. External lookups are off by default and need an explicit operator opt-in.

## Data flow
Alert or event, then adapter normalization, then entity extraction, then storage with the raw hash, then case linking, then the sufficiency check, then optional AI synthesis, then a report that an analyst approves.

## Trust boundaries
All evidence text is untrusted input: it is escaped, bounded and never executed. Client role selection never grants access; the server decides from the authenticated token.
