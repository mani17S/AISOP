"""
Ingest knowledge_base/ into pgvector and run sample retrievals (RAG verification, owner-authorized 2026-11-20).

Needs: DATABASE_URL (PostgreSQL + pgvector, schema at head) and a running Ollama with the embedding model.
Run from the repository root:

    .venv\Scripts\python.exe backend\scripts\ingest_knowledge_base.py [--force] [--query "text" ...]

Idempotent: unchanged documents are skipped unless --force. Prints counts and, for each query, the top results with
source document and similarity (no chunk text is printed beyond a short prefix). Windows needs the selector event loop.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

DEFAULT_QUERIES = [
    "encoded PowerShell command line execution",
    "repeated failed logons followed by a successful logon",
    "phishing email with credential harvesting link and command and control beacon",
    "Windows security event log cleared",
]


async def main(force: bool, queries: list[str]) -> int:
    from app.db.session import get_db_session_factory
    from app.modules.ai.knowledge.ingestion_service import KnowledgeIngestionService
    from app.modules.ai.knowledge.retriever import KnowledgeRetriever
    from app.schemas.knowledge import RetrievalRequest

    factory = get_db_session_factory()
    async with factory() as session:
        results = await KnowledgeIngestionService().ingest_directory(session, force_reindex=force)
        await session.commit()
    for r in results:
        print(f"{r.status:10s} {r.source_document}  chunks={r.total_chunks} ok={r.successful_chunks} dup={r.skipped_duplicates}")
    failed = [r for r in results if r.status == "failed"]

    retriever = KnowledgeRetriever()
    async with factory() as session:
        for q in queries or DEFAULT_QUERIES:
            hits = await retriever.retrieve(RetrievalRequest(query=q, top_k=3), session)
            print(f"\nQ: {q}")
            for h in hits:
                print(f"  {h.similarity_score:.3f}  {h.source_document}  | {h.content[:70].strip()!r}")
    return 1 if failed else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--query", action="append", default=[])
    a = ap.parse_args()
    raise SystemExit(asyncio.run(main(a.force, a.query)))
