"""
AISOP Document Chunker.

Implements a deterministic sliding-window word-level chunker that splits
SourceSection objects into ChunkRecord objects suitable for embedding and
persistence in the knowledge_embeddings table.

Algorithm invariants:
  - Same input always produces identical chunks and content_hash values.
  - chunk_index is a continuous, 0-based index across the entire document (0 to N-1).
  - Every emitted chunk has a unique position within its document.
  - Section changes do NOT reset the document-wide chunk_index.
  - Empty sections or whitespace-only sections are skipped and do not create index gaps.
  - Repeated identical chunks are preserved as separate distinct occurrences.
  - Tail chunks with fewer than MIN_TAIL_WORDS words are merged into the preceding chunk.
  - No external chunker library is used; pure Python only.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.models.knowledge import KnowledgeEmbedding
from app.schemas.knowledge import ChunkRecord, SourceSection

# Tail chunks shorter than this word count are merged with the previous chunk
MIN_TAIL_WORDS: int = 20


class DocumentChunker:
    """
    Deterministic sliding-window chunker for knowledge source sections.

    Supports both single-section chunking (with optional index offset) and
    document-wide multi-section chunking with continuous 0-based indexing.

    Usage:
        chunker = DocumentChunker()
        # Document-wide:
        chunks = chunker.chunk_document(sections)
        # Or single section:
        chunks = chunker.chunk_section(section)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or get_settings()
        self._chunk_size = cfg.KNOWLEDGE_CHUNK_SIZE
        self._chunk_overlap = cfg.KNOWLEDGE_CHUNK_OVERLAP
        self._embedding_model = cfg.EMBEDDING_MODEL

    @property
    def chunk_size(self) -> int:
        """Configured target chunk size in words."""
        return self._chunk_size

    @property
    def chunk_overlap(self) -> int:
        """Configured word overlap between consecutive chunks."""
        return self._chunk_overlap

    def _slice_words(self, words: list[str]) -> list[str]:
        """
        Split a list of words into sliding-window text chunks with tail merging.

        Args:
            words: Ordered list of words to chunk.

        Returns:
            List of chunk text strings.
        """
        if not words:
            return []

        chunk_size = self._chunk_size
        overlap = self._chunk_overlap
        step = max(1, chunk_size - overlap)

        raw_chunks: list[str] = []
        start = 0
        while start < len(words):
            end = min(start + chunk_size, len(words))
            chunk_words = words[start:end]
            raw_chunks.append(" ".join(chunk_words))
            if end >= len(words):
                break
            start += step

        # Tail merge: if last chunk is shorter than MIN_TAIL_WORDS, merge with previous
        if len(raw_chunks) > 1 and len(raw_chunks[-1].split()) < MIN_TAIL_WORDS:
            raw_chunks[-2] = raw_chunks[-2] + " " + raw_chunks[-1]
            raw_chunks.pop()

        return raw_chunks

    def chunk_section(
        self,
        section: SourceSection,
        embedding_model: str | None = None,
        start_index: int = 0,
        total_chunks: int | None = None,
    ) -> list[ChunkRecord]:
        """
        Split a single SourceSection into deterministic ChunkRecord objects.

        Args:
            section: The source section to chunk.
            embedding_model: Override the configured embedding model name stored
                             in chunk_metadata. Defaults to settings.EMBEDDING_MODEL.
            start_index: 0-based starting index for the first chunk in this section
                         (enables document-wide continuous indexing when called iteratively).
            total_chunks: Override the total_chunks count reported in ChunkRecord.
                          Defaults to the number of chunks produced in this section.

        Returns:
            Ordered list of ChunkRecord objects (1 or more).

        Raises:
            ValueError: If section.raw_text is empty or whitespace-only.
        """
        model_name = embedding_model or self._embedding_model
        raw_text = section.raw_text.strip()

        if not raw_text:
            raise ValueError(
                f"Cannot chunk empty section: source_document='{section.source_document}', "
                f"section_title='{section.section_title}'"
            )

        words = raw_text.split()
        if len(words) == 0:
            raise ValueError(
                f"Section produces no words after splitting: "
                f"source_document='{section.source_document}'"
            )

        raw_chunks = self._slice_words(words)
        sec_total = len(raw_chunks)
        reported_total = total_chunks if total_chunks is not None else sec_total

        records: list[ChunkRecord] = []
        for sec_idx, chunk_text in enumerate(raw_chunks):
            doc_chunk_idx = start_index + sec_idx
            content_hash = KnowledgeEmbedding.compute_hash(chunk_text)
            metadata = {
                "source_document": section.source_document,
                "section_title": section.section_title,
                "doc_version": section.doc_version,
                "chunk_index": doc_chunk_idx,
                "total_chunks": reported_total,
                "section_chunk_index": sec_idx,
                "section_total_chunks": sec_total,
                "embedding_model": model_name,
            }
            records.append(
                ChunkRecord(
                    source_document=section.source_document,
                    section_title=section.section_title,
                    content=chunk_text,
                    content_hash=content_hash,
                    chunk_index=doc_chunk_idx,
                    total_chunks=reported_total,
                    chunk_metadata=metadata,
                )
            )

        return records

    def chunk_document(
        self,
        sections: list[SourceSection],
        embedding_model: str | None = None,
    ) -> list[ChunkRecord]:
        """
        Chunk all sections of a document, assigning continuous, document-wide 0-based indices.

        Invariants:
          - For a document producing N chunks, indices are exactly 0 through N-1.
          - Section changes do NOT reset the document-wide index.
          - Empty or whitespace-only sections are skipped without creating index gaps.
          - Repeated identical chunks are preserved as distinct occurrences with unique indices.
          - Preserves section-level metadata inside chunk_metadata.

        Args:
            sections: Ordered list of SourceSection objects for a document.
            embedding_model: Optional override for embedding model name.

        Returns:
            Ordered list of ChunkRecord objects spanning the full document (empty if no valid content).
        """
        if not sections:
            return []

        model_name = embedding_model or self._embedding_model

        # Step 1: Pre-slice all non-empty sections to establish total document chunk count
        section_raw_chunks: list[tuple[SourceSection, list[str]]] = []
        for sec in sections:
            raw_text = sec.raw_text.strip()
            if not raw_text:
                continue
            words = raw_text.split()
            if not words:
                continue
            raw_chunks = self._slice_words(words)
            if raw_chunks:
                section_raw_chunks.append((sec, raw_chunks))

        total_doc_chunks = sum(len(raws) for _, raws in section_raw_chunks)
        if total_doc_chunks == 0:
            return []

        # Step 2: Assign continuous 0-based document-wide indices
        records: list[ChunkRecord] = []
        global_idx = 0

        for sec, raw_chunks in section_raw_chunks:
            sec_total = len(raw_chunks)
            for sec_idx, chunk_text in enumerate(raw_chunks):
                content_hash = KnowledgeEmbedding.compute_hash(chunk_text)
                metadata = {
                    "source_document": sec.source_document,
                    "section_title": sec.section_title,
                    "doc_version": sec.doc_version,
                    "chunk_index": global_idx,
                    "total_chunks": total_doc_chunks,
                    "section_chunk_index": sec_idx,
                    "section_total_chunks": sec_total,
                    "embedding_model": model_name,
                }
                records.append(
                    ChunkRecord(
                        source_document=sec.source_document,
                        section_title=sec.section_title,
                        content=chunk_text,
                        content_hash=content_hash,
                        chunk_index=global_idx,
                        total_chunks=total_doc_chunks,
                        chunk_metadata=metadata,
                    )
                )
                global_idx += 1

        return records

    def chunk_sections(
        self,
        sections: list[SourceSection],
        embedding_model: str | None = None,
    ) -> list[ChunkRecord]:
        """Alias for chunk_document."""
        return self.chunk_document(sections, embedding_model=embedding_model)
