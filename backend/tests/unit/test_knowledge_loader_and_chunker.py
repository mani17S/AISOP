"""
Unit tests for KnowledgeSourceLoader and DocumentChunker.

Validates:
- Discovery of .md, .txt, .yaml, .yml files.
- Path traversal defense.
- Unsupported format rejection.
- Markdown heading extraction into SourceSection.
- doc_version deterministic calculation.
- Sliding-window chunking, word boundaries, tail merge, and chunk metadata provenance.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest
from app.core.config import Settings
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.knowledge.chunker import DocumentChunker
from app.modules.ai.knowledge.loader import (
    KnowledgeSourceLoader,
    UnsupportedFormatError,
)
from app.schemas.knowledge import SourceSection


@pytest.fixture
def temp_kb_dir(tmp_path: Path):
    """Create a temporary directory structure mimicking knowledge_base/."""
    kb = tmp_path / "knowledge_base"
    kb.mkdir()

    # Markdown document with headings
    md_file = kb / "mitre_test.md"
    md_file.write_text(
        "# Title\n\nIntroductory overview.\n\n"
        "## Technique T1059\nCommand and Scripting Interpreter details.\n\n"
        "### Sub-technique T1059.001\nPowerShell execution semantics.\n",
        encoding="utf-8",
    )

    # Plain text document
    txt_file = kb / "notes.txt"
    txt_file.write_text("General security notes for SOC analysts.\n", encoding="utf-8")

    # YAML metadata document
    yaml_file = kb / "rule.yaml"
    yaml_file.write_text(
        "title: Suspicious PowerShell\nstatus: stable\n", encoding="utf-8"
    )

    # Unsupported format document
    bad_file = kb / "binary.bin"
    bad_file.write_bytes(b"\x00\x01\x02\x03")

    return kb


def test_loader_path_traversal_defense(temp_kb_dir: Path):
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    # Attempting to load a file outside kb_dir must raise ValueError
    outside_file = temp_kb_dir.parent / "secret.txt"
    outside_file.write_text("secret", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        loader.load_file(outside_file)

    assert "Path traversal detected" in str(exc_info.value)


def test_loader_unsupported_format_raises_error(temp_kb_dir: Path):
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    bad_file = temp_kb_dir / "binary.bin"
    with pytest.raises(UnsupportedFormatError) as exc_info:
        loader.load_file(bad_file)

    assert exc_info.value.extension == ".bin"


def test_loader_markdown_sections_and_doc_version(temp_kb_dir: Path):
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    md_file = temp_kb_dir / "mitre_test.md"
    sections = loader.load_file(md_file)

    assert len(sections) >= 3
    # Preamble section
    assert sections[0].section_title == "mitre_test"
    assert "Introductory overview" in sections[0].raw_text
    # Heading sections
    titles = [s.section_title for s in sections]
    assert "Technique T1059" in titles
    assert "Sub-technique T1059.001" in titles

    # All sections share the same source_document and doc_version
    for s in sections:
        assert s.source_document == "mitre_test.md"
        assert len(s.doc_version) == 64  # SHA-256


def test_loader_load_directory_yields_accepted_files(temp_kb_dir: Path):
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    all_sections = list(loader.load_directory())
    assert len(all_sections) >= 5
    docs = {s.source_document for s in all_sections}
    assert "mitre_test.md" in docs
    assert "notes.txt" in docs
    assert "rule.yaml" in docs
    assert "binary.bin" not in docs


def test_chunker_deterministic_output():
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=20, KNOWLEDGE_CHUNK_OVERLAP=5)
    chunker = DocumentChunker(settings=settings)

    section = SourceSection(
        source_document="mitre/t1059.md",
        section_title="PowerShell Execution",
        raw_text="PowerShell is a cross-platform task automation solution consisting of a command-line shell and scripting language. "
        * 10,
        doc_version="a" * 64,
    )

    chunks1 = chunker.chunk_section(section)
    chunks2 = chunker.chunk_section(section)

    assert len(chunks1) > 1
    assert len(chunks1) == len(chunks2)
    for c1, c2 in zip(chunks1, chunks2):
        assert c1.content == c2.content
        assert c1.content_hash == c2.content_hash
        assert c1.chunk_index == c2.chunk_index
        assert c1.chunk_metadata["doc_version"] == "a" * 64
        assert c1.chunk_metadata["embedding_model"] == "nomic-embed-text"


def test_chunker_tail_merge():
    # 25 words total: with chunk_size=20, overlap=0, raw chunks would be 20 and 5 words.
    # Because 5 < MIN_TAIL_WORDS (20), the 5 words should be merged into the previous chunk.
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=20, KNOWLEDGE_CHUNK_OVERLAP=0)
    chunker = DocumentChunker(settings=settings)

    words = ["word"] * 25
    section = SourceSection(
        source_document="test.md",
        section_title="Tail Test",
        raw_text=" ".join(words),
        doc_version="b" * 64,
    )

    chunks = chunker.chunk_section(section)
    assert len(chunks) == 1
    assert len(chunks[0].content.split()) == 25


def test_chunker_empty_section_raises_value_error():
    chunker = DocumentChunker()
    section = SourceSection(
        source_document="empty.md",
        section_title="Empty",
        raw_text="   \n   ",
    )
    with pytest.raises(ValueError) as exc_info:
        chunker.chunk_section(section)

    assert "Cannot chunk empty section" in str(exc_info.value)


# ==============================================================================
# Phase B Provenance & Security Test Suite
# ==============================================================================


def test_continuous_indices_across_multiple_sections():
    """
    Test 1: Continuous indices across multiple sections.
    Indices must run 0 to N-1 without resetting at section boundaries.
    """
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=20, KNOWLEDGE_CHUNK_OVERLAP=5)
    chunker = DocumentChunker(settings=settings)

    # 3 sections producing 2, 2, and 1 chunks respectively
    # (With chunk_size=20, overlap=5, MIN_TAIL_WORDS=20, 35 words yields 2 chunks: [20, 20])
    sec1 = SourceSection(
        source_document="mitre/t1059.md",
        section_title="Overview",
        raw_text="Word " * 35,  # 35 words -> 2 chunks
        doc_version="v1" * 32,
    )
    sec2 = SourceSection(
        source_document="mitre/t1059.md",
        section_title="Technique Detail",
        raw_text="Command " * 35,  # 35 words -> 2 chunks
        doc_version="v1" * 32,
    )
    sec3 = SourceSection(
        source_document="mitre/t1059.md",
        section_title="Mitigation",
        raw_text="Execution restriction and policy enforcement rules.",  # ~6 words -> 1 chunk
        doc_version="v1" * 32,
    )

    chunks = chunker.chunk_document([sec1, sec2, sec3])
    assert len(chunks) == 5
    indices = [c.chunk_index for c in chunks]
    assert indices == [0, 1, 2, 3, 4]

    for c in chunks:
        assert c.total_chunks == 5
        assert c.chunk_metadata["chunk_index"] == c.chunk_index
        assert c.chunk_metadata["total_chunks"] == 5
        assert c.chunk_metadata["doc_version"] == "v1" * 32
        assert c.source_document == "mitre/t1059.md"


def test_zero_based_indices_single_and_multi_section():
    """
    Test 2: Zero-based indices for single-section and multi-section documents.
    """
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=20, KNOWLEDGE_CHUNK_OVERLAP=5)
    chunker = DocumentChunker(settings=settings)

    # Single-section: 50 words produces exactly 3 chunks [20, 20, 20]
    single_sec = SourceSection(
        source_document="single.md",
        section_title="Single Section",
        raw_text="Alpha " * 50,
        doc_version="s1" * 32,
    )
    single_chunks = chunker.chunk_document([single_sec])
    assert len(single_chunks) == 3
    assert [c.chunk_index for c in single_chunks] == [0, 1, 2]
    assert all(c.total_chunks == 3 for c in single_chunks)

    # Multi-section: 35 words each produces 2 chunks per section -> 4 total
    multi_sec1 = SourceSection(
        source_document="multi.md",
        section_title="Sec 1",
        raw_text="Beta " * 35,
        doc_version="m1" * 32,
    )
    multi_sec2 = SourceSection(
        source_document="multi.md",
        section_title="Sec 2",
        raw_text="Gamma " * 35,
        doc_version="m1" * 32,
    )
    multi_chunks = chunker.chunk_document([multi_sec1, multi_sec2])
    assert len(multi_chunks) == 4
    assert multi_chunks[0].chunk_index == 0
    assert [c.chunk_index for c in multi_chunks] == [0, 1, 2, 3]
    assert all(c.total_chunks == 4 for c in multi_chunks)


def test_empty_documents_empty_sections_and_whitespace(temp_kb_dir: Path):
    """
    Test 3: Empty documents, empty sections and whitespace-only content.
    Empty sections must be skipped without creating gaps in document-wide indices.
    """
    settings = Settings(
        KNOWLEDGE_BASE_PATH=str(temp_kb_dir),
        KNOWLEDGE_CHUNK_SIZE=20,
        KNOWLEDGE_CHUNK_OVERLAP=5,
    )
    chunker = DocumentChunker(settings=settings)
    loader = KnowledgeSourceLoader(settings=settings)

    # 1. Empty list of sections
    assert chunker.chunk_document([]) == []

    # 2. Document with interspersed empty/whitespace sections
    sec1 = SourceSection(
        source_document="doc.md",
        section_title="Valid 1",
        raw_text="Valid content section one with sufficient text.",
    )
    sec_empty = SourceSection(
        source_document="doc.md",
        section_title="Empty Section",
        raw_text="   \n\t   ",
    )
    sec2 = SourceSection(
        source_document="doc.md",
        section_title="Valid 2",
        raw_text="Valid content section two with subsequent text.",
    )
    chunks = chunker.chunk_document([sec1, sec_empty, sec2])
    assert len(chunks) == 2
    assert [c.chunk_index for c in chunks] == [0, 1]
    assert [c.total_chunks for c in chunks] == [2, 2]
    assert chunks[0].section_title == "Valid 1"
    assert chunks[1].section_title == "Valid 2"

    # 3. Completely empty document file
    empty_file = temp_kb_dir / "empty_doc.md"
    empty_file.write_text("   \n\n   ", encoding="utf-8")
    loaded_sections = loader.load_file(empty_file)
    empty_doc_chunks = chunker.chunk_document(loaded_sections)
    assert empty_doc_chunks == []


def test_repeated_identical_chunks_within_one_document():
    """
    Test 4: Repeated identical chunks within one document.
    Must not drop occurrences; each occurrence receives its own distinct chunk_index.
    """
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=20, KNOWLEDGE_CHUNK_OVERLAP=5)
    chunker = DocumentChunker(settings=settings)

    identical_text = (
        "Adversaries may use PowerShell to execute malicious automation scripts "
        "on victim machines."
    )
    sec1 = SourceSection(
        source_document="playbook.md",
        section_title="Stage 1",
        raw_text=identical_text,
        doc_version="h" * 64,
    )
    sec2 = SourceSection(
        source_document="playbook.md",
        section_title="Stage 2",
        raw_text=identical_text,
        doc_version="h" * 64,
    )

    chunks = chunker.chunk_document([sec1, sec2])
    assert len(chunks) == 2
    assert chunks[0].content == chunks[1].content
    assert chunks[0].content_hash == chunks[1].content_hash
    # Distinct indices
    assert chunks[0].chunk_index == 0
    assert chunks[1].chunk_index == 1
    # Section titles preserved
    assert chunks[0].section_title == "Stage 1"
    assert chunks[1].section_title == "Stage 2"


def test_identical_chunks_from_different_documents():
    """
    Test 5: Identical chunks from different documents.
    Both occurrences preserved with distinct source_document identifiers.
    """
    chunker = DocumentChunker()
    text = "Adversaries execute binaries directly via cmd.exe."

    sec_a = SourceSection(
        source_document="doc_a.md",
        section_title="Sec A",
        raw_text=text,
    )
    sec_b = SourceSection(
        source_document="sub/doc_b.md",
        section_title="Sec B",
        raw_text=text,
    )

    chunks_a = chunker.chunk_document([sec_a])
    chunks_b = chunker.chunk_document([sec_b])

    assert len(chunks_a) == 1
    assert len(chunks_b) == 1
    assert chunks_a[0].content_hash == chunks_b[0].content_hash
    assert chunks_a[0].source_document == "doc_a.md"
    assert chunks_b[0].source_document == "sub/doc_b.md"
    assert chunks_a[0].chunk_index == 0
    assert chunks_b[0].chunk_index == 0


def test_deterministic_indices_and_output_order():
    """
    Test 6: Deterministic indices and output order for identical input.
    """
    settings = Settings(KNOWLEDGE_CHUNK_SIZE=15, KNOWLEDGE_CHUNK_OVERLAP=3)
    chunker = DocumentChunker(settings=settings)

    sec1 = SourceSection(
        source_document="det.md",
        section_title="Section 1",
        raw_text="The quick brown fox jumps over the lazy dog repeatedly for testing purposes.",
    )
    sec2 = SourceSection(
        source_document="det.md",
        section_title="Section 2",
        raw_text="Deterministic hashing and indexing are critical invariants in security RAG.",
    )

    baseline = chunker.chunk_document([sec1, sec2])
    for _ in range(5):
        run = chunker.chunk_document([sec1, sec2])
        assert len(run) == len(baseline)
        for b, r in zip(baseline, run):
            assert b.chunk_index == r.chunk_index
            assert b.content == r.content
            assert b.content_hash == r.content_hash
            assert b.source_document == r.source_document
            assert b.chunk_metadata == r.chunk_metadata


def test_stable_posix_relative_source_paths_on_windows(temp_kb_dir: Path):
    """
    Test 7: Stable POSIX relative source paths on Windows.
    Must always use forward slashes and contain no absolute drive letters.
    """
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)
    chunker = DocumentChunker(settings=settings)

    sub_dir = temp_kb_dir / "windows_sub" / "deep_dir"
    sub_dir.mkdir(parents=True, exist_ok=True)
    test_file = sub_dir / "target.md"
    test_file.write_text("## Deep Heading\nContent inside deep directory.\n", encoding="utf-8")

    # Pass relative path with backslashes mimicking Windows input
    rel_win_path = Path("windows_sub\\deep_dir\\target.md")
    sections = loader.load_file(rel_win_path)
    assert len(sections) >= 1
    assert sections[0].source_document == "windows_sub/deep_dir/target.md"
    assert "\\" not in sections[0].source_document

    chunks = chunker.chunk_document(sections)
    assert len(chunks) >= 1
    assert chunks[0].source_document == "windows_sub/deep_dir/target.md"
    assert "\\" not in chunks[0].source_document
    assert chunks[0].chunk_metadata["source_document"] == "windows_sub/deep_dir/target.md"


def test_traversal_attempts_with_separator_variants(temp_kb_dir: Path):
    """
    Test 8: Traversal attempts using '..', absolute paths, separator variants,
    and sibling directories sharing the root prefix.
    All traversal attempts outside knowledge_base root must raise ValueError.
    """
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    # Outside secret file
    secret = temp_kb_dir.parent / "secret_file.txt"
    secret.write_text("secret", encoding="utf-8")

    # Sibling directory starting with the root directory name
    sibling_dir = temp_kb_dir.parent / f"{temp_kb_dir.name}_extra"
    sibling_dir.mkdir(parents=True, exist_ok=True)
    sibling_file = sibling_dir / "leak.txt"
    sibling_file.write_text("sibling leak", encoding="utf-8")

    traversal_paths = [
        temp_kb_dir.parent / "secret_file.txt",  # absolute outside
        Path("../secret_file.txt"),  # relative POSIX
        Path("..\\secret_file.txt"),  # relative Windows
        Path("sub/../../secret_file.txt"),  # nested POSIX escape
        Path("sub\\..\\..\\secret_file.txt"),  # nested Windows escape
        Path("/etc/passwd"),  # POSIX absolute
        Path("C:\\Windows\\System32\\cmd.exe"),  # Windows absolute
        sibling_file,  # sibling directory absolute path
        Path(f"../{temp_kb_dir.name}_extra/leak.txt"),  # sibling relative POSIX
        Path(f"..\\{temp_kb_dir.name}_extra\\leak.txt"),  # sibling relative Windows
    ]

    for bad_path in traversal_paths:
        with pytest.raises(ValueError) as exc_info:
            loader.load_file(bad_path)
        assert "Path traversal detected" in str(exc_info.value)


def test_symlink_escape_behavior(temp_kb_dir: Path):
    """
    Test 9: Symlink escape behavior where the existing test environment safely verifies it.
    Symlinks pointing outside knowledge_base root must be rejected with ValueError.
    """
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    outside_file = temp_kb_dir.parent / "external_secret.md"
    outside_file.write_text("## Secret\nExternal secret data.\n", encoding="utf-8")

    link_path = temp_kb_dir / "symlink_test.md"
    try:
        link_path.symlink_to(outside_file)
    except OSError as e:
        pytest.skip(f"Symlinks not permitted in current test environment: {e}")

    with pytest.raises(ValueError) as exc_info:
        loader.load_file(link_path)
    assert "Path traversal detected" in str(exc_info.value)


def test_loader_valid_paths_containment(temp_kb_dir: Path):
    """
    Focused test for valid paths:
    Relative paths, absolute paths, nested subdirectory paths, and internal symlinks
    resolving inside knowledge_base root must succeed without raising ValueError.
    """
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    # 1. Valid relative path at root
    rel_path = Path("mitre_test.md")
    resolved_rel = loader._safe_resolve(rel_path)
    assert resolved_rel == (temp_kb_dir / "mitre_test.md").resolve()
    sections_rel = loader.load_file(rel_path)
    assert len(sections_rel) >= 1
    assert sections_rel[0].source_document == "mitre_test.md"

    # 2. Valid absolute path at root
    abs_path = (temp_kb_dir / "notes.txt").resolve()
    resolved_abs = loader._safe_resolve(abs_path)
    assert resolved_abs == abs_path
    sections_abs = loader.load_file(abs_path)
    assert len(sections_abs) == 1
    assert sections_abs[0].source_document == "notes.txt"

    # 3. Valid nested subdirectory paths (both relative and absolute)
    nested_dir = temp_kb_dir / "nested" / "sub"
    nested_dir.mkdir(parents=True, exist_ok=True)
    nested_file = nested_dir / "doc.md"
    nested_file.write_text("## Nested Heading\nNested document text.\n", encoding="utf-8")

    rel_nested = Path("nested/sub/doc.md")
    assert loader._safe_resolve(rel_nested) == nested_file.resolve()
    assert len(loader.load_file(rel_nested)) >= 1

    abs_nested = nested_file.resolve()
    assert loader._safe_resolve(abs_nested) == nested_file.resolve()
    assert len(loader.load_file(abs_nested)) >= 1

    # 4. Valid internal symlink pointing within knowledge_base root
    link_valid = temp_kb_dir / "internal_link.md"
    try:
        link_valid.symlink_to(nested_file)
    except OSError:
        pass  # Skip if symlinks not permitted
    else:
        assert loader._safe_resolve(link_valid) == nested_file.resolve()
        sections_link = loader.load_file(link_valid)
        assert len(sections_link) >= 1


def test_loader_sibling_prefix_directory_escape(temp_kb_dir: Path):
    """
    Focused test for sibling directory prefix escape defense:
    A directory sharing the root prefix (e.g., 'kb_extra' vs 'kb')
    must raise ValueError on both _safe_resolve() and load_file().
    """
    settings = Settings(KNOWLEDGE_BASE_PATH=str(temp_kb_dir))
    loader = KnowledgeSourceLoader(settings=settings)

    # Create sibling directory sharing prefix: e.g. <temp_kb_dir>_extra
    sibling_dir = temp_kb_dir.parent / f"{temp_kb_dir.name}_extra"
    sibling_dir.mkdir(parents=True, exist_ok=True)
    sibling_file = sibling_dir / "confidential.md"
    sibling_file.write_text("## Confidential\nExfiltrated data.\n", encoding="utf-8")

    # 1. Absolute path to sibling file
    with pytest.raises(ValueError) as exc_info:
        loader._safe_resolve(sibling_file)
    assert "Path traversal detected" in str(exc_info.value)
    assert str(sibling_file.resolve()) in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        loader.load_file(sibling_file)
    assert "Path traversal detected" in str(exc_info.value)

    # 2. Relative traversal into sibling directory (POSIX)
    rel_posix = Path(f"../{temp_kb_dir.name}_extra/confidential.md")
    with pytest.raises(ValueError) as exc_info:
        loader._safe_resolve(rel_posix)
    assert "Path traversal detected" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        loader.load_file(rel_posix)
    assert "Path traversal detected" in str(exc_info.value)

    # 3. Relative traversal into sibling directory (Windows backslash)
    rel_win = Path(f"..\\{temp_kb_dir.name}_extra\\confidential.md")
    with pytest.raises(ValueError) as exc_info:
        loader._safe_resolve(rel_win)
    assert "Path traversal detected" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        loader.load_file(rel_win)
    assert "Path traversal detected" in str(exc_info.value)

    # 4. Symlink within KB root pointing to sibling file
    link_to_sibling = temp_kb_dir / "symlink_to_sibling.md"
    try:
        link_to_sibling.symlink_to(sibling_file)
    except OSError:
        pass  # Skip if symlinks not permitted
    else:
        with pytest.raises(ValueError) as exc_info:
            loader._safe_resolve(link_to_sibling)
        assert "Path traversal detected" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            loader.load_file(link_to_sibling)
        assert "Path traversal detected" in str(exc_info.value)
def test_stable_sha256_canonical_content_hashing():
    """
    Test 10: Stable SHA-256 results for the documented canonical content.
    Canonical content is stripped of leading/trailing whitespace and encoded UTF-8.
    """
    chunker = DocumentChunker()
    raw_content = "   powershell.exe -ExecutionPolicy Bypass -File script.ps1   "
    canonical_stripped = "powershell.exe -ExecutionPolicy Bypass -File script.ps1"
    expected_hash = hashlib.sha256(canonical_stripped.encode("utf-8")).hexdigest()

    sec = SourceSection(
        source_document="powershell.md",
        section_title="Exec",
        raw_text=raw_content,
    )
    chunks = chunker.chunk_document([sec])
    assert len(chunks) == 1
    assert chunks[0].content_hash == expected_hash
    assert KnowledgeEmbedding.compute_hash(raw_content) == expected_hash
    assert len(chunks[0].content_hash) == 64


def test_preservation_of_section_metadata_and_provenance():
    """
    Test 11: No accidental loss of section metadata or source provenance.
    """
    settings = Settings(
        KNOWLEDGE_CHUNK_SIZE=20,
        KNOWLEDGE_CHUNK_OVERLAP=5,
        EMBEDDING_MODEL="nomic-embed-text",
    )
    chunker = DocumentChunker(settings=settings)

    sec1 = SourceSection(
        source_document="mitre/t1059.md",
        section_title="Initial Access",
        raw_text="Word " * 35,  # 35 words -> 2 chunks
        doc_version="deadbeef" * 8,
    )
    sec2 = SourceSection(
        source_document="mitre/t1059.md",
        section_title="Execution Phase",
        raw_text="Execution " * 20,  # 1 chunk
        doc_version="deadbeef" * 8,
    )

    chunks = chunker.chunk_document([sec1, sec2])
    assert len(chunks) == 3

    # Chunk 0
    assert chunks[0].chunk_index == 0
    assert chunks[0].section_title == "Initial Access"
    assert chunks[0].chunk_metadata["section_chunk_index"] == 0
    assert chunks[0].chunk_metadata["section_total_chunks"] == 2
    assert chunks[0].chunk_metadata["total_chunks"] == 3
    assert chunks[0].chunk_metadata["doc_version"] == "deadbeef" * 8
    assert chunks[0].chunk_metadata["embedding_model"] == "nomic-embed-text"

    # Chunk 1
    assert chunks[1].chunk_index == 1
    assert chunks[1].section_title == "Initial Access"
    assert chunks[1].chunk_metadata["section_chunk_index"] == 1
    assert chunks[1].chunk_metadata["section_total_chunks"] == 2
    assert chunks[1].chunk_metadata["total_chunks"] == 3

    # Chunk 2
    assert chunks[2].chunk_index == 2
    assert chunks[2].section_title == "Execution Phase"
    assert chunks[2].chunk_metadata["section_chunk_index"] == 0
    assert chunks[2].chunk_metadata["section_total_chunks"] == 1
    assert chunks[2].chunk_metadata["total_chunks"] == 3


def test_backwards_compatibility_and_chunk_sections_alias():
    """
    Test 12: Compatibility with existing callers and chunk_sections alias.
    """
    chunker = DocumentChunker()
    sec = SourceSection(
        source_document="legacy.md",
        section_title="Legacy Section",
        raw_text="Legacy compatibility test content for DocumentChunker.",
    )

    # Calling chunk_section directly with start_index
    chunks_single = chunker.chunk_section(sec, start_index=10, total_chunks=15)
    assert len(chunks_single) == 1
    assert chunks_single[0].chunk_index == 10
    assert chunks_single[0].total_chunks == 15

    # Calling chunk_sections alias
    chunks_alias = chunker.chunk_sections([sec])
    chunks_doc = chunker.chunk_document([sec])
    assert len(chunks_alias) == len(chunks_doc)
    assert chunks_alias[0].chunk_index == chunks_doc[0].chunk_index == 0
