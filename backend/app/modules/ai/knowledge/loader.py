"""
AISOP Knowledge Source Loader.

Discovers and reads knowledge source documents from the knowledge_base/ directory,
extracting logical sections (Markdown headings) to produce SourceSection objects
ready for the DocumentChunker.

Accepted formats: .md (Markdown), .txt (plain text), .yaml/.yml (Sigma rule metadata).
All other extensions raise UnsupportedFormatError.

Security:
  - All paths are resolved relative to KNOWLEDGE_BASE_PATH and verified to remain
    within that root before any file I/O. Path traversal raises ValueError.
  - File content is returned as raw text. No code execution or shell invocation occurs.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Generator

from app.core.config import Settings, get_settings
from app.schemas.knowledge import SourceSection
from loguru import logger

# Extensions accepted for P2-H3. Extend via UnsupportedFormatError documentation.
_ACCEPTED_EXTENSIONS: frozenset[str] = frozenset({".md", ".txt", ".yaml", ".yml"})

# Regex matching Markdown level-2 and level-3 headings at line start
_MD_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+)$", re.MULTILINE)


class UnsupportedFormatError(Exception):
    """Raised when the loader encounters a file extension not in the accepted set."""

    def __init__(self, path: Path, extension: str) -> None:
        super().__init__(
            f"Unsupported file format '{extension}' for '{path}'. "
            f"Accepted: {sorted(_ACCEPTED_EXTENSIONS)}"
        )
        self.path = path
        self.extension = extension


class KnowledgeSourceLoader:
    """
    Discovers and segments knowledge source documents into SourceSection objects.

    Usage:
        loader = KnowledgeSourceLoader()
        for section in loader.load_directory():
            ...  # pass section to DocumentChunker
    """

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or get_settings()
        self._kb_root = Path(cfg.KNOWLEDGE_BASE_PATH).resolve()

    @property
    def knowledge_base_root(self) -> Path:
        """Absolute path to the knowledge_base/ root directory."""
        return self._kb_root

    def _safe_resolve(self, path: Path) -> Path:
        """
        Resolve path and assert it remains within the knowledge_base root.

        Raises:
            ValueError: If the resolved path escapes knowledge_base/.
        """
        if not path.is_absolute():
            resolved = (self._kb_root / path).resolve()
        else:
            resolved = path.resolve()
        try:
            resolved.relative_to(self._kb_root)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: '{resolved}' is outside "
                f"knowledge_base root '{self._kb_root}'"
            )
        return resolved

    def _relative_source_document(self, file_path: Path) -> str:
        """Return the path relative to knowledge_base/ root, using forward slashes."""
        return file_path.relative_to(self._kb_root).as_posix()

    def _extract_sections_markdown(
        self, content: str, source_document: str, file_stem: str, doc_version: str
    ) -> list[SourceSection]:
        """
        Split a Markdown document into sections on ## / ### headings.

        If no headings are found, the entire document is returned as a single section
        titled with the filename stem.
        """
        # Split on heading matches, keeping the heading text
        parts = _MD_HEADING_RE.split(content)
        # parts layout: [pre_heading_text, hashes, heading_text, body, hashes, heading_text, body ...]

        sections: list[SourceSection] = []

        # parts[0] is the preamble before the first heading
        preamble = parts[0].strip()
        if preamble:
            sections.append(
                SourceSection(
                    source_document=source_document,
                    section_title=file_stem,
                    raw_text=preamble,
                    doc_version=doc_version,
                )
            )

        # Every triplet (hashes, heading_text, body) forms one section
        i = 1
        while i + 2 <= len(parts):
            # parts[i] = hashes ("##" / "###"), parts[i+1] = heading text, parts[i+2] = body
            heading_text = parts[i + 1].strip()
            body = parts[i + 2].strip() if i + 2 < len(parts) else ""
            section_content = f"{heading_text}\n\n{body}".strip()
            if section_content:
                sections.append(
                    SourceSection(
                        source_document=source_document,
                        section_title=heading_text,
                        raw_text=section_content,
                        doc_version=doc_version,
                    )
                )
            i += 3

        if not sections:
            # No headings found and no preamble — return full document as one section
            sections.append(
                SourceSection(
                    source_document=source_document,
                    section_title=file_stem,
                    raw_text=content.strip(),
                    doc_version=doc_version,
                )
            )

        return sections

    def _extract_sections_plain(
        self, content: str, source_document: str, file_stem: str, doc_version: str
    ) -> list[SourceSection]:
        """Return the entire plain-text file as a single section."""
        return [
            SourceSection(
                source_document=source_document,
                section_title=file_stem,
                raw_text=content.strip(),
                doc_version=doc_version,
            )
        ]

    def load_file(self, file_path: Path) -> list[SourceSection]:
        """
        Load and section a single knowledge source file.

        Args:
            file_path: Absolute or relative path to the source file.

        Returns:
            List of SourceSection objects extracted from the file.

        Raises:
            UnsupportedFormatError: If the file extension is not in the accepted set.
            ValueError: If the file path escapes the knowledge_base root.
        """
        resolved = self._safe_resolve(file_path)
        ext = resolved.suffix.lower()

        if ext not in _ACCEPTED_EXTENSIONS:
            raise UnsupportedFormatError(resolved, ext)

        source_document = self._relative_source_document(resolved)
        file_stem = resolved.stem

        logger.debug(
            "Loading knowledge source file",
            source_document=source_document,
            extension=ext,
        )

        content = resolved.read_text(encoding="utf-8", errors="replace")
        doc_version = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if ext == ".md":
            return self._extract_sections_markdown(
                content, source_document, file_stem, doc_version
            )
        else:
            # .txt, .yaml, .yml — return as single section
            return self._extract_sections_plain(
                content, source_document, file_stem, doc_version
            )

    def load_directory(
        self, subdirectory: str | None = None
    ) -> Generator[SourceSection, None, None]:
        """
        Recursively discover and load all accepted files under knowledge_base/.

        Args:
            subdirectory: Optional sub-path relative to knowledge_base/ root
                          (e.g. "mitre") to restrict the scan.

        Yields:
            SourceSection objects in filesystem traversal order.
        """
        scan_root = self._kb_root
        if subdirectory:
            scan_root = self._safe_resolve(self._kb_root / subdirectory)

        logger.info(
            "Starting knowledge source directory scan",
            scan_root=str(scan_root),
        )

        file_count = 0
        section_count = 0

        for file_path in sorted(scan_root.rglob("*")):
            if not file_path.is_file():
                continue
            ext = file_path.suffix.lower()
            if ext not in _ACCEPTED_EXTENSIONS:
                logger.debug(
                    "Skipping unsupported file",
                    path=str(file_path),
                    extension=ext,
                )
                continue

            try:
                sections = self.load_file(file_path)
                file_count += 1
                section_count += len(sections)
                yield from sections
            except (ValueError, OSError) as exc:
                logger.warning(
                    "Failed to load knowledge source file",
                    path=str(file_path),
                    error=str(exc),
                )

        logger.info(
            "Knowledge source directory scan complete",
            scan_root=str(scan_root),
            files_loaded=file_count,
            sections_extracted=section_count,
        )
