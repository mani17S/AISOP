"""
AISOP Telemetry Parser Protocol & Registry.

Defines the contract that any log/telemetry parser must fulfill (ADR-004).
New telemetry formats (e.g. Zeek, Suricata, AWS CloudTrail, EVTX) can be plugged in
as new implementations of this protocol without modifying AISOP Core.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.schemas.normalized_event import CanonicalEvent


@runtime_checkable
class Parser(Protocol):
    """
    Interface contract for all telemetry parsers in AISOP.
    """

    def parser_name(self) -> str:
        """Unique identifier for this parser (e.g. 'sysmon', 'windows_event')."""
        ...

    def can_parse(self, raw_data: dict[str, Any] | str) -> bool:
        """Inspect raw payload structure to determine if this parser can handle it."""
        ...

    def parse(
        self,
        raw_data: dict[str, Any] | str,
        raw_ref: str | None = None,
    ) -> list[CanonicalEvent]:
        """
        Transform raw telemetry payload into one or more CanonicalEvents.
        """
        ...


class ParserRegistry:
    """Registry managing available telemetry parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def register(self, parser: Parser) -> None:
        self._parsers[parser.parser_name().lower()] = parser

    def get(self, name: str) -> Parser | None:
        return self._parsers.get(name.lower())

    def find_matching_parser(self, raw_data: dict[str, Any] | str) -> Parser | None:
        for parser in self._parsers.values():
            if parser.can_parse(raw_data):
                return parser
        return None
