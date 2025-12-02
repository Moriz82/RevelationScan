"""Core orchestration primitives."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Type

from .findings import Finding, SeverityCounts


@dataclass
class ScanContext:
    config: Dict[str, object]
    cve_feed: Path | None
    output_format: str
    suggest_exploits: bool
    plugins: Sequence[Path]


class Trumpet:
    """Base class for Revelation Scan modules."""

    slug: str = ""
    title: str = ""
    description: str = ""

    def blow(self, context: ScanContext) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


class TrumpetRegistry:
    def __init__(self) -> None:
        self._registry: Dict[str, Type[Trumpet]] = {}

    def register(self, trumpet_cls: Type[Trumpet]) -> None:
        slug = trumpet_cls.slug or trumpet_cls.__name__.lower()
        if slug in self._registry:
            raise ValueError(f"Duplicate trumpet slug: {slug}")
        self._registry[slug] = trumpet_cls

    def extend(self, trumpet_classes: Iterable[Type[Trumpet]]) -> None:
        for trumpet_cls in trumpet_classes:
            self.register(trumpet_cls)

    def create_all(self) -> List[Trumpet]:
        return [cls() for cls in self._registry.values()]

    def slugs(self) -> List[str]:
        return list(self._registry.keys())

    def get(self, slug: str) -> Type[Trumpet]:
        return self._registry[slug]


def summarize(findings: List[Finding]) -> SeverityCounts:
    counts: SeverityCounts = {"critical": 0, "warning": 0, "info": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts
