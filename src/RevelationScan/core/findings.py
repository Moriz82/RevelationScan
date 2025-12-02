"""Finding data structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    severity: str
    title: str
    details: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    remediation: Optional[str] = None
    exploit: Optional[str] = None


SeverityCounts = dict[str, int]
