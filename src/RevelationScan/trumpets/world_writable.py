"""Trumpet scanning system paths for world-writable entries."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode


class WorldWritableTrumpet(Trumpet):
    slug = "world_writable"
    title = "Trumpet I: World-Writable Sanctuaries"
    description = "Detect critical directories and files that anyone can alter."

    TARGETS = [
        (Path("/etc"), "system configuration"),
        (Path("/usr/local/bin"), "local executables"),
        (Path("/usr/local/sbin"), "local administrative executables"),
    ]

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for root_path, label in self.TARGETS:
            if not root_path.exists():
                continue
            insecure = self._collect_insecure(root_path)
            if insecure:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"World-writable content under {root_path}",
                        details=[f"{entry} ({item_type}, mode {mode})" for entry, item_type, mode in insecure],
                        remediation="Tighten permissions with chmod/chown and audit the files for tampering.",
                    )
                )
        return findings

    def _collect_insecure(self, target: Path, limit: int = 30) -> List[tuple[str, str, str]]:
        insecure: List[tuple[str, str, str]] = []
        for root, dirnames, filenames in os.walk(target, followlinks=False):
            for name in dirnames:
                candidate = Path(root) / name
                if self._is_insecure(candidate):
                    insecure.append((str(candidate), "directory", human_mode(candidate.lstat().st_mode)))
                if len(insecure) >= limit:
                    return insecure
            for name in filenames:
                candidate = Path(root) / name
                if self._is_insecure(candidate):
                    insecure.append((str(candidate), "file", human_mode(candidate.lstat().st_mode)))
                if len(insecure) >= limit:
                    return insecure
        return insecure

    @staticmethod
    def _is_insecure(path: Path) -> bool:
        try:
            st = path.lstat()
        except (FileNotFoundError, PermissionError, OSError):
            return False
        if stat.S_ISLNK(st.st_mode):
            return False
        return bool(st.st_mode & stat.S_IWOTH)
