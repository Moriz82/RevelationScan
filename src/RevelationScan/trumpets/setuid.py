"""Trumpet investigating setuid binaries."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode


class SetuidTrumpet(Trumpet):
    slug = "setuid"
    title = "Trumpet V: Setuid Watch"
    description = "Surface setuid binaries with suspicious ownership or permissions."

    TARGETS: Iterable[Path] = (
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
    )

    LIMIT = 50

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for target in self.TARGETS:
            if not target.exists():
                continue
            for root, _, filenames in os.walk(target, followlinks=False):
                for name in filenames:
                    path = Path(root) / name
                    try:
                        st = path.lstat()
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
                    if not (st.st_mode & stat.S_ISUID):
                        continue
                    issues: List[str] = []
                    severity = None
                    if st.st_uid != 0:
                        severity = severity or "warning"
                        issues.append(f"setuid owned by UID {st.st_uid}")
                    if st.st_mode & stat.S_IWOTH:
                        severity = "critical"
                        issues.append("world-writable")
                    if issues:
                        findings.append(
                            Finding(
                                severity=severity or "info",
                                title="Suspicious setuid binary",
                                details=[f"{path} ({'; '.join(issues)}; mode {human_mode(st.st_mode)})"],
                                remediation="Audit binary provenance and restrict permissions if not required.",
                            )
                        )
                        if len(findings) >= self.LIMIT:
                            return findings
        return findings
