"""Trumpet guarding PATH hygiene."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List, Set

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode


class PathHygieneTrumpet(Trumpet):
    slug = "path_hygiene"
    title = "Trumpet II: PATH Vigil"
    description = "Highlight risky PATH entries that enable hijacking."

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Path] = set()
        for raw in os.environ.get("PATH", "").split(os.pathsep):
            if not raw:
                continue
            if raw == ".":
                findings.append(
                    Finding(
                        severity="critical",
                        title="PATH contains relative entry",
                        details=["'.' allows command hijacking from the working directory."],
                        remediation="Remove '.' from PATH and reference binaries explicitly when needed.",
                    )
                )
                continue
            path = Path(raw).expanduser()
            if not path.is_absolute():
                findings.append(
                    Finding(
                        severity="warning",
                        title="Non-absolute PATH entry",
                        details=[f"{raw} resolves to {path}"],
                        remediation="Use absolute paths to avoid unexpected resolution.",
                    )
                )
            try:
                resolved = path.resolve(strict=False)
            except RuntimeError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            if not path.exists():
                findings.append(
                    Finding(
                        severity="warning",
                        title="Missing PATH directory",
                        details=[f"{path} does not exist"],
                        remediation="Prune stale PATH entries to speed up lookups and reduce confusion.",
                    )
                )
                continue
            try:
                st = path.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            severity = None
            details: List[str] = []
            title = "PATH directory with weak permissions"
            if st.st_mode & stat.S_IWOTH:
                severity = "critical"
                details.append("world-writable")
                title = "World-writable directory in PATH"
            if st.st_uid != 0:
                context_note = f"owned by UID {st.st_uid}"
                if os.geteuid() == 0:
                    severity = "critical"
                else:
                    severity = severity or "info"
                    context_note += " (expected for user-local PATH)"
                details.append(context_note)
                if severity == "info":
                    title = "User-owned directory in PATH"
            if details:
                findings.append(
                    Finding(
                        severity=severity or "warning",
                        title=title,
                        details=[f"{path} ({', '.join(details)}; mode {human_mode(st.st_mode)})"],
                        remediation="Restrict permissions and ensure critical PATH entries are root-owned and non-writable.",
                    )
                )
        return findings
