"""Trumpet inspecting Docker socket exposure."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label


class DockerTrumpet(Trumpet):
    slug = "docker"
    title = "Trumpet X: Leviathan's Chain"
    description = "Detect broad access to the Docker UNIX socket."

    socket_path = Path("/var/run/docker.sock")

    def blow(self, context: ScanContext) -> List[Finding]:
        if not self.socket_path.exists():
            return []
        try:
            st = self.socket_path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            return []
        issues: List[str] = []
        severity = None
        if st.st_mode & 0o002:
            severity = "critical"
            issues.append("world-writable")
        if st.st_mode & 0o020:
            severity = severity or "warning"
            issues.append("group-writable")
        current_euid = os.geteuid() if hasattr(os, "geteuid") else None
        if current_euid not in {None, 0}:
            groups = set(os.getgroups()) if hasattr(os, "getgroups") else set()
            if st.st_gid in groups:
                severity = severity or "warning"
                issues.append("current user in docker group")
            if st.st_uid == current_euid:
                severity = severity or "info"
                issues.append("current user owns docker socket")
        if not issues:
            return []
        return [
            Finding(
                severity=severity or "info",
                title="Docker socket accessible",
                details=[
                    f"{self.socket_path} owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)} - {', '.join(issues)}",
                ],
                remediation="Restrict docker.sock to root-only or use rootless Docker.",
                exploit="gaining docker group access often grants root via mounting the host filesystem",
            )
        ]
