"""Trumpet inspecting sensitive file permissions."""
from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode


class SensitiveFilesTrumpet(Trumpet):
    slug = "sensitive_files"
    title = "Trumpet III: Covenant Files"
    description = "Confirm critical system files have restrictive permissions."

    TARGETS = [
        (Path("/etc/passwd"), 0o022, "should not be writable by group/others"),
        (Path("/etc/shadow"), 0o077, "should only be readable by root"),
        (Path("/etc/sudoers"), 0o022, "must remain immutable to non-root accounts"),
    ]

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, forbidden_bits, guidance in self.TARGETS:
            if not path.exists():
                continue
            try:
                st = path.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if st.st_mode & forbidden_bits:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Permissions too broad on {path}",
                        details=[f"Mode {human_mode(st.st_mode)} - {guidance}"],
                        remediation="Run 'chmod' to enforce least privilege and verify file integrity.",
                    )
                )
        return findings
