"""Trumpet inspecting systemd ExecStart definitions."""
from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class SystemdExecTrumpet(Trumpet):
    slug = "systemd_exec"
    title = "Trumpet VII: Systemd Sentinels"
    description = "Check for unquoted ExecStart paths that contain spaces."

    DIRECTORIES = [
        Path("/etc/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
    ]

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for directory in self.DIRECTORIES:
            if not directory.exists():
                continue
            for service_file in directory.rglob("*.service"):
                try:
                    lines = service_file.read_text(errors="ignore").splitlines()
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                for line in lines:
                    stripped = line.strip()
                    if not stripped.startswith("ExecStart="):
                        continue
                    command = stripped.split("=", 1)[1].lstrip()
                    if command.startswith("-"):
                        command = command[1:].lstrip()
                    if not command or command.startswith("\""):
                        continue
                    first_token = command.split()[0]
                    if " " in first_token:
                        findings.append(
                            Finding(
                                severity="warning",
                                title="Potentially unsafe ExecStart path",
                                details=[f"{service_file}: {first_token} contains spaces but is not quoted"],
                                remediation="Quote paths with spaces in service unit ExecStart directives.",
                            )
                        )
        return findings
