"""Trumpet scanning NFS exports."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class NFSTrumpet(Trumpet):
    slug = "nfs"
    title = "Trumpet IX: Exports of the Covenant"
    description = "Highlight NFS exports that weaken root or allow wildcards."

    def blow(self, context: ScanContext) -> List[Finding]:
        exports_path = Path("/etc/exports")
        if not exports_path.exists():
            return []
        try:
            lines = exports_path.read_text(errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            return []
        findings: List[Finding] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            display = f"{exports_path}:{idx} {stripped}"
            if "no_root_squash" in stripped:
                findings.append(
                    Finding(
                        severity="critical",
                        title="NFS export without root squashing",
                        details=[display],
                        remediation="Add 'root_squash' to prevent clients from mapping root to root.",
                        exploit="Mount export and escalate privileges using preserved root permissions.",
                    )
                )
            elif re.search(r"\*(\s*\(|\s)", stripped):
                findings.append(
                    Finding(
                        severity="warning",
                        title="NFS export allows wildcard clients",
                        details=[display],
                        remediation="Restrict allowed hosts to explicit addresses or subnets.",
                    )
                )
        return findings
