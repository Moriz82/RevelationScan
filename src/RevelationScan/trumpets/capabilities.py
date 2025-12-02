"""Trumpet enumerating files with Linux capabilities."""
from __future__ import annotations

import shutil
import subprocess
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class CapabilitiesTrumpet(Trumpet):
    slug = "capabilities"
    title = "Trumpet XIV: Mantle of Capabilities"
    description = "Detect binaries granted ambient Linux capabilities that may allow privilege escalation."

    def blow(self, context: ScanContext) -> List[Finding]:
        if not shutil.which("getcap"):
            return []
        try:
            completed = subprocess.run(
                ["getcap", "-r", "/"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.SubprocessError, PermissionError) as exc:
            return [
                Finding(
                    severity="info",
                    title="Unable to enumerate capabilities",
                    details=[f"getcap failed: {exc}"],
                )
            ]
        entries = completed.stdout.splitlines()
        findings: List[Finding] = []
        for line in entries:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" = ", 1)
            if len(parts) != 2:
                continue
            path, caps = parts
            severity = "warning"
            if any(flag in caps for flag in ("cap_dac_read_search", "cap_setuid", "cap_sys_admin")):
                severity = "critical"
            findings.append(
                Finding(
                    severity=severity,
                    title="Binary with elevated capabilities",
                    details=[f"{path} => {caps}"],
                    remediation="Review necessity of capabilities or drop them with setcap -r.",
                    exploit="Leverage capability to bypass DAC or escalate privileges.",
                )
            )
        return findings[:100]
