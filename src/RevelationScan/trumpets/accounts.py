"""Trumpet reviewing local accounts for privilege anomalies."""
from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class AccountsTrumpet(Trumpet):
    slug = "accounts"
    title = "Trumpet XVII: Census of the Faithful"
    description = "Inspect /etc/passwd for privileged or login-capable service accounts."

    passwd_path = Path("/etc/passwd")

    def blow(self, context: ScanContext) -> List[Finding]:
        if not self.passwd_path.exists():
            return []
        try:
            lines = self.passwd_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            return []
        findings: List[Finding] = []
        allowed_shells = {"/usr/sbin/nologin", "/bin/false", "", "/usr/bin/nologin"}
        for line in lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, gid, desc, home, shell = parts
            try:
                uid_int = int(uid)
            except ValueError:
                continue
            shell = shell.strip()
            if uid_int == 0 and user != "root":
                findings.append(
                    Finding(
                        severity="critical",
                        title="Additional UID 0 account",
                        details=[f"{user} ({desc}) shell={shell}"],
                        remediation="Remove extra UID 0 accounts or adjust UID to non-privileged value.",
                        exploit="Use alternate root account to bypass sudo policies.",
                    )
                )
                continue
            if uid_int >= 1000 and shell not in allowed_shells:
                if desc.lower().startswith("service"):
                    severity = "warning"
                else:
                    severity = "info"
                findings.append(
                    Finding(
                        severity=severity,
                        title="Interactive user account",
                        details=[f"{user} home={home} shell={shell}"],
                        remediation="Verify onboarding/offboarding and enforce strong credentials.",
                    )
                )
            if shell in {"/bin/sh", "/bin/bash"} and desc.lower().startswith("daemon"):
                findings.append(
                    Finding(
                        severity="warning",
                        title="Service account with interactive shell",
                        details=[f"{user} shell={shell}"],
                        remediation="Set shell to /usr/sbin/nologin for service accounts.",
                    )
                )
        return findings
