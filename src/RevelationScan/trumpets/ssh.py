"""Trumpet for SSH daemon configuration."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class SSHConfigTrumpet(Trumpet):
    slug = "ssh_config"
    title = "Trumpet VIII: Watchers at the Gate"
    description = "Report permissive sshd_config options."

    def blow(self, context: ScanContext) -> List[Finding]:
        config_path = Path("/etc/ssh/sshd_config")
        if not config_path.exists():
            return []
        try:
            lines = config_path.read_text(errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            return []
        settings: Dict[str, str] = {}
        for line in lines:
            trimmed = line.split("#", 1)[0].strip()
            if not trimmed:
                continue
            parts = trimmed.split(None, 1)
            if not parts:
                continue
            key = parts[0].lower()
            value = parts[1].strip().lower() if len(parts) > 1 else ""
            settings[key] = value
        findings: List[Finding] = []
        root_login = settings.get("permitrootlogin")
        if root_login == "yes":
            findings.append(
                Finding(
                    severity="critical",
                    title="SSH permits direct root login",
                    details=[f"PermitRootLogin {root_login}"],
                    remediation="Set PermitRootLogin prohibit-password or no and use sudo escalation instead.",
                )
            )
        elif root_login in {"without-password", "withoutpassword"}:
            findings.append(
                Finding(
                    severity="warning",
                    title="SSH root login allowed with keys",
                    details=[f"PermitRootLogin {root_login}"],
                    remediation="Consider disabling direct root SSH access entirely.",
                )
            )
        password_auth = settings.get("passwordauthentication")
        if password_auth == "yes":
            findings.append(
                Finding(
                    severity="warning",
                    title="SSH password authentication enabled",
                    details=["PasswordAuthentication yes"],
                    remediation="Set PasswordAuthentication no after ensuring key-based access is configured.",
                )
            )
        if settings.get("permitemptypasswords") == "yes":
            findings.append(
                Finding(
                    severity="critical",
                    title="SSH allows empty passwords",
                    details=["PermitEmptyPasswords yes"],
                    remediation="Set PermitEmptyPasswords no and audit user accounts.",
                )
            )
        return findings
