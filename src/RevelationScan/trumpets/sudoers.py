"""Trumpet reviewing sudoers fragments and sudo -l output."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label


class SudoersTrumpet(Trumpet):
    slug = "sudoers"
    title = "Trumpet IV: Guardians of Sudo"
    description = "Assess sudoers permissions and flag exploitable sudo -l entries."

    include_dir = Path("/etc/sudoers.d")

    GTFOBINS: Dict[str, Dict[str, str]] = {
        "awk": {"hint": "sudo awk 'BEGIN {system(\"/bin/sh\")}'", "url": "https://gtfobins.github.io/gtfobins/awk/"},
        "bash": {"hint": "sudo bash", "url": "https://gtfobins.github.io/gtfobins/bash/"},
        "cat": {"hint": "sudo cat /root/.ssh/id_rsa", "url": "https://gtfobins.github.io/gtfobins/cat/"},
        "cp": {"hint": "sudo cp /bin/sh /tmp/shell && sudo chmod +s /tmp/shell", "url": "https://gtfobins.github.io/gtfobins/cp/"},
        "docker": {"hint": "sudo docker run -v /:/host -it alpine chroot /host /bin/sh", "url": "https://gtfobins.github.io/gtfobins/docker/"},
        "find": {"hint": "sudo find . -exec /bin/sh \\;", "url": "https://gtfobins.github.io/gtfobins/find/"},
        "less": {"hint": "sudo less /etc/passwd !/bin/sh", "url": "https://gtfobins.github.io/gtfobins/less/"},
        "nano": {"hint": "sudo nano /etc/passwd then ^R^X to exec commands", "url": "https://gtfobins.github.io/gtfobins/nano/"},
        "nmap": {"hint": "sudo nmap --interactive", "url": "https://gtfobins.github.io/gtfobins/nmap/"},
        "perl": {"hint": "sudo perl -e 'exec \"/bin/sh\";'", "url": "https://gtfobins.github.io/gtfobins/perl/"},
        "pip": {"hint": "sudo pip install . --user --upgrade", "url": "https://gtfobins.github.io/gtfobins/pip/"},
        "python": {"hint": "sudo python -c 'import os; os.system(\"/bin/sh\")'", "url": "https://gtfobins.github.io/gtfobins/python/"},
        "python3": {"hint": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'", "url": "https://gtfobins.github.io/gtfobins/python/"},
        "rsync": {"hint": "sudo rsync -e sh localhost:/root/.ssh/id_rsa /tmp", "url": "https://gtfobins.github.io/gtfobins/rsync/"},
        "tar": {"hint": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", "url": "https://gtfobins.github.io/gtfobins/tar/"},
        "vim": {"hint": "sudo vim -c ':!/bin/sh'", "url": "https://gtfobins.github.io/gtfobins/vim/"},
        "zip": {"hint": "sudo zip foo.zip /tmp -T --unzip-command='sh -c /bin/sh'", "url": "https://gtfobins.github.io/gtfobins/zip/"},
    }

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_include_directory())
        findings.extend(self._analyze_sudo_list(context))
        return findings

    def _check_include_directory(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.include_dir.exists() or not self.include_dir.is_dir():
            return findings
        try:
            entries = sorted(self.include_dir.iterdir())
        except (PermissionError, OSError) as exc:
            return [
                Finding(
                    severity="info",
                    title="Unable to inspect sudoers include directory",
                    details=[f"{self.include_dir}: {exc}"],
                )
            ]
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                st = entry.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if entry.is_dir():
                continue
            issues: List[str] = []
            severity = None
            if st.st_uid != 0:
                severity = "critical"
                issues.append("owned by non-root user")
            if st.st_mode & 0o002:
                severity = "critical"
                issues.append("world-writable")
            elif st.st_mode & 0o020:
                severity = severity or "warning"
                issues.append("group-writable")
            if issues:
                findings.append(
                    Finding(
                        severity=severity or "warning",
                        title="Risky sudoers include file",
                        details=[
                            f"{entry} owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)} - {', '.join(issues)}",
                        ],
                        remediation="Fix ownership/mode and validate sudoers syntax with 'visudo -c'.",
                    )
                )
        return findings

    def _analyze_sudo_list(self, context: ScanContext) -> List[Finding]:
        try:
            completed = subprocess.run(
                ["sudo", "-n", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            return []
        except (subprocess.SubprocessError, PermissionError) as exc:
            return [
                Finding(
                    severity="info",
                    title="sudo -l execution failed",
                    details=[str(exc)],
                )
            ]

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        if completed.returncode != 0:
            message = stderr or stdout or "sudo -l returned non-zero exit status"
            return [
                Finding(
                    severity="info",
                    title="sudo -l unavailable",
                    details=[message],
                )
            ]

        commands = self._extract_nopasswd_commands(stdout)
        findings: List[Finding] = []
        for command in commands:
            findings.append(self._build_command_finding(command, context))
        return findings

    def _extract_nopasswd_commands(self, text: str) -> List[str]:
        commands: List[str] = []
        current: List[str] = []
        collecting = False

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                collecting = False
                continue

            if "NOPASSWD:" in line:
                collecting = True
                remainder = line.split("NOPASSWD:", 1)[1]
                current.extend(self._split_commands(remainder))
                continue

            if collecting:
                if re.search(r"\(.*\).*:", line):
                    collecting = False
                    continue
                current.extend(self._split_commands(line))

        for command in current:
            if command:
                commands.append(command)
        return commands

    @staticmethod
    def _split_commands(segment: str) -> List[str]:
        cleaned = segment.replace("\\", "")
        return [item.strip() for item in cleaned.split(",") if item.strip()]

    def _build_command_finding(self, command: str, context: ScanContext) -> Finding:
        if command.upper() == "ALL":
            details = ["User may run ALL commands as root without a password."]
            exploit_hint = "sudo -n /bin/bash"
            return Finding(
                severity="critical",
                title="NOPASSWD sudo access to ALL commands",
                details=details,
                remediation="Remove NOPASSWD:ALL or restrict to specific commands.",
                exploit=exploit_hint if context.suggest_exploits else None,
            )

        bin_name = Path(command).name
        suggestion = self.GTFOBINS.get(bin_name)
        details = [f"NOPASSWD sudo access to {command}"]
        exploit = None
        if suggestion:
            details.append(f"Common privesc: {suggestion['hint']}")
            if context.suggest_exploits:
                exploit = f"GTFOBins: {suggestion['hint']} ({suggestion['url']})"
        elif context.suggest_exploits:
            exploit = "Check GTFOBins for sudo escalation techniques."

        return Finding(
            severity="critical",
            title="NOPASSWD sudo command",
            details=details,
            remediation="Review sudoers entry and remove NOPASSWD or constrain execution.",
            exploit=exploit,
        )
