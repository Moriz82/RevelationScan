"""Trumpet enumerating cron configuration."""
from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label


class CronTrumpet(Trumpet):
    slug = "cron"
    title = "Trumpet VI: Timekeepers"
    description = "Review cron artifacts for permissive ownership or modes."

    TARGETS = [
        (Path("/etc/crontab"), "system crontab"),
        (Path("/etc/cron.allow"), "cron allow list"),
        (Path("/etc/cron.deny"), "cron deny list"),
        (Path("/etc/cron.d"), "cron.d directory"),
        (Path("/etc/cron.daily"), "daily jobs"),
        (Path("/etc/cron.hourly"), "hourly jobs"),
        (Path("/etc/cron.weekly"), "weekly jobs"),
        (Path("/etc/cron.monthly"), "monthly jobs"),
    ]

    LIMIT = 60

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for target, label in self.TARGETS:
            if not target.exists():
                continue
            try:
                st = target.stat()
            except (FileNotFoundError, PermissionError, OSError):
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
                        title="Insecure cron metadata",
                        details=[
                            f"{target} ({label}) owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)} - {', '.join(issues)}",
                        ],
                        remediation="Reset ownership to root:root and chmod 600/700 as appropriate.",
                    )
                )
                if len(findings) >= self.LIMIT:
                    return findings
            if target.is_dir():
                for entry in sorted(target.iterdir()):
                    if len(findings) >= self.LIMIT:
                        return findings
                    if entry.is_dir():
                        continue
                    try:
                        st_entry = entry.stat()
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
                    entry_issues: List[str] = []
                    entry_severity = None
                    if st_entry.st_uid != 0:
                        entry_severity = entry_severity or "warning"
                        entry_issues.append("owned by non-root user")
                    if st_entry.st_mode & 0o002:
                        entry_severity = "critical"
                        entry_issues.append("world-writable")
                    elif st_entry.st_mode & 0o020:
                        entry_severity = entry_severity or "warning"
                        entry_issues.append("group-writable")
                    if entry_issues:
                        findings.append(
                            Finding(
                                severity=entry_severity or "warning",
                                title="Cron job with weak permissions",
                                details=[
                                    f"{entry} owner {owner_label(st_entry.st_uid, st_entry.st_gid)} mode {human_mode(st_entry.st_mode)} - {', '.join(entry_issues)}",
                                ],
                                remediation="Ensure cron jobs are root-owned and not writable by untrusted users.",
                            )
                        )
        return findings
