"""Trumpet assessing kernel hardening sysctl settings."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class KernelHardeningTrumpet(Trumpet):
    slug = "kernel_hardening"
    title = "Trumpet XVI: Ramparts of Zion"
    description = "Evaluate kernel sysctl flags tied to hardening and attack surface reduction."

    CHECKS = {
        Path("/proc/sys/kernel/randomize_va_space"): (
            "critical",
            "ASLR disabled",
            "Enable ASLR by setting kernel.randomize_va_space=2.",
            "2",
        ),
        Path("/proc/sys/kernel/kptr_restrict"): (
            "warning",
            "Kernel pointer exposure",
            "Set kernel.kptr_restrict=1 to hide kernel addresses from unprivileged users.",
            {"1", "2"},
        ),
        Path("/proc/sys/kernel/yama/ptrace_scope"): (
            "warning",
            "ptrace scope permissive",
            "Set kernel.yama.ptrace_scope=1 or higher to restrict cross-process debugging.",
            {"1", "2", "3"},
        ),
        Path("/proc/sys/kernel/modules_disabled"): (
            "info",
            "Kernel modules can be loaded",
            "Consider disabling module loading in hardened environments (modules_disabled=1).",
            {"1"},
        ),
        Path("/proc/sys/net/ipv4/ip_forward"): (
            "warning",
            "IPv4 forwarding enabled",
            "Disable ipv4 forwarding unless system acts as router (net.ipv4.ip_forward=0).",
            {"0"},
        ),
    }

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, (severity, title, remediation, expected) in self.CHECKS.items():
            value = self._read_value(path)
            if value is None:
                continue
            desired = expected
            if isinstance(desired, set):
                compliant = value in desired
            else:
                compliant = value == desired
            if not compliant:
                findings.append(
                    Finding(
                        severity=severity,
                        title=title,
                        details=[f"{path}: current={value}"],
                        remediation=remediation,
                    )
                )
        return findings

    @staticmethod
    def _read_value(path: Path) -> Optional[str]:
        try:
            return path.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None
