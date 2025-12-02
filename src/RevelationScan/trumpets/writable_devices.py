"""Trumpet scanning device nodes for weak permissions."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label


class WritableDevicesTrumpet(Trumpet):
    slug = "writable_devices"
    title = "Trumpet XV: Watchers of the Forge"
    description = "Identify world-writable device nodes that could grant direct hardware access."

    ROOT = Path("/dev")
    LIMIT = 80
    BASELINE = {
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
        "/dev/ptmx",
        "/dev/net/tun",
    }

    def blow(self, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        for root, _, filenames in os.walk(self.ROOT, followlinks=False):
            for name in filenames:
                path = Path(root) / name
                if len(findings) >= self.LIMIT:
                    return findings
                try:
                    st = path.lstat()
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if not stat.S_ISCHR(st.st_mode) and not stat.S_ISBLK(st.st_mode):
                    continue
                if st.st_mode & 0o002:
                    canonical = str(path)
                    severity = "critical" if stat.S_ISCHR(st.st_mode) else "warning"
                    if canonical in self.BASELINE:
                        severity = "info"
                    elif "nvidia" in canonical or "dri" in canonical or "fuse" in canonical:
                        severity = "warning"
                    elif "vhost" in canonical:
                        severity = "warning"
                    findings.append(
                        Finding(
                            severity=severity,
                            title="World-writable device node",
                            details=[
                                f"{path} owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)}",
                            ],
                            remediation="Restrict device permissions or remove unneeded device nodes.",
                        )
                    )
        return findings
