"""Trumpet examining package metadata freshness."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class PackageMetadataTrumpet(Trumpet):
    slug = "package_metadata"
    title = "Trumpet XII: Manna Freshness"
    description = "Warn when local package indices appear stale."

    apt_lists = Path("/var/lib/apt/lists")

    def blow(self, context: ScanContext) -> List[Finding]:
        if not self.apt_lists.exists():
            return []
        newest_mtime = None
        for path in self.apt_lists.glob("**/*"):
            if not path.is_file():
                continue
            try:
                mtime = path.stat().st_mtime
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if newest_mtime is None or mtime > newest_mtime:
                newest_mtime = mtime
        if newest_mtime is None:
            return []
        now = datetime.now(timezone.utc).timestamp()
        age_days = (now - newest_mtime) / 86400.0
        if age_days <= 30:
            return []
        return [
            Finding(
                severity="warning",
                title="APT package lists appear stale",
                details=[f"Last update about {int(age_days)} days ago"],
                remediation="Run 'apt update' (or distribution equivalent) to refresh vulnerability data.",
            )
        ]
