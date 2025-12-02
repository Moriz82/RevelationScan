"""Trumpet cross-referencing local service versions with CVE advisories."""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.feed import load_feed
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import is_version_vulnerable


@dataclass
class Advisory:
    cve: str
    fixed_version: str
    description: str
    remediation: str
    exploit: str | None = None


@dataclass
class ServiceSpec:
    name: str
    command: List[str]
    pattern: str
    advisories: List[Advisory]


class ServiceVersionTrumpet(Trumpet):
    slug = "service_versions"
    title = "Trumpet XI: Herald of Vulnerabilities"
    description = "Compare installed toolchain versions with CVE advisories from feeds or data files."

    def blow(self, context: ScanContext) -> List[Finding]:
        specs = self._load_specs(context)
        if not specs:
            return []
        findings: List[Finding] = []
        for spec in specs:
            output = self._run_command(spec.command)
            if output is None:
                continue
            installed = self._extract_version(output, spec.pattern)
            if installed is None:
                continue
            for advisory in spec.advisories:
                if is_version_vulnerable(installed, advisory.fixed_version):
                    findings.append(
                        Finding(
                            severity="critical",
                            title=f"{spec.name} may be vulnerable ({advisory.cve})",
                            details=[
                                f"Detected {spec.name} {installed} – fixed in {advisory.fixed_version}. {advisory.description}",
                            ],
                            cve=advisory.cve,
                            remediation=advisory.remediation,
                            exploit=advisory.exploit if context.suggest_exploits else None,
                        )
                    )
        return findings

    def _load_specs(self, context: ScanContext) -> List[ServiceSpec]:
        raw: Dict[str, object] | None = None
        # Attempt remote fetch if configured
        feed_url = context.config.get("cve_feed_url") if context.config else None
        if feed_url:
            try:
                with urllib.request.urlopen(str(feed_url), timeout=5) as response:  # nosec B310
                    raw = json.load(response)
            except (urllib.error.URLError, ValueError):
                raw = None
        if raw is None:
            raw = load_feed(context.cve_feed)
        services = raw.get("services", []) if isinstance(raw, dict) else []
        specs: List[ServiceSpec] = []
        for entry in services:
            if not isinstance(entry, dict):
                continue
            try:
                advisories = [
                    Advisory(
                        cve=adv["cve"],
                        fixed_version=adv["fixed_version"],
                        description=adv.get("description", ""),
                        remediation=adv.get("remediation", "Review vendor guidance."),
                        exploit=adv.get("exploit"),
                    )
                    for adv in entry.get("advisories", [])
                    if isinstance(adv, dict)
                ]
                specs.append(
                    ServiceSpec(
                        name=entry["name"],
                        command=list(entry["command"]),
                        pattern=entry["pattern"],
                        advisories=advisories,
                    )
                )
            except KeyError:
                continue
        return specs

    @staticmethod
    def _run_command(command: List[str]) -> str | None:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except FileNotFoundError:
            return None
        except (subprocess.SubprocessError, PermissionError):
            return None
        return (completed.stdout or "") + (completed.stderr or "")

    @staticmethod
    def _extract_version(output: str, pattern: str) -> str | None:
        import re

        match = re.search(pattern, output, re.IGNORECASE)
        if not match:
            return None
        return match.group(1)
