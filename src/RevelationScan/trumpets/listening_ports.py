"""Trumpet enumerating listening network services."""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding


class ListeningPortsTrumpet(Trumpet):
    slug = "listening_ports"
    title = "Trumpet XIII: Watchmen on the Wall"
    description = "Enumerate listening network services and highlight broad exposure."

    MAX_ROWS = 30
    ADMIN_PORTS = {"22", "23", "3389", "5900"}

    def blow(self, context: ScanContext) -> List[Finding]:
        command = self._select_command()
        if command is None:
            return [
                Finding(
                    severity="info",
                    title="Unable to enumerate listening sockets",
                    details=["Neither ss nor netstat found on PATH"],
                )
            ]

        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as exc:
            return [
                Finding(
                    severity="info",
                    title="Socket enumeration failed",
                    details=[f"{command}: {exc}"],
                )
            ]

        output = completed.stdout or completed.stderr
        rows: List[str] = []
        interesting: List[str] = []
        warning_detected = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(("netid", "proto")):
                continue
            parts = stripped.split()
            if len(parts) < 5:
                continue

            proto = parts[0]
            local = parts[4]
            if local in {"*", "0"} and len(parts) > 5:
                local = parts[5]

            process = self._extract_process(stripped)
            port = self._port_from_address(local)

            if any(bound in local for bound in ("0.0.0.0:", "[::]:")):
                warning_detected = True
                interesting.append(f"{port}:{process or proto}")
            elif port in self.ADMIN_PORTS:
                interesting.append(f"{port}:{process or proto}")

            rows.append(stripped)
            if len(rows) >= self.MAX_ROWS:
                break

        if not rows:
            return [
                Finding(
                    severity="info",
                    title="No listening sockets reported",
                    details=["Enumeration completed but produced no rows."],
                )
            ]

        summary = ", ".join(sorted(dict.fromkeys(interesting))) if interesting else "none"
        severity = "warning" if warning_detected else "info"
        details = [
            f"Interesting ports: {summary}",
            "Raw sockets:",
            *[f"    {row}" for row in rows],
        ]

        return [
            Finding(
                severity=severity,
                title="Listening services overview",
                details=details,
                remediation="Limit exposure with firewalls or service binding when possible.",
            )
        ]

    @staticmethod
    def _select_command() -> list[str] | None:
        for candidate in (["ss", "-tulpn"], ["ss", "-tunlp"], ["netstat", "-tulpn"]):
            if shutil.which(candidate[0]):
                return list(candidate)
        return None

    @staticmethod
    def _port_from_address(address: str) -> str:
        if ":" not in address:
            return address
        return address.rsplit(":", 1)[-1] or address

    @staticmethod
    def _extract_process(line: str) -> str:
        match = re.search(r"users:\(([^)]+)\)", line)
        if match:
            cleaned = match.group(1).replace('"', "").strip()
            return cleaned.split(",", 1)[0].strip()
        if "pid=" in line:
            tail = line.split("pid=", 1)[1]
            return tail.split(",", 1)[0].strip()
        return ""
