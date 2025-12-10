# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the listening ports trumpet. This module will allow the application to:

# 1. Enumerate all listening network ports on the system

# 2. Identify services that are exposed to all interfaces (0.0.0.0)

# 3. Highlight administrative ports that might be exposed

from __future__ import annotations

import re
import shutil
import subprocess
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: ListeningPortsTrumpet

Function: A trumpet that finds all listening network ports. It's like checking

what doors and windows are open on your house - you want to know what's exposed!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class ListeningPortsTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "listening_ports"
    ### Human-readable title
    title = "Network / Port Enumerating"
    ### Description of what this trumpet does
    description = "Enumerate listening network services and highlight broad exposure."

    ### Maximum number of rows to include in the output
    MAX_ROWS = 30
    ### Ports that are commonly used for administration (SSH, RDP, VNC, etc.)
    ADMIN_PORTS = {"22", "23", "3389", "5900"}

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that uses ss or netstat to find listening

    ports. It identifies services that are exposed to all interfaces (bad!).

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing network exposure issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Try to find a command we can use (ss or netstat)
        command = self._select_command()
        ### If neither is available, report it
        if command is None:
            return [
                Finding(
                    severity="info",
                    title="Unable to enumerate listening sockets",
                    details=["Neither ss nor netstat found on PATH"],
                )
            ]

        try:
            ### Run the command to get listening ports
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as exc:
            ### If it fails, report the error
            return [
                Finding(
                    severity="info",
                    title="Socket enumeration failed",
                    details=[f"{command}: {exc}"],
                )
            ]

        ### Get output from stdout or stderr (whichever has data)
        output = completed.stdout or completed.stderr
        ### List to store raw socket lines
        rows: List[str] = []
        ### List to store interesting ports we found
        interesting: List[str] = []
        ### Flag to track if we found services bound to all interfaces
        warning_detected = False

        ### Process each line of output
        for line in output.splitlines():
            ### Strip whitespace
            stripped = line.strip()
            ### Skip empty lines and header lines
            if not stripped or stripped.lower().startswith(("netid", "proto")):
                continue
            ### Split the line into parts
            parts = stripped.split()
            ### Need at least 5 parts to parse properly
            if len(parts) < 5:
                continue

            ### Extract protocol and local address
            proto = parts[0]
            local = parts[4]
            ### Sometimes the address is in a different position
            if local in {"*", "0"} and len(parts) > 5:
                local = parts[5]

            ### Try to extract the process name
            process = self._extract_process(stripped)
            ### Extract the port number from the address
            port = self._port_from_address(local)

            ### Check if service is bound to all interfaces (0.0.0.0 or [::])
            if any(bound in local for bound in ("0.0.0.0:", "[::]:")):
                warning_detected = True
                interesting.append(f"{port}:{process or proto}")
            ### Check if it's an admin port (SSH, RDP, etc.)
            elif port in self.ADMIN_PORTS:
                interesting.append(f"{port}:{process or proto}")

            ### Add this line to our rows list
            rows.append(stripped)
            ### If we've hit our limit, stop processing
            if len(rows) >= self.MAX_ROWS:
                break

        ### If we didn't find any rows, report it
        if not rows:
            return [
                Finding(
                    severity="info",
                    title="No listening sockets reported",
                    details=["Enumeration completed but produced no rows."],
                )
            ]

        ### Create a summary of interesting ports (remove duplicates)
        summary = ", ".join(sorted(dict.fromkeys(interesting))) if interesting else "none"
        ### Set severity based on whether we found services bound to all interfaces
        severity = "warning" if warning_detected else "info"
        ### Build the details list
        details = [
            f"Interesting ports: {summary}",
            "Raw sockets:",
            *[f"    {row}" for row in rows],
        ]

        ### Return a single finding with all the socket information
        return [
            Finding(
                severity=severity,
                title="Listening services overview",
                details=details,
                remediation="Limit exposure with firewalls or service binding when possible.",
            )
        ]

#$ End blow

    ###########################################################################

    """

    Name: _select_command

    Function: Helper method to find which command is available (ss or netstat).

    Prefers ss over netstat because it's more modern.

    Arguments: None

    Returns: List of command and arguments, or None if neither is available

    """

    @staticmethod
    def _select_command() -> list[str] | None:
        ### Try ss first (modern), then netstat (old but reliable)
        for candidate in (["ss", "-tulpn"], ["ss", "-tunlp"], ["netstat", "-tulpn"]):
            ### Check if the command exists
            if shutil.which(candidate[0]):
                return list(candidate)
        ### If neither is found, return None
        return None

#$ End _select_command

    ###########################################################################

    """

    Name: _port_from_address

    Function: Helper method to extract the port number from an address string.

    Arguments: address - address string like "0.0.0.0:22" or "[::]:80"

    Returns: Port number as a string

    """

    @staticmethod
    def _port_from_address(address: str) -> str:
        ### If there's no colon, assume the whole thing is the port
        if ":" not in address:
            return address
        ### Split from the right and take the last part (the port)
        return address.rsplit(":", 1)[-1] or address

#$ End _port_from_address

    ###########################################################################

    """

    Name: _extract_process

    Function: Helper method to extract the process name from ss/netstat output.

    It looks for patterns like "users:(process)" or "pid=1234".

    Arguments: line - a line from ss or netstat output

    Returns: Process name as a string, or empty string if not found

    """

    @staticmethod
    def _extract_process(line: str) -> str:
        ### Try to match "users:(process)" pattern
        match = re.search(r"users:\(([^)]+)\)", line)
        if match:
            ### Clean up the match and take the first part
            cleaned = match.group(1).replace('"', "").strip()
            return cleaned.split(",", 1)[0].strip()
        ### Try to match "pid=1234" pattern
        if "pid=" in line:
            tail = line.split("pid=", 1)[1]
            return tail.split(",", 1)[0].strip()
        ### If we can't find it, return empty string
        return ""

#$ End _extract_process

#$ End ListeningPortsTrumpet
