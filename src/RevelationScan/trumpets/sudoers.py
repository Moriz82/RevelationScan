# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the sudoers trumpet. This module will allow the application to:

# 1. Check sudoers files for insecure permissions

# 2. Analyze sudo -l output to find NOPASSWD commands

# 3. Flag commands that can be exploited for privilege escalation

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label

###########################################################################

"""

Name: SudoersTrumpet

Function: A trumpet that checks sudoers configuration and sudo permissions.

If users can run commands with sudo without a password, that's a security risk!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class SudoersTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "sudoers"
    ### Human-readable title
    title = "Sudo'able files"
    ### Description of what this trumpet does
    description = "Assess sudoers permissions and flag exploitable sudo -l entries."

    ### Path to the sudoers include directory
    include_dir = Path("/etc/sudoers.d")

    ### Dictionary of commands that can be exploited via GTFOBins (common privesc techniques)
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

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks sudoers files and sudo -l

    output. It combines findings from both checks.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing sudo security issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Check the sudoers include directory for permission issues
        findings.extend(self._check_include_directory())
        ### Analyze sudo -l output for exploitable commands
        findings.extend(self._analyze_sudo_list(context))
        ### Return all findings
        return findings

#$ End blow

    ###########################################################################

    """

    Name: _check_include_directory

    Function: Check files in /etc/sudoers.d for insecure permissions. These

    files should be owned by root and not writable by others!

    Arguments: None

    Returns: List of Finding objects for permission issues found

    """

    def _check_include_directory(self) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### If the directory doesn't exist or isn't a directory, return empty
        if not self.include_dir.exists() or not self.include_dir.is_dir():
            return findings
        try:
            ### Get all entries in the directory
            entries = sorted(self.include_dir.iterdir())
        except (PermissionError, OSError) as exc:
            ### If we can't read the directory, report it
            return [
                Finding(
                    severity="info",
                    title="Unable to inspect sudoers include directory",
                    details=[f"{self.include_dir}: {exc}"],
                )
            ]
        ### Check each entry
        for entry in entries:
            ### Skip hidden files
            if entry.name.startswith("."):
                continue
            try:
                ### Get file stats
                st = entry.stat()
            except (FileNotFoundError, PermissionError, OSError):
                ### If we can't stat it, skip it
                continue
            ### Skip directories
            if entry.is_dir():
                continue
            ### List to collect issues
            issues: List[str] = []
            severity = None
            ### Check if owned by non-root
            if st.st_uid != 0:
                severity = "critical"
                issues.append("owned by non-root user")
            ### Check if world-writable
            if st.st_mode & 0o002:
                severity = "critical"
                issues.append("world-writable")
            ### Check if group-writable
            elif st.st_mode & 0o020:
                severity = severity or "warning"
                issues.append("group-writable")
            ### If we found issues, create a finding
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
        ### Return all findings
        return findings

#$ End _check_include_directory

    ###########################################################################

    """

    Name: _analyze_sudo_list

    Function: Run sudo -l to see what commands the current user can run without

    a password. This is where the real security issues are!

    Arguments: context - the ScanContext object with config

    Returns: List of Finding objects for exploitable sudo commands found

    """

    def _analyze_sudo_list(self, context: ScanContext) -> List[Finding]:
        try:
            ### Run sudo -n -l (non-interactive, list commands)
            completed = subprocess.run(
                ["sudo", "-n", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            ### sudo command doesn't exist
            return []
        except (subprocess.SubprocessError, PermissionError) as exc:
            ### Command failed for some reason
            return [
                Finding(
                    severity="info",
                    title="sudo -l execution failed",
                    details=[str(exc)],
                )
            ]

        ### Get stdout and stderr
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        ### If sudo -l failed, report it
        if completed.returncode != 0:
            message = stderr or stdout or "sudo -l returned non-zero exit status"
            return [
                Finding(
                    severity="info",
                    title="sudo -l unavailable",
                    details=[message],
                )
            ]

        ### Extract NOPASSWD commands from the output
        commands = self._extract_nopasswd_commands(stdout)
        ### List to collect findings
        findings: List[Finding] = []
        ### Create a finding for each exploitable command
        for command in commands:
            findings.append(self._build_command_finding(command, context))
        ### Return all findings
        return findings

#$ End _analyze_sudo_list

    ###########################################################################

    """

    Name: _extract_nopasswd_commands

    Function: Parse sudo -l output to extract commands that can be run with

    NOPASSWD (without password). This is the dangerous stuff!

    Arguments: text - the stdout from sudo -l

    Returns: List of command strings that can be run without password

    """

    def _extract_nopasswd_commands(self, text: str) -> List[str]:
        ### List to collect all commands
        commands: List[str] = []
        ### Current list being built
        current: List[str] = []
        ### Flag to track if we're currently collecting commands
        collecting = False

        ### Process each line
        for raw_line in text.splitlines():
            line = raw_line.strip()
            ### Empty line means we're done collecting
            if not line:
                collecting = False
                continue

            ### If we see NOPASSWD, start collecting commands
            if "NOPASSWD:" in line:
                collecting = True
                ### Get everything after NOPASSWD:
                remainder = line.split("NOPASSWD:", 1)[1]
                current.extend(self._split_commands(remainder))
                continue

            ### If we're collecting, continue adding commands
            if collecting:
                ### Stop if we hit a new rule (pattern like "(ALL) :")
                if re.search(r"\(.*\).*:", line):
                    collecting = False
                    continue
                current.extend(self._split_commands(line))

        ### Add all collected commands to the final list
        for command in current:
            if command:
                commands.append(command)
        ### Return all commands found
        return commands

#$ End _extract_nopasswd_commands

    ###########################################################################

    """

    Name: _split_commands

    Function: Helper method to split a command string by commas and clean it up.

    Arguments: segment - string containing comma-separated commands

    Returns: List of cleaned command strings

    """

    @staticmethod
    def _split_commands(segment: str) -> List[str]:
        ### Remove backslashes (used for line continuation)
        cleaned = segment.replace("\\", "")
        ### Split by comma and strip whitespace
        return [item.strip() for item in cleaned.split(",") if item.strip()]

#$ End _split_commands

    ###########################################################################

    """

    Name: _build_command_finding

    Function: Create a Finding for a sudo command. If it's "ALL", that's critical!

    Otherwise, check if it's in GTFOBins for exploit hints.

    Arguments: command - the command that can be run with sudo

                context - the ScanContext object with config

    Returns: Finding object for this command

    """

    def _build_command_finding(self, command: str, context: ScanContext) -> Finding:
        ### If the command is "ALL", that's the worst case - full root access!
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

        ### Extract the binary name from the command
        bin_name = Path(command).name
        ### Check if we have exploit info for this command
        suggestion = self.GTFOBINS.get(bin_name)
        details = [f"NOPASSWD sudo access to {command}"]
        exploit = None
        ### If we have a suggestion, add it to details
        if suggestion:
            details.append(f"Common privesc: {suggestion['hint']}")
            ### If exploits are enabled, add the full exploit info
            if context.suggest_exploits:
                exploit = f"GTFOBins: {suggestion['hint']} ({suggestion['url']})"
        ### Otherwise, just suggest checking GTFOBins
        elif context.suggest_exploits:
            exploit = "Check GTFOBins for sudo escalation techniques."

        ### Return a finding for this command
        return Finding(
            severity="critical",
            title="NOPASSWD sudo command",
            details=details,
            remediation="Review sudoers entry and remove NOPASSWD or constrain execution.",
            exploit=exploit,
        )

#$ End _build_command_finding

#$ End SudoersTrumpet
