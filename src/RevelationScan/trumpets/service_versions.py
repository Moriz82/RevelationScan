# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the service versions trumpet. This module will allow the application to:

# 1. Check installed service versions against CVE advisories

# 2. Run version commands to detect what's installed

# 3. Compare versions to see if they're vulnerable

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

###########################################################################

"""

Name: Advisory

Function: A data class that represents a CVE advisory. It contains information

about a vulnerability and how to fix it.

Arguments: None (it's a dataclass)

Returns: No value returned

"""

@dataclass
class Advisory:
    ### CVE identifier (like "CVE-2021-3156")
    cve: str
    ### Version that fixes the vulnerability
    fixed_version: str
    ### Description of the vulnerability
    description: str
    ### How to fix it
    remediation: str
    ### Optional exploit information
    exploit: str | None = None

#$ End Advisory

###########################################################################

"""

Name: ServiceSpec

Function: A data class that represents a service to check. It contains the

command to run, pattern to extract version, and list of advisories.

Arguments: None (it's a dataclass)

Returns: No value returned

"""

@dataclass
class ServiceSpec:
    ### Name of the service (like "sudo" or "openssl")
    name: str
    ### Command to run to get version (like ["sudo", "--version"])
    command: List[str]
    ### Regex pattern to extract version from command output
    pattern: str
    ### List of advisories for this service
    advisories: List[Advisory]

#$ End ServiceSpec


###########################################################################

"""

Name: ServiceVersionTrumpet

Function: A trumpet that checks service versions against CVE advisories. It

runs version commands, extracts versions, and compares them to known vulnerabilities.

Arguments: None (it's a class definition)

Returns: No value returned

"""

class ServiceVersionTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "service_versions"
    ### Human-readable title
    title = "Service Versions / CVE advisories"
    ### Description of what this trumpet does
    description = "Compare installed toolchain versions with CVE advisories from feeds or data files."

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that loads service specs, runs version

    commands, and checks for vulnerabilities. It's like checking if your software

    is up to date, but for security!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing vulnerable services found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Load the service specifications from the feed
        specs = self._load_specs(context)
        ### If we don't have any specs, we can't check anything
        if not specs:
            return []
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each service spec
        for spec in specs:
            ### Run the version command
            output = self._run_command(spec.command)
            ### If the command failed, skip this service
            if output is None:
                continue
            ### Extract the version from the output
            installed = self._extract_version(output, spec.pattern)
            ### If we couldn't extract a version, skip it
            if installed is None:
                continue
            ### Check each advisory for this service
            for advisory in spec.advisories:
                ### Check if the installed version is vulnerable
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
        ### Return all findings we collected
        return findings

#$ End blow

    ###########################################################################

    """

    Name: _load_specs

    Function: Load service specifications from the CVE feed. Tries remote URL

    first if configured, then falls back to local feed file.

    Arguments: context - the ScanContext object with config

    Returns: List of ServiceSpec objects

    """

    def _load_specs(self, context: ScanContext) -> List[ServiceSpec]:
        raw: Dict[str, object] | None = None
        ### Try to fetch from remote URL if configured
        feed_url = context.config.get("cve_feed_url") if context.config else None
        if feed_url:
            try:
                ### Download the feed from the URL
                with urllib.request.urlopen(str(feed_url), timeout=5) as response:  # nosec B310
                    raw = json.load(response)
            except (urllib.error.URLError, ValueError):
                ### If download fails, set to None to use local feed
                raw = None
        ### If we don't have remote feed, load from local file
        if raw is None:
            raw = load_feed(context.cve_feed)
        ### Extract the services list from the feed
        services = raw.get("services", []) if isinstance(raw, dict) else []
        ### List to collect service specs
        specs: List[ServiceSpec] = []
        ### Process each service entry
        for entry in services:
            ### Skip invalid entries
            if not isinstance(entry, dict):
                continue
            try:
                ### Build list of advisories for this service
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
                ### Create a ServiceSpec and add it to our list
                specs.append(
                    ServiceSpec(
                        name=entry["name"],
                        command=list(entry["command"]),
                        pattern=entry["pattern"],
                        advisories=advisories,
                    )
                )
            except KeyError:
                ### If required fields are missing, skip this entry
                continue
        ### Return all the specs we built
        return specs

#$ End _load_specs

    ###########################################################################

    """

    Name: _run_command

    Function: Helper method to run a command and get its output. Returns None

    if the command fails or doesn't exist.

    Arguments: command - list of command and arguments to run

    Returns: Command output as string, or None if it failed

    """

    @staticmethod
    def _run_command(command: List[str]) -> str | None:
        try:
            ### Run the command with a 5 second timeout
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except FileNotFoundError:
            ### Command doesn't exist
            return None
        except (subprocess.SubprocessError, PermissionError):
            ### Command failed for some reason
            return None
        ### Return combined stdout and stderr
        return (completed.stdout or "") + (completed.stderr or "")

#$ End _run_command

    ###########################################################################

    """

    Name: _extract_version

    Function: Helper method to extract version string from command output using

    a regex pattern. The pattern should have a capture group for the version.

    Arguments: output - the command output string

                pattern - regex pattern with capture group for version

    Returns: Version string, or None if not found

    """

    @staticmethod
    def _extract_version(output: str, pattern: str) -> str | None:
        import re

        ### Search for the pattern in the output (case-insensitive)
        match = re.search(pattern, output, re.IGNORECASE)
        ### If no match, return None
        if not match:
            return None
        ### Return the first capture group (the version)
        return match.group(1)

#$ End _extract_version

#$ End ServiceVersionTrumpet
