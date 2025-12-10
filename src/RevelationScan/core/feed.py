# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the feed module. This module will allow the application to:

# 1. Define a default CVE feed with known vulnerabilities

# 2. Load CVE feed data from files or resources

# 3. Update CVE feeds from remote sources (like downloading from the internet)

# 4. Resolve where to get feed data from (config, args, or defaults)

from __future__ import annotations

import copy
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List

from importlib import resources

from RevelationScan import data as _data_pkg  # ensure package bundled

from .utils import user_feed_path

### Default CVE feed with some common vulnerabilities we know about
DEFAULT_FEED: Dict[str, object] = {
    "services": [
        {
            "name": "sudo",
            "command": ["sudo", "--version"],
            "pattern": "sudo version (\\d+\\.\\d+\\.\\d+p?\\d*)",
            "advisories": [
                {
                    "cve": "CVE-2021-3156",
                    "fixed_version": "1.9.5p2",
                    "description": "Heap-based overflow via sudoedit allows local privilege escalation.",
                    "remediation": "Upgrade sudo to 1.9.5p2 or later and redeploy across managed hosts.",
                    "exploit": "If vulnerable, edit /etc/passwd via sudoedit overflow to escalate to root.",
                }
            ],
        },
        {
            "name": "openssl",
            "command": ["openssl", "version"],
            "pattern": "OpenSSL (\\d+\\.\\d+\\.\\d+[a-z]?)",
            "advisories": [
                {
                    "cve": "CVE-2021-3450",
                    "fixed_version": "1.1.1k",
                    "description": "Improper certificate verification permits CA bypass.",
                    "remediation": "Upgrade OpenSSL to 1.1.1k or newer and restart dependent services.",
                    "exploit": "With crafted certificates, MITM traffic to services trusting the flawed CA chain.",
                }
            ],
        },
        {
            "name": "bash",
            "command": ["bash", "--version"],
            "pattern": "GNU bash, version (\\d+\\.\\d+(?:\\.\\d+)?)",
            "advisories": [
                {
                    "cve": "CVE-2014-6271",
                    "fixed_version": "4.4",
                    "description": "Shellshock allows environment variable code injection.",
                    "remediation": "Patch Bash to 4.4 or later and restart exposed services.",
                    "exploit": "Send crafted headers to CGI scripts to execute arbitrary commands.",
                }
            ],
        },
    ]
}

#$ End DEFAULT_FEED

###########################################################################

"""

Name: _default_feed

Function: Return a deep copy of the default feed. We use deepcopy so we don't

accidentally modify the original (because that would be bad).

Arguments: None

Returns: Dictionary containing the default CVE feed data

"""

def _default_feed() -> Dict[str, object]:
    ### Make a deep copy so we don't mess with the original
    return copy.deepcopy(DEFAULT_FEED)

#$ End _default_feed

###########################################################################

"""

Name: load_feed

Function: Load CVE feed data from a file path, or from the package resources if

no path is provided. If loading fails, fall back to the default feed.

Arguments: path - optional path to a feed file, or None to use package resources

Returns: Dictionary containing the CVE feed data

"""

def load_feed(path: Path | None = None) -> Dict[str, object]:
    ### If no path was provided, try to load from package resources
    if path is None:
        try:
            ### Get the cve_feed.json file from the package data
            resource = resources.files(_data_pkg).joinpath("cve_feed.json")
            ### Open it and load the JSON
            with resource.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (FileNotFoundError, ModuleNotFoundError):
            ### If that fails, use the default feed
            return _default_feed()
    ### If a path was provided, try to load from that file
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        ### If the file doesn't exist, fall back to default feed
        return _default_feed()

#$ End load_feed

###########################################################################

"""

Name: update_feed

Function: Download CVE feed data from remote URLs and merge them together into

a single feed file. It's like going shopping at multiple stores and combining

all your purchases into one bag.

Arguments: target - path where we want to save the merged feed

            sources - iterable of URLs to download feeds from

Returns: Tuple of (success boolean, list of error messages)

"""

def update_feed(target: Path, sources: Iterable[str]) -> tuple[bool, List[str]]:
    ### List to collect any errors we encounter
    errors: List[str] = []
    ### Start with an empty merged feed
    merged: Dict[str, object] = {"services": []}
    ### Index to track services by name (so we can merge duplicates)
    service_index: Dict[str, Dict[str, object]] = {}
    ### Flag to track if we successfully downloaded at least one feed
    had_success = False

    ### Loop through each URL and try to download it
    for url in sources:
        try:
            ### Open the URL with a 10 second timeout (don't wait forever!)
            with urllib.request.urlopen(url, timeout=10) as response:  # nosec B310
                payload = json.load(response)
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            ### If downloading fails, add to errors and move on
            errors.append(f"{url}: {exc}")
            continue
        ### Extract the services array from the payload
        services = payload.get("services") if isinstance(payload, dict) else None
        ### Make sure it's actually a list
        if not isinstance(services, list):
            errors.append(f"{url}: missing 'services' array")
            continue
        ### Mark that we had at least one success
        had_success = True
        ### Process each service entry
        for entry in services:
            ### Skip invalid entries
            if not isinstance(entry, dict) or "name" not in entry:
                continue
            name = entry["name"]
            ### Check if we've seen this service before
            existing = service_index.get(name)
            if existing is None:
                ### New service, so add it to our merged feed
                result = {
                    "name": name,
                    "command": entry.get("command", []),
                    "pattern": entry.get("pattern", ""),
                    "advisories": entry.get("advisories", []),
                }
                merged["services"].append(result)
                service_index[name] = result
            else:
                ### Service already exists, so merge the advisories
                existing_adv = {adv.get("cve"): adv for adv in existing.get("advisories", []) if isinstance(adv, dict)}
                for adv in entry.get("advisories", []):
                    ### Skip invalid advisories
                    if not isinstance(adv, dict) or "cve" not in adv:
                        continue
                    ### Add or update the advisory by CVE ID
                    existing_adv[adv["cve"]] = adv
                existing["advisories"] = list(existing_adv.values())
                ### Update command and pattern if provided
                if entry.get("command"):
                    existing["command"] = entry["command"]
                if entry.get("pattern"):
                    existing["pattern"] = entry["pattern"]

    ### If we had any success, save the merged feed to the target file
    if had_success:
        ### Make sure the directory exists
        target.parent.mkdir(parents=True, exist_ok=True)
        ### Write the merged feed as pretty JSON
        with target.open("w", encoding="utf-8") as handle:
            json.dump(merged, handle, indent=2)
            handle.write("\n")
    ### Return whether we succeeded and any errors we collected
    return had_success, errors

#$ End update_feed

###########################################################################

"""

Name: resolve_update_sources

Function: Figure out where to get CVE feed update sources from. Check override

first, then config, or return empty list if nothing is configured.

Arguments: config - configuration dictionary

            override - optional comma-separated string of URLs to override config

Returns: List of URL strings to use as update sources

"""

def resolve_update_sources(config: Dict[str, object], override: str | None) -> List[str]:
    ### If override is provided, use that (split by commas and strip whitespace)
    if override:
        return [item.strip() for item in override.split(",") if item.strip()]
    ### Otherwise, check the config for update_sources
    sources = config.get("update_sources") if config else None
    ### If it's a list of strings, return them
    if isinstance(sources, list):
        return [str(item) for item in sources if isinstance(item, str)]
    ### If nothing is configured, return empty list
    return []

#$ End resolve_update_sources

###########################################################################

"""

Name: compute_target_feed

Function: Figure out where the CVE feed file should be located. Check command

line args first, then config, then fall back to user's default location.

Arguments: args_cve_feed - optional path from command line arguments

            config - configuration dictionary

Returns: Path object pointing to where the feed file should be

"""

def compute_target_feed(args_cve_feed: Path | None, config: Dict[str, object]) -> Path:
    ### If a path was provided as an argument, use that (expand ~ to home dir)
    if args_cve_feed:
        return args_cve_feed.expanduser()
    ### Otherwise, check config for cve_feed setting
    feed = config.get("cve_feed")
    ### If it's a string, convert it to a Path and expand ~
    if isinstance(feed, str):
        return Path(feed).expanduser()
    ### Last resort: use the default user feed path
    return user_feed_path()

#$ End compute_target_feed
