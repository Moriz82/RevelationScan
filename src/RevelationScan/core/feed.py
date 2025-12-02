"""Feed management utilities."""
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


def _default_feed() -> Dict[str, object]:
    return copy.deepcopy(DEFAULT_FEED)


def load_feed(path: Path | None = None) -> Dict[str, object]:
    if path is None:
        try:
            resource = resources.files(_data_pkg).joinpath("cve_feed.json")
            with resource.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (FileNotFoundError, ModuleNotFoundError):
            return _default_feed()
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return _default_feed()


def update_feed(target: Path, sources: Iterable[str]) -> tuple[bool, List[str]]:
    errors: List[str] = []
    merged: Dict[str, object] = {"services": []}
    service_index: Dict[str, Dict[str, object]] = {}
    had_success = False

    for url in sources:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:  # nosec B310
                payload = json.load(response)
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            errors.append(f"{url}: {exc}")
            continue
        services = payload.get("services") if isinstance(payload, dict) else None
        if not isinstance(services, list):
            errors.append(f"{url}: missing 'services' array")
            continue
        had_success = True
        for entry in services:
            if not isinstance(entry, dict) or "name" not in entry:
                continue
            name = entry["name"]
            existing = service_index.get(name)
            if existing is None:
                result = {
                    "name": name,
                    "command": entry.get("command", []),
                    "pattern": entry.get("pattern", ""),
                    "advisories": entry.get("advisories", []),
                }
                merged["services"].append(result)
                service_index[name] = result
            else:
                existing_adv = {adv.get("cve"): adv for adv in existing.get("advisories", []) if isinstance(adv, dict)}
                for adv in entry.get("advisories", []):
                    if not isinstance(adv, dict) or "cve" not in adv:
                        continue
                    existing_adv[adv["cve"]] = adv
                existing["advisories"] = list(existing_adv.values())
                if entry.get("command"):
                    existing["command"] = entry["command"]
                if entry.get("pattern"):
                    existing["pattern"] = entry["pattern"]

    if had_success:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(merged, handle, indent=2)
            handle.write("\n")
    return had_success, errors


def resolve_update_sources(config: Dict[str, object], override: str | None) -> List[str]:
    if override:
        return [item.strip() for item in override.split(",") if item.strip()]
    sources = config.get("update_sources") if config else None
    if isinstance(sources, list):
        return [str(item) for item in sources if isinstance(item, str)]
    return []


def compute_target_feed(args_cve_feed: Path | None, config: Dict[str, object]) -> Path:
    if args_cve_feed:
        return args_cve_feed.expanduser()
    feed = config.get("cve_feed")
    if isinstance(feed, str):
        return Path(feed).expanduser()
    return user_feed_path()
