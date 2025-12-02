"""Utility helpers shared across trumpets."""
from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, Dict, List


def state_dir() -> Path:
    base = Path.home() / ".cache" / "RevelationScan"
    base.mkdir(parents=True, exist_ok=True)
    return base


def user_feed_path() -> Path:
    return state_dir() / "cve_feed.json"

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover
    grp = None  # type: ignore
    pwd = None  # type: ignore


def human_mode(st_mode: int) -> str:
    try:
        return stat.filemode(st_mode)
    except Exception:
        return oct(st_mode & 0o777)


def owner_label(uid: int, gid: int) -> str:
    user = str(uid)
    group = str(gid)
    if pwd is not None:
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    if grp is not None:
        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            pass
    return f"{user}({uid}):{group}({gid})"


def load_json_resource(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_json_resource_optional(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return load_json_resource(path)


def version_tokens(version: str) -> List[int]:
    import re

    tokens: List[int] = []
    for piece in re.findall(r"\d+|[a-zA-Z]+", version):
        if piece.isdigit():
            tokens.append(int(piece))
        else:
            for char in piece:
                tokens.append(ord(char.lower()) - 96)
    return tokens


def is_version_vulnerable(installed: str, safe: str) -> bool:
    lhs = version_tokens(installed)
    rhs = version_tokens(safe)
    length = max(len(lhs), len(rhs))
    lhs.extend([0] * (length - len(lhs)))
    rhs.extend([0] * (length - len(rhs)))
    return lhs < rhs


def read_config(path: Path | None) -> Dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return load_json_resource(path)


def resolve_cve_feed(config: Dict[str, Any]) -> Path | None:
    feed = config.get("cve_feed")
    if feed:
        return Path(feed).expanduser()
    return None
