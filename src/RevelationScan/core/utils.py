# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the utils module. This module will allow the application to:

# 1. Manage state directories and file paths

# 2. Convert file modes and ownership info to human-readable formats

# 3. Load JSON resources from files

# 4. Compare version strings to check if they're vulnerable

# 5. Read configuration files

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, Dict, List

###########################################################################

"""

Name: state_dir

Function: Get the path to the application's state directory (where we store

cache files and such). Creates the directory if it doesn't exist.

Arguments: None

Returns: Path object pointing to the state directory

"""

def state_dir() -> Path:
    ### Build the path to ~/.cache/RevelationScan
    base = Path.home() / ".cache" / "RevelationScan"
    ### Create the directory and all parent directories if needed
    base.mkdir(parents=True, exist_ok=True)
    ### Return the path
    return base

#$ End state_dir

###########################################################################

"""

Name: user_feed_path

Function: Get the path to the user's CVE feed file (stored in the state directory).

Arguments: None

Returns: Path object pointing to the user feed file

"""

def user_feed_path() -> Path:
    ### Return the path to cve_feed.json in the state directory
    return state_dir() / "cve_feed.json"

#$ End user_feed_path

### Try to import pwd and grp modules (for looking up user/group names)
### These might not be available on all platforms (like Windows)
try:
    import grp
    import pwd
except ImportError:  # pragma: no cover
    ### If they're not available, set them to None
    grp = None  # type: ignore
    pwd = None  # type: ignore

###########################################################################

"""

Name: human_mode

Function: Convert a file mode integer to a human-readable string like "rwxr-xr-x".

If that fails, fall back to showing the octal representation.

Arguments: st_mode - the file mode integer from stat()

Returns: String representation of the file mode

"""

def human_mode(st_mode: int) -> str:
    try:
        ### Try to use stat.filemode to get a nice string like "rwxr-xr-x"
        return stat.filemode(st_mode)
    except Exception:
        ### If that fails, just show the octal representation of the permissions bits
        return oct(st_mode & 0o777)

#$ End human_mode

###########################################################################

"""

Name: owner_label

Function: Convert a UID and GID to a human-readable string with both names

and numeric IDs. Tries to look up the actual user/group names if possible.

Arguments: uid - user ID integer

            gid - group ID integer

Returns: String like "username(1000):groupname(1000)"

"""

def owner_label(uid: int, gid: int) -> str:
    ### Start with just the numeric IDs as strings
    user = str(uid)
    group = str(gid)
    ### If pwd module is available, try to look up the username
    if pwd is not None:
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            ### If lookup fails, just keep the numeric ID
            pass
    ### If grp module is available, try to look up the group name
    if grp is not None:
        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            ### If lookup fails, just keep the numeric ID
            pass
    ### Return a formatted string with both names and IDs
    return f"{user}({uid}):{group}({gid})"

#$ End owner_label

###########################################################################

"""

Name: load_json_resource

Function: Load a JSON file from a path and return the parsed data. Simple

and straightforward - just opens the file and parses it.

Arguments: path - path to the JSON file to load

Returns: Dictionary containing the parsed JSON data

"""

def load_json_resource(path: Path) -> Dict[str, Any]:
    ### Open the file and load the JSON
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)

#$ End load_json_resource

###########################################################################

"""

Name: load_json_resource_optional

Function: Load a JSON file if it exists, otherwise return an empty dictionary.

It's like load_json_resource, but it won't complain if the file doesn't exist.

Arguments: path - path to the JSON file to load (if it exists)

Returns: Dictionary containing the parsed JSON data, or empty dict if file doesn't exist

"""

def load_json_resource_optional(path: Path) -> Dict[str, Any]:
    ### If the file doesn't exist, return empty dict
    if not path.exists():
        return {}
    ### Otherwise, load it normally
    return load_json_resource(path)

#$ End load_json_resource_optional

###########################################################################

"""

Name: version_tokens

Function: Convert a version string into a list of comparable integers. This

allows us to compare versions like "1.2.3" vs "1.10.0" correctly. Numbers

stay as numbers, letters get converted to their position in the alphabet.

Arguments: version - version string to convert (like "1.2.3" or "1.9.5p2")

Returns: List of integers representing the version

"""

def version_tokens(version: str) -> List[int]:
    import re

    ### List to hold our converted tokens
    tokens: List[int] = []
    ### Find all sequences of digits or letters in the version string
    for piece in re.findall(r"\d+|[a-zA-Z]+", version):
        ### If it's all digits, convert to int
        if piece.isdigit():
            tokens.append(int(piece))
        else:
            ### If it's letters, convert each character to its alphabet position (a=1, b=2, etc.)
            for char in piece:
                tokens.append(ord(char.lower()) - 96)
    ### Return the list of tokens
    return tokens

#$ End version_tokens

###########################################################################

"""

Name: is_version_vulnerable

Function: Check if an installed version is vulnerable by comparing it to a

safe version. Returns True if installed < safe (meaning it's vulnerable).

Arguments: installed - the version string that's currently installed

            safe - the version string that fixes the vulnerability

Returns: Boolean - True if vulnerable, False if safe

"""

def is_version_vulnerable(installed: str, safe: str) -> bool:
    ### Convert both versions to token lists
    lhs = version_tokens(installed)
    rhs = version_tokens(safe)
    ### Find the longer list so we can pad the shorter one
    length = max(len(lhs), len(rhs))
    ### Pad both lists to the same length with zeros (so comparison works)
    lhs.extend([0] * (length - len(lhs)))
    rhs.extend([0] * (length - len(rhs)))
    ### Return True if installed version is less than safe version
    return lhs < rhs

#$ End is_version_vulnerable

###########################################################################

"""

Name: read_config

Function: Read a configuration file from a path. If no path is provided,

return an empty dict. If the file doesn't exist, raise an error.

Arguments: path - optional path to the config file

Returns: Dictionary containing the parsed config data

"""

def read_config(path: Path | None) -> Dict[str, Any]:
    ### If no path provided, return empty config
    if path is None:
        return {}
    ### If the file doesn't exist, complain loudly
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    ### Load and return the JSON config
    return load_json_resource(path)

#$ End read_config

###########################################################################

"""

Name: resolve_cve_feed

Function: Get the CVE feed path from the config dictionary. If it's not

in the config, return None.

Arguments: config - configuration dictionary

Returns: Path object or None if not configured

"""

def resolve_cve_feed(config: Dict[str, Any]) -> Path | None:
    ### Get the cve_feed setting from config
    feed = config.get("cve_feed")
    ### If it exists, convert to Path and expand ~ to home directory
    if feed:
        return Path(feed).expanduser()
    ### Otherwise, return None
    return None

#$ End resolve_cve_feed
