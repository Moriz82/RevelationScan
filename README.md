# Revelation Scan

Revelation Scan is a modular, self-contained Linux security reconnaissance tool inspired by the depth of linPEAS. It focuses on misconfiguration discovery inside controlled lab environments for ethical security research.

## Highlights
- Pure Python standard library – no third-party dependencies for runtime or scanning.
- “Trumpet” module architecture: each check is a class that can be extended or replaced via plugins.
- Colorized, animated console experience with an ASCII banner on first launch plus optional JSON reporting.
- Expanded reconnaissance trumpets inspired by linPEAS: PATH hygiene, cron, sudoers, listening services, kernel hardening, device permissions, capabilities, and more.
- Configurable CVE/service version trumpet that ingests JSON feeds (local or remote) to stay current without code changes; `--update-feed` fetches fresh data.
- Optional exploit suggestions and remediation hints per finding.
- Build scripts and helper for `.pyz` archives or fully self-contained ELF binaries.

## Quickstart
```bash
cd RevelationScan
make run                         # run all trumpets with default settings
make run ARGS="--list-trumpets"  # enumerate available trumpets
make run ARGS="--trumpets path_hygiene,ssh_config"  # selective execution
```

## Configuration
- `--config`: path to a JSON file with keys such as `cve_feed` (local file), `cve_feed_url`, or `update_sources` (array of feed URLs).
- `--cve-feed`: override path to CVE feed without editing the config file (stored in `~/.cache/RevelationScan` when combined with `--update-feed`).
- `--cve-feed-url`: supply a URL (or comma-delimited list) for fetching CVE data.
- `--update-feed`: pull down remote feeds and merge them into your local cache before scanning.
- `--plugin-dir`: supply custom trumpet implementations; any class inheriting `Trumpet` will be auto-registered.
- `--output` and `--format {text,json}`: write reports to disk.
- `--suggest-exploits`: include exploit ideas from the CVE feed.
- `--no-color`: disable ANSI styling/spinner for log capture or headless use.

The default CVE feed lives at `src/RevelationScan/data/cve_feed.json`. Update or replace this file, or run `--update-feed` with your own sources, to keep pace with new advisories.

## Packaging
```bash
make bundle           # creates dist/RevelationScan.pyz (requires Python on target)
make binary           # requires pyinstaller, outputs dist/revelation-scan (no Python on target)
./build_binary.sh     # builds an ELF via isolated PyInstaller workflow
```

## Plugins
Drop a Python file that defines one or more subclasses of `Trumpet` into a directory and run:
```bash
make run ARGS="--plugin-dir /path/to/trumpets --trumpets new_trumpet"
```
Each plugin can import shared utilities from `RevelationScan.core` for consistency.

## Data Feed Schema
A CVE feed is a JSON object with a `services` array. Each service requires:
```json
{
  "name": "sudo",
  "command": ["sudo", "--version"],
  "pattern": "sudo version (\\d+\\.\\d+\\.\\d+p?\\d*)",
  "advisories": [
    {
      "cve": "CVE-2021-3156",
      "fixed_version": "1.9.5p2",
      "description": "Heap overflow...",
      "remediation": "Upgrade sudo...",
      "exploit": "(optional)"
    }
  ]
}
```
This format lets you sync with NVD/NIST exports, Exploit DB mirrors, or bespoke lab datasets without modifying Revelation Scan itself. Combine multiple URLs via `--cve-feed-url url1,url2` and run `--update-feed` to merge into your personal cache under `~/.cache/RevelationScan/cve_feed.json`.

## Ethics
Use Revelation Scan only inside authorized lab or sandbox environments. Many trumpets highlight misconfigurations that, if exploited without permission, could violate law or policy.
