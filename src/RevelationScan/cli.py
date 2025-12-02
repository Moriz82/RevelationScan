"""Command-line interface for Revelation Scan."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

if __package__ is None or __package__ == "":  # support running as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from RevelationScan import __version__
from RevelationScan.core.base import ScanContext, Trumpet, TrumpetRegistry, summarize
from RevelationScan.core.colors import Palette, apply_color, set_color_enabled
from RevelationScan.core.feed import compute_target_feed, resolve_update_sources, update_feed
from RevelationScan.core.findings import Finding
from RevelationScan.core.registry import load_plugins, register_builtin_trumpets
from RevelationScan.core.spinner import Spinner
from RevelationScan.core.utils import read_config, resolve_cve_feed, state_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Revelation Scan",
        description="Revelation Scan – modular Linux misconfiguration auditor inspired by linPEAS.",
    )
    parser.add_argument("--version", action="version", version=f"Revelation Scan {__version__}")
    parser.add_argument("--list-trumpets", action="store_true", help="List available trumpets and exit")
    parser.add_argument(
        "--trumpets",
        help="Comma-separated list of trumpet slugs to run (defaults to all)",
    )
    parser.add_argument("--output", type=Path, help="Write report to file (text or json format)")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for reports (defaults to text)",
    )
    parser.add_argument("--config", type=Path, help="Path to JSON configuration file")
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        help="Additional directory containing custom trumpet plugins",
    )
    parser.add_argument(
        "--cve-feed",
        type=Path,
        help="Path to local CVE/service version feed JSON (overrides config)",
    )
    parser.add_argument(
        "--cve-feed-url",
        help="URL to fetch CVE feed JSON (overrides local feed if reachable)",
    )
    parser.add_argument("--suggest-exploits", action="store_true", help="Include exploit suggestions where available")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors and spinner animations")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output (use with --output)")
    parser.add_argument("--update-feed", action="store_true", help="Download and refresh CVE/service feed")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        set_color_enabled(False)

    config: Dict[str, object] = {}
    if args.config:
        try:
            config = read_config(args.config)
        except FileNotFoundError as exc:
            parser.error(str(exc))
    if args.cve_feed_url:
        config["cve_feed_url"] = args.cve_feed_url

    plugin_paths = [Path(p).expanduser() for p in args.plugin_dir]
    feed_path: Path | None = args.cve_feed.expanduser() if args.cve_feed else resolve_cve_feed(config)

    if args.update_feed:
        sources = resolve_update_sources(config, args.cve_feed_url)
        if not sources:
            parser.error("No update sources specified; provide --cve-feed-url or update_sources in config")
        target = compute_target_feed(args.cve_feed, config)
        success, errors = update_feed(target, sources)
        for message in errors:
            print(apply_color(f"[Feed] {message}", Palette.YELLOW if success else Palette.RED))
        if not success:
            parser.error("Feed update failed; no sources succeeded")
        feed_path = target
        config["cve_feed"] = str(target)
        if not args.quiet:
            print(apply_color(f"[Feed] Updated feed stored at {target}", Palette.GREEN, Palette.BOLD))

    maybe_display_banner(args.quiet)

    context = ScanContext(
        config=config,
        cve_feed=feed_path,
        output_format=args.format,
        suggest_exploits=args.suggest_exploits,
        plugins=plugin_paths,
    )

    registry = TrumpetRegistry()
    register_builtin_trumpets(registry)
    load_plugins(plugin_paths, registry)

    if args.list_trumpets:
        for slug in registry.slugs():
            print(slug)
        return 0

    wanted_slugs = None
    if args.trumpets:
        wanted_slugs = {slug.strip() for slug in args.trumpets.split(",") if slug.strip()}
        unknown = wanted_slugs - set(registry.slugs())
        if unknown:
            parser.error(f"Unknown trumpets: {', '.join(sorted(unknown))}")

    chosen_trumpets = []
    for slug in registry.slugs():
        if wanted_slugs is None or slug in wanted_slugs:
            trumpet_cls = registry.get(slug)
            chosen_trumpets.append(trumpet_cls())

    if not chosen_trumpets:
        parser.error("No trumpets selected")

    report = run_trumpets(chosen_trumpets, context, quiet=args.quiet)

    if args.output:
        write_report(report, args.output, args.format)

    if not args.quiet:
        emit_summary(report)

    return 0


def run_trumpets(trumpets: List[Trumpet], context: ScanContext, quiet: bool = False) -> Dict[str, object]:
    all_findings: List[Finding] = []
    sections: List[Dict[str, object]] = []

    for trumpet in trumpets:
        findings = blow_trumpet(trumpet, context, quiet=quiet)
        all_findings.extend(findings)
        sections.append(
            {
                "slug": trumpet.slug,
                "title": trumpet.title,
                "description": trumpet.description,
                "findings": [finding_to_dict(f) for f in findings],
            }
        )

    counts = summarize(all_findings)
    return {
        "tool": "Revelation Scan",
        "version": __version__,
        "counts": counts,
        "sections": sections,
    }


def blow_trumpet(trumpet: Trumpet, context: ScanContext, quiet: bool = False) -> List[Finding]:
    spinner = Spinner(prefix="    ")
    if not quiet:
        header = apply_color(f"[Trumpet] {trumpet.title}", Palette.CYAN, Palette.BOLD)
        print(header)
        print(apply_color(f"    {trumpet.description}", Palette.DIM))
        spinner.start()
    try:
        findings = trumpet.blow(context)
    finally:
        spinner.stop()
    if quiet:
        return findings

    if not findings:
        print(apply_color("    ✓ No issues observed", Palette.GREEN, Palette.BOLD))
    else:
        for finding in findings:
            severity_color = {
                "critical": Palette.RED,
                "warning": Palette.YELLOW,
                "info": Palette.BLUE,
            }.get(finding.severity, Palette.MAGENTA)
            severity_label = apply_color(f"    {finding.severity.upper()}", severity_color, Palette.BOLD)
            print(f"{severity_label} {finding.title}")
            for detail in finding.details:
                print(apply_color(f"        - {detail}", Palette.DIM))
            if finding.cve and context.output_format != "json":
                print(apply_color(f"        CVE: {finding.cve}", Palette.DIM))
            if finding.remediation:
                print(apply_color(f"        Remediation: {finding.remediation}", Palette.DIM))
            if finding.exploit and context.suggest_exploits:
                print(apply_color(f"        Exploit: {finding.exploit}", Palette.DIM))
    print()
    return findings


def finding_to_dict(finding: Finding) -> Dict[str, object]:
    return {
        "severity": finding.severity,
        "title": finding.title,
        "details": finding.details,
        "cve": finding.cve,
        "remediation": finding.remediation,
        "exploit": finding.exploit,
    }


def write_report(report: Dict[str, object], path: Path, fmt: str) -> None:
    if fmt == "json":
        payload = json.dumps(report, indent=2)
    else:
        payload = render_text_report(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")


def render_text_report(report: Dict[str, object]) -> str:
    lines = [f"Revelation Scan v{report['version']}"]
    counts = report.get("counts", {})
    lines.append(
        f"Totals -> critical: {counts.get('critical', 0)}, warning: {counts.get('warning', 0)}, info: {counts.get('info', 0)}"
    )
    for section in report.get("sections", []):
        lines.append("")
        lines.append(section.get("title", "Trumpet"))
        lines.append("  " + section.get("description", ""))
        findings = section.get("findings", [])
        if not findings:
            lines.append("    ✓ No issues observed")
        else:
            for finding in findings:
                lines.append(f"    [{finding.get('severity','info').upper()}] {finding.get('title')}")
                for detail in finding.get("details", []):
                    lines.append(f"        - {detail}")
                if finding.get("cve"):
                    lines.append(f"        CVE: {finding['cve']}")
                if finding.get("remediation"):
                    lines.append(f"        Remediation: {finding['remediation']}")
                if finding.get("exploit"):
                    lines.append(f"        Exploit: {finding['exploit']}")
    return "\n".join(lines)


def emit_summary(report: Dict[str, object]) -> None:
    counts = report.get("counts", {})
    line = (
        f"Summary -> critical={counts.get('critical', 0)} warning={counts.get('warning', 0)} info={counts.get('info', 0)}"
    )
    print(apply_color(line, Palette.BOLD))


def maybe_display_banner(quiet: bool) -> None:
    if quiet:
        return
    marker = state_dir() / "banner_seen"
    if marker.exists():
        return
    art = r"""
 ______            _           _ _              _____
|  ____|          | |         | (_)            / ____|
| |__ ___  ___ ___| |__   __ _| |_ _ __   ___ | (___   ___ __ _ _ __
|  __/ _ \/ __/ __| '_ \ / _` | | | '_ \ / _ \ \___ \ / __/ _` | '_ \
| | |  __/\__ \__ \ | | | (_| | | | | | |  __/ ____) | (_| (_| | | | |
|_|  \___||___/___/_| |_|\__,_|_|_|_| |_|\___||_____/ \___\__,_|_| |_|
"""
    for line in art.strip("\n").splitlines():
        print(apply_color(line, Palette.MAGENTA, Palette.BOLD))
    marker.write_text("seen\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
