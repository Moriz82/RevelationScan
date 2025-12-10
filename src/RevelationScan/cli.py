# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the CLI application for Revelation Scan. This application will allow users to:
# 1. Run security scans on Linux systems using "trumpets" (security checks)
# 2. List available trumpets
# 3. Generate reports in text or JSON format
# 4. Update CVE feeds for vulnerability checking

from __future__ import annotations  # This lets us use fancy type hints like List[str] | None

import argparse  # For parsing command line arguments (the user's input)
import json  # For making JSON reports (computers love JSON)
import sys  # System stuff, like exiting the program
from pathlib import Path  # For dealing with file paths in a cool way
from typing import Dict, List  # Type hints so we know what types things are

### Check if we're running as a script (not imported as a module)
if __package__ is None or __package__ == "":  # support running as a script
    # Add the parent directory to the path so Python can find our modules
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
#$ End conditional

### Import all the cool stuff from our RevelationScan package
from RevelationScan import __version__  # Get the version number (for bragging rights)
from RevelationScan.core.base import ScanContext, Trumpet, TrumpetRegistry, summarize  # Core scanning stuff
from RevelationScan.core.colors import Palette, apply_color, set_color_enabled  # Make it pretty with colors!
from RevelationScan.core.feed import compute_target_feed, resolve_update_sources, update_feed  # CVE feed management
from RevelationScan.core.findings import Finding  # What we find when scanning
from RevelationScan.core.registry import load_plugins, register_builtin_trumpets  # Plugin system magic
from RevelationScan.core.spinner import Spinner  # The spinning thing that shows we're working
from RevelationScan.core.utils import read_config, resolve_cve_feed, state_dir  # Utility functions

###########################################################################################################

### The description string that tells people what this tool does
description = f'Revelation Scan {__version__} – modular Linux misconfiguration auditor inspired by linPEAS.'

###########################################################################################################

"""

Name: build_parser

Function: Builds the argument parser that handles all the command line options.

Arguments: None

Returns: An ArgumentParser object that knows about all our options

"""

def build_parser() -> argparse.ArgumentParser:
    ### Create the main parser object with our program name and description
    parser = argparse.ArgumentParser(
        prog="Revelation Scan",
        description=description,
    )
    
    ### Add the --version flag so users can see what version they're running
    parser.add_argument(
        "--version",
        action="version",
        version=f"Revelation Scan {__version__}"
    )
    
    ### Add flag to list all available trumpets (security checks)
    parser.add_argument(
        "--list-trumpets",
        action="store_true",
        help="List available trumpets and exit"
    )
    
    ### Let users pick which trumpets to run (or run all by default)
    parser.add_argument(
        "--trumpets",
        help="Comma-separated list of trumpet slugs to run (defaults to all)",
    )
    
    ### Option to save the report to a file instead of just printing it
    parser.add_argument(
        "--output",
        type=Path,
        help="Write report to file (text or json format)"
    )
    
    ### Choose between text and JSON format (JSON is for machines, text is for humans)
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for reports (defaults to text)",
    )
    
    ### Allow users to provide a config file for settings
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to JSON configuration file"
    )
    
    ### Let users add custom trumpet plugins from directories
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        help="Additional directory containing custom trumpet plugins",
    )
    
    ### Specify a local CVE feed file (vulnerability database)
    parser.add_argument(
        "--cve-feed",
        type=Path,
        help="Path to local CVE/service version feed JSON (overrides config)",
    )
    
    ### Or fetch the CVE feed from a URL (the internet is cool!)
    parser.add_argument(
        "--cve-feed-url",
        help="URL to fetch CVE feed JSON (overrides local feed if reachable)",
    )
    
    ### Option to show exploit suggestions (for educational purposes, of course)
    parser.add_argument(
        "--suggest-exploits",
        action="store_true",
        help="Include exploit suggestions where available"
    )
    
    ### Disable colors for people who don't like pretty things (or are using old terminals)
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors and spinner animations"
    )
    
    ### Quiet mode - shhh, don't print anything (useful when saving to file)
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (use with --output)"
    )
    
    ### Update the CVE feed from the internet (stay up to date!)
    parser.add_argument(
        "--update-feed",
        action="store_true",
        help="Download and refresh CVE/service feed"
    )

    # Return the parser so we can use it to parse arguments
    return parser

#$ End build_parser

###########################################################################################################

"""

Name: main

Function: The main driver function that orchestrates the entire scanning process.

Arguments: argv - Optional list of command line arguments (None means use sys.argv)

Returns: Integer exit code (0 for success, non-zero for errors)

"""

def main(argv: List[str] | None = None) -> int:
    ### Build the parser and parse the arguments from the command line
    parser = build_parser()
    args = parser.parse_args(argv)

    ### Check if user wants to disable colors (some people are boring like that)
    if args.no_color:
        set_color_enabled(False)  # Turn off the pretty colors
#$ End conditional

    ### Initialize the config dictionary (empty to start)
    config: Dict[str, object] = {}
    
    ### If user provided a config file, try to read it
    if args.config:
        try:
            config = read_config(args.config)  # Read the config file
        except FileNotFoundError as exc:
            # Oops, file not found! Tell the user and exit
            parser.error(str(exc))
#$ End conditional
    
    ### If user provided a CVE feed URL, add it to the config
    if args.cve_feed_url:
        config["cve_feed_url"] = args.cve_feed_url
#$ End conditional

    ### Expand the plugin directory paths (handle ~ for home directory)
    plugin_paths = [Path(p).expanduser() for p in args.plugin_dir]
    
    ### Figure out where the CVE feed is (either from args or config)
    feed_path: Path | None = args.cve_feed.expanduser() if args.cve_feed else resolve_cve_feed(config)

    ### If user wants to update the feed, let's do it!
    if args.update_feed:
        # Find where we should get the feed from
        sources = resolve_update_sources(config, args.cve_feed_url)
        if not sources:
            # Can't update if we don't know where to get it from!
            parser.error("No update sources specified; provide --cve-feed-url or update_sources in config")
        
        # Figure out where to save the updated feed
        target = compute_target_feed(args.cve_feed, config)
        
        # Actually update the feed (this might take a moment)
        success, errors = update_feed(target, sources)
        
        # Print any error messages (yellow if successful, red if failed)
        for message in errors:
            print(apply_color(f"[Feed] {message}", Palette.YELLOW if success else Palette.RED))
#$ End iteration
        
        if not success:
            # Update failed completely, can't continue
            parser.error("Feed update failed; no sources succeeded")
        
        # Update our feed path and config to point to the new feed
        feed_path = target
        config["cve_feed"] = str(target)
        
        # Tell the user we succeeded (if they're not in quiet mode)
        if not args.quiet:
            print(apply_color(f"[Feed] Updated feed stored at {target}", Palette.GREEN, Palette.BOLD))
#$ End conditional
#$ End conditional

    ### Show the cool ASCII art banner (unless user is in quiet mode)
    maybe_display_banner(args.quiet)

    ### Create the scan context with all our settings
    context = ScanContext(
        config=config,
        cve_feed=feed_path,
        output_format=args.format,
        suggest_exploits=args.suggest_exploits,
        plugins=plugin_paths,
    )

    ### Set up the trumpet registry (this is where all our security checks live)
    registry = TrumpetRegistry()
    register_builtin_trumpets(registry)  # Add the built-in trumpets
    load_plugins(plugin_paths, registry)  # Load any custom plugins

    ### If user just wants to list trumpets, do that and exit
    if args.list_trumpets:
        for slug in registry.slugs():
            print(slug)  # Print each trumpet slug
#$ End iteration
        return 0  # Exit successfully
#$ End conditional

    ### Figure out which trumpets the user wants to run
    wanted_slugs = None
    if args.trumpets:
        # Parse the comma-separated list and clean it up
        wanted_slugs = {slug.strip() for slug in args.trumpets.split(",") if slug.strip()}
        
        # Check if any of the requested trumpets don't exist
        unknown = wanted_slugs - set(registry.slugs())
        if unknown:
            # User asked for trumpets that don't exist, tell them!
            parser.error(f"Unknown trumpets: {', '.join(sorted(unknown))}")
#$ End conditional

    ### Build the list of trumpet instances to run
    chosen_trumpets = []
    for slug in registry.slugs():
        # If no specific trumpets requested, or this one is in the list, add it
        if wanted_slugs is None or slug in wanted_slugs:
            trumpet_cls = registry.get(slug)  # Get the class
            chosen_trumpets.append(trumpet_cls())  # Create an instance and add it
#$ End iteration

    ### Make sure we have at least one trumpet to run
    if not chosen_trumpets:
        parser.error("No trumpets selected")  # Can't scan without trumpets!
#$ End conditional

    ### Actually run the trumpets and get the report
    report = run_trumpets(chosen_trumpets, context, quiet=args.quiet)

    ### If user wants to save the report to a file, do it
    if args.output:
        write_report(report, args.output, args.format)
#$ End conditional

    ### Print a summary unless user is in quiet mode
    if not args.quiet:
        emit_summary(report)
#$ End conditional

    # Return 0 to indicate success (everything went well!)
    return 0

#$ End main

###########################################################################################################

"""

Name: run_trumpets

Function: Runs all the trumpets (security checks) and collects their findings into a report.

Arguments: trumpets - List of trumpet instances to run
           context - The scan context with all the settings
           quiet - Whether to suppress output (default False)

Returns: Dictionary containing the complete report with all findings

"""

def run_trumpets(trumpets: List[Trumpet], context: ScanContext, quiet: bool = False) -> Dict[str, object]:
    ### Initialize lists to collect all our findings
    all_findings: List[Finding] = []  # All findings from all trumpets
    sections: List[Dict[str, object]] = []  # Sections for the report

    ### Loop through each trumpet and let it do its thing
    for trumpet in trumpets:
        # Blow the trumpet (run the security check) and get findings
        findings = blow_trumpet(trumpet, context, quiet=quiet)
        
        # Add all findings to our master list
        all_findings.extend(findings)
        
        # Create a section for this trumpet in the report
        sections.append(
            {
                "slug": trumpet.slug,  # The identifier
                "title": trumpet.title,  # The display name
                "description": trumpet.description,  # What it does
                "findings": [finding_to_dict(f) for f in findings],  # Convert findings to dicts
            }
        )
#$ End iteration

    ### Count up all the findings by severity (critical, warning, info)
    counts = summarize(all_findings)
    
    ### Build and return the complete report
    return {
        "tool": "Revelation Scan",  # Who we are
        "version": __version__,  # What version we are
        "counts": counts,  # Summary counts
        "sections": sections,  # All the detailed findings
    }

#$ End run_trumpets

###########################################################################################################

"""

Name: blow_trumpet

Function: Runs a single trumpet (security check) and displays its findings in a pretty way.

Arguments: trumpet - The trumpet instance to run
           context - The scan context with settings
           quiet - Whether to suppress output (default False)

Returns: List of Finding objects from this trumpet

"""

def blow_trumpet(trumpet: Trumpet, context: ScanContext, quiet: bool = False) -> List[Finding]:
    ### Create a spinner to show we're working (the spinning thing!)
    spinner = Spinner(prefix="    ")
    
    ### If not in quiet mode, show the trumpet header and start the spinner
    if not quiet:
        # Make a pretty header with the trumpet title
        header = apply_color(f"[Trumpet] {trumpet.title}", Palette.CYAN, Palette.BOLD)
        print(header)
        # Print the description in a dim color
        print(apply_color(f"    {trumpet.description}", Palette.DIM))
        spinner.start()  # Start spinning!
#$ End conditional
    
    ### Actually run the trumpet (this is where the magic happens)
    try:
        findings = trumpet.blow(context)  # Blow the trumpet and get findings
    finally:
        spinner.stop()  # Always stop the spinner, even if something goes wrong
#$ End try
    
    ### If we're in quiet mode, just return the findings without printing
    if quiet:
        return findings
#$ End conditional

    ### If no findings, tell the user everything is good (green checkmark!)
    if not findings:
        print(apply_color("    ✓ No issues observed", Palette.GREEN, Palette.BOLD))
    else:
        ### Loop through each finding and display it nicely
        for finding in findings:
            # Pick a color based on severity (red for critical, yellow for warning, etc.)
            severity_color = {
                "critical": Palette.RED,  # Red = bad news
                "warning": Palette.YELLOW,  # Yellow = be careful
                "info": Palette.BLUE,  # Blue = just info
            }.get(finding.severity, Palette.MAGENTA)  # Magenta if we don't know what it is
            
            # Make a pretty severity label
            severity_label = apply_color(f"    {finding.severity.upper()}", severity_color, Palette.BOLD)
            print(f"{severity_label} {finding.title}")  # Print the title
            
            # Print all the details for this finding
            for detail in finding.details:
                print(apply_color(f"        - {detail}", Palette.DIM))
#$ End iteration
            
            # If there's a CVE associated, show it (unless we're outputting JSON)
            if finding.cve and context.output_format != "json":
                print(apply_color(f"        CVE: {finding.cve}", Palette.DIM))
#$ End conditional
            
            # If there's a remediation suggestion, show it
            if finding.remediation:
                print(apply_color(f"        Remediation: {finding.remediation}", Palette.DIM))
#$ End conditional
            
            # If exploits are enabled and there's an exploit, show it
            if finding.exploit and context.suggest_exploits:
                print(apply_color(f"        Exploit: {finding.exploit}", Palette.DIM))
#$ End conditional
#$ End iteration
#$ End conditional
    
    # Print a blank line for spacing
    print()
    
    # Return the findings so they can be collected
    return findings

#$ End blow_trumpet

###########################################################################################################

"""

Name: finding_to_dict

Function: Converts a Finding object into a dictionary (for JSON serialization).

Arguments: finding - The Finding object to convert

Returns: Dictionary representation of the finding

"""

def finding_to_dict(finding: Finding) -> Dict[str, object]:
    ### Convert the finding object to a dictionary so we can serialize it
    return {
        "severity": finding.severity,  # How bad it is
        "title": finding.title,  # What the issue is
        "details": finding.details,  # The gory details
        "cve": finding.cve,  # CVE number if applicable
        "remediation": finding.remediation,  # How to fix it
        "exploit": finding.exploit,  # Exploit info if available
    }

#$ End finding_to_dict

###########################################################################################################

"""

Name: write_report

Function: Writes the report to a file in the specified format (JSON or text).

Arguments: report - The report dictionary to write
           path - Where to write the file
           fmt - Format to use ("json" or "text")

Returns: No value returned

"""

def write_report(report: Dict[str, object], path: Path, fmt: str) -> None:
    ### Check what format the user wants
    if fmt == "json":
        # Convert the report to JSON string with nice indentation
        payload = json.dumps(report, indent=2)
    else:
        # Render as plain text for humans to read
        payload = render_text_report(report)
#$ End conditional
    
    ### Make sure the directory exists (create it if it doesn't)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    ### Write the report to the file (with a newline at the end)
    path.write_text(payload + "\n", encoding="utf-8")

#$ End write_report

###########################################################################################################

"""

Name: render_text_report

Function: Converts the report dictionary into a human-readable text format.

Arguments: report - The report dictionary to render

Returns: String containing the formatted text report

"""

def render_text_report(report: Dict[str, object]) -> str:
    ### Start building the report lines
    lines = [f"Revelation Scan v{report['version']}"]  # Header with version
    
    ### Get the counts and add a summary line
    counts = report.get("counts", {})
    lines.append(
        f"Totals -> critical: {counts.get('critical', 0)}, warning: {counts.get('warning', 0)}, info: {counts.get('info', 0)}"
    )
    
    ### Loop through each section (trumpet) in the report
    for section in report.get("sections", []):
        lines.append("")  # Blank line for spacing
        lines.append(section.get("title", "Trumpet"))  # Section title
        lines.append("  " + section.get("description", ""))  # Section description
        
        ### Get the findings for this section
        findings = section.get("findings", [])
        
        ### If no findings, say everything is good
        if not findings:
            lines.append("    ✓ No issues observed")
        else:
            ### Loop through each finding and format it nicely
            for finding in findings:
                # Add the finding with severity label
                lines.append(f"    [{finding.get('severity', 'info').upper()}] {finding.get('title')}")
                
                # Add all the details
                for detail in finding.get("details", []):
                    lines.append(f"        - {detail}")
#$ End iteration
                
                # Add CVE if present
                if finding.get("cve"):
                    lines.append(f"        CVE: {finding['cve']}")
#$ End conditional
                
                # Add remediation if present
                if finding.get("remediation"):
                    lines.append(f"        Remediation: {finding['remediation']}")
#$ End conditional
                
                # Add exploit if present
                if finding.get("exploit"):
                    lines.append(f"        Exploit: {finding['exploit']}")
#$ End conditional
#$ End iteration
#$ End conditional
#$ End iteration
    
    ### Join all lines with newlines and return the complete report
    return "\n".join(lines)

#$ End render_text_report

###########################################################################################################

"""

Name: emit_summary

Function: Prints a summary of the scan results to the console.

Arguments: report - The report dictionary containing the counts

Returns: No value returned

"""

def emit_summary(report: Dict[str, object]) -> None:
    ### Get the counts from the report
    counts = report.get("counts", {})
    
    ### Build the summary line with all the counts
    line = (
        f"Summary -> critical={counts.get('critical', 0)} warning={counts.get('warning', 0)} info={counts.get('info', 0)}"
    )
    
    ### Print it in bold so it stands out
    print(apply_color(line, Palette.BOLD))

#$ End emit_summary

###########################################################################################################

"""

Name: maybe_display_banner

Function: Displays the cool ASCII art banner (unless user is in quiet mode).

Arguments: quiet - Whether to suppress the banner (True = don't show it)

Returns: No value returned

"""

def maybe_display_banner(quiet: bool) -> None:
    ### If user wants quiet mode, skip the banner
    if quiet:
        return  # Exit early, no banner for you!
#$ End conditional
    
    ### The awesome ASCII art banner (looks cool in the terminal!)
    art = r"""
    ____                 __      __  _            _____                
   / __ \___ _   _____  / /___ _/ /_(_)___  ____ / ___/_________ _____ 
  / /_/ / _ \ | / / _ \/ / __ `/ __/ / __ \/ __ \\__ \/ ___/ __ `/ __ \
 / _, _/  __/ |/ /  __/ / /_/ / /_/ / /_/ / / / /__/ / /__/ /_/ / / / /
/_/ |_|\___/|___/\___/_/\__,_/\__/_/\____/_/ /_/____/\___/\__,_/_/ /_/ 
"""
    
    ### Print each line of the banner in magenta and bold (so pretty!)
    for line in art.strip("\n").splitlines():
        print(apply_color(line, Palette.MAGENTA, Palette.BOLD))
#$ End iteration
    
    ### Print the description below the banner
    print(description)

#$ End maybe_display_banner

###########################################################################################################

### This is the entry point when running the script directly
### If someone imports this module, this won't run (which is good!)
if __name__ == "__main__":
    # Call main() and exit with whatever code it returns (0 = success, non-zero = error)
    sys.exit(main())

#?# Start the program by calling main when run as a script :)
