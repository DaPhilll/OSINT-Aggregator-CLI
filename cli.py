#!/usr/bin/env python3
"""Command-line interface for the OSINT aggregator.

Examples:
    python cli.py 8.8.8.8
    python cli.py example.com --json
    python cli.py https://example.com/path --only virustotal,urlscan
"""
import argparse
import json
import sys

from osint_aggregator.aggregator import scan_indicator

STATUS_LABEL = {
    "ok": "[OK]",
    "not_found": "[--]",
    "error": "[ERR]",
    "skipped": "[SKIP]",
}


def format_text(report):
    lines = []
    indicator = report["indicator"]
    itype = report["type"]

    if itype is None:
        lines.append(f"Indicator: {indicator}")
        lines.append(f"Error: {report.get('error', 'unknown error')}")
        return "\n".join(lines)

    lines.append(f"Indicator: {indicator}  (type: {itype})")
    lines.append("-" * 60)

    if not report["results"]:
        lines.append("No sources support this indicator type.")
        return "\n".join(lines)

    for result in report["results"]:
        label = STATUS_LABEL.get(result["status"], "[?]")
        lines.append(f"{label} {result['source']}: {result['summary']}")

    return "\n".join(lines)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Query multiple OSINT sources for a single indicator."
    )
    parser.add_argument("indicator",
                        help="IP, domain, URL, email, or file hash to look up.")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of formatted text.")
    parser.add_argument("--only",
                        help="Comma-separated source names to query "
                             "(e.g. virustotal,abuseipdb).")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    only = None
    if args.only:
        only = {name.strip() for name in args.only.split(",") if name.strip()}

    report = scan_indicator(args.indicator, only_sources=only)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_text(report))

    # Exit non-zero if the indicator type could not be determined.
    return 1 if report["type"] is None else 0


if __name__ == "__main__":
    sys.exit(main())
