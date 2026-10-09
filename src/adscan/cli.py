"""ADScan command line interface with predictable stdout/stderr and exit status."""

import argparse
import os
import sys
import tomllib
from pathlib import Path

from pydantic import ValidationError

from adscan import __version__
from adscan.analysis.semgrep import SemgrepError
from adscan.config import Config
from adscan.extractors import FRAMEWORK_NAMES
from adscan.models import SEVERITIES, Report
from adscan.output.json import render_json
from adscan.output.terminal import render_terminal
from adscan.scanner import scan


def parser() -> argparse.ArgumentParser:
    """Build the CLI; options can appear before or after a command selector."""
    result = argparse.ArgumentParser(
        prog="adscan",
        description="Offline static security triage for web service source code.",
        epilog="Examples: adscan ./service; adscan ./service endpoint '/files/{name}'; "
        "adscan ./service --output report.json. Findings are heuristic and require manual review.",
    )
    result.add_argument("path", type=Path, help="project source directory or source file")
    result.add_argument(
        "command", nargs="?", default="scan", choices=("scan", "endpoints", "findings", "endpoint")
    )
    result.add_argument(
        "endpoint_path", nargs="?", help="exact route path for the endpoint command"
    )
    result.add_argument(
        "--format",
        choices=("terminal", "json"),
        default=None,
        help="stdout format (default: terminal)",
    )
    result.add_argument(
        "--output", type=Path, help="save JSON report; stdout keeps the selected format"
    )
    result.add_argument(
        "--severity",
        type=str.upper,
        choices=SEVERITIES,
        help="minimum finding severity / endpoint priority",
    )
    result.add_argument("--method", type=str.upper, help="filter HTTP method, e.g. GET or POST")
    result.add_argument("--show-code", action="store_true", help="show source around findings")
    result.add_argument("--no-color", action="store_true", help="disable terminal ANSI colors")
    result.add_argument(
        "--framework",
        type=str.lower,
        choices=tuple(FRAMEWORK_NAMES),
        help="select a framework extractor",
    )
    result.add_argument(
        "--language",
        type=str.lower,
        choices=("python", "javascript", "typescript", "java", "go", "rust"),
        help="select endpoint language",
    )
    result.add_argument(
        "--include-tests", action="store_true", help="include nested test directories and test_*.py"
    )
    result.add_argument(
        "-v", "--verbose", action="store_true", help="show parser and scanner diagnostics on stderr"
    )
    result.add_argument("--debug", action="store_true", help="show scanner and parser diagnostics")
    result.add_argument(
        "--semgrep", action="store_true", help="run optional Semgrep with local rules"
    )
    result.add_argument(
        "--semgrep-config",
        action="append",
        type=Path,
        help="local YAML rules file; repeat to combine files (implies --semgrep)",
    )
    result.add_argument("--semgrep-binary", help="Semgrep executable path (implies --semgrep)")
    result.add_argument("--version", action="version", version=f"ADScan {__version__}")
    return result


def select_report(
    report: Report, mode: str, minimum: str, route: str | None, method: str | None
) -> Report:
    """Apply output selection after scoring; never alter scores by filtering evidence."""
    threshold = SEVERITIES.index(minimum)
    endpoints = []
    for endpoint in report.endpoints:
        if route is not None and endpoint.path != route:
            continue
        if method and endpoint.method != method:
            continue
        if mode == "findings":
            findings = [
                finding
                for finding in endpoint.findings
                if SEVERITIES.index(finding.severity) >= threshold
            ]
            if findings:
                endpoints.append(endpoint.model_copy(update={"findings": findings}))
        elif SEVERITIES.index(endpoint.priority) >= threshold:
            endpoints.append(endpoint)
    unmatched = (
        [
            finding
            for finding in report.unmatched_findings
            if SEVERITIES.index(finding.severity) >= threshold
        ]
        if route is None and method is None
        else []
    )
    return report.model_copy(update={"endpoints": endpoints, "unmatched_findings": unmatched})


def main(argv: list[str] | None = None) -> int:
    """Return 0 on a completed scan, 1 on I/O errors, 2 on invalid input or no endpoint match."""
    argument_parser = parser()
    args = argument_parser.parse_intermixed_args(argv)
    if args.command == "endpoint" and args.endpoint_path is None:
        argument_parser.error("endpoint requires an exact route path")
    if args.command != "endpoint" and args.endpoint_path is not None:
        argument_parser.error("a route path is only valid with the endpoint command")
    try:
        root = args.path.resolve()
        if not root.is_dir() and not root.is_file():
            print(f"adscan: Project path does not exist: {root}", file=sys.stderr)
            return 2
        source_root = root.parent if root.is_file() else root
        try:
            config = Config.load(source_root)
        except (tomllib.TOMLDecodeError, ValidationError) as error:
            print(f"adscan: invalid configuration: {error}", file=sys.stderr)
            return 2
        if args.include_tests:
            config.include_tests = True
        if args.semgrep or args.semgrep_config or args.semgrep_binary:
            config.semgrep_enabled = True
        if args.semgrep_config:
            config.semgrep_configs = [str(path.resolve()) for path in args.semgrep_config]
        if args.semgrep_binary:
            config.semgrep_binary = args.semgrep_binary
        report = scan(root, config, FRAMEWORK_NAMES.get(args.framework), args.language)
        if args.debug or args.verbose:
            for diagnostic in report.diagnostics:
                location = diagnostic.file + (f":{diagnostic.line}" if diagnostic.line else "")
                print(f"[WARN] {location}: {diagnostic.message}", file=sys.stderr)
        report = select_report(
            report,
            args.command,
            args.severity or config.minimum_severity,
            args.endpoint_path if args.command == "endpoint" else None,
            args.method,
        )
        if not (args.debug or args.verbose):
            report = report.model_copy(update={"diagnostics": []})
        if args.command == "endpoint" and not report.endpoints:
            print(f"adscan: no endpoint matched {args.endpoint_path!r}", file=sys.stderr)
            return 2
        json_text = render_json(report)
        if args.output:
            args.output.write_text(json_text, encoding="utf-8")
        use_color = (
            config.color
            and not args.no_color
            and sys.stdout.isatty()
            and "NO_COLOR" not in os.environ
        )
        rendered = (
            json_text
            if args.format == "json"
            else render_terminal(report, source_root, args.command, args.show_code, use_color)
        )
        sys.stdout.write(rendered)
        return 0
    except SemgrepError as error:
        print(f"adscan: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"adscan: {error}", file=sys.stderr)
        return 1
