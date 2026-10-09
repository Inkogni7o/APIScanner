"""Compact summaries and detailed endpoint evidence, with optional source snippets."""

import tokenize
from pathlib import Path

from adscan import __version__
from adscan.extractors import CST_EXTRACTORS, EXTRACTORS
from adscan.models import Endpoint, Finding, Report, Severity

COLORS = {"INFO": "36", "LOW": "32", "MEDIUM": "33", "HIGH": "31", "CRITICAL": "91"}


def colored(text: str, severity: Severity, color: bool) -> str:
    return f"\033[{COLORS[severity]}m{text}\033[0m" if color else text


def snippet(root: Path, finding: Finding, context: int = 2) -> list[str]:
    """Read a source fragment around a finding from the scanned project."""
    path = root / finding.file
    if path.suffix == ".py":
        with tokenize.open(path) as stream:
            lines = stream.read().splitlines()
    else:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    start = max(0, finding.line - context - 1)
    end = min(len(lines), finding.line + context)
    return [f"      {index + 1:>4} | {lines[index]}" for index in range(start, end)]


def finding_lines(finding: Finding, root: Path, show_code: bool, color: bool) -> list[str]:
    lines = [
        colored(f"{finding.severity} {finding.title}", finding.severity, color),
        f"  {finding.endpoint or 'No statically resolved endpoint'}",
        f"  {finding.file}:{finding.line}",
        f"  Confidence: {finding.confidence}",
    ]
    if finding.source:
        lines.append(f"  Source: {finding.source.location} parameter {finding.source.name!r}")
    if show_code:
        lines.extend(snippet(root, finding))
    return lines


def endpoint_detail(endpoint: Endpoint, root: Path, show_code: bool, color: bool) -> list[str]:
    lines = [
        endpoint.identifier,
        f"  Location: {endpoint.file}:{endpoint.line}",
        f"  Handler: {endpoint.handler_name}",
        f"  Authentication: {', '.join(item.name for item in endpoint.auth) or 'not recognized'}",
        f"  Priority: {endpoint.priority}; score: {endpoint.score}",
        "",
        "Parameters:",
    ]
    lines.extend(
        f"  {parameter.name}: {parameter.location}, {parameter.type or 'unknown type'}, "
        f"required={parameter.required}"
        + (f", alias={parameter.alias!r}" if parameter.alias else "")
        for parameter in endpoint.parameters
    )
    if not endpoint.parameters:
        lines.append("  None recognized")
    lines.extend(["", "Score reasons:"])
    lines.extend(f"  +{reason.points} {reason.reason}" for reason in endpoint.score_reasons)
    if not endpoint.score_reasons:
        lines.append("  No recognized risk factors")
    lines.extend(["", "Called functions:"])
    for reference in endpoint.called_functions:
        location = f" ({reference.file}:{reference.line})" if reference.file else ""
        lines.append(f"  {reference.name}{location}")
    lines.extend(["", "Findings:"])
    if not endpoint.findings:
        lines.append("  None recognized")
    for finding in endpoint.findings:
        lines.extend(finding_lines(finding, root, show_code, color))
        lines.append(f"  {finding.description}")
        if finding.dataflow:
            lines.append("  Data flow:")
            lines.extend(
                f"    {'-> ' if index else ''}{step.expression} ({step.file}:{step.line})"
                for index, step in enumerate(finding.dataflow)
            )
        lines.append("")
    return lines


def render_terminal(
    report: Report,
    root: Path,
    mode: str = "scan",
    show_code: bool = False,
    color: bool = False,
) -> str:
    """Render one report without rescanning or applying hidden severity filters."""
    if mode == "endpoint":
        return (
            "\n".join(
                line
                for endpoint in report.endpoints
                for line in endpoint_detail(endpoint, root, show_code, color) + [""]
            ).rstrip()
            + "\n"
        )
    if mode == "endpoints":
        lines = ["METHOD  PATH  AUTH  HANDLER"]
        lines.extend(
            f"{endpoint.method:<7} {endpoint.path}  "
            f"{', '.join(auth.name for auth in endpoint.auth) or '-'}  "
            f"{endpoint.handler_name} ({endpoint.file}:{endpoint.line})"
            for endpoint in report.endpoints
        )
        return "\n".join(lines) + "\n"
    if mode == "findings":
        lines = []
        for endpoint in report.endpoints:
            for finding in endpoint.findings:
                lines.extend(finding_lines(finding, root, show_code, color) + [""])
        for finding in report.unmatched_findings:
            lines.extend(finding_lines(finding, root, show_code, color) + [""])
        return "\n".join(lines).rstrip() + "\n" if lines else "No findings recognized.\n"
    project = report.project
    count = sum(len(endpoint.findings) for endpoint in report.endpoints) + len(
        report.unmatched_findings
    )
    lines = [
        f"ADScan {__version__}",
        "",
        "Project:",
        f"  Languages: {', '.join(project.languages) or 'not recognized'}",
        f"  Frameworks: {', '.join(project.frameworks) or 'not recognized'}",
        "  Entry points: " + (", ".join(project.entry_points) or "not recognized"),
        "",
        f"Files scanned: {project.files_scanned}; files parsed: {project.files_parsed}",
        f"Endpoints: {len(report.endpoints)}",
        f"Findings: {count}",
        "",
        "Priority endpoints:",
        "",
    ]
    for endpoint in report.endpoints:
        lines.append(
            colored(
                f"{endpoint.priority:<9} {endpoint.score:>3}  {endpoint.method:<7} {endpoint.path}",
                endpoint.priority,
                color,
            )
        )
        titles = ", ".join(dict.fromkeys(finding.title for finding in endpoint.findings))
        if titles:
            lines.append(f"               {titles}")
        lines.append(f"               {endpoint.file}:{endpoint.line}")
        if show_code:
            for finding in endpoint.findings:
                lines.extend(snippet(root, finding))
        lines.append("")
    if not report.endpoints:
        lines.append("  No statically recognized routes matched the selection.")
    if report.unmatched_findings:
        lines.extend(["", "Findings without a resolved endpoint:"])
        for finding in report.unmatched_findings:
            lines.extend(finding_lines(finding, root, show_code, color))
    unsupported = [
        framework
        for framework in project.frameworks
        if framework not in EXTRACTORS and framework not in CST_EXTRACTORS
    ]
    if unsupported:
        lines.append("Detected frameworks without route extraction: " + ", ".join(unsupported))
    lines.append("Heuristic analysis: findings require manual review.")
    return "\n".join(lines).rstrip() + "\n"
