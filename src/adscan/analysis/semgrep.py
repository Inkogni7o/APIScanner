"""Optional offline Semgrep runner and endpoint/helper result correlation."""

import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from adscan.analysis.reachability import ReachableSpan
from adscan.models import SEVERITIES, Confidence, Diagnostic, Endpoint, Finding, FlowStep, Severity


class SemgrepError(RuntimeError):
    """An explicitly requested external scan could not be completed."""


class SemgrepPosition(BaseModel):
    line: int
    col: int = 1


class SemgrepExtra(BaseModel):
    message: str
    severity: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SemgrepMatch(BaseModel):
    check_id: str
    path: str
    start: SemgrepPosition
    end: SemgrepPosition
    extra: SemgrepExtra


class SemgrepOutput(BaseModel):
    results: list[SemgrepMatch]
    errors: list[dict[str, Any]] = Field(default_factory=list)


def default_rule_files() -> list[Path]:
    """Use the shipped rule snapshot; explicit configs replace this entire selection."""
    directory = Path(__file__).parents[1] / "rules"
    third_party = directory / "third_party"
    return [
        directory / "semgrep.yml",
        *sorted(third_party.rglob("*.yml")),
        *sorted(third_party.rglob("*.yaml")),
    ]


def run_semgrep(
    contents: dict[Path, str], configs: list[Path], executable: str = "semgrep", timeout: int = 120
) -> tuple[list[SemgrepMatch], list[Diagnostic]]:
    """Scan a snapshot of exactly the selected files; no registry, telemetry or builds."""
    rule_files = configs or default_rule_files()
    for path in rule_files:
        if not path.is_file():
            raise SemgrepError(f"Semgrep rules must be local files: {path}")
    command = [
        shutil.which(executable) or str(Path(executable).resolve()),
        "scan",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
    ]
    for path in rule_files:
        command.extend(["--config", str(path.resolve())])
    command.append(".")
    environment = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    with TemporaryDirectory(prefix="adscan-semgrep-") as temporary:
        snapshot = Path(temporary)
        environment.update(
            {
                "XDG_CONFIG_HOME": temporary,
                "XDG_CACHE_HOME": temporary,
                "SEMGREP_SETTINGS_FILE": str(snapshot / ".semgrep" / "settings.yml"),
                "SEMGREP_LOG_FILE": str(snapshot / ".semgrep" / "semgrep.log"),
                "SEMGREP_APP_TOKEN": "",
            }
        )
        for path, source in contents.items():
            target = snapshot / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        try:
            process = subprocess.run(
                command,
                cwd=snapshot,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as error:
            raise SemgrepError(
                f"Semgrep executable not found: {executable}. "
                "Install Semgrep or set --semgrep-binary."
            ) from error
        except subprocess.TimeoutExpired as error:
            raise SemgrepError(
                f"Semgrep exceeded {timeout}s; set [semgrep].timeout_seconds in .adscan.toml."
            ) from error
        if process.returncode != 0:
            details = process.stderr.strip() or process.stdout.strip()
            raise SemgrepError(f"Semgrep exited with code {process.returncode}: {details}")
        try:
            output = SemgrepOutput.model_validate_json(process.stdout)
        except ValidationError as error:
            raise SemgrepError(f"Invalid Semgrep JSON output: {error}") from error
        for match in output.results:
            path = Path(match.path)
            match.path = (path.relative_to(snapshot) if path.is_absolute() else path).as_posix()
        diagnostics = [
            Diagnostic(
                file=str(error.get("path", "semgrep")),
                message=str(error.get("message", error.get("type", "Semgrep scan warning"))),
            )
            for error in output.errors
        ]
        return output.results, diagnostics


def normalize(
    match: SemgrepMatch, endpoint: str = "", chain: list[FlowStep] | None = None
) -> Finding:
    metadata = match.extra.metadata
    severity_name = str(
        metadata.get("severity", metadata.get("security-severity", match.extra.severity))
    ).upper()
    severity: Severity = "MEDIUM"
    if severity_name in SEVERITIES:
        severity = SEVERITIES[SEVERITIES.index(severity_name)]
    elif severity_name == "ERROR":
        severity = "HIGH"
    elif severity_name == "WARNING":
        severity = "MEDIUM"
    confidence_name = str(metadata.get("confidence", "MEDIUM")).upper()
    confidence: Confidence = (
        "HIGH" if confidence_name == "HIGH" else "LOW" if confidence_name == "LOW" else "MEDIUM"
    )
    return Finding(
        rule_id="semgrep:" + match.check_id,
        title=str(metadata.get("title", metadata.get("shortDescription", match.check_id))),
        severity=severity,
        file=match.path,
        line=match.start.line,
        description=match.extra.message,
        source=None,
        sink=None,
        confidence=confidence,
        endpoint=endpoint,
        dataflow=(chain or [])
        + [FlowStep(expression=match.extra.message, file=match.path, line=match.start.line)],
    )


def correlate(
    matches: list[SemgrepMatch], routes: list[tuple[Endpoint, list[ReachableSpan]]]
) -> list[Finding]:
    """A helper may belong to multiple routes; unmatched results remain in the report."""
    unmatched = []
    seen = set()
    for match in sorted(matches, key=lambda item: (item.path, item.start.line, item.check_id)):
        key = (
            match.check_id,
            match.path,
            match.start.line,
            match.start.col,
            match.end.line,
            match.end.col,
        )
        if key in seen:
            continue
        seen.add(key)
        attached = False
        for endpoint, spans in routes:
            candidates = [
                span
                for span in spans
                if span.file == match.path
                and (span.start, span.start_column) <= (match.start.line, match.start.col)
                and (match.end.line, match.end.col) <= (span.end, span.end_column)
            ]
            if candidates:
                span = min(candidates, key=lambda item: (len(item.chain), item.end - item.start))
                endpoint.findings.append(normalize(match, endpoint.identifier, span.chain))
                attached = True
        if not attached:
            unmatched.append(normalize(match))
    return unmatched
