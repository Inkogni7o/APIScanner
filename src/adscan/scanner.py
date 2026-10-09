"""Pipeline: detection -> extraction -> handler analysis -> scoring -> report."""

from pathlib import Path

from adscan.analysis.cst_dataflow import CSTDataflowAnalyzer
from adscan.analysis.dataflow import DataflowAnalyzer
from adscan.analysis.reachability import reachable_cst, reachable_python
from adscan.analysis.scoring import score_endpoint
from adscan.analysis.semgrep import correlate, run_semgrep
from adscan.config import Config
from adscan.detector.project import scan_project
from adscan.extractors import CST_EXTRACTORS, EXTRACTORS
from adscan.extractors.base import ExtractedEndpoint
from adscan.models import Diagnostic, Report
from adscan.parsers.cst import CSTEndpoint, CSTIndex
from adscan.parsers.python import PythonIndex


def scan(
    root: Path,
    config: Config | None = None,
    framework: str | None = None,
    language: str | None = None,
) -> Report:
    """Analyze a source directory or file without executing or importing its contents."""
    config = config or Config.load(root.parent if root.is_file() else root)
    scanned = scan_project(root, config)
    index = PythonIndex(scanned.contents, scanned.diagnostics)
    cst_index = CSTIndex(scanned.contents, scanned.diagnostics)
    scanned.project.files_parsed = len(index.by_file) + len(cst_index.modules)
    frameworks = [framework] if framework else scanned.project.frameworks
    extracted: list[ExtractedEndpoint | CSTEndpoint] = []
    for name in frameworks:
        extractor = EXTRACTORS.get(name)
        if extractor:
            extracted.extend(extractor().extract(index))
        cst_extractor = CST_EXTRACTORS.get(name)
        if cst_extractor:
            extracted.extend(cst_extractor().extract(cst_index))
    # Django/DRF and Spring Boot/MVC may both describe the same concrete route.
    extracted = list(
        {
            (item.endpoint.method, item.endpoint.path, item.endpoint.file, item.endpoint.line): item
            for item in extracted
        }.values()
    )
    if language:
        suffixes = {
            "python": {".py"},
            "javascript": {".js", ".jsx", ".mjs", ".cjs"},
            "typescript": {".ts", ".tsx", ".mts", ".cts"},
            "java": {".java"},
            "go": {".go"},
            "rust": {".rs"},
        }
        extracted = [
            item for item in extracted if Path(item.endpoint.file).suffix in suffixes[language]
        ]
    if not extracted and any(
        module.language in {"rust", "go", "typescript", "tsx"}
        for module in cst_index.modules.values()
    ):
        scanned.diagnostics.append(
            Diagnostic(
                file=".",
                message="No HTTP routes could be resolved. Check the supported frameworks, "
                "selected filters and static route registration; use --framework "
                "to select an extractor explicitly.",
            )
        )
    routes = []
    for item in extracted:
        if isinstance(item, ExtractedEndpoint):
            if item.handler is not None:
                DataflowAnalyzer(index, item).analyze()
            spans = reachable_python(index, item)
        else:
            CSTDataflowAnalyzer(cst_index, item).analyze()
            spans = reachable_cst(cst_index, item)
        routes.append((item.endpoint, spans))
        # Normalize duplicate inputs recognized in both path and handler syntax.
        item.endpoint.parameters = list(
            {
                (parameter.name, parameter.location): parameter
                for parameter in item.endpoint.parameters
            }.values()
        )
    unmatched = []
    if config.semgrep_enabled:
        matches, diagnostics = run_semgrep(
            scanned.contents,
            [scanned.root / path for path in config.semgrep_configs],
            config.semgrep_binary,
            config.semgrep_timeout_seconds,
        )
        scanned.diagnostics.extend(diagnostics)
        unmatched = correlate(matches, routes)
    for item in extracted:
        score_endpoint(item.endpoint)
    scanned.project.entry_points = sorted(index.entry_points | cst_index.entry_points)
    endpoints = sorted(
        (item.endpoint for item in extracted),
        key=lambda endpoint: (
            -endpoint.score,
            endpoint.path,
            endpoint.method,
            endpoint.file,
            endpoint.line,
        ),
    )
    return Report(
        project=scanned.project,
        endpoints=endpoints,
        diagnostics=scanned.diagnostics,
        unmatched_findings=unmatched,
    )
