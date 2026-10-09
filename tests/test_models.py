import json
from pathlib import Path

from adscan.cli import select_report
from adscan.models import Report
from adscan.output.json import render_json
from adscan.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "fastapi_vulnerable"


def test_previous_json_contract_round_trips_through_pydantic():
    example = Path(__file__).parents[1] / "docs" / "example-report.json"
    previous = example.read_text(encoding="utf-8")
    report = Report.model_validate_json(previous)
    assert json.loads(render_json(report)) == json.loads(previous)
    assert report.endpoints[0].identifier == "POST /run"
    assert report.endpoints[0].findings[0].sink.shell is True
    report.project.name = "сервис"
    assert "сервис" in render_json(report)


def test_filtering_pydantic_report_keeps_full_report_and_original_scores():
    full = scan(FIXTURE)
    original = full.model_dump()
    selected = select_report(full, "findings", "CRITICAL", None, None)
    assert len(selected.endpoints) == 1
    assert selected.endpoints[0].path == "/run"
    assert selected.endpoints[0].score == full.endpoints[0].score
    assert full.model_dump() == original
