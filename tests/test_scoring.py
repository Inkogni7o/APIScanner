from pathlib import Path

import pytest

from adscan.analysis.scoring import priority
from adscan.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "fastapi_vulnerable"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "INFO"),
        (19, "INFO"),
        (20, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (59, "MEDIUM"),
        (60, "HIGH"),
        (89, "HIGH"),
        (90, "CRITICAL"),
    ],
)
def test_priority_thresholds(score, expected):
    assert priority(score) == expected


def test_acceptance_scores_are_explainable_and_sorted():
    report = scan(FIXTURE)
    endpoints = {endpoint.path: endpoint for endpoint in report.endpoints}
    assert endpoints["/health"].priority == "INFO"
    assert endpoints["/health"].score == 0
    assert endpoints["/files/{filename}"].priority == "HIGH"
    assert endpoints["/proxy"].priority == "HIGH"
    assert endpoints["/run"].priority == "CRITICAL"
    assert endpoints["/private/files/{filename}"].score < endpoints["/files/{filename}"].score
    assert all(
        endpoint.score == sum(reason.points for reason in endpoint.score_reasons)
        for endpoint in report.endpoints
    )
    assert [endpoint.score for endpoint in report.endpoints] == sorted(
        [endpoint.score for endpoint in report.endpoints], reverse=True
    )
