"""Stable JSON serialization, with report models as the only data contract."""

from adscan.models import Report


def render_json(report: Report) -> str:
    """Serialize relative paths, sources, sinks, flow evidence and score reasons."""
    return report.model_dump_json(indent=2) + "\n"
