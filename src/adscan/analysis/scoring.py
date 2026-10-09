"""Explainable endpoint priority, separate from individual finding severity."""

from adscan.models import Endpoint, ScoreReason, Severity


def priority(score: int) -> Severity:
    if score >= 90:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def score_endpoint(endpoint: Endpoint) -> None:
    """Count each source/sink-independent risk factor once to avoid duplicate inflation."""
    reasons: list[ScoreReason] = []
    local_findings = [finding for finding in endpoint.findings if finding.sink]
    external_findings = [
        finding for finding in endpoint.findings if finding.rule_id.startswith("semgrep:")
    ]
    if local_findings:
        categories = {finding.sink.category for finding in local_findings if finding.sink}
        reasons.extend(
            ScoreReason(points=20, reason=f"{category} sink receives HTTP input")
            for category in sorted(categories)
        )
        reasons.append(ScoreReason(points=25, reason="client-controlled value reaches a sink"))
        reasons.append(ScoreReason(points=15, reason="statically recognized data flow"))
        if not endpoint.auth:
            reasons.append(
                ScoreReason(points=10, reason="authentication dependency not recognized")
            )
        if "http" in categories:
            reasons.append(ScoreReason(points=10, reason="client-controlled outbound URL"))
        if any(finding.sink and finding.sink.shell for finding in endpoint.findings):
            reasons.append(ScoreReason(points=25, reason="shell or dynamic code execution"))
        distinct = {(f.rule_id, f.file, f.line) for f in local_findings}
        if len(distinct) > 1:
            reasons.append(
                ScoreReason(
                    points=min(20, (len(distinct) - 1) * 10), reason="multiple dangerous operations"
                )
            )
    if external_findings:
        points = {"INFO": 0, "LOW": 20, "MEDIUM": 40, "HIGH": 60, "CRITICAL": 90}
        external_score = max(points[finding.severity] for finding in external_findings)
        local_score = sum(reason.points for reason in reasons)
        if external_score > local_score:
            reasons.append(
                ScoreReason(
                    points=external_score - local_score,
                    reason="Semgrep finding severity; HTTP taint not established by this score",
                )
            )
    if any(parameter.location == "file" for parameter in endpoint.parameters):
        reasons.append(ScoreReason(points=10, reason="file upload parameter"))
    endpoint.score_reasons = reasons
    endpoint.score = sum(reason.points for reason in reasons)
    endpoint.priority = priority(endpoint.score)
