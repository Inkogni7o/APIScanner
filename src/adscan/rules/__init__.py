"""Rules consume normalized sink evidence independently of route extraction."""

from pydantic import BaseModel, ConfigDict

from adscan.models import Confidence, Endpoint, Finding, FlowStep, Severity, Sink, Source


class Rule(BaseModel):
    """One MVP rule with deliberately heuristic wording."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    severity: Severity
    description: str

    def finding(
        self,
        endpoint: Endpoint,
        sink: Sink,
        source: Source,
        steps: list[FlowStep],
        confidence: Confidence = "HIGH",
    ) -> Finding:
        severity = self.severity
        if sink.category == "command" and not sink.shell:
            severity = "HIGH"
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity,
            file=sink.file,
            line=sink.line,
            description=self.description,
            source=source,
            sink=sink,
            confidence=confidence,
            endpoint=endpoint.identifier,
            dataflow=steps,
        )


RULES: dict[str, Rule] = {
    "command": Rule(
        rule_id="command_injection",
        title="Command Injection",
        severity="CRITICAL",
        description="HTTP input reaches a command or code execution operation. "
        "Review input validation, shell parsing and the executable selection; "
        "this flow alone does not prove exploitation.",
    ),
    "file": Rule(
        rule_id="path_traversal",
        title="Path Traversal",
        severity="HIGH",
        description="HTTP input influences a filesystem path. "
        "Review canonicalization and directory containment.",
    ),
    "http": Rule(
        rule_id="ssrf",
        title="SSRF",
        severity="HIGH",
        description="HTTP input influences an outbound request URL. "
        "Review allowed destinations and redirects.",
    ),
}
