"""Framework-independent public report models; paths are relative to the scanned root."""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
SEVERITIES: tuple[Severity, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class Parameter(BaseModel):
    """An HTTP input, including the Python binding and its wire name."""

    name: str
    location: str
    type: str | None = None
    required: bool | None = None
    alias: str | None = None


class AuthInfo(BaseModel):
    """A statically recognized security dependency, never proof of enforcement."""

    name: str
    kind: str
    file: str
    line: int
    confidence: Confidence = "MEDIUM"


class Source(BaseModel):
    """A client-controlled value and where it enters a handler."""

    name: str
    location: str
    file: str
    line: int


class Sink(BaseModel):
    """A potentially dangerous operation."""

    name: str
    category: str
    file: str
    line: int
    expression: str
    shell: bool = False


class FlowStep(BaseModel):
    """A source, assignment, transformation, or sink in an evidence chain."""

    expression: str
    file: str
    line: int


class FunctionReference(BaseModel):
    """A called function, with a location when it can be resolved statically."""

    name: str
    file: str | None
    line: int | None


class Finding(BaseModel):
    """A security observation; endpoint is empty when no static association is known."""

    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int
    description: str
    source: Source | None
    sink: Sink | None
    confidence: Confidence
    endpoint: str
    dataflow: list[FlowStep] = Field(default_factory=list)


class ScoreReason(BaseModel):
    """One independently counted risk factor."""

    points: int
    reason: str


class Endpoint(BaseModel):
    """One HTTP method/path and all evidence used to rank it."""

    method: str
    path: str
    handler_name: str
    file: str
    line: int
    framework: str
    parameters: list[Parameter] = Field(default_factory=list)
    auth: list[AuthInfo] = Field(default_factory=list)
    called_functions: list[FunctionReference] = Field(default_factory=list)
    sinks: list[Sink] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: int = 0
    priority: Severity = "INFO"
    score_reasons: list[ScoreReason] = Field(default_factory=list)

    @property
    def identifier(self) -> str:
        return f"{self.method} {self.path}"


class Diagnostic(BaseModel):
    """A recoverable read, parse or static resolution problem."""

    file: str
    message: str
    line: int | None = None


class Project(BaseModel):
    """Project metadata with no absolute source paths or application execution."""

    name: str
    languages: list[str]
    frameworks: list[str]
    files_scanned: int
    files_parsed: int = 0
    entry_points: list[str] = Field(default_factory=list)


class Report(BaseModel):
    """Versioned JSON-compatible scan result."""

    project: Project
    endpoints: list[Endpoint]
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    unmatched_findings: list[Finding] = Field(default_factory=list)
    schema_version: str = "1.1"
    tool_version: str = "0.1.0"
