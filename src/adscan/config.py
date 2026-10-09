"""Small, validated TOML configuration shared by scanner and CLI."""

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from adscan.models import Severity


class _ConfigSections(BaseModel):
    """TOML section tables before their values are validated by Config."""

    analysis: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    severity: dict[str, Any] = Field(default_factory=dict)
    ignore: dict[str, Any] = Field(default_factory=dict)
    semgrep: dict[str, Any] = Field(default_factory=dict)


class Config(BaseModel):
    """Scanner limits, ignore patterns and output defaults."""

    model_config = ConfigDict(strict=True)

    include_tests: bool = False
    color: bool = True
    minimum_severity: Severity = "INFO"
    ignore_paths: list[str] = Field(default_factory=list)
    max_file_bytes: int = Field(default=2_000_000, gt=0)
    semgrep_enabled: bool = False
    semgrep_configs: list[str] = Field(default_factory=list)
    semgrep_binary: str = "semgrep"
    semgrep_timeout_seconds: int = Field(default=120, gt=0)

    @field_validator("minimum_severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @classmethod
    def load(cls, root: Path) -> "Config":
        """Read .adscan.toml and validate user-supplied configuration."""
        path = root / ".adscan.toml"
        if not path.exists():
            return cls()
        with path.open("rb") as stream:
            sections = _ConfigSections.model_validate(tomllib.load(stream))
        return cls(
            include_tests=sections.analysis.get("include_tests", False),
            color=sections.output.get("color", True),
            minimum_severity=sections.severity.get("minimum", "INFO"),
            ignore_paths=sections.ignore.get("paths", []),
            max_file_bytes=sections.analysis.get("max_file_bytes", 2_000_000),
            semgrep_enabled=sections.semgrep.get("enabled", False),
            semgrep_configs=sections.semgrep.get("configs", []),
            semgrep_binary=sections.semgrep.get("binary", "semgrep"),
            semgrep_timeout_seconds=sections.semgrep.get("timeout_seconds", 120),
        )
