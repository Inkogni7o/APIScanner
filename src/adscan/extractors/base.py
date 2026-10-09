"""Minimal extractor contract and registry."""

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from adscan.models import Endpoint
from adscan.parsers.python import FunctionNode, PythonIndex, PythonModule


class ExtractedEndpoint(BaseModel):
    """A normalized endpoint with its parsed handler and owning module."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    endpoint: Endpoint
    module: PythonModule
    handler: FunctionNode | None


class BaseExtractor(Protocol):
    """Convert framework-specific routes into shared endpoint models."""

    framework: str

    def extract(self, index: PythonIndex) -> list[ExtractedEndpoint]: ...
