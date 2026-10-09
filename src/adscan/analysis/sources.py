"""Recognize direct access to Starlette/FastAPI request inputs."""

import ast

from adscan.models import Source
from adscan.parsers.python import dotted_name

REQUEST_COLLECTIONS = {
    "query_params": "query",
    "path_params": "path",
    "headers": "header",
    "cookies": "cookie",
    "args": "query",
    "GET": "query",
    "POST": "form",
    "FILES": "file",
    "files": "file",
    "form": "form",
    "data": "body",
    "json": "body",
    "body": "body",
}
REQUEST_BODY_METHODS = {"json", "body", "form", "stream", "get_json", "get_data"}


def request_source(node: ast.AST, request_names: set[str], file: str) -> Source | None:
    """Identify request input without treating every request attribute as client data."""
    expression = node
    name: str | None = None
    if isinstance(node, ast.Subscript):
        expression = node.value
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            name = node.slice.value
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get", "getlist"}:
            expression = node.func.value
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                name = node.args[0].value
        elif node.func.attr in REQUEST_BODY_METHODS:
            receiver = dotted_name(node.func.value)
            if receiver in request_names:
                return Source(
                    name=f"{receiver}.{node.func.attr}()",
                    location="body",
                    file=file,
                    line=node.lineno,
                )
    dotted = dotted_name(expression)
    receiver, _, collection = dotted.rpartition(".")
    if receiver in request_names and collection in REQUEST_COLLECTIONS:
        return Source(
            name=name or dotted,
            location=REQUEST_COLLECTIONS[collection],
            file=file,
            line=getattr(node, "lineno", 1),
        )
    return None
