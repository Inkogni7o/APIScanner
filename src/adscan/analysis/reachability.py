"""Static handler/helper spans for associating external findings with HTTP routes."""

import ast
from collections.abc import Iterator

from pydantic import BaseModel
from tree_sitter import Node

from adscan.extractors.base import ExtractedEndpoint
from adscan.models import FlowStep, FunctionReference
from adscan.parsers.cst import (
    CALL_TYPES,
    FUNCTION_TYPES,
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    call_name,
    field,
)
from adscan.parsers.python import FunctionNode, PythonIndex, PythonModule, dotted_name


class ReachableSpan(BaseModel):
    file: str
    start: int
    end: int
    start_column: int = 1
    end_column: int = 1
    chain: list[FlowStep]


def python_calls(handler: FunctionNode) -> Iterator[ast.Call]:
    pending: list[ast.AST] = list(handler.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            yield node
        pending.extend(ast.iter_child_nodes(node))


def cst_calls(handler: Node, index: CSTIndex, module: CSTModule) -> Iterator[Node]:
    body = field(handler, "body")
    pending = [body] if body is not None else list(handler.named_children)
    while pending:
        node = pending.pop()
        if node.type in FUNCTION_TYPES:
            continue
        if node.type in CALL_TYPES:
            yield node
        if node.type == "macro_invocation" and module.language == "rust":
            pending.extend(index.macro_expressions(module, node))
            continue
        pending.extend(node.named_children)


def reachable_python(index: PythonIndex, item: ExtractedEndpoint) -> list[ReachableSpan]:
    if item.handler is None:
        return []
    result = []
    pending: list[tuple[PythonModule, FunctionNode, str, list[FlowStep]]] = [
        (item.module, item.handler, item.endpoint.handler_name, [])
    ]
    visited = set()
    while pending:
        module, handler, symbol, chain = pending.pop()
        key = module.file, handler.lineno
        if key in visited:
            continue
        visited.add(key)
        result.append(
            ReachableSpan(
                file=module.file,
                start=handler.lineno,
                end=handler.end_lineno or handler.lineno,
                start_column=handler.col_offset + 1,
                end_column=(handler.end_col_offset or 0) + 1,
                chain=chain,
            )
        )
        for call in python_calls(handler):
            name = dotted_name(call.func)
            if name.startswith("self.") and "." in symbol:
                name = symbol.rsplit(".", 1)[0] + "." + name.removeprefix("self.")
            qualified = index.resolve(module, name)
            target = index.function(qualified)
            if not target:
                continue
            owner, function = target
            reference = FunctionReference(name=qualified, file=owner.file, line=function.lineno)
            if (
                module is item.module
                and handler is item.handler
                and reference not in item.endpoint.called_functions
            ):
                item.endpoint.called_functions.append(reference)
            step = FlowStep(expression=f"call {qualified}", file=module.file, line=call.lineno)
            pending.append(
                (owner, function, qualified.removeprefix(owner.name + "."), chain + [step])
            )
    return result


def reachable_cst(index: CSTIndex, item: CSTEndpoint) -> list[ReachableSpan]:
    result = []
    pending: list[tuple[CSTModule, Node, str, list[FlowStep]]] = [
        (item.module, item.handler, item.endpoint.handler_name, [])
    ]
    visited = set()
    while pending:
        module, handler, symbol, chain = pending.pop()
        key = module.file, handler.start_byte
        if key in visited:
            continue
        visited.add(key)
        result.append(
            ReachableSpan(
                file=module.file,
                start=handler.start_point.row + 1,
                end=handler.end_point.row + 1,
                start_column=handler.start_point.column + 1,
                end_column=handler.end_point.column + 1,
                chain=chain,
            )
        )
        for call in cst_calls(handler, index, module):
            name = call_name(call)
            if name.startswith("this."):
                class_name = index.symbol(module, handler).rsplit(".", 1)[0]
                name = class_name + "." + name.removeprefix("this.")
            target = index.function(module, name)
            if not target and "." in symbol and "." not in name:
                name = symbol.rsplit(".", 1)[0] + "." + name
                target = index.function(module, name)
            owner, function = target if target else (None, None)
            if module is item.module and handler == item.handler:
                reference = FunctionReference(
                    name=name,
                    file=owner.file if owner else None,
                    line=function.start_point.row + 1 if function else None,
                )
                if reference not in item.endpoint.called_functions:
                    item.endpoint.called_functions.append(reference)
            if owner is not None and function is not None:
                step = FlowStep(
                    expression=f"call {name}", file=module.file, line=call.start_point.row + 1
                )
                pending.append((owner, function, name, chain + [step]))
    return result
