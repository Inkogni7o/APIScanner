"""Hono and Elysia router builders, nested applications and registration callbacks."""

from tree_sitter import Node

from adscan.extractors.fastapi import join_path
from adscan.extractors.javascript import auth_evidence, request_parameters
from adscan.extractors.python_web import path_parameters
from adscan.models import Diagnostic, Endpoint
from adscan.parsers.cst import (
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    arguments,
    bindings,
    call_name,
    field,
    properties,
    receiver,
    text,
    walk,
)


class HonoExtractor:
    framework = "Hono"
    constructor = "hono.Hono"

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        self.index = index
        candidates: list[tuple[CSTModule, Node]] = []
        mounted: set[tuple[str, int]] = set()
        for module in index.modules.values():
            if module.language not in {"javascript", "typescript", "tsx"}:
                continue
            for node in walk(module.tree.root_node, "call_expression", "new_expression"):
                if node.type == "call_expression" and call_name(node).rsplit(".", 1)[-1] in {
                    "route",
                    "use",
                }:
                    for argument in arguments(node):
                        value = self._root(module, argument, set())
                        if value:
                            mounted.add((value[0].file, value[1].start_byte))
                if self._root(module, node, set()):
                    parent = node.parent
                    if (
                        parent
                        and parent.type == "member_expression"
                        and parent.parent
                        and parent.parent.type == "call_expression"
                    ):
                        continue
                    # Constructor values with separate app.get calls are represented by those calls.
                    if node.type == "new_expression":
                        continue
                    candidates.append((module, node))
        result = []
        for module, node in candidates:
            root = self._root(module, node, set())
            if root and (root[0].file, root[1].start_byte) not in mounted:
                result.extend(self._routes(module, node, "", set(), set()))
                index.entry_points.add(module.file)
        return result

    def _value(
        self, module: CSTModule, node: Node, visited: set[tuple[str, int, int]]
    ) -> tuple[CSTModule, Node] | None:
        key = module.file, node.start_byte, node.end_byte
        if key in visited:
            return None
        if node.type == "identifier":
            if text(node) in module.imports:
                target, symbol = module.imports[text(node)]
                owner = self.index.imported_module(target)
                if owner:
                    owner, symbol = self.index.exported_symbol(owner, symbol)
                    value = self.index.constant(owner, symbol, owner.tree.root_node)
                    return (owner, value) if value else None
            value = self.index.constant(module, text(node), node)
            return (module, value) if value else None
        if node.type == "call_expression" and receiver(node) is None:
            target_function = self.index.function(module, call_name(node))
            if target_function:
                owner, handler = target_function
                returns = list(walk(handler, "return_statement"))
                body = field(handler, "body")
                if len(returns) == 1 and returns[0].named_children:
                    return owner, returns[0].named_children[0]
                if body and body.type != "statement_block":
                    return owner, body
        return None

    def _root(
        self, module: CSTModule, node: Node | None, visited: set[tuple[str, int, int]]
    ) -> tuple[CSTModule, Node] | None:
        if node is None or (module.file, node.start_byte, node.end_byte) in visited:
            return None
        visited = visited | {(module.file, node.start_byte, node.end_byte)}
        if node.type == "new_expression" and self.index.resolve(
            module, text(field(node, "constructor"))
        ) in {self.constructor, self.constructor.removesuffix(".Elysia")}:
            return module, node
        value = self._value(module, node, set())
        if value:
            return self._root(*value, visited)
        return (
            self._root(module, receiver(node), visited) if node.type == "call_expression" else None
        )

    def _routes(
        self,
        module: CSTModule,
        node: Node,
        prefix: str,
        bound: set[str],
        visited: set[tuple[str, int, int]],
    ) -> list[CSTEndpoint]:
        key = module.file, node.start_byte, node.end_byte
        if key in visited:
            return []
        visited = visited | {key}
        value = self._value(module, node, set())
        if value:
            return self._routes(*value, prefix, bound, visited)
        if node.type != "call_expression":
            return []
        args, owner = arguments(node), receiver(node)
        method = call_name(node).rsplit(".", 1)[-1]
        if not (
            self._root(module, node, set())
            or owner
            and (
                text(owner) in bound
                or any(text(child) in bound for child in walk(owner, "identifier"))
            )
        ):
            return []
        if method == "basePath" and args:
            path = self._path(module, args[0])
            return (
                self._routes(module, owner, join_path(prefix, path), bound, visited)
                if path is not None and owner
                else []
            )
        effective = self._prefix(module, owner, prefix)
        if effective is None:
            return []
        result = self._routes(module, owner, prefix, bound, visited) if owner else []
        if (
            method.lower() in {"get", "post", "put", "patch", "delete", "head", "options", "all"}
            and len(args) >= 2
        ):
            path = self._path(module, args[0])
            target = self.index.handler(module, args[1] if self.framework == "Elysia" else args[-1])
            if path is not None and target:
                owner_module, handler = target
                full_path = join_path(effective, path)
                result.append(
                    CSTEndpoint(
                        endpoint=Endpoint(
                            method="ANY" if method == "all" else method.upper(),
                            path=full_path,
                            handler_name=text(field(handler, "name"))
                            or f"<handler@{handler.start_point.row + 1}>",
                            file=owner_module.file,
                            line=handler.start_point.row + 1,
                            framework=self.framework,
                            parameters=path_parameters(full_path)
                            + request_parameters(self.index, owner_module, handler),
                            auth=auth_evidence(module, args[1:-1]),
                        ),
                        module=owner_module,
                        handler=handler,
                    )
                )
            elif path is not None:
                self.index.diagnostics.append(
                    Diagnostic(
                        file=module.file,
                        line=node.start_point.row + 1,
                        message="TypeScript route handler could not be resolved statically",
                    )
                )
        elif method == "route" and self.framework == "Hono" and len(args) >= 2:
            path = self._path(module, args[0])
            if path is not None:
                result.extend(
                    self._routes(module, args[1], join_path(effective, path), bound, visited)
                )
                value = self._value(module, args[1], set())
                if value:
                    owner_module, expression = value
                    # Hono mutates a separately declared router rather than always chaining.
                    for call in walk(owner_module.tree.root_node, "call_expression"):
                        root = self._root(owner_module, call, set())
                        target_root = self._root(owner_module, expression, set())
                        if root and target_root and root == target_root:
                            result.extend(
                                self._routes(
                                    owner_module, call, join_path(effective, path), bound, visited
                                )
                            )
        elif method == "group" and self.framework == "Elysia" and len(args) >= 2:
            path = self._path(module, args[0])
            target = self.index.handler(module, args[-1])
            if path is not None and target:
                owner_module, handler = target
                params = field(handler, "parameters") or field(handler, "parameter")
                callback_bound = set(bindings(params))
                body = field(handler, "body")
                if body:
                    for call in walk(body, "call_expression"):
                        result.extend(
                            self._routes(
                                owner_module,
                                call,
                                join_path(effective, path),
                                callback_bound,
                                visited,
                            )
                        )
        elif method == "use" and self.framework == "Elysia":
            for arg in args:
                result.extend(self._routes(module, arg, effective, bound, visited))
        return result

    def _prefix(
        self,
        module: CSTModule,
        node: Node | None,
        prefix: str,
        visited: set[tuple[str, int, int]] | None = None,
    ) -> str | None:
        if node is None:
            return prefix
        visited = visited or set()
        key = module.file, node.start_byte, node.end_byte
        if key in visited:
            return None
        visited = visited | {key}
        value = self._value(module, node, set())
        if value:
            return self._prefix(*value, prefix, visited)
        if node.type == "new_expression" and self.framework == "Elysia":
            args = arguments(node)
            options = properties(args[0]) if args else {}
            if "prefix" in options:
                path = self._path(module, options["prefix"])
                return join_path(prefix, path) if path is not None else None
        if node.type == "call_expression":
            inherited = self._prefix(module, receiver(node), prefix, visited)
            if inherited is not None and call_name(node).endswith(".basePath"):
                args = arguments(node)
                path = self._path(module, args[0]) if args else None
                return join_path(inherited, path) if path is not None else None
            return inherited
        return prefix

    def _path(self, module: CSTModule, node: Node) -> str | None:
        path = self.index.literal(module, node)
        if isinstance(path, str):
            return path
        self.index.diagnostics.append(
            Diagnostic(
                file=module.file,
                line=node.start_point.row + 1,
                message="Dynamic TypeScript route path cannot be resolved",
            )
        )
        return None


class ElysiaExtractor(HonoExtractor):
    framework = "Elysia"
    constructor = "elysia.Elysia"
