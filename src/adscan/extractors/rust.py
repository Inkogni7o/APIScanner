"""Axum router expressions, Actix services/scopes and Rocket mounted route macros."""

from tree_sitter import Node

from adscan.extractors.fastapi import join_path
from adscan.extractors.python_web import path_parameters
from adscan.models import AuthInfo, Diagnostic, Endpoint, Parameter
from adscan.parsers.cst import (
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    arguments,
    bindings,
    call_name,
    field,
    receiver,
    text,
    walk,
)


def rust_attributes(handler: Node) -> list[Node]:
    result: list[Node] = []
    node = handler.prev_named_sibling
    while node and node.type == "attribute_item":
        result.insert(0, node)
        node = node.prev_named_sibling
    return result


def return_expressions(handler: Node) -> list[Node]:
    body = field(handler, "body")
    if body is None:
        return []
    result = []
    for node in walk(body, "return_expression"):
        if node.named_children:
            result.append(node.named_children[0])
    if body.named_children and body.named_children[-1].type not in {
        "let_declaration",
        "expression_statement",
    }:
        result.append(body.named_children[-1])
    return result


class AxumExtractor:
    framework = "Axum"

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        self.index = index
        self.attributed: dict[tuple[str, int], list[tuple[str, str]]] = {}
        candidates: list[tuple[CSTModule, Node]] = []
        served: list[tuple[CSTModule, Node]] = []
        for module in index.modules.values():
            if module.language != "rust":
                continue
            for handler in module.functions.values():
                entries = []
                for item in rust_attributes(handler):
                    attribute = item.named_children[0] if item.named_children else None
                    if attribute is None:
                        continue
                    name_node = next(
                        (
                            child
                            for child in attribute.named_children
                            if child.type in {"identifier", "scoped_identifier"}
                        ),
                        None,
                    )
                    canonical = index.resolve(module, text(name_node))
                    package = "actix_web" if self.framework == "Actix Web" else "rocket"
                    method = canonical.rsplit("::", 1)[-1].upper()
                    if canonical.startswith(package + "::") and method in {
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "HEAD",
                        "OPTIONS",
                        "ROUTE",
                    }:
                        tokens = field(attribute, "arguments")
                        strings = (
                            list(walk(tokens, "string_literal", "raw_string_literal"))
                            if tokens
                            else []
                        )
                        path = index.literal(module, strings[0]) if strings else None
                        if isinstance(path, str):
                            entries.append((method if method != "ROUTE" else "ANY", path))
                if entries:
                    self.attributed[module.file, handler.start_byte] = entries
            for call in walk(module.tree.root_node, "call_expression"):
                canonical = index.resolve(module, call_name(call))
                if self.framework == "Axum" and canonical in {"axum::serve", "axum::Server::bind"}:
                    args = arguments(call)
                    if canonical == "axum::serve" and len(args) >= 2:
                        served.append((module, args[1]))
                if canonical in self._constructors():
                    top = call
                    while (
                        top.parent
                        and top.parent.type == "field_expression"
                        and field(top.parent, "value") == top
                    ):
                        parent = top.parent.parent
                        if parent and parent.type == "call_expression":
                            top = parent
                        else:
                            break
                    candidates.append((module, top))
        if served:
            roots = served
        else:
            # Nested routers referenced by another builder are emitted at their mount only.
            used: set[tuple[str, int]] = set()
            for module, expression in candidates:
                for owner, candidate in candidates:
                    if (
                        owner is module
                        and expression.start_byte <= candidate.start_byte
                        and candidate.end_byte <= expression.end_byte
                        and candidate != expression
                    ):
                        used.add((owner.file, candidate.start_byte))
                for node in walk(expression, "identifier", "call_expression"):
                    resolved = self._value(module, node)
                    if resolved:
                        owner, value = resolved
                        if value != expression:
                            used.add((owner.file, value.start_byte))
            roots = [
                (module, node)
                for module, node in candidates
                if (module.file, node.start_byte) not in used
            ]
        result = []
        for module, node in roots:
            endpoints = self._routes(module, node, "", [], set())
            if endpoints:
                index.entry_points.add(module.file)
                result.extend(endpoints)
        if not roots:
            for module in index.modules.values():
                for handler in module.functions.values():
                    result.extend(self._attribute_routes(module, handler, "", []))
        return result

    def _constructors(self) -> set[str]:
        if self.framework == "Axum":
            return {"axum::Router::new"}
        if self.framework == "Actix Web":
            return {"actix_web::App::new"}
        return {"rocket::build", "rocket::ignite"}

    def _value(self, module: CSTModule, node: Node) -> tuple[CSTModule, Node] | None:
        if node.type == "identifier":
            value = self.index.constant(module, text(node), node)
            return (module, value) if value is not None else None
        if node.type == "call_expression" and receiver(node) is None:
            target = self.index.function(module, call_name(node))
            if target:
                owner, handler = target
                returns = return_expressions(handler)
                if len(returns) == 1:
                    return owner, returns[0]
        return None

    def _routes(
        self,
        module: CSTModule,
        node: Node,
        prefix: str,
        auth: list[AuthInfo],
        visited: set[tuple[str, int, int]],
    ) -> list[CSTEndpoint]:
        key = module.file, node.start_byte, node.end_byte
        if key in visited:
            return []
        visited = visited | {key}
        value = self._value(module, node)
        if value:
            return self._routes(*value, prefix, auth, visited)
        if (
            node.type
            in {
                "reference_expression",
                "try_expression",
                "await_expression",
                "parenthesized_expression",
                "block",
            }
            and node.named_children
        ):
            return self._routes(module, node.named_children[-1], prefix, auth, visited)
        if node.type != "call_expression":
            resolved_handler = self.index.handler(module, node)
            return (
                self._attribute_routes(*resolved_handler, prefix, auth) if resolved_handler else []
            )
        owner_node = receiver(node)
        canonical = self.index.resolve(module, call_name(node))
        args = arguments(node)
        function = field(node, "function")
        method = text(field(function, "field")) if function is not None else ""
        if method in {"layer", "route_layer", "wrap", "wrap_fn"}:
            auth = auth + [
                AuthInfo(
                    name=text(arg),
                    kind="middleware",
                    file=module.file,
                    line=arg.start_point.row + 1,
                )
                for arg in args
                if "auth" in text(arg).lower()
            ]
        if self.framework == "Actix Web" and canonical in {
            "actix_web::web::scope",
            "actix_web::web::resource",
        }:
            return []
        result = self._routes(module, owner_node, prefix, auth, visited) if owner_node else []
        if self.framework == "Axum":
            if method == "route" and len(args) >= 2:
                path = self._path(module, args[0])
                if path is not None:
                    for verb, target in self._method_handlers(module, args[1]):
                        result.extend(
                            self._endpoint(module, target, verb, join_path(prefix, path), auth)
                        )
            elif method == "nest" and len(args) >= 2:
                path = self._path(module, args[0])
                if path is not None:
                    result.extend(
                        self._routes(module, args[1], join_path(prefix, path), auth, visited)
                    )
            elif method == "merge" and args:
                result.extend(self._routes(module, args[0], prefix, auth, visited))
        elif self.framework == "Actix Web":
            # A scope/resource receiver contributes its path to everything added to it.
            base = self._scope_path(module, owner_node)
            if base is None:
                return []
            effective = join_path(prefix, base) if base else prefix
            if method == "service":
                for argument in args:
                    result.extend(self._routes(module, argument, effective, auth, visited))
            elif method == "route" and args:
                target = args[-1]
                path = self._path(module, args[0]) if len(args) >= 2 else ""
                if path is not None:
                    for verb, handler in self._method_handlers(module, target):
                        result.extend(
                            self._endpoint(module, handler, verb, join_path(effective, path), auth)
                        )
            elif method == "configure" and args:
                resolved_configure = self.index.handler(module, args[0])
                if resolved_configure:
                    owner, function = resolved_configure
                    body = field(function, "body")
                    for call in walk(body, "call_expression") if body else []:
                        parent = call.parent
                        if not (parent and parent.type == "field_expression"):
                            result.extend(self._routes(owner, call, effective, auth, visited))
        elif method == "mount" and len(args) >= 2:
            path = self._path(module, args[0])
            if path is not None and args[1].type == "macro_invocation":
                tokens = next(
                    (child for child in args[1].named_children if child.type == "token_tree"), None
                )
                for target in tokens.named_children if tokens else []:
                    result.extend(
                        self._routes(module, target, join_path(prefix, path), auth, visited)
                    )
        return result

    def _scope_path(self, module: CSTModule, node: Node | None) -> str | None:
        if node is None or node.type != "call_expression":
            return ""
        if self.index.resolve(module, call_name(node)) in {
            "actix_web::web::scope",
            "actix_web::web::resource",
        }:
            args = arguments(node)
            return self._path(module, args[0]) if args else ""
        return self._scope_path(module, receiver(node))

    def _path(self, module: CSTModule, node: Node) -> str | None:
        value = self.index.literal(module, node)
        if isinstance(value, str):
            return value
        self.index.diagnostics.append(
            Diagnostic(
                file=module.file,
                line=node.start_point.row + 1,
                message="Dynamic Rust route path cannot be resolved",
            )
        )
        return None

    def _method_handlers(self, module: CSTModule, node: Node) -> list[tuple[str, Node]]:
        if node.type != "call_expression":
            return []
        name = self.index.resolve(module, call_name(node))
        owner = receiver(node)
        function = field(node, "function")
        method = (text(field(function, "field")) if function is not None else "") or name.rsplit(
            "::", 1
        )[-1]
        args = arguments(node)
        result = self._method_handlers(module, owner) if owner else []
        verbs = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "any"}
        if method in verbs and args and (owner is not None or name.startswith("axum::routing::")):
            result.append((method.upper(), args[0]))
        elif method == "to" and args and owner:
            verb = self.index.resolve(module, call_name(owner)).rsplit("::", 1)[-1].upper()
            if verb.lower() in verbs:
                result.append((verb, args[0]))
        return result

    def _attribute_routes(
        self, module: CSTModule, handler: Node, prefix: str, auth: list[AuthInfo]
    ) -> list[CSTEndpoint]:
        return [
            self._build(module, handler, verb, join_path(prefix, path), auth)
            for verb, path in self.attributed.get((module.file, handler.start_byte), [])
        ]

    def _endpoint(
        self, module: CSTModule, handler_node: Node, verb: str, path: str, auth: list[AuthInfo]
    ) -> list[CSTEndpoint]:
        target = self.index.handler(module, handler_node)
        if target is None:
            self.index.diagnostics.append(
                Diagnostic(
                    file=module.file,
                    line=handler_node.start_point.row + 1,
                    message="Rust route handler could not be resolved statically",
                )
            )
            return []
        return [self._build(*target, verb, path, auth)]

    def _build(
        self, module: CSTModule, handler: Node, verb: str, path: str, auth: list[AuthInfo]
    ) -> CSTEndpoint:
        parameters = path_parameters(path)
        if self.framework == "Rocket":
            import re

            path, _, query = path.partition("?")
            parameters = [
                Parameter(name=name, location="path", required=True)
                for name in re.findall(r"<(\w+)(?:\.\.)?>", path)
            ]
            parameters.extend(
                Parameter(name=name, location="query")
                for name in re.findall(r"<(\w+)(?:\.\.)?>", query)
            )
        params = field(handler, "parameters")
        for param in params.named_children if params else []:
            type_node = field(param, "type")
            typename = text(type_node)
            canonical = self.index.resolve(module, typename.split("<", 1)[0])
            location = {
                "Path": "path",
                "Query": "query",
                "Json": "body",
                "Form": "form",
                "Multipart": "file",
            }.get(canonical.rsplit("::", 1)[-1])
            if not location:
                continue
            pattern = field(param, "pattern")
            names = bindings(pattern)
            for name in names:
                parameters = [
                    item
                    for item in parameters
                    if not (item.name == name and item.location == location)
                ]
                parameters.append(
                    Parameter(name=name, location=location, type=typename, required=True)
                )
        return CSTEndpoint(
            endpoint=Endpoint(
                method=verb,
                path=path,
                handler_name=text(field(handler, "name"))
                or f"<handler@{handler.start_point.row + 1}>",
                file=module.file,
                line=handler.start_point.row + 1,
                framework=self.framework,
                parameters=parameters,
                auth=auth.copy(),
            ),
            module=module,
            handler=handler,
        )


class ActixExtractor(AxumExtractor):
    framework = "Actix Web"


class RocketExtractor(AxumExtractor):
    framework = "Rocket"
