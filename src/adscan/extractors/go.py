"""Go router constructors, registration functions, groups and HTTP handlers."""

from pydantic import BaseModel, Field
from tree_sitter import Node

from adscan.extractors.fastapi import join_path
from adscan.extractors.javascript import auth_evidence
from adscan.extractors.python_web import path_parameters
from adscan.models import AuthInfo, Diagnostic, Endpoint
from adscan.parsers.cst import (
    FUNCTION_TYPES,
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    arguments,
    bindings,
    call_name,
    field,
    receiver,
    text,
)


class GoGroup(BaseModel):
    prefix: str
    auth: list[AuthInfo] = Field(default_factory=list)


class GinExtractor:
    framework = "Gin"
    package = "github.com/gin-gonic/gin"
    constructors = {"Default", "New"}

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        self.index = index
        self.result: list[CSTEndpoint] = []
        for module in index.modules.values():
            if module.language != "go":
                continue
            globals_: dict[str, GoGroup] = {}
            self._visit(module, module.tree.root_node, globals_, set())
            for function in module.functions.values():
                body = field(function, "body")
                if body:
                    self._visit(module, body, globals_.copy(), {(module.file, function.start_byte)})
        return self.result

    def _group(
        self, module: CSTModule, node: Node | None, groups: dict[str, GoGroup]
    ) -> GoGroup | None:
        if node is None:
            return None
        if node.type == "identifier":
            return groups.get(text(node))
        if node.type != "call_expression":
            return None
        name = self.index.resolve(module, call_name(node))
        package, _, constructor = name.rpartition(".")
        if package.startswith(self.package) and constructor in self.constructors:
            self.index.entry_points.add(module.file)
            return GoGroup(prefix="")
        owner = receiver(node)
        parent = self._group(module, owner, groups)
        if not parent:
            return None
        method = call_name(node).rsplit(".", 1)[-1]
        args = arguments(node)
        if method in {"Group", "PathPrefix"} and args:
            prefix = self.index.literal(module, args[0])
            if not isinstance(prefix, str):
                self._dynamic(module, node, "group prefix")
                return None
            return GoGroup(
                prefix=join_path(parent.prefix, prefix),
                auth=parent.auth + auth_evidence(module, args[1:]),
            )
        if method == "With":
            return GoGroup(prefix=parent.prefix, auth=parent.auth + auth_evidence(module, args))
        if method == "Subrouter":
            return parent.model_copy(deep=True)
        return None

    def _visit(
        self, module: CSTModule, node: Node, groups: dict[str, GoGroup], stack: set[tuple[str, int]]
    ) -> None:
        if node.type in FUNCTION_TYPES:
            return
        if node.type in {"short_var_declaration", "var_spec", "assignment_statement"}:
            left = field(node, "left") or field(node, "name")
            right = field(node, "right") or field(node, "value")
            names = (
                left.named_children
                if left and left.type == "expression_list"
                else [left]
                if left
                else []
            )
            values = (
                right.named_children
                if right and right.type == "expression_list"
                else [right]
                if right
                else []
            )
            for name, value in zip(names, values, strict=False):
                group = self._group(module, value, groups)
                if group:
                    groups[text(name)] = group
                else:
                    groups.pop(text(name), None)
        if node.type == "call_expression":
            self._call(module, node, groups, stack)
        for child in node.named_children:
            self._visit(module, child, groups, stack)

    def _call(
        self, module: CSTModule, call: Node, groups: dict[str, GoGroup], stack: set[tuple[str, int]]
    ) -> None:
        name = call_name(call)
        method = name.rsplit(".", 1)[-1]
        args = arguments(call)
        group = self._group(module, receiver(call), groups)
        if self.framework == "net/http" and self.index.resolve(module, name) in {
            "net/http.HandleFunc",
            "net/http.Handle",
        }:
            group = GoGroup(prefix="")
            self.index.entry_points.add(module.file)
        if group:
            if method == "Use":
                group.auth.extend(auth_evidence(module, args))
            elif method in {"Route", "Group"} and args and self.framework == "Chi":
                prefix = self.index.literal(module, args[0]) if method == "Route" else ""
                if isinstance(prefix, str):
                    self._registration(
                        module,
                        args[-1],
                        [GoGroup(prefix=join_path(group.prefix, prefix), auth=group.auth.copy())],
                        stack,
                    )
                else:
                    self._dynamic(module, call, "group prefix")
            elif method == "Mount" and len(args) >= 2:
                # Handler factories need a statically resolvable router return value.
                pass
            elif len(args) >= 2 and method.upper() in {
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "TRACE",
                "CONNECT",
                "ANY",
                "ALL",
                "HANDLE",
                "HANDLEFUNC",
                "METHOD",
                "METHODFUNC",
            }:
                # Gorilla's Methods chain supplies the verbs instead of an extra ANY endpoint.
                parent = call.parent
                chained = parent.parent if parent and parent.type == "selector_expression" else None
                if (
                    chained
                    and chained.type == "call_expression"
                    and call_name(chained).endswith(".Methods")
                ):
                    methods = [self.index.literal(module, arg) for arg in arguments(chained)]
                elif method in {"Method", "MethodFunc"} and len(args) >= 3:
                    methods = [self.index.literal(module, args[0])]
                    args = args[1:]
                else:
                    methods = [
                        "ANY"
                        if method in {"Any", "All", "Handle", "HandleFunc"}
                        else method.upper()
                    ]
                path = self.index.literal(module, args[0])
                if not isinstance(path, str):
                    self._dynamic(module, call, "route path")
                    return
                if self.framework == "net/http":
                    verb, separator, pattern = path.partition(" ")
                    if separator:
                        methods, path = [verb], pattern
                    # A ServeMux host pattern precedes the first slash.
                    path = path[path.find("/") :] if "/" in path else path
                handler_node = args[1] if self.framework == "Echo" else args[-1]
                if (
                    handler_node.type == "call_expression"
                    and self.index.resolve(module, call_name(handler_node))
                    == "net/http.HandlerFunc"
                ):
                    wrapped = arguments(handler_node)
                    handler_node = wrapped[0] if wrapped else handler_node
                target = self.index.handler(module, handler_node)
                if target:
                    owner, handler = target
                    middleware = args[2:] if self.framework == "Echo" else args[1:-1]
                    for method_value in methods:
                        if isinstance(method_value, str):
                            full_path = join_path(group.prefix, path)
                            self.result.append(
                                CSTEndpoint(
                                    endpoint=Endpoint(
                                        method=method_value.upper(),
                                        path=full_path,
                                        handler_name=text(field(handler, "name"))
                                        or f"<handler@{handler.start_point.row + 1}>",
                                        file=owner.file,
                                        line=handler.start_point.row + 1,
                                        framework=self.framework,
                                        parameters=path_parameters(full_path),
                                        auth=group.auth.copy() + auth_evidence(module, middleware),
                                    ),
                                    module=owner,
                                    handler=handler,
                                )
                            )
                else:
                    self.index.diagnostics.append(
                        Diagnostic(
                            file=module.file,
                            line=call.start_point.row + 1,
                            message="Go route handler could not be resolved statically",
                        )
                    )
        # Router parameters in registration helpers retain the caller's prefix and middleware.
        bound = [self._group(module, arg, groups) for arg in args]
        if any(bound):
            function = field(call, "function")
            if function:
                self._registration(module, function, bound, stack)

    def _registration(
        self,
        module: CSTModule,
        node: Node,
        passed: list[GoGroup | None],
        stack: set[tuple[str, int]],
    ) -> None:
        target = self.index.handler(module, node)
        if not target:
            return
        owner, handler = target
        key = owner.file, handler.start_byte
        body, params = field(handler, "body"), field(handler, "parameters")
        if key in stack or body is None:
            return
        names = (
            [name for param in params.named_children for name in bindings(param)] if params else []
        )
        local = {
            name: group.model_copy(deep=True)
            for name, group in zip(names, passed, strict=False)
            if group is not None
        }
        self._visit(owner, body, local, stack | {key})

    def _dynamic(self, module: CSTModule, node: Node, what: str) -> None:
        self.index.diagnostics.append(
            Diagnostic(
                file=module.file,
                line=node.start_point.row + 1,
                message=f"Dynamic Go {what} cannot be resolved",
            )
        )


class EchoExtractor(GinExtractor):
    framework = "Echo"
    package = "github.com/labstack/echo"
    constructors = {"New"}


class FiberExtractor(GinExtractor):
    framework = "Fiber"
    package = "github.com/gofiber/fiber"
    constructors = {"New"}


class HTTPExtractor(GinExtractor):
    framework = "net/http"
    package = "net/http"
    constructors = {"NewServeMux"}


class ChiExtractor(GinExtractor):
    framework = "Chi"
    package = "github.com/go-chi/chi"
    constructors = {"NewRouter", "NewMux"}


class MuxExtractor(GinExtractor):
    framework = "Gorilla Mux"
    package = "github.com/gorilla/mux"
    constructors = {"NewRouter"}
