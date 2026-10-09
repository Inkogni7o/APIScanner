"""Express routers and Fastify routes/plugins over JavaScript/TypeScript syntax trees."""

from pydantic import BaseModel, Field
from tree_sitter import Node

from adscan.extractors.fastapi import join_path
from adscan.extractors.python_web import path_parameters
from adscan.models import AuthInfo, Diagnostic, Endpoint, Parameter
from adscan.parsers.cst import (
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    arguments,
    call_name,
    field,
    properties,
    text,
    walk,
)


def scope(node: Node) -> int:
    parent = node.parent
    while parent:
        if parent.type in {"function_declaration", "function_expression", "arrow_function"}:
            return parent.start_byte
        parent = parent.parent
    return -1


def auth_evidence(module: CSTModule, nodes: list[Node]) -> list[AuthInfo]:
    result = []
    for node in nodes:
        name = call_name(node) if node.type == "call_expression" else text(node)
        if any(
            word in name.lower()
            for word in ("auth", "jwt", "session_required", "permission", "guard")
        ):
            result.append(
                AuthInfo(
                    name=name, kind="middleware", file=module.file, line=node.start_point.row + 1
                )
            )
    return result


def request_parameters(index: CSTIndex, module: CSTModule, handler: Node) -> list[Parameter]:
    result: dict[tuple[str, str], Parameter] = {}
    parameters = field(handler, "parameters")
    first = (
        parameters.named_children[0]
        if parameters and parameters.named_children
        else field(handler, "parameter")
    )
    binding = text(field(first, "pattern")) or text(first) if first else ""
    for node in walk(handler, "member_expression", "subscript_expression"):
        expression = text(node)
        for collection, location in (
            ("query", "query"),
            ("params", "path"),
            ("body", "body"),
            ("headers", "header"),
            ("cookies", "cookie"),
            ("file", "file"),
            ("files", "file"),
        ):
            prefix = binding + "." + collection
            if binding and expression.startswith(prefix + "."):
                name = expression[len(prefix) + 1 :].split(".", 1)[0]
                if name:
                    result[name, location] = Parameter(name=name, location=location)
            elif (
                binding
                and node.type == "subscript_expression"
                and text(field(node, "object")) == prefix
            ):
                wire_name = index.literal(module, field(node, "index"))
                if isinstance(wire_name, str):
                    result[wire_name, location] = Parameter(name=wire_name, location=location)
            elif binding and expression == prefix and location in {"body", "file"}:
                result[collection, location] = Parameter(name=collection, location=location)
    return list(result.values())


class JSRouter(BaseModel):
    key: str
    file: str
    application: bool = False
    auth: list[AuthInfo] = Field(default_factory=list)


class JSMount(BaseModel):
    parent: str
    child: str
    prefix: str | None
    auth: list[AuthInfo] = Field(default_factory=list)


class ExpressExtractor:
    framework = "Express"
    constructors = {"express", "express.Router"}

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        self.index = index
        self.routers: dict[str, JSRouter] = {}
        self.mounts: list[JSMount] = []
        for module in index.modules.values():
            if module.language not in {"javascript", "typescript", "tsx"}:
                continue
            for node in walk(module.tree.root_node, "variable_declarator"):
                value, name = field(node, "value"), text(field(node, "name"))
                if value and value.type == "call_expression":
                    constructor = index.resolve(module, call_name(value))
                    factory = field(value, "function")
                    if (
                        factory
                        and factory.type == "call_expression"
                        and call_name(factory) == "require"
                    ):
                        args = arguments(factory)
                        package = index.literal(module, args[0]) if args else None
                        if isinstance(package, str):
                            constructor = package
                    if constructor in self.constructors:
                        key = self._key(module, name, node)
                        self.routers[key] = JSRouter(
                            key=key,
                            file=module.file,
                            application=not constructor.endswith(".Router"),
                        )
                        if not constructor.endswith(".Router"):
                            index.entry_points.add(module.file)
        # Applications commonly pass their router to a separate routes(app) function.
        changed = True
        while changed:
            changed = False
            for module in index.modules.values():
                for call in walk(module.tree.root_node, "call_expression"):
                    target = index.function(module, call_name(call))
                    if not target:
                        continue
                    owner, handler = target
                    params = field(handler, "parameters")
                    if not params:
                        continue
                    for param, arg in zip(params.named_children, arguments(call), strict=False):
                        parent = self._router_key(module, text(arg), call)
                        if not parent:
                            continue
                        binding = text(field(param, "pattern")) or text(param)
                        key = f"{owner.file}:{handler.start_byte}:{binding}"
                        if key not in self.routers:
                            self.routers[key] = JSRouter(key=key, file=owner.file)
                            changed = True
                        mount = JSMount(parent=parent, child=key, prefix="")
                        if mount not in self.mounts:
                            self.mounts.append(mount)
        # Discover Fastify plugin parameters before examining the plugin's route calls.
        if self.framework == "Fastify":
            changed = True
            while changed:
                changed = False
                for module in index.modules.values():
                    for call in walk(module.tree.root_node, "call_expression"):
                        receiver, _, method = call_name(call).rpartition(".")
                        parent = self._router_key(module, receiver, call)
                        args = arguments(call)
                        if method != "register" or not parent or not args:
                            continue
                        plugin = index.handler(module, args[0])
                        if not plugin:
                            continue
                        owner, handler = plugin
                        params = field(handler, "parameters")
                        if not params or not params.named_children:
                            continue
                        binding = text(field(params.named_children[0], "pattern")) or text(
                            params.named_children[0]
                        )
                        key = f"{owner.file}:{handler.start_byte}:{binding}"
                        options = properties(args[1]) if len(args) > 1 else {}
                        prefix = (
                            index.literal(module, options.get("prefix"))
                            if "prefix" in options
                            else ""
                        )
                        if not isinstance(prefix, str):
                            self._dynamic(module, call, "Fastify plugin prefix")
                            continue
                        if key not in self.routers:
                            self.routers[key] = JSRouter(key=key, file=owner.file)
                            changed = True
                        mount = JSMount(parent=parent, child=key, prefix=prefix)
                        if mount not in self.mounts:
                            self.mounts.append(mount)
        for module in index.modules.values():
            for call in walk(module.tree.root_node, "call_expression"):
                receiver, _, method = call_name(call).rpartition(".")
                parent = self._router_key(module, receiver, call)
                args = arguments(call)
                if not parent or method != "use" or not args:
                    continue
                literal = index.literal(module, args[0])
                prefix = literal if isinstance(literal, str) else ""
                callbacks = args[1:] if isinstance(literal, str) else args
                evidence = auth_evidence(module, callbacks)
                unknown_prefix = (
                    not isinstance(literal, str)
                    and len(args) > 1
                    and not self._router_key(module, text(args[0]), call)
                    and not index.handler(module, args[0])
                    and not auth_evidence(module, [args[0]])
                )
                has_mount = False
                for callback in callbacks:
                    child = self._router_key(module, text(callback), call)
                    if child:
                        self.mounts.append(
                            JSMount(
                                parent=parent,
                                child=child,
                                prefix=None if unknown_prefix else prefix,
                                auth=evidence,
                            )
                        )
                        has_mount = True
                if unknown_prefix and has_mount:
                    self._dynamic(module, call, "Express mount prefix")
                if not has_mount and prefix == "":
                    self.routers[parent].auth.extend(evidence)
        contexts: dict[str, list[tuple[str, list[AuthInfo]]]] = {key: [] for key in self.routers}

        def visit(key: str, prefix: str, auth: list[AuthInfo], visited: set[str]) -> None:
            if key in visited:
                return
            inherited = auth + self.routers[key].auth
            context = (prefix, inherited)
            if context not in contexts[key]:
                contexts[key].append(context)
            for mount in self.mounts:
                if mount.parent == key and mount.prefix is not None:
                    visit(
                        mount.child,
                        join_path(prefix, mount.prefix),
                        inherited + mount.auth,
                        visited | {key},
                    )

        mounted = {mount.child for mount in self.mounts}
        for key in self.routers:
            if key not in mounted:
                visit(key, "", [], set())
        result = []
        for module in index.modules.values():
            for call in walk(module.tree.root_node, "call_expression"):
                receiver, _, method = call_name(call).rpartition(".")
                args = arguments(call)
                route_path: object = None
                function = field(call, "function")
                chained = field(function, "object") if function else None
                if chained and chained.type == "call_expression":
                    chain = self._chain(module, chained)
                    if chain:
                        receiver, route_path = chain
                route_key = self._router_key(module, receiver, call)
                if not route_key:
                    continue
                route_auth: list[AuthInfo] = []
                methods = [method.upper()]
                handler_node: Node | None = None
                if method.lower() in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                    "all",
                }:
                    if route_path is None:
                        route_path = index.literal(module, args[0]) if args else None
                        callbacks = args[1:]
                    else:
                        callbacks = args
                    if not callbacks:
                        continue
                    handler_node = callbacks[-1]
                    route_auth = auth_evidence(module, callbacks[:-1])
                    if self.framework == "Fastify" and len(callbacks) > 1:
                        options = properties(callbacks[0])
                        route_auth.extend(
                            auth_evidence(module, [options["preHandler"]])
                            if "preHandler" in options
                            else []
                        )
                    if method.lower() == "all":
                        methods = ["ANY"]
                elif self.framework == "Fastify" and method == "route" and args:
                    options = properties(args[0])
                    route_path = index.literal(module, options.get("url") or options.get("path"))
                    verbs = index.literal(module, options.get("method"))
                    methods = [
                        str(verb).upper()
                        for verb in (verbs if isinstance(verbs, list) else [verbs])
                        if isinstance(verb, str)
                    ]
                    handler_node = options.get("handler")
                    route_auth = (
                        auth_evidence(module, [options["preHandler"]])
                        if "preHandler" in options
                        else []
                    )
                else:
                    continue
                paths = route_path if isinstance(route_path, list) else [route_path]
                if not all(isinstance(path, str) for path in paths):
                    self._dynamic(module, call, "route path")
                    continue
                resolved = index.handler(module, handler_node) if handler_node else None
                if not resolved:
                    index.diagnostics.append(
                        Diagnostic(
                            file=module.file,
                            line=call.start_point.row + 1,
                            message="Route handler could not be resolved statically",
                        )
                    )
                    continue
                owner, handler = resolved
                for prefix, auth in contexts[route_key]:
                    for path in paths:
                        full_path = join_path(prefix, str(path))
                        for verb in methods:
                            result.append(
                                CSTEndpoint(
                                    endpoint=Endpoint(
                                        method=verb,
                                        path=full_path,
                                        handler_name=index.symbol(owner, handler)
                                        or text(handler_node)
                                        if handler.type
                                        not in {"arrow_function", "function_expression"}
                                        else f"<handler@{handler.start_point.row + 1}>",
                                        file=owner.file,
                                        line=handler.start_point.row + 1,
                                        framework=self.framework,
                                        parameters=path_parameters(full_path)
                                        + request_parameters(index, owner, handler),
                                        auth=auth + route_auth,
                                    ),
                                    module=owner,
                                    handler=handler,
                                )
                            )
        return result

    def _dynamic(self, module: CSTModule, node: Node, what: str) -> None:
        self.index.diagnostics.append(
            Diagnostic(
                file=module.file,
                line=node.start_point.row + 1,
                message=f"Dynamic {what} cannot be resolved",
            )
        )

    def _key(self, module: CSTModule, name: str, node: Node) -> str:
        return f"{module.file}:{scope(node)}:{name}"

    def _router_key(
        self,
        module: CSTModule,
        name: str,
        node: Node,
        visited: set[tuple[str, str, int]] | None = None,
    ) -> str | None:
        visited = visited or set()
        visit_key = module.file, name, scope(node)
        if visit_key in visited:
            return None
        visited = visited | {visit_key}
        wrapped = next(
            (
                child
                for child in walk(
                    node, "await_expression", "parenthesized_expression", "as_expression"
                )
                if text(child) == name
            ),
            None,
        )
        if wrapped and wrapped.named_children:
            wrapped_value = wrapped.named_children[0]
            return self._router_key(module, text(wrapped_value), wrapped_value, visited)
        for key in [self._key(module, name, node), f"{module.file}:-1:{name}"]:
            if key in self.routers:
                return key
        if name in module.imports:
            path, symbol = module.imports[name]
            owner = self.index.imported_module(path)
            if owner:
                owner, symbol = self.index.exported_symbol(owner, symbol)
                key = f"{owner.file}:-1:{symbol}"
                if key in self.routers:
                    return key
                value = self.index.constant(owner, symbol, owner.tree.root_node)
                if value:
                    return self._router_key(owner, text(value), value, visited)
        # Follow a statically returned router from a local/imported factory.
        expression = next(
            (child for child in walk(node, "call_expression") if text(child) == name), None
        )
        if expression:
            target = self.index.function(module, call_name(expression))
            if target:
                owner, handler = target
                returns = list(walk(handler, "return_statement"))
                if len(returns) == 1 and returns[0].named_children:
                    value = returns[0].named_children[0]
                    return self._router_key(owner, text(value), value, visited)
        for declaration in walk(module.tree.root_node, "variable_declarator"):
            if text(field(declaration, "name")) == name and scope(declaration) in {scope(node), -1}:
                value = field(declaration, "value")
                if value:
                    return self._router_key(module, text(value), value, visited)
        return None

    def _chain(self, module: CSTModule, call: Node) -> tuple[str, object] | None:
        name = call_name(call)
        if name.endswith(".route"):
            args = arguments(call)
            return name.removesuffix(".route"), self.index.literal(
                module, args[0]
            ) if args else None
        function = field(call, "function")
        receiver = field(function, "object") if function else None
        return (
            self._chain(module, receiver)
            if receiver and receiver.type == "call_expression"
            else None
        )


class FastifyExtractor(ExpressExtractor):
    framework = "Fastify"
    constructors = {"fastify"}
