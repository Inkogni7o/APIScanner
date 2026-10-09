"""NestJS and Spring annotated controllers, mappings, inputs and auth evidence."""

from tree_sitter import Node

from adscan.extractors.fastapi import join_path
from adscan.extractors.python_web import path_parameters
from adscan.models import AuthInfo, Diagnostic, Endpoint, Parameter
from adscan.parsers.cst import (
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    annotation_arguments,
    annotation_name,
    annotations,
    arguments,
    call_name,
    field,
    properties,
    text,
    walk,
)


def values(index: CSTIndex, module: CSTModule, node: Node | None, default: str = "") -> list[str]:
    if node is None:
        return [default]
    value = index.literal(module, node)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [str(item) for item in value]
    return []


class NestJSExtractor:
    framework = "NestJS"

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        global_prefixes: set[str] = set()
        dynamic_prefix = False
        for module in index.modules.values():
            apps = set()
            for declaration in walk(module.tree.root_node, "variable_declarator"):
                value = field(declaration, "value")
                if value and any(
                    index.resolve(module, call_name(call)) == "@nestjs/core.NestFactory.create"
                    for call in walk(value, "call_expression")
                ):
                    apps.add(text(field(declaration, "name")))
                    index.entry_points.add(module.file)
            for call in walk(module.tree.root_node, "call_expression"):
                receiver, _, method = call_name(call).rpartition(".")
                if receiver in apps and method == "setGlobalPrefix":
                    args = arguments(call)
                    prefix_value = index.literal(module, args[0]) if args else None
                    if isinstance(prefix_value, str):
                        global_prefixes.add(prefix_value)
                    else:
                        dynamic_prefix = True
                        index.diagnostics.append(
                            Diagnostic(
                                file=module.file,
                                line=call.start_point.row + 1,
                                message="Dynamic NestJS global prefix cannot be resolved",
                            )
                        )
        if dynamic_prefix and not global_prefixes:
            return []
        prefixes = sorted(global_prefixes) or [""]
        result = []
        for module in index.modules.values():
            for cls in walk(module.tree.root_node, "class_declaration"):
                controller = next(
                    (
                        node
                        for node in annotations(cls)
                        if index.resolve(module, annotation_name(node))
                        == "@nestjs/common.Controller"
                    ),
                    None,
                )
                if not controller:
                    continue
                args = annotation_arguments(controller)
                path_node = (
                    properties(args[0]).get("path")
                    if args and args[0].type == "object"
                    else args[0]
                    if args
                    else None
                )
                class_paths = values(index, module, path_node)
                class_auth = self._auth(index, module, annotations(cls))
                body = field(cls, "body")
                if body is None:
                    continue
                for handler in body.named_children:
                    if handler.type != "method_definition":
                        continue
                    for annotation in annotations(handler):
                        name = index.resolve(module, annotation_name(annotation))
                        if not name.startswith("@nestjs/common.") or name.rsplit(".", 1)[
                            -1
                        ] not in {
                            "Get",
                            "Post",
                            "Put",
                            "Patch",
                            "Delete",
                            "Options",
                            "Head",
                            "All",
                        }:
                            continue
                        verb = name.rsplit(".", 1)[-1].upper()
                        args = annotation_arguments(annotation)
                        routes = values(index, module, args[0] if args else None)
                        if not routes or not class_paths:
                            index.diagnostics.append(
                                Diagnostic(
                                    file=module.file,
                                    line=annotation.start_point.row + 1,
                                    message="Dynamic NestJS controller path cannot be resolved",
                                )
                            )
                        for prefix in prefixes:
                            for class_path in class_paths:
                                for route in routes:
                                    path = join_path(join_path(prefix, class_path), route)
                                    result.append(
                                        CSTEndpoint(
                                            endpoint=Endpoint(
                                                method="ANY" if verb == "ALL" else verb,
                                                path=path,
                                                handler_name=text(field(cls, "name"))
                                                + "."
                                                + text(field(handler, "name")),
                                                file=module.file,
                                                line=handler.start_point.row + 1,
                                                framework=self.framework,
                                                parameters=self._parameters(
                                                    index, module, handler, path
                                                ),
                                                auth=class_auth
                                                + self._auth(index, module, annotations(handler)),
                                            ),
                                            module=module,
                                            handler=handler,
                                        )
                                    )
        return result

    def _auth(self, index: CSTIndex, module: CSTModule, nodes: list[Node]) -> list[AuthInfo]:
        return [
            AuthInfo(name=text(node), kind="guard", file=module.file, line=node.start_point.row + 1)
            for node in nodes
            if index.resolve(module, annotation_name(node)) == "@nestjs/common.UseGuards"
        ]

    def _parameters(
        self, index: CSTIndex, module: CSTModule, handler: Node, path: str
    ) -> list[Parameter]:
        result = path_parameters(path)
        params = field(handler, "parameters")
        locations = {
            "Param": "path",
            "Query": "query",
            "Body": "body",
            "Headers": "header",
            "UploadedFile": "file",
            "UploadedFiles": "file",
        }
        for param in params.named_children if params else []:
            for annotation in annotations(param):
                canonical = index.resolve(module, annotation_name(annotation))
                name = canonical.rsplit(".", 1)[-1]
                if canonical.startswith("@nestjs/common.") and name in locations:
                    args = annotation_arguments(annotation)
                    alias = index.literal(module, args[0]) if args else None
                    binding = text(field(param, "pattern"))
                    wire_name = alias if isinstance(alias, str) else binding
                    result = [
                        item
                        for item in result
                        if not (item.name == wire_name and item.location == locations[name])
                    ]
                    result.append(
                        Parameter(
                            name=binding,
                            alias=alias if isinstance(alias, str) else None,
                            location=locations[name],
                            type=text(field(param, "type")).removeprefix(":").strip() or None,
                            required=locations[name] == "path" or None,
                        )
                    )
        return result


class SpringExtractor:
    framework = "Spring MVC"

    def extract(self, index: CSTIndex) -> list[CSTEndpoint]:
        result = []
        for module in index.modules.values():
            if module.language != "java":
                continue
            for cls in walk(module.tree.root_node, "class_declaration"):
                class_annotations = annotations(cls)
                if not any(
                    self._canonical(index, module, node)
                    in {
                        "org.springframework.web.bind.annotation.RestController",
                        "org.springframework.stereotype.Controller",
                    }
                    for node in class_annotations
                ):
                    continue
                index.entry_points.add(module.file)
                mapping = next(
                    (
                        node
                        for node in class_annotations
                        if self._canonical(index, module, node).endswith(".RequestMapping")
                    ),
                    None,
                )
                class_paths = self._paths(index, module, mapping) if mapping else [""]
                class_methods = self._verbs(mapping) if mapping else ["ANY"]
                body = field(cls, "body")
                for handler in body.named_children if body else []:
                    if handler.type != "method_declaration":
                        continue
                    for annotation in annotations(handler):
                        canonical = self._canonical(index, module, annotation)
                        if not canonical.startswith(
                            "org.springframework.web.bind.annotation."
                        ) or canonical.rsplit(".", 1)[-1] not in {
                            "RequestMapping",
                            "GetMapping",
                            "PostMapping",
                            "PutMapping",
                            "PatchMapping",
                            "DeleteMapping",
                        }:
                            continue
                        paths = self._paths(index, module, annotation)
                        verbs = self._verbs(annotation)
                        if verbs == ["ANY"]:
                            verbs = class_methods
                        elif class_methods != ["ANY"]:
                            verbs = [verb for verb in verbs if verb in class_methods]
                        if not paths or not class_paths:
                            index.diagnostics.append(
                                Diagnostic(
                                    file=module.file,
                                    line=annotation.start_point.row + 1,
                                    message="Dynamic Spring request mapping cannot be resolved",
                                )
                            )
                        for class_path in class_paths:
                            for route in paths:
                                path = join_path(class_path, route)
                                for verb in verbs:
                                    result.append(
                                        CSTEndpoint(
                                            endpoint=Endpoint(
                                                method=verb,
                                                path=path,
                                                handler_name=text(field(cls, "name"))
                                                + "."
                                                + text(field(handler, "name")),
                                                file=module.file,
                                                line=handler.start_point.row + 1,
                                                framework=self.framework,
                                                parameters=self._parameters(
                                                    index, module, handler, path
                                                ),
                                                auth=self._auth(
                                                    index,
                                                    module,
                                                    class_annotations + annotations(handler),
                                                ),
                                            ),
                                            module=module,
                                            handler=handler,
                                        )
                                    )
        return result

    def _canonical(self, index: CSTIndex, module: CSTModule, node: Node) -> str:
        name = annotation_name(node)
        resolved = index.resolve(module, name)
        if resolved != name or "." in name:
            return resolved
        for package in (
            "org.springframework.web.bind.annotation",
            "org.springframework.stereotype",
            "org.springframework.security.access.prepost",
            "org.springframework.security.access.annotation",
            "jakarta.annotation.security",
            "javax.annotation.security",
        ):
            if package + ".*" in module.aliases:
                valid = (
                    {
                        "RestController",
                        "RequestMapping",
                        "GetMapping",
                        "PostMapping",
                        "PutMapping",
                        "PatchMapping",
                        "DeleteMapping",
                        "RequestParam",
                        "PathVariable",
                        "RequestHeader",
                        "CookieValue",
                        "RequestBody",
                        "RequestPart",
                    }
                    if package.endswith("web.bind.annotation")
                    else {"Controller"}
                    if package.endswith("stereotype")
                    else {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed"}
                )
                if name in valid:
                    return package + "." + name
        return name

    def _paths(self, index: CSTIndex, module: CSTModule, node: Node) -> list[str]:
        args = annotation_arguments(node)
        options = properties(field(node, "arguments"))
        path_node = (
            options.get("path")
            or options.get("value")
            or (args[0] if args and args[0].type != "element_value_pair" else None)
        )
        return values(index, module, path_node)

    def _verbs(self, node: Node) -> list[str]:
        name = annotation_name(node).rsplit(".", 1)[-1]
        if name != "RequestMapping":
            return [name.removesuffix("Mapping").upper()]
        method = properties(field(node, "arguments")).get("method")
        if method is None:
            return ["ANY"]
        return [
            text(child).rsplit(".", 1)[-1]
            for child in (
                method.named_children
                if method.type == "element_value_array_initializer"
                else [method]
            )
        ]

    def _auth(self, index: CSTIndex, module: CSTModule, nodes: list[Node]) -> list[AuthInfo]:
        result = []
        for node in nodes:
            canonical = self._canonical(index, module, node)
            if canonical.rsplit(".", 1)[-1] in {
                "PreAuthorize",
                "Secured",
                "RolesAllowed",
            } and canonical.startswith(
                (
                    "org.springframework.security.",
                    "jakarta.annotation.security.",
                    "javax.annotation.security.",
                )
            ):
                args = annotation_arguments(node)
                value = index.literal(module, args[0]) if args else None
                if isinstance(value, str) and value in {"permitAll()", "true"}:
                    continue
                result.append(
                    AuthInfo(
                        name=text(node),
                        kind="annotation",
                        file=module.file,
                        line=node.start_point.row + 1,
                    )
                )
        return result

    def _parameters(
        self, index: CSTIndex, module: CSTModule, handler: Node, path: str
    ) -> list[Parameter]:
        result = path_parameters(path)
        params = field(handler, "parameters")
        locations = {
            "PathVariable": "path",
            "RequestParam": "query",
            "RequestHeader": "header",
            "CookieValue": "cookie",
            "RequestBody": "body",
            "RequestPart": "file",
        }
        for param in params.named_children if params else []:
            for annotation in annotations(param):
                canonical = self._canonical(index, module, annotation)
                name = canonical.rsplit(".", 1)[-1]
                if (
                    not canonical.startswith("org.springframework.web.bind.annotation.")
                    or name not in locations
                ):
                    continue
                args = annotation_arguments(annotation)
                options = properties(field(annotation, "arguments"))
                alias_node = (
                    options.get("name")
                    or options.get("value")
                    or (args[0] if args and args[0].type != "element_value_pair" else None)
                )
                alias = index.literal(module, alias_node)
                binding = text(field(param, "name"))
                required = (
                    index.literal(module, options["required"])
                    if "required" in options
                    else "defaultValue" not in options
                )
                result = [
                    item
                    for item in result
                    if not (item.name == (alias or binding) and item.location == locations[name])
                ]
                result.append(
                    Parameter(
                        name=binding,
                        alias=alias if isinstance(alias, str) else None,
                        location=locations[name],
                        type=text(field(param, "type")) or None,
                        required=required if isinstance(required, bool) else None,
                    )
                )
        return result
