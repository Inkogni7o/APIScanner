"""Static FastAPI routes, router inclusion graph, dependencies and signature inputs."""

import ast
import re
from collections.abc import Callable

from pydantic import BaseModel, Field

from adscan.analysis.auth import dependency_calls, detect_auth
from adscan.extractors.base import ExtractedEndpoint
from adscan.models import AuthInfo, Diagnostic, Endpoint, Parameter
from adscan.parsers.python import FunctionNode, PythonIndex, PythonModule, dotted_name, keyword

METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
INPUT_MARKERS = {
    "Path": "path",
    "Query": "query",
    "Body": "body",
    "Form": "body",
    "Header": "header",
    "Cookie": "cookie",
    "File": "file",
}


def join_path(*parts: str) -> str:
    """Compose prefixes while preserving the route's significant trailing slash."""
    nonempty = [part for part in parts if part]
    if not nonempty:
        return "/"
    joined = "/" + "/".join(part.strip("/") for part in nonempty if part.strip("/"))
    if nonempty[-1].endswith("/") and joined != "/":
        joined += "/"
    return joined


class Router(BaseModel):
    name: str
    prefix: str
    application: bool
    module: PythonModule
    auth: list[AuthInfo] = Field(default_factory=list)


class Mount(BaseModel):
    parent: str
    child: str
    prefix: str
    auth: list[AuthInfo]


class FastAPIExtractor:
    """Resolve statically named routers across modules and all their mount prefixes."""

    framework = "FastAPI"

    def extract(self, index: PythonIndex) -> list[ExtractedEndpoint]:
        routers: dict[str, Router] = {}
        mounts: list[Mount] = []
        uncertain_mounts: set[str] = set()
        for module in index.modules.values():
            value: ast.expr | None
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Assign):
                    value, targets = node.value, node.targets
                elif isinstance(node, ast.AnnAssign):
                    value, targets = node.value, [node.target]
                else:
                    continue
                if not isinstance(value, ast.Call):
                    continue
                constructor = index.resolve(module, dotted_name(value.func))
                if constructor not in {"fastapi.FastAPI", "fastapi.APIRouter"}:
                    continue
                if constructor == "fastapi.FastAPI":
                    index.entry_points.add(module.file)
                prefix_node = keyword(value, "prefix")
                prefix = index.literal(module, prefix_node) if prefix_node else ""
                if not isinstance(prefix, str):
                    self._warn(index, module, node, "Dynamic router prefix: routes skipped")
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        name = index.resolve(module, target.id)
                        if name in routers:
                            self._warn(index, module, node, "Repeated router binding is ambiguous")
                        routers[name] = Router(
                            name=name,
                            prefix=prefix,
                            application=constructor == "fastapi.FastAPI",
                            module=module,
                            auth=detect_auth(index, module, keyword(value, "dependencies")),
                        )
        for module in index.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "include_router":
                    continue
                parent = index.resolve(module, dotted_name(node.func.value))
                child_node = node.args[0] if node.args else keyword(node, "router")
                child = index.resolve(module, dotted_name(child_node))
                if parent not in routers or child not in routers:
                    self._warn(index, module, node, "Unresolved include_router target")
                    continue
                prefix_node = keyword(node, "prefix")
                prefix = index.literal(module, prefix_node) if prefix_node else ""
                if not isinstance(prefix, str):
                    self._warn(index, module, node, "Dynamic include_router prefix: mount skipped")
                    uncertain_mounts.add(child)
                    continue
                mounts.append(
                    Mount(
                        parent=parent,
                        child=child,
                        prefix=prefix,
                        auth=detect_auth(index, module, keyword(node, "dependencies")),
                    )
                )

        parents: dict[str, list[Mount]] = {}
        for mount in mounts:
            parents.setdefault(mount.child, []).append(mount)

        def prefixes(name: str, visited: frozenset[str]) -> list[tuple[str, list[AuthInfo]]]:
            if name in visited:
                index.diagnostics.append(
                    Diagnostic(file=routers[name].module.file, message="Router include cycle")
                )
                return []
            router = routers[name]
            if name not in parents:
                if name in uncertain_mounts:
                    return []
                return [(router.prefix, router.auth)]
            result: list[tuple[str, list[AuthInfo]]] = []
            for mount in parents[name]:
                for prefix, auth in prefixes(mount.parent, visited | {name}):
                    result.append(
                        (
                            join_path(prefix, mount.prefix, router.prefix).rstrip("/"),
                            auth + mount.auth + router.auth,
                        )
                    )
            return result

        result: list[ExtractedEndpoint] = []
        for module in index.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        result.extend(
                            self._route(index, module, node, decorator, routers, prefixes)
                        )
            # add_api_route('/path', handler, methods=[...]) uses the same conversion.
            for call in ast.walk(module.tree):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr != "add_api_route":
                    continue
                handler_expr = call.args[1] if len(call.args) > 1 else keyword(call, "endpoint")
                resolved = index.function(index.resolve(module, dotted_name(handler_expr)))
                if resolved:
                    owner, handler = resolved
                    result.extend(
                        self._route(index, module, handler, call, routers, prefixes, owner)
                    )
                else:
                    self._warn(index, module, call, "Unresolved add_api_route handler")
        # Multiple mounts can converge on the same path; keep genuinely different handlers.
        unique: dict[tuple[str, str, str, int], ExtractedEndpoint] = {}
        for item in result:
            endpoint = item.endpoint
            key = endpoint.method, endpoint.path, endpoint.file, endpoint.line
            if key in unique:
                unique[key].endpoint.auth = self._unique_auth(
                    unique[key].endpoint.auth + endpoint.auth
                )
            else:
                unique[key] = item
        return list(unique.values())

    def _route(
        self,
        index: PythonIndex,
        module: PythonModule,
        handler: FunctionNode,
        call: ast.Call,
        routers: dict[str, Router],
        prefixes: Callable[[str, frozenset[str]], list[tuple[str, list[AuthInfo]]]],
        owner: PythonModule | None = None,
    ) -> list[ExtractedEndpoint]:
        if not isinstance(call.func, ast.Attribute):
            return []
        method = call.func.attr.lower()
        if method not in METHODS | {"api_route", "add_api_route"}:
            return []
        receiver = index.resolve(module, dotted_name(call.func.value))
        if receiver not in routers:
            return []
        path_node = call.args[0] if call.args else keyword(call, "path")
        path = index.literal(module, path_node)
        if not isinstance(path, str):
            self._warn(index, module, call, "Dynamic route path: route skipped")
            return []
        if method in {"api_route", "add_api_route"}:
            methods_node = keyword(call, "methods")
            methods_value = index.literal(module, methods_node) if methods_node else ["GET"]
            if (
                not isinstance(methods_value, list)
                or not methods_value
                or any(
                    not isinstance(item, str) or item.lower() not in METHODS
                    for item in methods_value
                )
            ):
                self._warn(index, module, call, "Unresolved HTTP methods: route skipped")
                return []
            methods = [str(item).upper() for item in methods_value]
        else:
            methods = [method.upper()]
        owner = owner or module
        result: list[ExtractedEndpoint] = []
        for prefix, inherited_auth in prefixes(receiver, frozenset()):
            full_path = join_path(prefix, path)
            auth = self._unique_auth(
                inherited_auth
                + detect_auth(index, module, keyword(call, "dependencies"))
                + detect_auth(index, owner, handler.args)
            )
            for http_method in methods:
                endpoint = Endpoint(
                    method=http_method,
                    path=full_path,
                    handler_name=handler.name,
                    file=owner.file,
                    line=handler.lineno,
                    framework=self.framework,
                    parameters=self._parameters(index, owner, handler, full_path),
                    auth=auth,
                )
                result.append(ExtractedEndpoint(endpoint=endpoint, module=owner, handler=handler))
        return result

    @staticmethod
    def _unique_auth(auth: list[AuthInfo]) -> list[AuthInfo]:
        return list({(item.name, item.kind, item.file, item.line): item for item in auth}.values())

    @staticmethod
    def _warn(index: PythonIndex, module: PythonModule, node: ast.AST, message: str) -> None:
        index.diagnostics.append(
            Diagnostic(file=module.file, message=message, line=getattr(node, "lineno", None))
        )

    def _parameters(
        self,
        index: PythonIndex,
        module: PythonModule,
        handler: FunctionNode,
        path: str,
    ) -> list[Parameter]:
        path_names = set(re.findall(r"\{([^}:]+)(?::[^}]+)?\}", path))
        positional = handler.args.posonlyargs + handler.args.args
        defaults: dict[str, ast.expr | None] = dict.fromkeys(item.arg for item in positional)
        default: ast.expr | None
        for argument, default in zip(
            positional[len(positional) - len(handler.args.defaults) :],
            handler.args.defaults,
            strict=True,
        ):
            defaults[argument.arg] = default
        defaults.update(
            {
                argument.arg: default
                for argument, default in zip(
                    handler.args.kwonlyargs, handler.args.kw_defaults, strict=True
                )
            }
        )
        result: list[Parameter] = []
        for argument in positional + handler.args.kwonlyargs:
            if argument.arg in {"self", "cls"}:
                continue
            default = defaults.get(argument.arg)
            annotation = argument.annotation
            if (annotation and dependency_calls(index, module, annotation)) or (
                default and dependency_calls(index, module, default)
            ):
                continue
            marker: ast.Call | None = None
            type_node = annotation
            if isinstance(annotation, ast.Subscript) and index.resolve(
                module, dotted_name(annotation.value)
            ) in {"typing.Annotated", "typing_extensions.Annotated"}:
                elements = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else []
                if elements:
                    type_node = elements[0]
                    marker = next(
                        (item for item in elements[1:] if isinstance(item, ast.Call)), None
                    )
            if isinstance(default, ast.Call):
                marker = default
            marker_name = (
                index.resolve(module, dotted_name(marker.func)).rsplit(".", 1)[-1] if marker else ""
            )
            if (
                marker
                and index.resolve(module, dotted_name(marker.func)) != f"fastapi.{marker_name}"
            ):
                marker_name = ""
            type_name = ast.unparse(type_node) if type_node else None
            base_type = index.resolve(module, dotted_name(type_node))
            if base_type in {
                "fastapi.Request",
                "starlette.requests.Request",
                "fastapi.Response",
                "fastapi.BackgroundTasks",
            }:
                continue
            location = (
                "path" if argument.arg in path_names else INPUT_MARKERS.get(marker_name, "query")
            )
            if "UploadFile" in (type_name or ""):
                location = "file"
            if (
                location == "query"
                and not marker_name
                and (self._is_model(index, module, type_node) or self._is_container(type_node))
            ):
                location = "body"
            required = default is None or (
                isinstance(default, ast.Constant) and default.value is Ellipsis
            )
            if marker and marker_name in INPUT_MARKERS and marker is default:
                marker_default = marker.args[0] if marker.args else keyword(marker, "default")
                required = marker_default is None or (
                    isinstance(marker_default, ast.Constant) and marker_default.value is Ellipsis
                )
            if location == "path":
                required = True
            alias = index.literal(module, keyword(marker, "alias")) if marker else None
            if location == "header" and alias is None:
                convert = (
                    index.literal(module, keyword(marker, "convert_underscores"))
                    if marker
                    else None
                )
                if convert is not False:
                    alias = argument.arg.replace("_", "-")
            result.append(
                Parameter(
                    name=argument.arg,
                    location=location,
                    type=type_name,
                    required=required,
                    alias=alias if isinstance(alias, str) else None,
                )
            )
        return result

    @staticmethod
    def _is_container(annotation: ast.expr | None) -> bool:
        if isinstance(annotation, ast.Subscript):
            annotation = annotation.value
        return dotted_name(annotation).rsplit(".", 1)[-1] in {
            "dict",
            "list",
            "tuple",
            "set",
            "frozenset",
            "Dict",
            "List",
            "Tuple",
            "Set",
            "Mapping",
        }

    def _is_model(
        self,
        index: PythonIndex,
        module: PythonModule,
        annotation: ast.expr | None,
        visited: frozenset[str] = frozenset(),
    ) -> bool:
        if annotation is None:
            return False
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode="eval").body
            except SyntaxError:
                return False
        if isinstance(annotation, ast.BinOp):
            return self._is_model(index, module, annotation.left, visited) or self._is_model(
                index, module, annotation.right, visited
            )
        if isinstance(annotation, ast.Subscript):
            return self._is_model(index, module, annotation.slice, visited)
        name = index.resolve(module, dotted_name(annotation))
        if name == "pydantic.BaseModel":
            return True
        if name in visited:
            return False
        for target in index.modules.values():
            for node in target.tree.body:
                if isinstance(node, ast.ClassDef) and f"{target.name}.{node.name}" == name:
                    return any(
                        self._is_model(index, target, base, visited | {name}) for base in node.bases
                    )
        return False
