"""Flask decorators, URL rules and nested Blueprint registrations."""

import ast

from pydantic import BaseModel

from adscan.extractors.base import ExtractedEndpoint
from adscan.extractors.fastapi import join_path
from adscan.extractors.python_web import decorator_auth, path_parameters
from adscan.models import Diagnostic, Endpoint
from adscan.parsers.python import PythonIndex, PythonModule, dotted_name, keyword


class FlaskRouter(BaseModel):
    name: str
    prefix: str
    application: bool
    file: str


class BlueprintMount(BaseModel):
    parent: str
    child: str
    prefix: str | None


class FlaskExtractor:
    framework = "Flask"

    def extract(self, index: PythonIndex) -> list[ExtractedEndpoint]:
        routers: dict[str, FlaskRouter] = {}
        mounts: list[BlueprintMount] = []
        for module in index.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                    continue
                constructor_call = node.value
                constructor = index.resolve(module, dotted_name(constructor_call.func))
                if constructor not in {"flask.Flask", "flask.Blueprint"}:
                    continue
                prefix_node = keyword(constructor_call, "url_prefix")
                prefix = index.literal(module, prefix_node) if prefix_node else ""
                if not isinstance(prefix, str):
                    index.diagnostics.append(
                        Diagnostic(
                            file=module.file,
                            line=node.lineno,
                            message="Dynamic Blueprint prefix cannot be resolved",
                        )
                    )
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = index.resolve(module, target.id)
                        routers[name] = FlaskRouter(
                            name=name,
                            prefix=prefix,
                            application=constructor == "flask.Flask",
                            file=module.file,
                        )
                        if constructor == "flask.Flask":
                            index.entry_points.add(module.file)
        for module in index.modules.values():
            for call in ast.walk(module.tree):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr != "register_blueprint" or not call.args:
                    continue
                parent = index.resolve(module, dotted_name(call.func.value))
                child = index.resolve(module, dotted_name(call.args[0]))
                if parent not in routers or child not in routers:
                    continue
                override = keyword(call, "url_prefix")
                prefix = index.literal(module, override) if override else routers[child].prefix
                if isinstance(prefix, str):
                    mounts.append(BlueprintMount(parent=parent, child=child, prefix=prefix))
                else:
                    index.diagnostics.append(
                        Diagnostic(
                            file=module.file,
                            line=call.lineno,
                            message="Dynamic Blueprint mount cannot be resolved",
                        )
                    )
                    # Mark it mounted so a made-up unprefixed route is not emitted.
                    mounts.append(BlueprintMount(parent=parent, child=child, prefix=None))
        prefixes: dict[str, list[str]] = {name: [] for name in routers}

        def visit(name: str, prefix: str, visited: set[str]) -> None:
            if name in visited or name not in routers:
                return
            if prefix not in prefixes[name]:
                prefixes[name].append(prefix)
            for mount in mounts:
                if mount.parent == name and mount.prefix is not None:
                    visit(mount.child, join_path(prefix, mount.prefix), visited | {name})

        mounted = {mount.child for mount in mounts}
        for name, router in routers.items():
            if router.application or name not in mounted:
                visit(name, router.prefix, set())
        result: list[ExtractedEndpoint] = []

        def add(
            module: PythonModule, call: ast.Call, handler_name: str, method: str | None = None
        ) -> None:
            assert isinstance(call.func, ast.Attribute)
            router = index.resolve(module, dotted_name(call.func.value))
            route_node = call.args[0] if call.args else keyword(call, "rule")
            path = index.literal(module, route_node)
            if router not in routers:
                return
            if not isinstance(path, str):
                index.diagnostics.append(
                    Diagnostic(
                        file=module.file,
                        line=call.lineno,
                        message="Dynamic Flask route cannot be resolved",
                    )
                )
                return
            resolved = index.function(handler_name)
            if not resolved:
                return
            owner, handler = resolved
            methods_node = keyword(call, "methods")
            methods = (
                [method]
                if method
                else index.literal(module, methods_node)
                if methods_node
                else ["GET"]
            )
            if not isinstance(methods, list) or not all(isinstance(item, str) for item in methods):
                index.diagnostics.append(
                    Diagnostic(
                        file=module.file,
                        line=call.lineno,
                        message="Dynamic Flask HTTP methods cannot be resolved",
                    )
                )
                return
            for prefix in prefixes[router]:
                full_path = join_path(prefix, path)
                for verb in methods:
                    result.append(
                        ExtractedEndpoint(
                            endpoint=Endpoint(
                                method=str(verb).upper(),
                                path=full_path,
                                handler_name=handler.name,
                                file=owner.file,
                                line=handler.lineno,
                                framework=self.framework,
                                parameters=path_parameters(full_path),
                                auth=decorator_auth(index, owner, handler),
                            ),
                            module=owner,
                            handler=handler,
                        )
                    )

        for module in index.modules.values():
            for name, handler in module.functions.items():
                for decorator in handler.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(
                        decorator.func, ast.Attribute
                    ):
                        verb = decorator.func.attr
                        if verb == "route" or verb in {
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                            "options",
                            "head",
                        }:
                            add(
                                module,
                                decorator,
                                f"{module.name}.{name}",
                                verb.upper() if verb != "route" else None,
                            )
            for call in ast.walk(module.tree):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "add_url_rule"
                ):
                    view = keyword(call, "view_func") or (
                        call.args[2] if len(call.args) > 2 else None
                    )
                    add(module, call, index.resolve(module, dotted_name(view)))
        return result
