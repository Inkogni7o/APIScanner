"""Django URLconfs, class views and DRF routers/actions, without importing settings."""

import ast

from pydantic import BaseModel, ConfigDict, Field

from adscan.extractors.base import ExtractedEndpoint
from adscan.extractors.fastapi import join_path
from adscan.extractors.python_web import HTTP_METHODS, decorator_auth, path_parameters
from adscan.models import AuthInfo, Diagnostic, Endpoint
from adscan.parsers.python import FunctionNode, PythonIndex, PythonModule, dotted_name, keyword


class DRFRouter(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    module: PythonModule
    registrations: list[tuple[str, str]] = Field(default_factory=list)
    trailing_slash: str = "/"


class DjangoExtractor:
    framework = "Django"

    def extract(self, index: PythonIndex) -> list[ExtractedEndpoint]:
        self.index = index
        self.routers: dict[str, DRFRouter] = {}
        self.result: list[ExtractedEndpoint] = []
        for module in index.modules.values():
            for name, value in module.constants.items():
                if isinstance(value, ast.Call) and index.resolve(
                    module, dotted_name(value.func)
                ) in {
                    "rest_framework.routers.DefaultRouter",
                    "rest_framework.routers.SimpleRouter",
                }:
                    slash = index.literal(module, keyword(value, "trailing_slash"))
                    self.routers[f"{module.name}.{name}"] = DRFRouter(
                        module=module, trailing_slash="" if slash is False else "/"
                    )
        for module in index.modules.values():
            for node in ast.walk(module.tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "register"
                    and len(node.args) >= 2
                ):
                    router = self.routers.get(index.resolve(module, dotted_name(node.func.value)))
                    prefix = index.literal(module, node.args[0])
                    if router and isinstance(prefix, str):
                        router.registrations.append(
                            (prefix, index.resolve(module, dotted_name(node.args[1])))
                        )
        included: set[str] = set()
        roots: list[str] = []
        for module in index.modules.values():
            root = index.literal(module, module.constants.get("ROOT_URLCONF"))
            if isinstance(root, str):
                roots.append(root)
            for node in ast.walk(module.tree):
                if (
                    isinstance(node, ast.Call)
                    and index.resolve(module, dotted_name(node.func)) == "django.urls.include"
                    and node.args
                ):
                    include_name = index.literal(module, node.args[0])
                    if isinstance(include_name, str):
                        included.add(include_name)
                    else:
                        resolved = index.resolve(module, dotted_name(node.args[0]))
                        included.add(resolved.removesuffix(".urlpatterns"))
        if not roots:
            roots = [
                module.name
                for module in index.modules.values()
                if "urlpatterns" in module.constants and module.name not in included
            ]
        for name in sorted(set(roots)):
            root_module = index.modules.get(name)
            if root_module and "urlpatterns" in root_module.constants:
                index.entry_points.add(root_module.file)
                self._expand(root_module, root_module.constants["urlpatterns"], "", set())
        # Expose standalone DRF router candidates when no URLconf mounts them.
        if not roots:
            for router in self.routers.values():
                self._router(router, "")
        return self.result

    def _expand(self, module: PythonModule, node: ast.AST, prefix: str, visited: set[str]) -> None:
        if isinstance(node, (ast.List, ast.Tuple)):
            for item in node.elts:
                self._expand(module, item, prefix, visited)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            self._expand(module, node.left, prefix, visited)
            self._expand(module, node.right, prefix, visited)
            return
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = self.index.resolve(module, dotted_name(node))
            if name in visited:
                return
            router = (
                self.routers.get(name.removesuffix(".urls")) if name.endswith(".urls") else None
            )
            if router:
                self._router(router, prefix)
                return
            for owner in self.index.modules.values():
                value = (
                    owner.constants.get(name.removeprefix(owner.name + "."))
                    if name.startswith(owner.name + ".")
                    else None
                )
                if value is not None:
                    self._expand(owner, value, prefix, visited | {name})
                    return
            return
        if not isinstance(node, ast.Call):
            return
        canonical = self.index.resolve(module, dotted_name(node.func))
        if canonical == "django.urls.include" and node.args:
            target = node.args[0]
            include_name = self.index.literal(module, target)
            if isinstance(include_name, str) and include_name not in visited:
                include_module = self.index.modules.get(include_name)
                if include_module and "urlpatterns" in include_module.constants:
                    self._expand(
                        include_module,
                        include_module.constants["urlpatterns"],
                        prefix,
                        visited | {include_name},
                    )
            elif isinstance(target, ast.Tuple) and target.elts:
                self._expand(module, target.elts[0], prefix, visited)
            else:
                self._expand(module, target, prefix, visited)
            return
        if canonical not in {"django.urls.path", "django.urls.re_path"} or len(node.args) < 2:
            return
        route = self.index.literal(module, node.args[0])
        if not isinstance(route, str):
            self.index.diagnostics.append(
                Diagnostic(
                    file=module.file,
                    line=node.lineno,
                    message="Dynamic Django URL pattern cannot be resolved",
                )
            )
            return
        full_path = join_path(prefix, route)
        view = node.args[1]
        if (
            isinstance(view, ast.Call)
            and self.index.resolve(module, dotted_name(view.func)) == "django.urls.include"
        ):
            self._expand(module, view, full_path, visited)
            return
        if canonical.endswith("re_path"):
            full_path = "regex:" + prefix + route
        self._view(module, view, full_path)

    def _class(self, name: str) -> tuple[PythonModule, ast.ClassDef] | None:
        for module in self.index.modules.values():
            for node in module.tree.body:
                if isinstance(node, ast.ClassDef) and f"{module.name}.{node.name}" == name:
                    return module, node
        return None

    def _methods(
        self, module: PythonModule, cls: ast.ClassDef, visited: set[str] | None = None
    ) -> dict[str, tuple[PythonModule, FunctionNode]]:
        visited = (visited or set()) | {f"{module.name}.{cls.name}"}
        result: dict[str, tuple[PythonModule, FunctionNode]] = {}
        for base in cls.bases:
            name = self.index.resolve(module, dotted_name(base))
            parent = self._class(name)
            if parent and name not in visited:
                result.update(self._methods(*parent, visited))
        result.update(
            {
                node.name: (module, node)
                for node in cls.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
        )
        return result

    def _auth(self, module: PythonModule, cls: ast.ClassDef) -> list[AuthInfo]:
        result = []
        for node in cls.body:
            if not isinstance(node, ast.Assign) or not any(
                isinstance(target, ast.Name)
                and target.id in {"permission_classes", "authentication_classes"}
                for target in node.targets
            ):
                continue
            for value in ast.walk(node.value):
                if isinstance(value, (ast.Name, ast.Attribute)):
                    name = self.index.resolve(module, dotted_name(value))
                    if name.rsplit(".", 1)[-1] in {"IsAuthenticated", "IsAdminUser"}:
                        result.append(
                            AuthInfo(
                                name=name, kind="permission", file=module.file, line=node.lineno
                            )
                        )
        return result

    def _bases(
        self, module: PythonModule, cls: ast.ClassDef, visited: set[str] | None = None
    ) -> set[str]:
        visited = (visited or set()) | {f"{module.name}.{cls.name}"}
        bases = {self.index.resolve(module, dotted_name(base)) for base in cls.bases}
        for name in list(bases):
            parent = self._class(name)
            if parent and name not in visited:
                bases.update(self._bases(*parent, visited))
        return bases

    def _inherited(
        self, module: PythonModule, cls: ast.ClassDef, verb: str, method: str, path: str
    ) -> None:
        # The implementation belongs to the external framework; no function body is invented.
        self.result.append(
            ExtractedEndpoint(
                endpoint=Endpoint(
                    method=verb,
                    path=path,
                    handler_name=f"{cls.name}.{method}",
                    file=module.file,
                    line=cls.lineno,
                    framework="Django REST Framework",
                    parameters=path_parameters(path),
                    auth=self._auth(module, cls),
                ),
                module=module,
                handler=None,
            )
        )

    def _add(
        self,
        module: PythonModule,
        handler: FunctionNode,
        method: str,
        path: str,
        framework: str,
        auth: list[AuthInfo] | None = None,
        class_name: str = "",
    ) -> None:
        if self.framework == "Django REST Framework" and framework != self.framework:
            return
        self.result.append(
            ExtractedEndpoint(
                endpoint=Endpoint(
                    method=method,
                    path=path,
                    handler_name=(class_name + "." if class_name else "") + handler.name,
                    file=module.file,
                    line=handler.lineno,
                    framework=framework,
                    parameters=path_parameters(path),
                    auth=(auth or []) + decorator_auth(self.index, module, handler),
                ),
                module=module,
                handler=handler,
            )
        )

    def _view(self, module: PythonModule, node: ast.AST, path: str) -> None:
        name = self.index.resolve(module, dotted_name(node))
        mapping: dict[str, str] = {}
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "as_view"
        ):
            name = self.index.resolve(module, dotted_name(node.func.value))
            if node.args and isinstance(node.args[0], ast.Dict):
                for key, value in zip(node.args[0].keys, node.args[0].values, strict=True):
                    verb, handler = (
                        self.index.literal(module, key),
                        self.index.literal(module, value),
                    )
                    if isinstance(verb, str) and isinstance(handler, str):
                        mapping[verb.upper()] = handler
        cls = self._class(name)
        if cls:
            owner, definition = cls
            bases = self._bases(owner, definition)
            framework = (
                "Django REST Framework"
                if any(base.startswith("rest_framework.") for base in bases)
                else "Django"
            )
            methods = self._methods(owner, definition)
            for verb, handler_name in (
                mapping or {verb: verb.lower() for verb in HTTP_METHODS}
            ).items():
                if handler_name in methods:
                    handler_module, handler = methods[handler_name]
                    self._add(
                        handler_module,
                        handler,
                        verb,
                        path,
                        framework,
                        self._auth(owner, definition),
                        definition.name,
                    )
            generic_methods = {
                "ListAPIView": ["GET"],
                "CreateAPIView": ["POST"],
                "RetrieveAPIView": ["GET"],
                "UpdateAPIView": ["PUT", "PATCH"],
                "DestroyAPIView": ["DELETE"],
                "ListCreateAPIView": ["GET", "POST"],
                "RetrieveUpdateAPIView": ["GET", "PUT", "PATCH"],
                "RetrieveDestroyAPIView": ["GET", "DELETE"],
                "RetrieveUpdateDestroyAPIView": ["GET", "PUT", "PATCH", "DELETE"],
            }
            for base in sorted(bases):
                if base.startswith("rest_framework.generics."):
                    for verb in generic_methods.get(base.rsplit(".", 1)[-1], []):
                        if verb.lower() not in methods:
                            self._inherited(owner, definition, verb, verb.lower(), path)
            return
        function = self.index.function(name)
        if not function:
            return
        owner, handler = function
        verbs = ["ANY"]
        framework = "Django"
        for decorator in handler.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            canonical = self.index.resolve(owner, dotted_name(decorator.func))
            if (
                canonical
                in {
                    "rest_framework.decorators.api_view",
                    "django.views.decorators.http.require_http_methods",
                }
                and decorator.args
            ):
                literal = self.index.literal(owner, decorator.args[0])
                if isinstance(literal, list):
                    verbs = [str(value).upper() for value in literal]
                if canonical.startswith("rest_framework"):
                    framework = "Django REST Framework"
        for decorator in handler.decorator_list:
            canonical = self.index.resolve(owner, dotted_name(decorator))
            if canonical.endswith(".require_GET"):
                verbs = ["GET"]
            elif canonical.endswith(".require_POST"):
                verbs = ["POST"]
            elif canonical.endswith(".require_safe"):
                verbs = ["GET", "HEAD"]
        for verb in verbs:
            self._add(owner, handler, verb, path, framework)

    def _router(self, router: DRFRouter, prefix: str) -> None:
        for route, name in router.registrations:
            cls = self._class(name)
            if not cls:
                continue
            module, definition = cls
            methods = self._methods(module, definition)
            bases = self._bases(module, definition)
            inherited = set()
            if "rest_framework.viewsets.ModelViewSet" in bases:
                inherited.update(
                    {"list", "create", "retrieve", "update", "partial_update", "destroy"}
                )
            if "rest_framework.viewsets.ReadOnlyModelViewSet" in bases:
                inherited.update({"list", "retrieve"})
            mixins = {
                "ListModelMixin": {"list"},
                "CreateModelMixin": {"create"},
                "RetrieveModelMixin": {"retrieve"},
                "UpdateModelMixin": {"update", "partial_update"},
                "DestroyModelMixin": {"destroy"},
            }
            for base in bases:
                if base.startswith("rest_framework.mixins."):
                    inherited.update(mixins.get(base.rsplit(".", 1)[-1], set()))
            attributes = {
                target.id: node.value
                for node in definition.body
                if isinstance(node, ast.Assign)
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            lookup = (
                self.index.literal(module, attributes.get("lookup_url_kwarg"))
                or self.index.literal(module, attributes.get("lookup_field"))
                or "pk"
            )
            collection = join_path(prefix, route).rstrip("/")
            detail = collection + "/{" + str(lookup) + "}"
            for verb, method, path in (
                ("GET", "list", collection),
                ("POST", "create", collection),
                ("GET", "retrieve", detail),
                ("PUT", "update", detail),
                ("PATCH", "partial_update", detail),
                ("DELETE", "destroy", detail),
            ):
                if method in methods:
                    owner, handler = methods[method]
                    self._add(
                        owner,
                        handler,
                        verb,
                        path + router.trailing_slash,
                        "Django REST Framework",
                        self._auth(module, definition),
                        definition.name,
                    )
                elif method in inherited:
                    self._inherited(module, definition, verb, method, path + router.trailing_slash)
            for method, (owner, handler) in methods.items():
                for decorator in handler.decorator_list:
                    if (
                        not isinstance(decorator, ast.Call)
                        or self.index.resolve(owner, dotted_name(decorator.func))
                        != "rest_framework.decorators.action"
                    ):
                        continue
                    is_detail = self.index.literal(owner, keyword(decorator, "detail"))
                    if not isinstance(is_detail, bool):
                        continue
                    suffix = self.index.literal(owner, keyword(decorator, "url_path")) or method
                    verbs = self.index.literal(owner, keyword(decorator, "methods")) or ["get"]
                    if isinstance(suffix, str) and isinstance(verbs, list):
                        for verb in verbs:
                            self._add(
                                owner,
                                handler,
                                str(verb).upper(),
                                join_path(detail if is_detail else collection, suffix)
                                + router.trailing_slash,
                                "Django REST Framework",
                                self._auth(module, definition),
                                definition.name,
                            )


class DRFExtractor(DjangoExtractor):
    framework = "Django REST Framework"
