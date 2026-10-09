"""Shared HTTP input and authentication evidence for Python web frameworks."""

import ast
import re

from adscan.models import AuthInfo, Parameter
from adscan.parsers.python import FunctionNode, PythonIndex, PythonModule, dotted_name

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE")


def path_parameters(path: str) -> list[Parameter]:
    parameters = []
    for match in re.finditer(r"<(?:(\w+):)?(\w+)>|\{(\w+)(?::[^}]+)?\}|:([A-Za-z_]\w*)", path):
        converter, flask_name, brace_name, colon_name = match.groups()
        parameters.append(
            Parameter(
                name=flask_name or brace_name or colon_name,
                location="path",
                type=converter,
                required=True,
            )
        )
    return parameters


def decorator_auth(
    index: PythonIndex, module: PythonModule, handler: FunctionNode
) -> list[AuthInfo]:
    result = []
    for decorator in handler.decorator_list:
        node = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = index.resolve(module, dotted_name(node))
        if (
            name == "rest_framework.decorators.permission_classes"
            and isinstance(decorator, ast.Call)
            and decorator.args
        ):
            for value in ast.walk(decorator.args[0]):
                if isinstance(value, (ast.Name, ast.Attribute)):
                    permission = index.resolve(module, dotted_name(value))
                    if permission.rsplit(".", 1)[-1] in {"IsAuthenticated", "IsAdminUser"}:
                        result.append(
                            AuthInfo(
                                name=permission,
                                kind="permission",
                                file=module.file,
                                line=decorator.lineno,
                            )
                        )
        if any(
            part in name.lower()
            for part in (
                "login_required",
                "permission_required",
                "auth_required",
                "jwt_required",
                "token_required",
            )
        ):
            result.append(
                AuthInfo(name=name, kind="decorator", file=module.file, line=decorator.lineno)
            )
    return result


def request_bindings(
    index: PythonIndex, module: PythonModule, handler: FunctionNode, framework: str
) -> set[str]:
    names = {name for name in module.aliases if index.resolve(module, name) == "flask.request"}
    if "flask" in module.aliases:
        names.add("flask.request")
    arguments = handler.args.posonlyargs + handler.args.args
    if framework in {"Django", "Django REST Framework"}:
        arguments = [argument for argument in arguments if argument.arg not in {"self", "cls"}]
        if arguments:
            names.add(arguments[0].arg)
        names.add("self.request")
    return names
