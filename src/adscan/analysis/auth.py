"""FastAPI dependency evidence; recognizing a name does not prove authorization."""

import ast
import re

from adscan.models import AuthInfo
from adscan.parsers.python import PythonIndex, PythonModule, dotted_name

AUTH_NAME = re.compile(
    r"auth|current_user|logged_in|login|jwt|token|oauth|permission|admin|role", re.I
)


def dependency_calls(index: PythonIndex, module: PythonModule, node: ast.AST) -> list[ast.Call]:
    return [
        item
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and index.resolve(module, dotted_name(item.func)) in {"fastapi.Depends", "fastapi.Security"}
    ]


def detect_auth(index: PythonIndex, module: PythonModule, node: ast.AST | None) -> list[AuthInfo]:
    """Recognize Security and auth-like Depends throughout dependency chains."""
    if node is None:
        return []
    result: list[AuthInfo] = []
    seen: set[str] = set()

    def visit(owner: PythonModule, expression: ast.AST, depth: int) -> None:
        if depth > 5:
            return
        for call in dependency_calls(index, owner, expression):
            dependency = (
                call.args[0]
                if call.args
                else next((item.value for item in call.keywords if item.arg == "dependency"), None)
            )
            name = dotted_name(dependency)
            canonical = index.resolve(owner, name)
            if canonical in seen:
                continue
            seen.add(canonical)
            security = index.resolve(owner, dotted_name(call.func)) == "fastapi.Security"
            constructor: ast.expr | None = owner.constants.get(name)
            if constructor is None and canonical:
                for target in index.modules.values():
                    if canonical.startswith(target.name + "."):
                        constructor = target.constants.get(canonical[len(target.name) + 1 :])
                        break
            security_object = isinstance(constructor, ast.Call) and bool(
                re.search(r"OAuth2|HTTPBearer|HTTPBasic|APIKey", dotted_name(constructor.func))
            )
            if security or AUTH_NAME.search(name) or security_object:
                result.append(
                    AuthInfo(
                        name=name or "implicit security dependency",
                        kind="Security" if security else "Depends",
                        file=owner.file,
                        line=call.lineno,
                        confidence="HIGH" if security or security_object else "MEDIUM",
                    )
                )
            target_function = index.function(canonical)
            if target_function:
                visit(target_function[0], target_function[1].args, depth + 1)

    visit(module, node, 0)
    return result
