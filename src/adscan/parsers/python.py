"""Python AST and a lightweight cross-module symbol index, with no imports executed."""

import ast
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from adscan.models import Diagnostic

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
BUILTINS = {"open", "eval", "exec", "str", "bytes", "int", "float", "dict", "list", "set"}


def dotted_name(node: ast.AST | None) -> str:
    """Return a dotted identifier only for simple static expressions."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


class PythonModule(BaseModel):
    """A parsed file and its static imports, assignments and function definitions."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    package: str
    file: str
    tree: ast.Module
    text: str
    aliases: dict[str, str] = Field(default_factory=dict)
    constants: dict[str, ast.expr] = Field(default_factory=dict)
    functions: dict[str, FunctionNode] = Field(default_factory=dict)


class PythonIndex:
    """Resolve imports/reexports and literal constants without loading analyzed code."""

    def __init__(self, contents: dict[Path, str], diagnostics: list[Diagnostic]) -> None:
        self.modules: dict[str, PythonModule] = {}
        self.by_file: dict[str, PythonModule] = {}
        self.diagnostics = diagnostics
        self.entry_points: set[str] = set()
        for path, text in sorted(contents.items()):
            if path.suffix != ".py":
                continue
            try:
                tree = ast.parse(text, filename=path.as_posix())
            except SyntaxError as error:
                diagnostics.append(
                    Diagnostic(
                        file=path.as_posix(),
                        message=f"Failed to parse: {error}",
                        line=getattr(error, "lineno", None),
                    )
                )
                continue
            parts = list(path.with_suffix("").parts)
            if parts[0] == "src":
                parts = parts[1:]
            is_package = parts[-1] == "__init__"
            if is_package:
                parts = parts[:-1]
            name = ".".join(parts) or "__root__"
            package = (name if is_package else name.rpartition(".")[0]) if parts else ""
            module = PythonModule(
                name=name, package=package, file=path.as_posix(), tree=tree, text=text
            )
            self.modules[name] = module
            self.by_file[module.file] = module
            self._collect(module)

    def _collect(self, module: PythonModule) -> None:
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    module.aliases[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                package = module.package.split(".") if module.package else []
                if node.level:
                    keep = len(package) - node.level + 1
                    base = ".".join(package[: max(0, keep)])
                    if node.module:
                        base = ".".join(filter(None, (base, node.module)))
                else:
                    base = node.module or ""
                for item in node.names:
                    if item.name != "*":
                        module.aliases[item.asname or item.name] = ".".join(
                            filter(None, (base, item.name))
                        )
        # Constants and alias assignments are module-level, to avoid local shadowing.
        for node in module.tree.body:
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            if value is not None:
                for target in targets:
                    if isinstance(target, ast.Name):
                        module.constants[target.id] = value
                        alias = dotted_name(value)
                        if alias and alias != target.id:
                            module.aliases[target.id] = self.resolve(module, alias)

        def functions(body: list[ast.stmt], prefix: str = "") -> None:
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    module.functions[prefix + node.name] = node
                elif isinstance(node, ast.ClassDef):
                    functions(node.body, prefix + node.name + ".")

        functions(module.tree.body)

    def resolve(self, module: PythonModule, name: str, depth: int = 0) -> str:
        """Resolve simple symbols including package reexports, with a cycle limit."""
        if not name or depth > 20:
            return name
        first, _, suffix = name.partition(".")
        if first in module.aliases:
            qualified = module.aliases[first] + ("." + suffix if suffix else "")
        elif first in BUILTINS and first not in module.constants and first not in module.functions:
            return name
        else:
            qualified = f"{module.name}.{name}"
        for candidate in sorted(self.modules, key=len, reverse=True):
            if qualified.startswith(candidate + "."):
                rest = qualified[len(candidate) + 1 :]
                target = self.modules[candidate]
                if rest.split(".")[0] in target.aliases:
                    return self.resolve(target, rest, depth + 1)
                break
        return qualified

    def function(self, qualified: str) -> tuple[PythonModule, FunctionNode] | None:
        for name, module in self.modules.items():
            if qualified.startswith(name + "."):
                node = module.functions.get(qualified[len(name) + 1 :])
                if node:
                    return module, node
        return None

    def literal(self, module: PythonModule, node: ast.AST | None, depth: int = 0) -> object:
        """Evaluate only bounded literal containers, additions, and constant references."""
        if node is None or depth > 20:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [self.literal(module, item, depth + 1) for item in node.elts]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.literal(module, node.left, depth + 1)
            right = self.literal(module, node.right, depth + 1)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        if isinstance(node, (ast.Name, ast.Attribute)):
            qualified = self.resolve(module, dotted_name(node))
            for name, target in self.modules.items():
                if qualified.startswith(name + "."):
                    constant = target.constants.get(qualified[len(name) + 1 :])
                    if constant is not None:
                        return self.literal(target, constant, depth + 1)
        return None

    def expression(self, module: PythonModule, node: ast.AST) -> str:
        return ast.get_source_segment(module.text, node) or ast.unparse(node)
