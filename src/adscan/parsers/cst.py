"""Tree-sitter syntax trees and local symbol resolution for JS/TS, Java, Go and Rust."""

import ast
import posixpath
import re
from collections.abc import Iterator
from pathlib import Path

import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_rust
import tree_sitter_typescript
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from tree_sitter import Language, Node, Parser, Tree

from adscan.models import Diagnostic, Endpoint

FUNCTION_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "method_declaration",
    "func_literal",
    "function_item",
    "closure_expression",
}
CALL_TYPES = {"call_expression", "method_invocation"}


def walk(node: Node, *types: str) -> Iterator[Node]:
    pending = [node]
    while pending:
        current = pending.pop()
        if not types or current.type in types:
            yield current
        pending.extend(reversed(current.named_children))


def text(node: Node | None) -> str:
    return node.text.decode("utf-8") if node is not None and node.text else ""


def field(node: Node, name: str) -> Node | None:
    return node.child_by_field_name(name)


def arguments(node: Node) -> list[Node]:
    value = field(node, "arguments")
    return value.named_children if value else []


def call_name(node: Node) -> str:
    if node.type == "method_invocation":
        owner = text(field(node, "object"))
        return ".".join(filter(None, (owner, text(field(node, "name")))))
    return function_name(field(node, "function"))


def function_name(node: Node | None) -> str:
    if node is None:
        return ""
    if node.type == "generic_function":
        return function_name(field(node, "function"))
    if node.type == "generic_type":
        return function_name(field(node, "type"))
    if node.type == "scoped_identifier" and field(node, "path"):
        return function_name(field(node, "path")) + "::" + text(field(node, "name"))
    return text(node)


def receiver(node: Node) -> Node | None:
    function = field(node, "function")
    if node.type == "method_invocation":
        return field(node, "object")
    if function is None:
        return None
    return field(function, "object") or field(function, "value") or field(function, "operand")


def bindings(node: Node | None) -> list[str]:
    """Names introduced by a parameter/destructuring pattern, excluding property keys."""
    if node is None:
        return []
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [text(node)]
    if node.type in {"pair_pattern", "field_pattern"}:
        return bindings(field(node, "value") or field(node, "pattern") or field(node, "name"))
    pattern = field(node, "pattern") or field(node, "name")
    if pattern is not None:
        return bindings(pattern)
    return [
        name
        for child in node.named_children
        if child != field(node, "type")
        for name in bindings(child)
    ]


def properties(node: Node | None) -> dict[str, Node]:
    if node is None:
        return {}
    result = {}
    for pair in node.named_children:
        if pair.type in {"pair", "element_value_pair"}:
            key, value = field(pair, "key"), field(pair, "value")
            if key and value:
                result[text(key).strip("\"'")] = value
        elif pair.type in {
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
        }:
            result[text(pair)] = pair
    return result


def function_scope(node: Node) -> int:
    parent = node.parent
    while parent:
        if parent.type in FUNCTION_TYPES:
            return parent.start_byte
        parent = parent.parent
    return -1


def annotations(node: Node) -> list[Node]:
    result = [child for child in node.named_children if child.type == "decorator"]
    modifiers = next((child for child in node.named_children if child.type == "modifiers"), None)
    if modifiers:
        result.extend(
            child
            for child in modifiers.named_children
            if child.type in {"annotation", "marker_annotation"}
        )
    # TypeScript attaches method decorators to the preceding class-body sibling.
    if node.type == "method_definition":
        sibling = node.prev_named_sibling
        while sibling and sibling.type == "decorator":
            result.insert(0, sibling)
            sibling = sibling.prev_named_sibling
    if node.type == "class_declaration" and node.parent and node.parent.type == "export_statement":
        result.extend(child for child in node.parent.named_children if child.type == "decorator")
    return result


def annotation_name(node: Node) -> str:
    if node.type == "decorator" and node.named_children:
        child = node.named_children[0]
        return call_name(child) if child.type == "call_expression" else text(child)
    return text(field(node, "name"))


def annotation_arguments(node: Node) -> list[Node]:
    if node.type == "decorator" and node.named_children:
        return arguments(node.named_children[0])
    return arguments(node)


class CSTModule(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    file: str
    language: str
    tree: Tree
    aliases: dict[str, str] = Field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = Field(default_factory=dict)
    constants: dict[str, Node] = Field(default_factory=dict)
    scoped_constants: dict[tuple[int, str], Node] = Field(default_factory=dict)
    functions: dict[str, Node] = Field(default_factory=dict)
    exports: dict[str, str] = Field(default_factory=dict)
    reexports: dict[str, tuple[str, str]] = Field(default_factory=dict)
    object_types: dict[str, str] = Field(default_factory=dict)


class CSTEndpoint(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    endpoint: Endpoint
    module: CSTModule
    handler: Node


class CompilerOptions(BaseModel):
    base_url: str = Field(default=".", alias="baseUrl")
    paths: dict[str, list[str]] = Field(default_factory=dict)


class TypeScriptConfig(BaseModel):
    compiler_options: CompilerOptions = Field(
        default_factory=CompilerOptions, alias="compilerOptions"
    )


class CSTIndex:
    def __init__(self, contents: dict[Path, str], diagnostics: list[Diagnostic]) -> None:
        languages = {
            "javascript": Language(tree_sitter_javascript.language()),
            "typescript": Language(tree_sitter_typescript.language_typescript()),
            "tsx": Language(tree_sitter_typescript.language_tsx()),
            "java": Language(tree_sitter_java.language()),
            "go": Language(tree_sitter_go.language()),
            "rust": Language(tree_sitter_rust.language()),
        }
        parsers = {name: Parser(language) for name, language in languages.items()}
        extensions = {
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "tsx",
            ".mts": "typescript",
            ".cts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
        }
        self.modules: dict[str, CSTModule] = {}
        self.entry_points: set[str] = set()
        self.diagnostics = diagnostics
        self.rust_parser = parsers["rust"]
        self.macro_trees: dict[str, Tree] = {}
        self.macro_nodes: dict[tuple[str, int], Node] = {}
        self.ts_paths: list[tuple[str, str]] = []
        self.go_modules: dict[str, str] = {}
        for path, source in contents.items():
            if path.name == "tsconfig.json":
                # JSONC permits comments and trailing commas in TypeScript configuration.
                config_text = re.sub(
                    r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/',
                    lambda match: match[0] if match[0].startswith('"') else "",
                    source,
                )
                config_text = re.sub(
                    r'"(?:\\.|[^"\\])*"|,\s*([}\]])',
                    lambda match: match[0] if match[0].startswith('"') else match[1],
                    config_text,
                )
                try:
                    config = TypeScriptConfig.model_validate_json(config_text)
                except ValidationError as error:
                    diagnostics.append(
                        Diagnostic(
                            file=path.as_posix(),
                            message=f"Invalid tsconfig: {error}",
                        )
                    )
                    continue
                options = config.compiler_options
                base = posixpath.join(path.parent.as_posix(), options.base_url)
                for pattern, targets in options.paths.items():
                    for target in targets:
                        self.ts_paths.append(
                            (pattern, posixpath.normpath(posixpath.join(base, target)))
                        )
            elif path.name == "go.mod":
                match = re.search(r"^\s*module\s+(\S+)", source, re.M)
                if match:
                    self.go_modules[match[1]] = path.parent.as_posix()
        for path, source in sorted(contents.items()):
            language = extensions.get(path.suffix)
            if language is None:
                continue
            tree = parsers[language].parse(source.encode("utf-8"))
            if tree.root_node.has_error:
                errors = [
                    node for node in walk(tree.root_node) if node.type == "ERROR" or node.is_missing
                ]
                for node in errors[:10]:
                    diagnostics.append(
                        Diagnostic(
                            file=path.as_posix(),
                            line=node.start_point.row + 1,
                            message="Syntax error; extracting valid syntax-tree regions",
                        )
                    )
            module = CSTModule(file=path.as_posix(), language=language, tree=tree)
            self.modules[module.file] = module
            self._collect(module)
        for module in self.modules.values():
            self._objects(module)

    def _objects(self, module: CSTModule) -> None:
        """Resolve explicit receiver types and ordinary constructor-bound controllers."""
        for node in walk(module.tree.root_node):
            if node.type in {"parameter_declaration", "required_parameter", "optional_parameter"}:
                typename = text(field(node, "type")).lstrip("*").removeprefix(":").strip()
                for binding in bindings(node):
                    if typename:
                        module.object_types[binding] = typename
            if node.type not in {"variable_declarator", "short_var_declaration", "var_spec"}:
                continue
            left = field(node, "name") or field(node, "left")
            right = field(node, "value") or field(node, "right")
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
                typename = ""
                if value.type == "new_expression":
                    typename = text(field(value, "constructor"))
                elif (
                    value.type == "unary_expression"
                    and value.named_children[-1].type == "composite_literal"
                ):
                    typename = text(field(value.named_children[-1], "type"))
                elif value.type == "call_expression" and module.language == "go":
                    target = self.function(module, call_name(value))
                    if target:
                        owner, constructor = target
                        result = field(constructor, "result")
                        typename = text(result).lstrip("*")
                        if (
                            owner is not module
                            and "." in call_name(value)
                            and typename
                            and "." not in typename
                        ):
                            typename = call_name(value).split(".", 1)[0] + "." + typename
                if typename:
                    module.object_types[text(name)] = typename

    def _collect(self, module: CSTModule) -> None:
        for node in walk(module.tree.root_node):
            if node.type in {
                "variable_declarator",
                "const_spec",
                "public_field_definition",
                "field_definition",
            }:
                name_node, value = field(node, "name"), field(node, "value")
                if value and value.type == "expression_list" and len(value.named_children) == 1:
                    value = value.named_children[0]
                if name_node and value:
                    module.constants[text(name_node)] = value
                    module.scoped_constants[function_scope(node), text(name_node)] = value
                    if value.type in FUNCTION_TYPES:
                        owner = node.parent
                        while owner and owner.type not in {"class_declaration", "program"}:
                            owner = owner.parent
                        prefix = (
                            text(field(owner, "name")) + "."
                            if owner and owner.type == "class_declaration"
                            else ""
                        )
                        module.functions[prefix + text(name_node)] = value
                    if value.type == "call_expression" and call_name(value) == "require":
                        args = arguments(value)
                        package = self.literal(module, args[0]) if args else None
                        if isinstance(package, str):
                            if name_node.type == "object_pattern":
                                for child in name_node.named_children:
                                    local = text(field(child, "value")) or text(child)
                                    imported = text(field(child, "key")) or text(child)
                                    self._import(module, local, package, imported)
                            else:
                                self._import(module, text(name_node), package, "default")
            elif node.type in {
                "function_declaration",
                "method_definition",
                "method_declaration",
                "function_item",
            }:
                name = text(field(node, "name"))
                parent = node.parent
                while parent and parent.type not in {
                    "class_declaration",
                    "impl_item",
                    "program",
                    "source_file",
                }:
                    parent = parent.parent
                if parent and parent.type == "class_declaration":
                    name = text(field(parent, "name")) + "." + name
                elif parent and parent.type == "impl_item":
                    name = text(field(parent, "type")) + "::" + name
                if node.type == "method_declaration" and module.language == "go":
                    method_receiver = field(node, "receiver")
                    if method_receiver and method_receiver.named_children:
                        receiver_type = text(
                            field(method_receiver.named_children[0], "type")
                        ).lstrip("*")
                        name = receiver_type + "." + name
                module.functions[name] = node
            elif (
                node.type in {"let_declaration", "const_item", "static_item"}
                and module.language == "rust"
            ):
                pattern, value = field(node, "pattern") or field(node, "name"), field(node, "value")
                if pattern and value and pattern.type == "identifier":
                    module.constants[text(pattern)] = value
                    module.scoped_constants[function_scope(node), text(pattern)] = value
            elif node.type == "use_declaration" and module.language == "rust":
                self._rust_use(module, field(node, "argument"))
            elif node.type == "import_statement":
                require_clause = next(
                    (
                        child
                        for child in node.named_children
                        if child.type == "import_require_clause"
                    ),
                    None,
                )
                package = self.literal(
                    module,
                    field(require_clause, "source") if require_clause else field(node, "source"),
                )
                if isinstance(package, str):
                    if require_clause:
                        self._import(
                            module, text(require_clause.named_children[0]), package, "default"
                        )
                    for child in node.named_children:
                        if child.type == "import_clause":
                            for item in child.named_children:
                                if item.type == "identifier":
                                    self._import(module, text(item), package, "default")
                                elif item.type == "namespace_import":
                                    self._import(
                                        module, text(item.named_children[-1]), package, "*"
                                    )
                                elif item.type == "named_imports":
                                    for spec in item.named_children:
                                        imported = text(field(spec, "name"))
                                        self._import(
                                            module,
                                            text(field(spec, "alias")) or imported,
                                            package,
                                            imported,
                                        )
            elif node.type == "import_spec":
                package = self.literal(module, field(node, "path"))
                if isinstance(package, str):
                    local = text(field(node, "name")) or package.rsplit("/", 1)[-1]
                    if local.startswith("v") and local[1:].isdigit():
                        local = package.rsplit("/", 2)[-2]
                    module.aliases[local] = package
            elif node.type == "import_declaration" and module.language == "java":
                identifier = next(
                    (child for child in node.named_children if child.type == "scoped_identifier"),
                    None,
                )
                name = text(identifier)
                if any(child.type == "asterisk" for child in node.named_children):
                    module.aliases[name + ".*"] = name
                else:
                    module.aliases[name.rsplit(".", 1)[-1]] = name
            elif node.type == "export_statement":
                declaration = field(node, "declaration")
                if declaration and "default" in [child.type for child in node.children]:
                    module.exports["default"] = text(field(declaration, "name"))
                elif not declaration and "default" in [child.type for child in node.children]:
                    value = field(node, "value")
                    module.exports["default"] = text(value)
                source_node = field(node, "source")
                package = self.literal(module, source_node)
                for spec in walk(node, "export_specifier"):
                    original = text(field(spec, "name"))
                    alias = text(field(spec, "alias")) or original
                    if isinstance(package, str):
                        target = posixpath.normpath(
                            posixpath.join(posixpath.dirname(module.file), package)
                        )
                        module.reexports[alias] = (target, original)
                    else:
                        module.exports[alias] = original
            elif node.type == "assignment_expression":
                left, right = field(node, "left"), field(node, "right")
                if text(left) == "module.exports":
                    module.exports["default"] = text(right)
                elif text(left).startswith("exports."):
                    module.exports[text(left).removeprefix("exports.")] = text(right)

    def constant(self, module: CSTModule, name: str, node: Node) -> Node | None:
        return module.scoped_constants.get(
            (function_scope(node), name)
        ) or module.scoped_constants.get((-1, name))

    def symbol(self, module: CSTModule, handler: Node) -> str:
        return next(
            (name for name, function in module.functions.items() if function == handler),
            text(field(handler, "name")),
        )

    def _import(self, module: CSTModule, local: str, package: str, imported: str) -> None:
        if package.startswith("."):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(module.file), package))
            module.imports[local] = (target, imported)
        else:
            for pattern, target in self.ts_paths:
                prefix, wildcard, suffix = pattern.partition("*")
                if (
                    wildcard and package.startswith(prefix) and package.endswith(suffix)
                ) or package == pattern:
                    middle = (
                        package[len(prefix) : len(package) - len(suffix) if suffix else None]
                        if wildcard
                        else ""
                    )
                    module.imports[local] = (target.replace("*", middle), imported)
                    return
            module.aliases[local] = package + (
                "." + imported if imported not in {"default", "*"} else ""
            )

    def _rust_use(self, module: CSTModule, node: Node | None, prefix: str = "") -> None:
        if node is None:
            return
        if node.type == "scoped_use_list":
            base = "::".join(filter(None, (prefix, text(field(node, "path")))))
            listing = field(node, "list")
            for child in listing.named_children if listing else []:
                self._rust_use(module, child, base)
        elif node.type == "use_list":
            for child in node.named_children:
                self._rust_use(module, child, prefix)
        else:
            path = text(field(node, "path")) if node.type == "use_as_clause" else text(node)
            qualified = "::".join(filter(None, (prefix, path)))
            local = text(field(node, "alias")) or path.rsplit("::", 1)[-1]
            module.aliases[local] = qualified

    def exported_symbol(
        self, module: CSTModule, symbol: str, visited: set[tuple[str, str]] | None = None
    ) -> tuple[CSTModule, str]:
        visited = visited or set()
        key = module.file, symbol
        if key in visited:
            return module, symbol
        if symbol in module.reexports:
            target, original = module.reexports[symbol]
            owner = self.imported_module(target)
            if owner:
                return self.exported_symbol(owner, original, visited | {key})
        return module, module.exports.get(symbol, symbol)

    def imported_module(self, path: str) -> CSTModule | None:
        for candidate in [
            path,
            *[
                path + ext
                for ext in (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".rs")
            ],
            path + "/index.ts",
            path + "/index.js",
            path + "/mod.rs",
        ]:
            if candidate in self.modules:
                return self.modules[candidate]
        # TS commonly imports the future emitted .js path for a .ts source file.
        if path.endswith(".js"):
            return self.modules.get(path[:-3] + ".ts")
        return None

    def resolve(self, module: CSTModule, name: str) -> str:
        if module.language == "rust":
            first, separator, rest = name.partition("::")
            return module.aliases.get(first, first) + (separator + rest if separator else "")
        first, dot, rest = name.partition(".")
        return module.aliases.get(first, first) + (dot + rest if dot else "")

    def function(self, module: CSTModule, name: str) -> tuple[CSTModule, Node] | None:
        first, _, rest = name.partition(".")
        if rest and first in module.object_types:
            name = module.object_types[first] + "." + rest
            first, _, rest = name.partition(".")
        if first in module.imports:
            target, imported = module.imports[first]
            owner = self.imported_module(target)
            if owner:
                symbol = rest if imported == "*" else imported
                owner, symbol = self.exported_symbol(owner, symbol)
                if rest and imported != "*":
                    symbol += "." + rest
                if symbol in owner.functions:
                    return owner, owner.functions[symbol]
        if name in module.functions:
            return module, module.functions[name]
        if module.language == "go":
            import_path = module.aliases.get(first)
            if import_path and rest:
                for module_name, directory in self.go_modules.items():
                    if import_path == module_name or import_path.startswith(module_name + "/"):
                        package_dir = posixpath.normpath(
                            posixpath.join(
                                directory, import_path.removeprefix(module_name).lstrip("/")
                            )
                        )
                        candidates = [
                            (owner, owner.functions[rest])
                            for owner in self.modules.values()
                            if owner.language == "go"
                            and posixpath.dirname(owner.file) == package_dir
                            and rest in owner.functions
                        ]
                        if len(candidates) == 1:
                            return candidates[0]
            candidates = [
                (owner, owner.functions[name])
                for owner in self.modules.values()
                if owner.language == "go"
                and posixpath.dirname(owner.file) == posixpath.dirname(module.file)
                and name in owner.functions
            ]
            if len(candidates) == 1:
                return candidates[0]
        elif module.language == "rust":
            qualified = self.resolve(module, name)
            parts = qualified.split("::")
            if len(parts) > 1:
                relative = module.file.split("/")
                source_root = (
                    "/".join(relative[: relative.index("src") + 1])
                    if "src" in relative
                    else posixpath.dirname(module.file)
                )
                if parts[0] == "crate":
                    parts = parts[1:]
                    directory = source_root
                elif parts[0] in {"self", "super"}:
                    directory = (
                        posixpath.dirname(module.file)
                        if posixpath.basename(module.file) in {"mod.rs", "lib.rs", "main.rs"}
                        else posixpath.splitext(module.file)[0]
                    )
                    if parts[0] == "self":
                        parts.pop(0)
                    while parts and parts[0] == "super":
                        parts.pop(0)
                        directory = posixpath.dirname(directory)
                else:
                    directory = source_root
                owner = self.imported_module(posixpath.join(directory, *parts[:-1]))
                if owner and parts[-1] in owner.functions:
                    return owner, owner.functions[parts[-1]]
        return None

    def handler(self, module: CSTModule, node: Node) -> tuple[CSTModule, Node] | None:
        if node.type in FUNCTION_TYPES:
            return module, node
        if (
            node.type in {"parenthesized_expression", "as_expression", "generic_function"}
            and node.named_children
        ):
            return self.handler(module, node.named_children[0])
        if node.type == "call_expression" and call_name(node).endswith(".bind"):
            owner_node = receiver(node)
            return self.handler(module, owner_node) if owner_node else None
        return self.function(module, text(node))

    def macro_expressions(self, module: CSTModule, node: Node) -> list[Node]:
        """Parse macro arguments as expressions, retaining the original byte/line positions."""
        tokens = next((child for child in node.named_children if child.type == "token_tree"), None)
        if tokens is None:
            return []
        if module.file not in self.macro_trees:
            source = bytearray(module.tree.root_node.text or b"")
            # Parse a single expression view of the file, rather than a full tree per macro.
            for invocation in walk(module.tree.root_node, "macro_invocation"):
                arguments_node = next(
                    (child for child in invocation.named_children if child.type == "token_tree"),
                    None,
                )
                if arguments_node is None:
                    continue
                for offset in range(invocation.start_byte, arguments_node.start_byte):
                    if source[offset] not in {10, 13}:
                        source[offset] = 32
                source[arguments_node.start_byte] = ord("(")
                source[arguments_node.end_byte - 1] = ord(")")
            tree = self.rust_parser.parse(bytes(source))
            self.macro_trees[module.file] = tree
            for expression_node in walk(
                tree.root_node, "tuple_expression", "parenthesized_expression"
            ):
                self.macro_nodes[module.file, expression_node.start_byte] = expression_node
        expression = self.macro_nodes.get((module.file, tokens.start_byte))
        return expression.named_children if expression else []

    def literal(
        self, module: CSTModule, node: Node | None, visited: set[str] | None = None
    ) -> object:
        if node is None or node.has_error:
            return None
        value = text(node)
        if node.type in {
            "string",
            "string_literal",
            "interpreted_string_literal",
            "template_string",
            "raw_string_literal",
        }:
            if node.type == "template_string" and any(
                child.type == "template_substitution" for child in node.named_children
            ):
                return None
            if value.startswith("`"):
                return value[1:-1]
            if module.language == "rust" and value.startswith("r"):
                return value[value.index('"') + 1 : value.rindex('"')]
            try:
                if module.language == "rust":
                    value = re.sub(
                        r"\\u\{([0-9a-fA-F_]+)\}",
                        lambda match: f"\\U{int(match[1].replace('_', ''), 16):08x}",
                        value,
                    )
                    value = re.sub(r"\\\r?\n\s*", "", value)
                    # Rust also permits literal newlines inside ordinary quoted strings.
                    value = value.replace("\r", "\\r").replace("\n", "\\n")
                return ast.literal_eval(value)
            except (ValueError, SyntaxError) as error:
                self.diagnostics.append(
                    Diagnostic(
                        file=module.file,
                        line=node.start_point.row + 1,
                        message=f"Invalid string literal: {error}",
                    )
                )
                return None
        if node.type in {"true", "false"}:
            return value == "true"
        if node.type in {
            "array",
            "element_value_array_initializer",
            "expression_list",
            "literal_value",
        }:
            return [self.literal(module, child, visited) for child in node.named_children]
        if node.type == "composite_literal":
            return self.literal(module, field(node, "body"), visited)
        if node.type == "binary_expression" and text(field(node, "operator")) == "+":
            left, right = (
                self.literal(module, field(node, "left"), visited),
                self.literal(module, field(node, "right"), visited),
            )
            return left + right if isinstance(left, str) and isinstance(right, str) else None
        if (
            node.type in {"identifier", "property_identifier"}
            and self.constant(module, value, node) is not None
            and value not in (visited or set())
        ):
            return self.literal(
                module, self.constant(module, value, node), (visited or set()) | {value}
            )
        return None
