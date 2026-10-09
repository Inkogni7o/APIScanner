"""Local HTTP-input propagation over Rust, Go and JavaScript/TypeScript syntax trees."""

import re

from pydantic import BaseModel, Field
from tree_sitter import Node

from adscan.models import FlowStep, Parameter, Sink, Source
from adscan.parsers.cst import (
    FUNCTION_TYPES,
    CSTEndpoint,
    CSTIndex,
    CSTModule,
    arguments,
    bindings,
    call_name,
    field,
    properties,
    receiver,
    text,
)
from adscan.rules import RULES


class CSTFlow(BaseModel):
    source: Source
    steps: list[FlowStep] = Field(default_factory=list)


class Value(BaseModel):
    flows: list[CSTFlow] = Field(default_factory=list)
    kind: str = ""
    literal: str | None = None
    shell: bool = False


def combine(values: list[Value], *, kind: str = "") -> Value:
    flows = []
    for value in values:
        for flow in value.flows:
            if flow not in flows:
                flows.append(flow)
    return Value(flows=flows, kind=kind)


class CSTDataflowAnalyzer:
    def __init__(self, index: CSTIndex, item: CSTEndpoint) -> None:
        self.index = index
        self.item = item
        self.endpoint = item.endpoint

    def analyze(self) -> None:
        if self.item.module.language == "java":
            return
        env: dict[str, Value] = {}
        params = field(self.item.handler, "parameters")
        parameter_nodes = (
            params.named_children if params else [field(self.item.handler, "parameter")]
        )
        for ordinal, param in enumerate(parameter_nodes):
            if param is None:
                continue
            names = bindings(param)
            typename = text(field(param, "type"))
            canonical_type = self.index.resolve(self.item.module, typename.split("<", 1)[0])
            for name in names:
                known = next(
                    (p for p in self.endpoint.parameters if p.name == name),
                    None,
                )
                if self.item.module.language == "rust":
                    location = next(
                        (
                            location
                            for wrapper, location in {
                                "Query": "query",
                                "Path": "path",
                                "Json": "body",
                                "Form": "form",
                                "Multipart": "file",
                            }.items()
                            if canonical_type.rsplit("::", 1)[-1] == wrapper
                        ),
                        None,
                    )
                    if location is None and known and self.endpoint.framework == "Rocket":
                        location = known.location
                    if location:
                        env[name] = self._source(self.item.module, param, name, location)
                        env[name].kind = location
                    elif "HttpRequest" in typename:
                        env[name] = Value(kind="request")
                elif self.item.module.language == "go":
                    if any(marker in typename for marker in (".Request", ".Context", ".Ctx")):
                        env[name] = Value(kind="request")
                elif known and self.endpoint.framework == "NestJS":
                    env[name] = self._source(
                        self.item.module, param, known.alias or name, known.location
                    )
                elif ordinal == 0:
                    if (
                        name in {"query", "params", "body", "headers", "cookie"}
                        and len(names) > 1
                        or text(field(param, "pattern") or param).startswith("{")
                    ):
                        kind = {"params": "path", "headers": "header", "cookie": "cookie"}.get(
                            name, name
                        )
                        for pair in self._pattern_properties(param):
                            if name in bindings(field(pair, "value")):
                                collection = text(field(pair, "key"))
                                kind = {
                                    "params": "path",
                                    "headers": "header",
                                    "cookie": "cookie",
                                }.get(collection, collection)
                        env[name] = Value(kind=kind)
                    else:
                        env[name] = Value(kind="request")
        body = field(self.item.handler, "body")
        if body:
            self._run(
                self.item.module, body, env, {(self.item.module.file, self.item.handler.start_byte)}
            )

    def _source(self, module: CSTModule, node: Node, name: str, location: str) -> Value:
        parameter = Parameter(name=name, location=location)
        if not any(p.name == name and p.location == location for p in self.endpoint.parameters):
            self.endpoint.parameters.append(parameter)
        step = FlowStep(expression=text(node), file=module.file, line=node.start_point.row + 1)
        return Value(
            flows=[
                CSTFlow(
                    source=Source(
                        name=name,
                        location=location,
                        file=module.file,
                        line=node.start_point.row + 1,
                    ),
                    steps=[step],
                )
            ]
        )

    def _pattern_properties(self, node: Node) -> list[Node]:
        pattern = field(node, "pattern") or node
        return [child for child in pattern.named_children if child.type == "pair_pattern"]

    def _step(self, module: CSTModule, node: Node, value: Value) -> Value:
        step = FlowStep(expression=text(node), file=module.file, line=node.start_point.row + 1)
        return value.model_copy(
            update={
                "flows": [
                    flow.model_copy(update={"steps": flow.steps + [step]}) for flow in value.flows
                ]
            }
        )

    def _run(
        self, module: CSTModule, node: Node, env: dict[str, Value], stack: set[tuple[str, int]]
    ) -> Value:
        if node.type in FUNCTION_TYPES:
            return Value()
        if node.type in {"block", "statement_block", "statement_list", "program"}:
            result = Value()
            for child in node.named_children:
                value = self._run(module, child, env, stack)
                if (
                    child.type
                    in {
                        "return_statement",
                        "return_expression",
                        "if_statement",
                        "if_expression",
                        "switch_statement",
                        "match_expression",
                    }
                    or module.language == "rust"
                    and child == node.named_children[-1]
                    and child.type != "expression_statement"
                ):
                    result = combine([result, value])
            return result
        if node.type in {
            "lexical_declaration",
            "variable_declaration",
            "var_declaration",
            "const_declaration",
        }:
            for child in node.named_children:
                self._run(module, child, env, stack)
            return Value()
        if node.type in {
            "variable_declarator",
            "let_declaration",
            "short_var_declaration",
            "var_spec",
            "const_spec",
            "assignment_statement",
            "assignment_expression",
            "augmented_assignment_expression",
            "compound_assignment_expr",
        }:
            left = field(node, "left") or field(node, "pattern") or field(node, "name")
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
            for offset, pattern in enumerate(names):
                value = (
                    self._expr(module, values[min(offset, len(values) - 1)], env, stack)
                    if values
                    else Value()
                )
                operator = text(field(node, "operator"))
                if node.type in {
                    "augmented_assignment_expression",
                    "compound_assignment_expr",
                } or operator not in {"", "=", ":="}:
                    value = combine([env.get(text(pattern), Value()), value])
                for name in (
                    bindings(pattern)
                    if pattern.type
                    not in {"member_expression", "selector_expression", "field_expression"}
                    else [text(pattern)]
                ):
                    # Destructuring a request collection introduces its wire field names.
                    if pattern.type == "object_pattern" and value.kind in {
                        "query",
                        "path",
                        "body",
                        "header",
                        "cookie",
                        "form",
                    }:
                        value_for_name = self._source(module, pattern, name, value.kind)
                        for pair in self._pattern_properties(pattern):
                            if name in bindings(field(pair, "value")):
                                value_for_name = self._source(
                                    module, pair, text(field(pair, "key")), value.kind
                                )
                    else:
                        value_for_name = value
                    env[name] = self._step(module, node, value_for_name)
            return Value()
        if node.type in {
            "if_statement",
            "if_expression",
            "switch_statement",
            "match_expression",
            "for_statement",
            "while_statement",
            "for_expression",
            "while_expression",
            "loop_expression",
        }:
            condition = field(node, "condition")
            if condition:
                self._expr(module, condition, env, stack)
            branches = [child for child in node.named_children if child != condition]
            outcomes = [env.copy()]
            results = []
            for branch in branches:
                local = env.copy()
                results.append(self._run(module, branch, local, stack))
                outcomes.append(local)
            for name in set().union(*(outcome.keys() for outcome in outcomes)):
                candidates = [outcome.get(name, Value()) for outcome in outcomes]
                env[name] = combine(
                    candidates, kind=next((v.kind for v in candidates if v.kind), "")
                )
            return combine(results)
        return self._expr(module, node, env, stack)

    def _expr(
        self,
        module: CSTModule,
        node: Node | None,
        env: dict[str, Value],
        stack: set[tuple[str, int]],
    ) -> Value:
        if node is None or node.type in FUNCTION_TYPES:
            return Value()
        if node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
            "compound_assignment_expr",
        }:
            self._run(module, node, env, stack)
            return env.get(text(field(node, "left")), Value())
        if text(node) in env:
            return env[text(node)]
        if (
            node.type
            in {
                "try_expression",
                "await_expression",
                "reference_expression",
                "unary_expression",
                "parenthesized_expression",
            }
            and node.named_children
        ):
            return self._expr(module, node.named_children[-1], env, stack)
        if node.type in {"identifier", "property_identifier", "field_identifier"}:
            return Value(literal=self._literal(module, node))
        if node.type in {
            "member_expression",
            "selector_expression",
            "field_expression",
            "subscript_expression",
        }:
            owner_node = field(node, "object") or field(node, "operand") or field(node, "value")
            owner = self._expr(module, owner_node, env, stack)
            member = (
                text(field(node, "property") or field(node, "field"))
                or self._literal(module, field(node, "index"))
                or "value"
            )
            if owner.kind == "request":
                kind = {
                    "req": "request",
                    "query": "query",
                    "params": "path",
                    "body": "body",
                    "Body": "body",
                    "headers": "header",
                    "Header": "header",
                    "cookies": "cookie",
                    "query_params": "query",
                    "URL": "url",
                }.get(member, "")
                return Value(kind=kind) if kind else Value()
            if owner.kind in {"query", "path", "body", "header", "cookie", "form"}:
                return self._source(module, node, member, owner.kind)
            return self._step(module, node, owner)
        if node.type in {"call_expression", "method_invocation"}:
            return self._call(module, node, env, stack)
        if (
            node.type == "composite_literal"
            and self.index.resolve(module, text(field(node, "type"))) == "net/http.Client"
        ):
            return Value(kind="http_client")
        if (
            node.type
            in {
                "string",
                "string_literal",
                "raw_string_literal",
                "interpreted_string_literal",
                "template_string",
            }
            and self._literal(module, node) is not None
        ):
            return Value(literal=self._literal(module, node))
        if node.type in {"block", "statement_block", "statement_list"}:
            return self._run(module, node, env, stack)
        if node.type == "macro_invocation":
            # format! preserves interpolation flow; assert!/println! are ordinary expressions.
            captured = []
            if text(field(node, "macro")).rsplit("::", 1)[-1] in {
                "format",
                "format_args",
                "write",
                "writeln",
                "println",
                "eprintln",
            }:
                tokens = next(
                    (child for child in node.named_children if child.type == "token_tree"), None
                )
                format_string = (
                    next(
                        (
                            child
                            for child in tokens.named_children
                            if child.type in {"string_literal", "raw_string_literal"}
                        ),
                        None,
                    )
                    if tokens
                    else None
                )
                for name in re.findall(
                    r"(?<!\{)\{([A-Za-z_]\w*)(?::[^}]*)?\}(?!\})", text(format_string)
                ):
                    if name in env:
                        captured.append(env[name])
            return combine(
                captured
                + [
                    self._expr(module, child, env, stack)
                    for child in self.index.macro_expressions(module, node)
                ]
            )
        return combine([self._expr(module, child, env, stack) for child in node.named_children])

    def _literal(self, module: CSTModule, node: Node | None) -> str | None:
        value = self.index.literal(module, node)
        return value if isinstance(value, str) else None

    def _call(
        self, module: CSTModule, node: Node, env: dict[str, Value], stack: set[tuple[str, int]]
    ) -> Value:
        name = self.index.resolve(module, call_name(node))
        member = name.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
        owner_node = receiver(node)
        owner = self._expr(module, owner_node, env, stack)
        args = arguments(node)
        values = [self._expr(module, arg, env, stack) for arg in args]
        first = values[0] if values else Value()
        if module.language == "go" and any(value.kind == "request" for value in values):
            if name.startswith("github.com/go-chi/chi") and member == "URLParam":
                return self._source(
                    module,
                    node,
                    values[1].literal or "param" if len(values) > 1 else "param",
                    "path",
                )
            if name == "github.com/gorilla/mux.Vars":
                return Value(kind="path")
        if owner.kind in {"request", "url", "query", "header", "cookie"}:
            locations = {
                "Query": "query",
                "QueryParam": "query",
                "QueryParams": "query",
                "DefaultQuery": "query",
                "query": "query",
                "queries": "query",
                "query_string": "query",
                "Param": "path",
                "Params": "path",
                "param": "path",
                "PathValue": "path",
                "match_info": "path",
                "PostForm": "form",
                "FormValue": "form",
                "FormFile": "file",
                "GetHeader": "header",
                "header": "header",
                "headers": "header",
                "Cookie": "cookie",
                "Cookies": "cookie",
                "cookie": "cookie",
                "json": "body",
                "text": "body",
                "Body": "body",
                "formData": "form",
                "parseBody": "body",
            }
            location = locations.get(member)
            if member == "Get" and owner.kind in {"query", "header", "cookie"}:
                location = owner.kind
            if owner.kind == "url" and member == "Query":
                return Value(kind="query")
            if member == "req" and owner.kind == "request":
                return owner
            if location:
                source = self._source(module, node, first.literal or member, location)
                if member in {"QueryParams", "match_info", "headers"}:
                    source.kind = location
                return source
            if member in {"BindJSON", "ShouldBindJSON", "Bind", "BodyParser"} and args:
                self._assign_body(module, args[0], env)
                return Value()
        # Hono's c.req object is the request, not a tainted URL by itself.
        if member == "NewDecoder" and name == "encoding/json.NewDecoder" and values:
            return Value(kind="decoder", flows=self._materialize(module, args[0], first).flows)
        if owner.kind == "decoder" and member == "Decode" and args:
            self._assign_body(module, args[0], env)
            return Value()
        language = module.language
        if language == "rust" and name in {
            "std::process::Command::new",
            "tokio::process::Command::new",
        }:
            return Value(
                kind="command",
                flows=first.flows,
                shell=(first.literal or "").rsplit("/", 1)[-1]
                in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"},
            )
        if language == "go" and name in {"os/exec.Command", "os/exec.CommandContext"}:
            command_values = values[1:] if member == "CommandContext" else values
            binary = command_values[0] if command_values else Value()
            shell = (binary.literal or "").rsplit("/", 1)[-1] in {
                "sh",
                "bash",
                "zsh",
                "cmd",
                "cmd.exe",
                "powershell",
                "pwsh",
            }
            value = combine(command_values if shell else [binary], kind="command")
            value.shell = shell
            return value
        if owner.kind == "command":
            if member in {"arg", "args", "Args"}:
                value = combine([owner, *values] if owner.shell else [owner], kind="command")
                value.shell = owner.shell
                binding = owner_node
                while binding and binding.type == "call_expression":
                    binding = receiver(binding)
                if binding and binding.type == "identifier":
                    env[text(binding)] = value
                return value
            if member in {
                "output",
                "status",
                "spawn",
                "exec",
                "Output",
                "CombinedOutput",
                "Run",
                "Start",
            }:
                self._sink(module, node, name, "command", owner, owner.shell)
                return owner
            return owner
        if (
            member in {"push_str", "push", "extend"}
            and owner_node
            and owner_node.type == "identifier"
        ):
            value = self._step(module, node, combine([owner, *values]))
            env[text(owner_node)] = value
            return value
        if name in {
            "reqwest::Client::new",
            "reqwest::blocking::Client::new",
            "net/http.Client",
            "reqwest::Client::builder",
            "reqwest::blocking::Client::builder",
        }:
            return Value(kind="http_client")
        if owner.kind == "http_client" and member in {"build", "unwrap", "expect", "clone"}:
            return owner
        if owner.kind == "http_client" and member.lower() in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "request",
        }:
            self._sink(module, node, name, "http", first)
        category, shell, value = "", False, first
        if language in {"javascript", "typescript", "tsx"}:
            normalized = name.removeprefix("node:")
            if normalized in {"child_process.exec", "child_process.execSync", "eval", "Function"}:
                category, shell = "command", True
            elif normalized in {
                "child_process.spawn",
                "child_process.spawnSync",
                "child_process.execFile",
                "child_process.execFileSync",
            }:
                options = properties(args[2]) if len(args) > 2 else {}
                shell = self.index.literal(module, options.get("shell")) is True
                shell = shell or (first.literal or "").rsplit("/", 1)[-1] in {
                    "sh",
                    "bash",
                    "cmd",
                    "cmd.exe",
                    "powershell",
                    "pwsh",
                }
                category = "command"
                value = combine(values[:2]) if shell else first
            elif (
                normalized.startswith(("fs.", "fs/promises."))
                and member
                in {
                    "readFile",
                    "readFileSync",
                    "writeFile",
                    "writeFileSync",
                    "appendFile",
                    "appendFileSync",
                    "open",
                    "openSync",
                    "createReadStream",
                    "createWriteStream",
                    "unlink",
                    "unlinkSync",
                    "readdir",
                    "readdirSync",
                    "stat",
                    "statSync",
                }
                or normalized == "Bun.file"
            ):
                category = "file"
            elif (
                normalized == "fetch"
                or normalized.startswith(("axios.", "http.", "https."))
                and member in {"get", "post", "put", "patch", "delete", "request"}
            ):
                category = "http"
            elif (
                member in {"sendFile", "download"}
                and owner_node
                and text(owner_node) in {"res", "response", "reply"}
            ):
                category = "file"
        elif language == "go":
            if name in {
                "os.Open",
                "os.OpenFile",
                "os.ReadFile",
                "os.WriteFile",
                "os.Create",
                "os.Remove",
                "os.ReadDir",
                "io/ioutil.ReadFile",
                "io/ioutil.WriteFile",
            }:
                category = "file"
            elif name in {
                "net/http.Get",
                "net/http.Post",
                "net/http.Head",
                "net/http.NewRequest",
                "net/http.NewRequestWithContext",
            }:
                category = "http"
                if member.startswith("NewRequest"):
                    value = (
                        values[2 if member.endswith("WithContext") else 1]
                        if len(values) > (2 if member.endswith("WithContext") else 1)
                        else Value()
                    )
        elif language == "rust":
            if name.startswith(("std::fs::", "tokio::fs::")) and member in {
                "read",
                "read_to_string",
                "write",
                "open",
                "create",
                "remove_file",
                "read_dir",
            }:
                category = "file"
            elif name in {"reqwest::get", "reqwest::blocking::get"}:
                category = "http"
        if category:
            self._sink(
                module,
                node,
                name,
                category,
                self._materialize(module, args[0], value) if args else value,
                shell,
            )
        target = self.index.function(module, call_name(node))
        if not target and call_name(node).startswith("this."):
            class_name = self.index.symbol(self.item.module, self.item.handler).rsplit(".", 1)[0]
            target = self.index.function(module, class_name + "." + member)
        if target:
            owner_module, handler = target
            key = owner_module.file, handler.start_byte
            if key not in stack:
                params = field(handler, "parameters")
                passed = (
                    [name for param in params.named_children for name in bindings(param)]
                    if params
                    else []
                )
                local = {
                    name: self._step(module, node, value)
                    for name, value in zip(passed, values, strict=False)
                }
                body = field(handler, "body")
                if body:
                    return self._run(owner_module, body, local, stack | {key})
        return self._step(module, node, combine([owner, *values]))

    def _materialize(self, module: CSTModule, node: Node, value: Value) -> Value:
        if value.kind in {"query", "path", "body", "header", "cookie", "form"} and not value.flows:
            return self._source(module, node, text(node), value.kind)
        return value

    def _assign_body(self, module: CSTModule, node: Node, env: dict[str, Value]) -> None:
        target = (
            node.named_children[-1]
            if node.type in {"unary_expression", "reference_expression"} and node.named_children
            else node
        )
        env[text(target)] = self._source(module, node, text(target), "body")

    def _sink(
        self,
        module: CSTModule,
        node: Node,
        name: str,
        category: str,
        value: Value,
        shell: bool = False,
    ) -> None:
        sink = Sink(
            name=name,
            category=category,
            file=module.file,
            line=node.start_point.row + 1,
            expression=text(node),
            shell=shell,
        )
        if sink not in self.endpoint.sinks:
            self.endpoint.sinks.append(sink)
        for flow in value.flows:
            finding = RULES[category].finding(
                self.endpoint,
                sink,
                flow.source,
                self._step(module, node, Value(flows=[flow])).flows[0].steps,
            )
            key = (
                finding.rule_id,
                finding.file,
                finding.line,
                flow.source.file,
                flow.source.line,
                flow.source.name,
            )
            if not any(
                (f.rule_id, f.file, f.line, f.source.file, f.source.line, f.source.name) == key
                for f in self.endpoint.findings
                if f.source
            ):
                self.endpoint.findings.append(finding)
