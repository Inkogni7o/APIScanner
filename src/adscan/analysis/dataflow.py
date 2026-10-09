"""Bounded intra-procedural taint tracking over Python AST statements and expressions."""

import ast

from pydantic import BaseModel

from adscan.analysis.sinks import CLIENT_TYPES, PATH_METHODS, SINKS, SinkSpec
from adscan.analysis.sources import request_source
from adscan.extractors.base import ExtractedEndpoint
from adscan.extractors.python_web import request_bindings
from adscan.models import FlowStep, FunctionReference, Parameter, Sink, Source
from adscan.parsers.python import PythonIndex, dotted_name, keyword
from adscan.rules import RULES


class Flow(BaseModel):
    """A tainted value's origin and bounded evidence chain."""

    source: Source
    steps: list[FlowStep]
    normalized: bool = False


type State = tuple[
    dict[str, list[Flow]],
    dict[str, str],
    set[str],
    dict[str, ast.List | ast.Tuple],
    dict[str, object],
]


def merge(*groups: list[Flow]) -> list[Flow]:
    """Keep one evidence chain per source and bound unions in large expressions."""
    found: dict[tuple[str, str, str, int], Flow] = {}
    for group in groups:
        for flow in group:
            source = flow.source
            key = source.name, source.location, source.file, source.line
            if key not in found or len(flow.steps) > len(found[key].steps):
                found[key] = flow
    return list(found.values())[:64]


class DataflowAnalyzer:
    """Analyze only route handlers; never execute application code or follow a full call graph."""

    def __init__(self, index: PythonIndex, extracted: ExtractedEndpoint) -> None:
        self.index = index
        self.module = extracted.module
        handler = extracted.handler
        assert handler is not None
        self.handler = handler
        self.endpoint = extracted.endpoint
        self.env: dict[str, list[Flow]] = {}
        self.objects: dict[str, str] = {}
        self.argv: dict[str, ast.List | ast.Tuple] = {}
        self.local_constants: dict[str, object] = {}
        self.request_names = request_bindings(
            index, self.module, self.handler, self.endpoint.framework
        )
        self.seen_findings: set[tuple[str, int, str, str]] = set()
        self.seen_calls: set[tuple[str, int]] = set()
        self.seen_sinks: set[tuple[str, int]] = set()
        self.bindings = {
            node.id
            for node in ast.walk(self.handler)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }
        self.bindings.update(
            argument.arg
            for argument in self.handler.args.posonlyargs
            + self.handler.args.args
            + self.handler.args.kwonlyargs
        )
        for argument in (
            self.handler.args.posonlyargs + self.handler.args.args + self.handler.args.kwonlyargs
        ):
            canonical = self.index.resolve(self.module, dotted_name(argument.annotation))
            if canonical in {"fastapi.Request", "starlette.requests.Request"}:
                self.request_names.add(argument.arg)
        for parameter in self.endpoint.parameters:
            source = Source(
                name=parameter.alias or parameter.name,
                location=parameter.location,
                file=self.module.file,
                line=self.handler.lineno,
            )
            self.env[parameter.name] = [
                Flow(source=source, steps=[self._step(parameter.name, self.handler)])
            ]

    def analyze(self) -> None:
        """Mutate an endpoint with evidence from its handler's reachable statements."""
        self._block(self.handler.body)

    def _step(self, expression: str, node: ast.AST) -> FlowStep:
        return FlowStep(
            expression=expression[:300],
            file=self.module.file,
            line=getattr(node, "lineno", self.handler.lineno),
        )

    def _append(
        self, flows: list[Flow], expression: str, node: ast.AST, normalized: bool = False
    ) -> list[Flow]:
        step = self._step(expression, node)
        return [
            flow.model_copy(
                update={
                    "steps": [flow.steps[0]] + (flow.steps[1:] + [step])[-29:],
                    "normalized": flow.normalized or normalized,
                }
            )
            for flow in flows
        ]

    def _canonical(self, node: ast.expr) -> str:
        name = dotted_name(node)
        first, _, suffix = name.partition(".")
        if first in self.objects:
            return self.objects[first] + ("." + suffix if suffix else "")
        if first in self.bindings:
            return f"local.{name}"
        return self.index.resolve(self.module, name)

    def _literal(self, node: ast.AST | None) -> object:
        if isinstance(node, ast.Name) and node.id in self.bindings:
            return self.local_constants.get(node.id)
        return self.index.literal(self.module, node)

    def _object_type(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.objects.get(node.id)
        if isinstance(node, ast.Call):
            name = self._canonical(node.func)
            if name in CLIENT_TYPES or name in {
                "pathlib.Path",
                "pathlib.PosixPath",
                "pathlib.WindowsPath",
            }:
                return "pathlib.Path" if name.startswith("pathlib.") else name
            if (
                isinstance(node.func, ast.Attribute)
                and self._object_type(node.func.value) == "pathlib.Path"
            ):
                if node.func.attr in {
                    "resolve",
                    "absolute",
                    "joinpath",
                    "with_name",
                    "with_suffix",
                }:
                    return "pathlib.Path"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if self._object_type(node.left) == "pathlib.Path":
                return "pathlib.Path"
        return None

    def _expr(self, node: ast.AST | None) -> list[Flow]:
        if node is None:
            return []
        direct = request_source(node, self.request_names, self.module.file)
        if direct:
            if not any(
                (parameter.name, parameter.location) == (direct.name, direct.location)
                for parameter in self.endpoint.parameters
            ):
                self.endpoint.parameters.append(
                    Parameter(name=direct.name, location=direct.location)
                )
            return [Flow(source=direct, steps=[self._step(ast.unparse(node), node)])]
        if isinstance(node, ast.Name):
            return self.env.get(node.id, [])
        if isinstance(node, ast.Constant):
            return []
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return []
        if isinstance(node, ast.NamedExpr):
            flows = self._expr(node.value)
            self._bind(node.target, flows, node.value)
            return flows
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.IfExp):
            self._expr(node.test)
            return self._append(
                merge(self._expr(node.body), self._expr(node.orelse)), ast.unparse(node), node
            )
        if isinstance(node, ast.Attribute):
            return self._append(self._expr(node.value), ast.unparse(node), node)
        if isinstance(node, ast.Subscript):
            # Indexing an untrusted body preserves its source; dynamic indexes are conservative.
            return self._append(
                merge(self._expr(node.value), self._expr(node.slice)), ast.unparse(node), node
            )
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            original = self._state()
            groups: list[list[Flow]] = []
            for generator in node.generators:
                flows = self._expr(generator.iter)
                self._bind(generator.target, flows, generator.iter)
                groups.append(flows)
                groups.extend(self._expr(condition) for condition in generator.ifs)
            if isinstance(node, ast.DictComp):
                groups.extend((self._expr(node.key), self._expr(node.value)))
            else:
                groups.append(self._expr(node.elt))
            self._restore(original)
            return self._append(merge(*groups), ast.unparse(node), node)
        flows = merge(*(self._expr(child) for child in ast.iter_child_nodes(node)))
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.IfExp)):
            return self._append(flows, ast.unparse(node), node)
        return flows

    def _call(self, node: ast.Call) -> list[Flow]:
        name = self._canonical(node.func)
        key = name or ast.unparse(node.func), node.lineno
        if key not in self.seen_calls:
            target = self.index.function(name)
            self.endpoint.called_functions.append(
                FunctionReference(
                    name=key[0],
                    file=target[0].file if target else None,
                    line=target[1].lineno if target else None,
                )
            )
            self.seen_calls.add(key)
        receiver = self._expr(node.func.value) if isinstance(node.func, ast.Attribute) else []
        arguments = [(argument, self._expr(argument)) for argument in node.args]
        arguments.extend((item.value, self._expr(item.value)) for item in node.keywords)
        lookup = {id(argument): flows for argument, flows in arguments}
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            variable = node.func.value.id
            if variable in self.env and node.func.attr in {
                "append",
                "extend",
                "insert",
                "update",
                "add",
                "clear",
                "pop",
                "remove",
                "reverse",
                "sort",
            }:
                self.env[variable] = (
                    []
                    if node.func.attr == "clear"
                    else self._append(
                        merge(receiver, *(flows for _, flows in arguments)), ast.unparse(node), node
                    )
                )
                self.argv.pop(variable, None)
        spec = SINKS.get(name)
        receiver_sink = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS:
            if self._object_type(node.func.value) == "pathlib.Path":
                spec = SinkSpec(category="file", positions=(), keywords=("target",))
                receiver_sink = True
                if node.func.attr in {"rename", "replace"}:
                    spec = SinkSpec(category="file", positions=(0,), keywords=("target",))
                name = "pathlib.Path." + node.func.attr
        if spec:
            expressions = spec.arguments(node)
            if spec.category == "command" and name.startswith("subprocess.") and not spec.shell:
                shell = self._literal(keyword(node, "shell"))
                if shell is not True:
                    # A constant program plus client-controlled argv is not shell injection.
                    # Explicit sh/bash -c is still command execution through a shell.
                    filtered: list[ast.expr] = []
                    for expression in expressions:
                        if isinstance(expression, ast.Name) and expression.id in self.argv:
                            expression = self.argv[expression.id]
                        if isinstance(expression, (ast.List, ast.Tuple)) and expression.elts:
                            program = self._literal(expression.elts[0])
                            options = [self._literal(item) for item in expression.elts[1:3]]
                            if (
                                isinstance(program, str)
                                and program.rsplit("/", 1)[-1]
                                in {"sh", "bash", "zsh", "cmd", "powershell"}
                                and any(
                                    item in {"-c", "/c", "-Command"}
                                    for item in options
                                    if isinstance(item, str)
                                )
                            ):
                                shell = True
                                filtered.append(expression)
                            else:
                                filtered.append(expression.elts[0])
                        else:
                            filtered.append(expression)
                    expressions = filtered
                else:
                    shell = True
            else:
                shell = spec.shell
            flows = merge(*(lookup.get(id(expression), []) for expression in expressions))
            # Executable selection may select a nested expression of an argv list.
            for expression in expressions:
                if id(expression) not in lookup:
                    flows = merge(flows, self._expr(expression))
            if receiver_sink:
                flows = merge(flows, receiver)
            sink = Sink(
                name=name,
                category=spec.category,
                file=self.module.file,
                line=node.lineno,
                expression=ast.unparse(node)[:300],
                shell=shell is True,
            )
            if (name, node.lineno) not in self.seen_sinks:
                self.endpoint.sinks.append(sink)
                self.seen_sinks.add((name, node.lineno))
            for flow in flows:
                finding_key = spec.category, node.lineno, flow.source.name, flow.source.location
                if finding_key in self.seen_findings:
                    continue
                self.seen_findings.add(finding_key)
                steps = self._append([flow], ast.unparse(node), node)[0].steps
                self.endpoint.findings.append(
                    RULES[spec.category].finding(
                        self.endpoint,
                        sink,
                        flow.source,
                        steps,
                        "MEDIUM"
                        if flow.normalized or (spec.category == "command" and not sink.shell)
                        else "HIGH",
                    )
                )
        normalized = name in {
            "os.path.basename",
            "os.path.normpath",
            "os.path.realpath",
            "os.path.abspath",
        } or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"resolve", "absolute"}
            and self._object_type(node.func.value) == "pathlib.Path"
        )
        return self._append(
            merge(receiver, *(flows for _, flows in arguments)), ast.unparse(node), node, normalized
        )

    def _bind(self, target: ast.expr, flows: list[Flow], value: ast.expr | None = None) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = self._append(flows, target.id, target)
            object_type = self._object_type(value) if value else None
            if value and dotted_name(value):
                canonical = self._canonical(value)
                if canonical in SINKS:
                    object_type = canonical
            if object_type:
                self.objects[target.id] = object_type
            else:
                self.objects.pop(target.id, None)
            if isinstance(value, ast.Name) and value.id in self.request_names:
                self.request_names.add(target.id)
            else:
                self.request_names.discard(target.id)
            if isinstance(value, (ast.List, ast.Tuple)):
                self.argv[target.id] = value
            elif isinstance(value, ast.Name) and value.id in self.argv:
                self.argv[target.id] = self.argv[value.id]
            else:
                self.argv.pop(target.id, None)
            if isinstance(value, ast.Constant):
                self.local_constants[target.id] = value.value
            elif isinstance(value, ast.Name) and value.id in self.local_constants:
                self.local_constants[target.id] = self.local_constants[value.id]
            else:
                self.local_constants.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item, flows)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            if isinstance(base, ast.Name):
                self.env[base.id] = self._append(
                    merge(self.env.get(base.id, []), flows), ast.unparse(target), target
                )
                self.argv.pop(base.id, None)
                self.local_constants.pop(base.id, None)

    def _state(self) -> State:
        return (
            self.env.copy(),
            self.objects.copy(),
            self.request_names.copy(),
            self.argv.copy(),
            self.local_constants.copy(),
        )

    def _restore(self, state: State) -> None:
        self.env, self.objects, self.request_names, self.argv, self.local_constants = (
            state[0].copy(),
            state[1].copy(),
            state[2].copy(),
            state[3].copy(),
            state[4].copy(),
        )

    def _branches(self, branches: list[list[ast.stmt]]) -> None:
        before = self._state()
        after = []
        for branch in branches:
            self._restore(before)
            self._block(branch)
            after.append(self._state())
        self._merge_states(after)

    def _merge_states(self, after: list[State]) -> None:
        self.env = {
            key: merge(*(state[0].get(key, []) for state in after))
            for key in set().union(*(state[0] for state in after))
        }
        # Retain a known object type only if all branches agree.
        self.objects = {
            key: value
            for key, value in after[0][1].items()
            if all(state[1].get(key) == value for state in after)
        }
        self.request_names = set.union(*(state[2] for state in after))
        self.argv = {
            key: value
            for key, value in after[0][3].items()
            if all(
                key in state[3] and ast.dump(state[3][key]) == ast.dump(value) for state in after
            )
        }
        self.local_constants = {
            key: value
            for key, value in after[0][4].items()
            if all(key in state[4] and state[4][key] == value for state in after)
        }

    def _block(self, statements: list[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, ast.Assign):
                flows = self._expr(node.value)
                for target in node.targets:
                    self._bind(target, flows, node.value)
            elif isinstance(node, ast.AnnAssign):
                self._bind(node.target, self._expr(node.value), node.value)
            elif isinstance(node, ast.AugAssign):
                self._bind(node.target, merge(self._expr(node.target), self._expr(node.value)))
            elif isinstance(node, (ast.Return, ast.Raise)):
                self._expr(node.value if isinstance(node, ast.Return) else node.exc)
                break
            elif isinstance(node, ast.Expr):
                self._expr(node.value)
            elif isinstance(node, ast.If):
                self._expr(node.test)
                self._branches([node.body, node.orelse])
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                flows = self._expr(node.iter)
                before = self._state()
                self._bind(node.target, flows)
                self._block(node.body)
                after = self._state()
                self._merge_states([before, after])
                self._block(node.orelse)
            elif isinstance(node, ast.While):
                self._expr(node.test)
                self._branches([[], node.body])
                self._block(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    flows = self._expr(item.context_expr)
                    if item.optional_vars:
                        self._bind(item.optional_vars, flows, item.context_expr)
                self._block(node.body)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                self._branches(
                    [node.body + node.orelse] + [handler.body for handler in node.handlers]
                )
                self._block(node.finalbody)
            elif isinstance(node, ast.Match):
                flows = self._expr(node.subject)
                for case in node.cases:
                    self._expr(case.guard)
                    for pattern in ast.walk(case.pattern):
                        if isinstance(pattern, ast.MatchAs) and pattern.name:
                            self.env[pattern.name] = flows
                self._branches([case.body for case in node.cases] + [[]])
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.env.pop(target.id, None)
                        self.objects.pop(target.id, None)
                        self.argv.pop(target.id, None)
                        self.local_constants.pop(target.id, None)
                        self.request_names.discard(target.id)
            elif isinstance(node, ast.Assert):
                self._expr(node.test)
