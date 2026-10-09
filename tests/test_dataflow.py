from pathlib import Path

import pytest

from adscan.analysis.dataflow import DataflowAnalyzer
from adscan.extractors.fastapi import FastAPIExtractor
from adscan.parsers.python import PythonIndex


def analyze(body, signature="value: str", imports="", method="get"):
    text = (
        "from fastapi import FastAPI, Request, UploadFile, File, Body\n"
        "import os, subprocess, requests, httpx, aiohttp\n"
        "from pathlib import Path\n"
        + imports
        + "\napp = FastAPI()\n"
        + f'@app.{method}("/test")\nasync def handler({signature}):\n'
        + "\n".join("    " + line for line in body.splitlines())
    )
    index = PythonIndex({Path("main.py"): text}, [])
    item = FastAPIExtractor().extract(index)[0]
    DataflowAnalyzer(index, item).analyze()
    return item.endpoint


@pytest.mark.parametrize(
    "expression",
    [
        "os.system(value)",
        "os.popen(value)",
        "eval(value)",
        "exec(value)",
        "subprocess.run(value, shell=True)",
        "subprocess.Popen(value, shell=True)",
        "subprocess.call(args=value, shell=True)",
        "subprocess.check_output(value, shell=True)",
        'subprocess.run(["sh", "-c", value])',
    ],
)
def test_command_sinks(expression):
    endpoint = analyze("return " + expression)
    assert len(endpoint.findings) == 1
    finding = endpoint.findings[0]
    assert (finding.rule_id, finding.severity, finding.confidence) == (
        "command_injection",
        "CRITICAL",
        "HIGH",
    )


@pytest.mark.parametrize(
    "expression",
    [
        'open("/tmp/" + value)',
        'open(file=value, mode="rb")',
        "os.remove(value)",
        'os.rename("/tmp/source", value)',
        "Path(value).read_text()",
        '(Path("/tmp") / value).read_bytes()',
    ],
)
def test_file_sinks(expression):
    endpoint = analyze("return " + expression)
    assert endpoint.findings[0].rule_id == "path_traversal"
    assert endpoint.findings[0].source.name == "value"


@pytest.mark.parametrize(
    "expression",
    [
        "requests.get(value)",
        "httpx.post(url=value)",
        'requests.request("GET", value)',
        "urllib.request.urlopen(value)",
        "aiohttp.request('GET', value)",
    ],
)
def test_http_sinks(expression):
    endpoint = analyze("return " + expression, imports="import urllib.request")
    assert endpoint.findings[0].rule_id == "ssrf"


def test_assignment_transformation_evidence_and_import_alias():
    endpoint = analyze(
        'filename = value\npath = os.path.join("/tmp", filename)\nreturn read_file(path)',
        imports="from builtins import open as read_file",
    )
    assert endpoint.findings[0].rule_id == "path_traversal"
    expressions = [step.expression for step in endpoint.findings[0].dataflow]
    assert "filename" in expressions
    assert "path" in expressions
    assert any("os.path.join" in expression for expression in expressions)


def test_reassignment_kills_taint_and_constant_destinations_are_safe():
    endpoint = analyze('value = "safe.txt"\nreturn open(value)')
    assert not endpoint.findings
    endpoint = analyze('return requests.get("https://example.com", params={"q": value})')
    assert not endpoint.findings


def test_subprocess_constant_executable_with_user_argv_does_not_claim_injection():
    endpoint = analyze('return subprocess.run(["echo", value], shell=False)')
    assert not endpoint.findings


def test_assigned_safe_argv_and_local_shell_flag():
    assert not analyze('argv = ["echo", value]\nreturn subprocess.run(argv)').findings
    endpoint = analyze("shell_flag = True\nreturn subprocess.run(value, shell=shell_flag)")
    assert endpoint.findings[0].severity == "CRITICAL"


def test_branch_state_does_not_hide_dynamic_executable():
    endpoint = analyze(
        'if value:\n    argv = [value]\nelse:\n    argv = ["echo", value]\n'
        "return subprocess.run(argv)"
    )
    assert endpoint.findings[0].rule_id == "command_injection"


def test_local_function_alias_and_shadowed_builtin():
    assert (
        analyze("runner = os.system\nreturn runner(value)").findings[0].rule_id
        == "command_injection"
    )
    assert not analyze("open = lambda name: name\nreturn open(value)").findings
    assert not analyze("return open(value)", imports="def open(name):\n    return name").findings


def test_container_mutation_propagates_client_data():
    endpoint = analyze("argv = []\nargv.append(value)\nreturn subprocess.run(argv, shell=True)")
    assert endpoint.findings[0].severity == "CRITICAL"
    endpoint = analyze('argv = ["echo", "safe"]\nargv[0] = value\nreturn subprocess.run(argv)')
    assert endpoint.findings[0].rule_id == "command_injection"


def test_flow_through_if_else_and_loop():
    endpoint = analyze(
        'path = "safe.txt"\nif value:\n    path = value\nelse:\n    path = "safe.txt"\n'
        "for item in [path]:\n    open(item)"
    )
    assert endpoint.findings[0].rule_id == "path_traversal"


def test_no_statements_after_return_are_analyzed():
    assert not analyze('return "ok"\nos.system(value)').findings


def test_unknown_helpers_are_listed_but_not_followed():
    endpoint = analyze(
        "return read_file(value)", imports="def read_file(name):\n    return open(name)"
    )
    assert not endpoint.findings
    assert endpoint.called_functions[0].file == "main.py"


@pytest.mark.parametrize(
    "body",
    [
        "url = request.query_params['url']\nreturn requests.get(url)",
        "url = request.headers.get('target')\nreturn requests.get(url)",
        "url = request.cookies['url']\nreturn requests.get(url)",
        "payload = await request.json()\nreturn requests.get(payload['url'])",
    ],
)
def test_request_sources(body):
    endpoint = analyze(body, signature="request: Request")
    assert endpoint.findings[0].rule_id == "ssrf"
    assert endpoint.findings[0].source.location in {"query", "header", "cookie", "body"}


@pytest.mark.parametrize(
    "constructor", ["httpx.AsyncClient", "aiohttp.ClientSession", "requests.Session"]
)
def test_http_client_instances(constructor):
    endpoint = analyze(f"async with {constructor}() as client:\n    return await client.get(value)")
    assert endpoint.findings[0].rule_id == "ssrf"


def test_pathlib_variables_and_normalization():
    endpoint = analyze(
        'path = Path("/tmp") / value\npath = path.resolve()\nreturn path.read_text()'
    )
    assert endpoint.findings[0].rule_id == "path_traversal"
    assert endpoint.findings[0].confidence == "MEDIUM"


def test_file_upload_filename_reaches_file_sink():
    endpoint = analyze(
        'return open("/tmp/" + upload.filename, "wb")', signature="upload: UploadFile = File(...)"
    )
    assert endpoint.parameters[0].location == "file"
    assert endpoint.findings[0].source.location == "file"


def test_multiple_client_sources_are_retained_without_repeated_sink_records():
    endpoint = analyze("return open(first + second)", signature="first: str, second: str")
    assert len(endpoint.findings) == 2
    assert len(endpoint.sinks) == 1


def test_choice_between_fixed_paths_does_not_taint_the_paths():
    assert not analyze('path = "a.txt" if value else "b.txt"\nreturn open(path)').findings


def test_request_sources_are_exposed_as_parameters():
    endpoint = analyze(
        "return requests.get(request.query_params['url'])", signature="request: Request"
    )
    assert [(p.name, p.location) for p in endpoint.parameters] == [("url", "query")]
