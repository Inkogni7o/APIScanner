import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from adscan.analysis.semgrep import (
    SemgrepError,
    SemgrepMatch,
    default_rule_files,
    normalize,
    run_semgrep,
)
from adscan.cli import main, select_report
from adscan.config import Config
from adscan.output.terminal import render_terminal
from adscan.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def match(file="utils.py", line=4, col=5, rule="test.shell", severity="ERROR"):
    return SemgrepMatch.model_validate(
        {
            "check_id": rule,
            "path": file,
            "start": {"line": line, "col": col},
            "end": {"line": line, "col": col + 5},
            "extra": {
                "message": "Review shell execution",
                "severity": severity,
                "metadata": {"confidence": "HIGH"},
            },
        }
    )


def test_semgrep_maps_helpers_and_retains_unmatched_findings(monkeypatch):
    findings = [match(), match(), match(line=7, rule="test.unused")]
    monkeypatch.setattr("adscan.scanner.run_semgrep", lambda *args: (findings, []))
    report = scan(FIXTURES / "semgrep", Config(semgrep_enabled=True))
    endpoint = next(item for item in report.endpoints if item.path == "/run")
    assert len(endpoint.findings) == 1
    assert endpoint.findings[0].rule_id == "semgrep:test.shell"
    assert endpoint.findings[0].endpoint == "POST /run"
    assert endpoint.findings[0].file == "utils.py" and endpoint.findings[0].confidence == "HIGH"
    assert endpoint.findings[0].source is None
    assert endpoint.findings[0].dataflow[0].expression == "call utils.execute"
    assert endpoint.priority == "HIGH" and endpoint.score == 60
    assert len(report.unmatched_findings) == 1 and report.unmatched_findings[0].endpoint == ""
    terminal = render_terminal(report, FIXTURES / "semgrep", mode="findings")
    assert "utils.py:7" in terminal and "No statically resolved endpoint" in terminal
    assert not select_report(report, "findings", "CRITICAL", None, None).unmatched_findings


def test_helper_cycles_and_shared_handlers_are_correlated_to_each_route(tmp_path, monkeypatch):
    source = (
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/a')\n@app.post('/b')\n"
        "def route(q:str):\n return helper(q)\ndef helper(q):\n route(q)\n return eval(q)\n"
    )
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    monkeypatch.setattr("adscan.scanner.run_semgrep", lambda *args: ([match("main.py", 9, 2)], []))
    report = scan(tmp_path, Config(semgrep_enabled=True))
    assert {endpoint.identifier for endpoint in report.endpoints} == {"GET /a", "POST /b"}
    assert all(len(endpoint.findings) == 1 for endpoint in report.endpoints)
    assert not report.unmatched_findings


def test_javascript_same_line_handlers_use_columns(tmp_path, monkeypatch):
    source = (
        "import express from 'express'; const app=express(); "
        "app.get('/a',(req,res)=>{eval(req.query.q)}); "
        "app.get('/b',(req,res)=>{res.send('ok')});"
    )
    (tmp_path / "main.js").write_text(source, encoding="utf-8")
    column = source.index("eval") + 1
    monkeypatch.setattr(
        "adscan.scanner.run_semgrep", lambda *args: ([match("main.js", 1, column)], [])
    )
    report = scan(tmp_path, Config(semgrep_enabled=True))
    assert (
        len(
            [
                finding
                for finding in next(
                    endpoint for endpoint in report.endpoints if endpoint.path == "/a"
                ).findings
                if finding.rule_id.startswith("semgrep:")
            ]
        )
        == 1
    )
    assert not next(endpoint for endpoint in report.endpoints if endpoint.path == "/b").findings


def test_disabled_semgrep_never_spawns_process(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Semgrep was not requested")

    monkeypatch.setattr("adscan.analysis.semgrep.subprocess.run", unexpected)
    assert scan(FIXTURES / "semgrep").endpoints


def test_runner_uses_local_rules_selected_snapshot_and_offline_flags(tmp_path, monkeypatch):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []", encoding="utf-8")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert "--metrics=off" in command and "--disable-version-check" in command
        assert "--no-rewrite-rule-ids" in command and str(rules) in command
        assert [command[i + 1] for i, arg in enumerate(command) if arg == "--config"] == [
            str(rules)
        ]
        cwd = kwargs["cwd"]
        assert (cwd / "main.py").read_text(encoding="utf-8") == "print('привет')"
        assert kwargs["env"]["SEMGREP_APP_TOKEN"] == ""
        assert kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"
        assert Path(kwargs["env"]["SEMGREP_SETTINGS_FILE"]).is_relative_to(cwd)
        result = match("main.py", 1, 1).model_dump()
        result["path"] = str(cwd / "main.py")
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {"results": [result], "errors": [{"path": "broken.py", "message": "Syntax error"}]}
            ),
            "",
        )

    monkeypatch.setattr("adscan.analysis.semgrep.subprocess.run", fake_run)
    matches, diagnostics = run_semgrep({Path("main.py"): "print('привет')"}, [rules])
    assert matches[0].path == "main.py" and diagnostics[0].file == "broken.py"
    assert len(calls) == 1


def test_default_scan_passes_bundled_third_party_rules(monkeypatch):
    def fake_run(command, **kwargs):
        configs = [Path(command[i + 1]) for i, arg in enumerate(command) if arg == "--config"]
        assert configs == [path.resolve() for path in default_rule_files()]
        assert configs[0].name == "semgrep.yml"
        assert {"gitlab", "njsscan"} <= {
            path.relative_to(configs[0].parent).parts[1] for path in configs[1:]
        }
        assert all(path.is_file() for path in configs)
        return subprocess.CompletedProcess(command, 0, '{"results": [], "errors": []}', "")

    monkeypatch.setattr("adscan.analysis.semgrep.subprocess.run", fake_run)
    assert run_semgrep({Path("main.py"): "pass"}, []) == ([], [])


def test_vendored_snapshot_matches_provenance_and_has_no_duplicate_rule_ids():
    directory = default_rule_files()[0].parent / "third_party"
    recorded = set()
    rule_ids = set()
    for path in directory.glob("*/provenance.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert len(manifest["commit"]) == 40
        assert (path.parent / "LICENSE").is_file()
        for record in manifest["files"]:
            content = (path.parent / record["path"]).read_bytes()
            assert hashlib.sha256(content).hexdigest() == record["sha256"]
            if "rule_ids" in record:
                recorded.add(path.parent / record["path"])
                assert not rule_ids.intersection(record["rule_ids"])
                rule_ids.update(record["rule_ids"])
    assert recorded == set(default_rule_files()[1:])


@pytest.mark.parametrize("severity", ["High", "Critical", "Low", "Info"])
def test_gitlab_metadata_preserves_security_severity_and_readable_title(severity):
    result = match()
    result.extra.metadata.update(
        {"security-severity": severity, "shortDescription": "SQL injection"}
    )
    finding = normalize(result)
    assert finding.severity == severity.upper()
    assert finding.title == "SQL injection"


@pytest.mark.parametrize("output,code", [("not-json", 0), ('{"results": []}', 7)])
def test_runner_reports_external_failures(monkeypatch, output, code):
    monkeypatch.setattr(
        "adscan.analysis.semgrep.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, code, output, "invalid rule"
        ),
    )
    with pytest.raises(SemgrepError):
        run_semgrep({}, [])


@pytest.mark.parametrize(
    "error", [FileNotFoundError("missing"), subprocess.TimeoutExpired("semgrep", 120)]
)
def test_runner_reports_missing_binary_and_timeout(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("adscan.analysis.semgrep.subprocess.run", fail)
    with pytest.raises(SemgrepError):
        run_semgrep({}, [])


def test_registry_config_is_rejected_without_running_anything(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("must not execute remote config")

    monkeypatch.setattr("adscan.analysis.semgrep.subprocess.run", unexpected)
    with pytest.raises(SemgrepError, match="local files"):
        run_semgrep({}, [Path("p/python")])


def test_semgrep_cli_error_is_clear(capsys):
    assert (
        main([str(FIXTURES / "semgrep"), "--semgrep-binary", "missing-semgrep-test-executable"])
        == 2
    )
    assert "Semgrep executable not found" in capsys.readouterr().err


def test_semgrep_cli_config_enables_engine_and_saves_results(tmp_path, monkeypatch, capsys):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []", encoding="utf-8")

    def fake_scan(contents, configs, executable, timeout):
        assert configs == [rules] and executable == "semgrep"
        return [match()], []

    monkeypatch.setattr("adscan.scanner.run_semgrep", fake_scan)
    assert (
        main([str(FIXTURES / "semgrep"), "--semgrep-config", str(rules), "--format", "json"]) == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["endpoints"][0]["findings"][0]["rule_id"] == "semgrep:test.shell"


@pytest.mark.skipif(
    not os.getenv("ADSCAN_TEST_SEMGREP"),
    reason="set ADSCAN_TEST_SEMGREP=1 to run installed Semgrep",
)
@pytest.mark.parametrize("fixture", ["semgrep", "express", "semgrep_multilang", "rust_axum"])
def test_installed_semgrep_integration(fixture):
    executable = Path(sys.executable).with_name(
        "semgrep.exe" if sys.platform == "win32" else "semgrep"
    )
    report = scan(FIXTURES / fixture, Config(semgrep_enabled=True, semgrep_binary=str(executable)))
    findings = [
        finding
        for endpoint in report.endpoints
        for finding in endpoint.findings
        if finding.rule_id.startswith("semgrep:adscan.")
    ]
    assert findings and all(finding.endpoint for finding in findings)
    assert not report.diagnostics
    if fixture == "semgrep":
        assert findings[0].file == "utils.py" and report.unmatched_findings[0].file == "utils.py"
    elif fixture == "express":
        assert {finding.endpoint for finding in findings} == {
            "POST /api/users/:id",
            "POST /v2/users/:id",
        }
    elif fixture == "rust_axum":
        assert {finding.endpoint for finding in findings} == {"GET /api/run", "GET /api/safe"}
        assert all(finding.file == "src/handlers.rs" for finding in findings)
    else:
        assert {finding.endpoint for finding in findings} == {
            "POST /java/run",
            "GET /go/run",
            "POST /ts/run",
            "POST /js/run",
        }


@pytest.mark.skipif(
    not os.getenv("ADSCAN_TEST_SEMGREP"),
    reason="set ADSCAN_TEST_SEMGREP=1 to run installed Semgrep",
)
def test_installed_semgrep_community_rules_find_real_flows_and_skip_safe_variants():
    executable = Path(sys.executable).with_name(
        "semgrep.exe" if sys.platform == "win32" else "semgrep"
    )
    report = scan(
        FIXTURES / "semgrep_community",
        Config(semgrep_enabled=True, semgrep_binary=str(executable)),
    )
    assert not report.diagnostics
    endpoints = {endpoint.identifier: endpoint for endpoint in report.endpoints}
    expected = {
        "GET /python/sql": "python_sql_rule-hardcoded-sql-expression",
        "GET /python/tls": "python_ssl_rule-req-no-certvalid",
        "GET /go/sql": "go_sql_rule-concat-sqli",
        "GET /ts/sql": "node_sqli_injection",
        "GET /ts/xss": "express_xss",
        "GET /js/nosql": "node_nosqli_js_injection",
        "GET /java/xml": "java_xxe_rule-XMLRdr",
    }
    for endpoint, rule in expected.items():
        findings = endpoints[endpoint].findings
        finding = next(f for f in findings if f.rule_id == f"semgrep:{rule}")
        assert finding.file and finding.line > 0 and finding.endpoint == endpoint
    sql = endpoints["GET /python/sql"]
    assert sql.priority == "HIGH" and sql.score == 60
    assert sql.findings[0].dataflow[0].expression == "call database.lookup"
    assert all(
        not endpoint.findings
        for identifier, endpoint in endpoints.items()
        if identifier.endswith("/safe")
    )
    assert any(
        finding.rule_id == "semgrep:java_password_rule-ConstantDBPassword"
        and finding.endpoint == ""
        and finding.severity == "CRITICAL"
        for finding in report.unmatched_findings
    )
