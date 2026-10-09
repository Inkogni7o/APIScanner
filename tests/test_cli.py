import json
import subprocess
import sys
from pathlib import Path

import pytest

from adscan.cli import main
from adscan.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_fixture_acceptance_and_json_stdout(capsys):
    assert main([str(FIXTURES / "fastapi_vulnerable"), "--format", "json"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert not captured.err
    assert report["schema_version"] == "1.1"
    assert report["project"]["languages"] == ["Python"]
    assert report["project"]["frameworks"] == ["FastAPI"]
    assert len(report["endpoints"]) == 9
    by_path = {endpoint["path"]: endpoint for endpoint in report["endpoints"]}
    assert by_path["/run"]["findings"][0]["severity"] == "CRITICAL"
    finding = by_path["/proxy"]["findings"][0]
    assert finding["source"]["location"] == "query"
    assert finding["sink"]["name"] == "requests.get"
    assert finding["dataflow"]
    assert all(not Path(endpoint["file"]).is_absolute() for endpoint in report["endpoints"])


def test_json_file_matches_stdout(tmp_path, capsys):
    output = tmp_path / "report.json"
    assert (
        main([str(FIXTURES / "fastapi_vulnerable"), "--format", "json", "--output", str(output)])
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(capsys.readouterr().out)


def test_endpoint_detail_with_code_and_method(capsys):
    assert (
        main(
            [
                str(FIXTURES / "fastapi_vulnerable"),
                "endpoint",
                "/files/{filename}",
                "--show-code",
                "--method",
                "get",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "Data flow:" in output
    assert "Score reasons:" in output
    assert "Confidence: HIGH" in output
    assert 'with open("/tmp/" + filename)' in output
    assert "main.py:" in output


def test_endpoint_missing_returns_nonzero(capsys):
    assert main([str(FIXTURES / "fastapi_basic"), "endpoint", "/missing"]) == 2
    assert "no endpoint matched" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["endpoints", "findings"])
def test_commands(command, capsys):
    assert main([str(FIXTURES / "fastapi_vulnerable"), command]) == 0
    assert "/run" in capsys.readouterr().out


def test_severity_and_no_color(capsys):
    assert main([str(FIXTURES / "fastapi_vulnerable"), "--severity", "critical", "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "/run" in output
    assert "/health" not in output
    assert "\033" not in output


def test_invalid_directory_and_config(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err
    (tmp_path / ".adscan.toml").write_text('[severity]\nminimum="invalid"', encoding="utf-8")
    assert main([str(tmp_path)]) == 2
    assert "minimum_severity" in capsys.readouterr().err


def test_broken_file_warns_only_in_verbose_mode(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("def ???", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        (FIXTURES / "fastapi_basic" / "main.py").read_text(), encoding="utf-8"
    )
    assert main([str(tmp_path)]) == 0
    assert not capsys.readouterr().err
    assert main([str(tmp_path), "-v", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert "[WARN] broken.py" in captured.err
    assert json.loads(captured.out)["diagnostics"]


def test_deterministic_serialization_and_no_execution(tmp_path):
    source = (FIXTURES / "fastapi_basic" / "main.py").read_text()
    (tmp_path / "main.py").write_text(
        "raise RuntimeError('must never execute')\n" + source, encoding="utf-8"
    )
    assert scan(tmp_path) == scan(tmp_path)
    assert len(scan(tmp_path).endpoints) == 2


def test_module_cli_and_help():
    result = subprocess.run(
        [sys.executable, "-m", "adscan", "--help"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "--show-code" in result.stdout
    result = subprocess.run(
        [sys.executable, "-m", "adscan", str(FIXTURES / "fastapi_vulnerable"), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert len(json.loads(result.stdout)["endpoints"]) == 9


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, RecursionError])
def test_implementation_errors_are_not_masked(monkeypatch, error_type):
    def failing_scan(*args):
        raise error_type("implementation failure")

    monkeypatch.setattr("adscan.cli.scan", failing_scan)
    with pytest.raises(error_type, match="implementation failure"):
        main([str(FIXTURES / "fastapi_basic")])


def test_json_output_accepts_arbitrary_file_extension(tmp_path, capsys):
    output = tmp_path / "report.txt"
    assert main([str(FIXTURES / "fastapi_basic"), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "1.1"
    assert "Endpoints: 2" in capsys.readouterr().out
