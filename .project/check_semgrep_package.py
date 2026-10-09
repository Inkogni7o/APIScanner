"""Verify that the wheel and sdist carry the offline Semgrep snapshot and licenses."""

import contextlib
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
package = root / ".project" / "package-check" / "semgrep81-wheel"
package.mkdir(parents=True, exist_ok=True)
source_files = [
    path for path in (root / "src" / "adscan" / "rules").rglob("*")
    if path.is_file() and "__pycache__" not in path.parts
]
with zipfile.ZipFile(root / "dist" / "adscan-0.1.0-py3-none-any.whl") as wheel:
    wheel_names = set(wheel.namelist())
    for path in source_files:
        name = path.relative_to(root / "src").as_posix()
        assert wheel.read(name) == path.read_bytes(), name
    assert not any(".project/" in name or "AGENTS.md" in name for name in wheel_names)
    for name in wheel_names:
        if name.startswith("adscan/"):
            target = package / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(wheel.read(name))

with tarfile.open(root / "dist" / "adscan-0.1.0.tar.gz") as sdist:
    members = {entry.name.split("/", 1)[-1]: entry for entry in sdist.getmembers()}
    assert not any(".project/" in name or "AGENTS.md" in name for name in members)
    for path in source_files:
        name = path.relative_to(root).as_posix()
        member = sdist.extractfile(members[name])
        assert member is not None and member.read() == path.read_bytes(), name

sys.path.insert(0, str(package))
import adscan
from adscan.cli import main

assert Path(adscan.__file__).is_relative_to(package)
output = io.StringIO()
with contextlib.redirect_stdout(output):
    exit_code = main([
        str(root / "tests" / "fixtures" / "semgrep_community"),
        "--semgrep",
        "--semgrep-binary", str(root / ".venv" / "Scripts" / "semgrep.exe"),
        "--format", "json",
    ])
assert exit_code == 0
report = json.loads(output.getvalue())
findings = [finding for endpoint in report["endpoints"] for finding in endpoint["findings"]]
assert not report["diagnostics"]
assert "semgrep:node_sqli_injection" in {finding["rule_id"] for finding in findings}
assert "semgrep:python_sql_rule-hardcoded-sql-expression" in {finding["rule_id"] for finding in findings}
assert all(not endpoint["findings"] for endpoint in report["endpoints"] if endpoint["path"].endswith("/safe"))
print(json.dumps({
    "package": str(package),
    "wheel_and_sdist_rules_licenses_verified": True,
    "endpoints": len(report["endpoints"]),
    "findings": len(findings),
    "unmatched": len(report["unmatched_findings"]),
    "diagnostics": report["diagnostics"],
}))
