from pathlib import Path

import pytest

from adscan.config import Config


def test_config_defaults_and_overrides(tmp_path):
    assert Config.load(tmp_path) == Config()
    (tmp_path / ".adscan.toml").write_text(
        """
[analysis]
include_tests = true
max_file_bytes = 50000
[output]
color = false
[severity]
minimum = "high"
[ignore]
paths = ["custom", "src/generated/*"]
""",
        encoding="utf-8",
    )
    assert Config.load(tmp_path) == Config(
        include_tests=True,
        color=False,
        minimum_severity="HIGH",
        ignore_paths=["custom", "src/generated/*"],
        max_file_bytes=50000,
    )


@pytest.mark.parametrize(
    "text",
    [
        '[analysis]\ninclude_tests="false"',
        "[analysis]\nmax_file_bytes=0",
        '[ignore]\npaths="vendor"',
        "[output]\ncolor=0",
        'analysis="bad"',
        "invalid = [",
    ],
)
def test_invalid_config_is_rejected(tmp_path, text):
    (tmp_path / ".adscan.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(tmp_path)


def test_config_root_has_no_dependency_on_cwd(tmp_path, monkeypatch):
    root = tmp_path / "service"
    root.mkdir()
    (root / ".adscan.toml").write_text("[output]\ncolor=false", encoding="utf-8")
    monkeypatch.chdir(Path(__file__).parent)
    assert Config.load(root).color is False
