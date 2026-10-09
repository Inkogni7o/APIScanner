from pathlib import Path

import pytest

from adscan.config import Config
from adscan.detector.framework import detect_frameworks
from adscan.detector.language import detect_languages
from adscan.detector.project import scan_project


def test_polyglot_detection():
    files = [
        Path(name)
        for name in (
            "api.py",
            "web.tsx",
            "package.json",
            "pom.xml",
            "go.mod",
            "Cargo.toml",
            "a.csproj",
            "composer.json",
        )
    ]
    assert detect_languages(files) == [
        "C#",
        "Go",
        "Java",
        "JavaScript",
        "PHP",
        "Python",
        "Rust",
        "TypeScript",
    ]


def test_import_and_manifest_framework_detection():
    contents = {
        Path("api.py"): "from fastapi import FastAPI\n# flask\ntext = 'django'\n",
        Path("requirements.txt"): "httpx\nflask>=3\ndjangorestframework\n",
        Path("package.json"): '{"dependencies": {"@nestjs/core": "*", "express": "*"}}',
        Path("web.ts"): "fetch('/api'); axios.get('/items');",
    }
    assert detect_frameworks(contents) == [
        "Django REST Framework",
        "Express",
        "FastAPI",
        "Flask",
        "NestJS",
    ]


def test_scan_prunes_dependencies_and_tests(tmp_path):
    for folder in (".venv", "node_modules", "tests", "custom", ".project", ".uv-cache"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "ignored.py").write_text("import flask", encoding="utf-8")
    (tmp_path / "app.py").write_text("import fastapi", encoding="utf-8")
    (tmp_path / "test_app.py").write_text("import django", encoding="utf-8")
    scan = scan_project(tmp_path, Config(ignore_paths=["custom"]))
    assert scan.project.files_scanned == 1
    assert scan.project.frameworks == ["FastAPI"]
    included = scan_project(tmp_path, Config(include_tests=True, ignore_paths=["custom"]))
    assert included.project.files_scanned == 3


def test_size_and_bad_encoding_are_diagnostics(tmp_path):
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"\xff\x00")
    scan = scan_project(tmp_path, Config(max_file_bytes=20))
    assert scan.project.files_scanned == 2
    assert not scan.contents
    assert len(scan.diagnostics) == 2


@pytest.mark.parametrize(
    "name,language",
    [
        ("api.php", "PHP"),
        ("view.phtml", "PHP"),
        ("controller.cs", "C#"),
        ("app.rb", "Ruby"),
        ("tasks.rake", "Ruby"),
        ("package.gemspec", "Ruby"),
        ("Gemfile", "Ruby"),
        ("Rakefile", "Ruby"),
        ("server.kt", "Kotlin"),
        ("script.kts", "Kotlin"),
        ("server.scala", "Scala"),
        ("build.sbt", "Scala"),
        ("server.c", "C"),
        ("api.h", "C"),
        ("server.cpp", "C++"),
        ("server.cc", "C++"),
        ("server.cxx", "C++"),
        ("server.C", "C++"),
        ("api.hpp", "C++"),
        ("api.hxx", "C++"),
        ("api.hh", "C++"),
    ],
)
def test_semgrep_languages_and_source_files_reach_the_selected_snapshot(tmp_path, name, language):
    path = tmp_path / name
    path.write_text("// selected source", encoding="utf-8")
    project = scan_project(tmp_path, Config())
    assert project.contents == {Path(name): "// selected source"}
    assert project.project.languages == [language]
    selected = scan_project(path, Config())
    assert selected.contents == project.contents
