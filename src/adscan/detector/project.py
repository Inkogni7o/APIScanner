"""Bounded, deterministic source enumeration that never follows symbolic links."""

import os
import tokenize
from fnmatch import fnmatchcase
from pathlib import Path

from pydantic import BaseModel

from adscan.config import Config
from adscan.detector.framework import MANIFEST_NAMES, detect_frameworks
from adscan.detector.language import EXTENSIONS, MANIFESTS, detect_languages
from adscan.models import Diagnostic, Project

IGNORED_DIRS = {
    ".git",
    ".project",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    "coverage",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    ".uv-cache",
}
TEST_DIRS = {"test", "tests", "__tests__"}


class ScannedProject(BaseModel):
    """Source text and detection metadata before parsing."""

    root: Path
    project: Project
    contents: dict[Path, str]
    diagnostics: list[Diagnostic]


def scan_project(root: Path, config: Config) -> ScannedProject:
    """Enumerate source and manifest files; skip binaries, huge files and link targets."""
    target = root.resolve()
    selected_file = target if target.is_file() else None
    root = target.parent if selected_file else target
    if not root.is_dir():
        raise ValueError(f"Project path does not exist: {target}")
    contents: dict[Path, str] = {}
    files: list[Path] = []
    diagnostics: list[Diagnostic] = []

    def ignored(path: Path) -> bool:
        relative = path.relative_to(root).as_posix()
        return any(
            fnmatchcase(relative, pattern.rstrip("/"))
            or fnmatchcase(path.name, pattern.rstrip("/"))
            or relative.startswith(pattern.rstrip("/") + "/")
            for pattern in config.ignore_paths
        )

    def walk_error(error: OSError) -> None:
        diagnostics.append(
            Diagnostic(file=".", message=f"Failed to list directory: {error.strerror}")
        )

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        base = Path(directory)
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in IGNORED_DIRS
            and (config.include_tests or name not in TEST_DIRS)
            and not (base / name).is_symlink()
            and not (base / name).is_junction()
            and not ignored(base / name)
        )
        if selected_file:
            dirs.clear()
        for name in sorted(names):
            path = base / name
            if selected_file is not None and path != selected_file:
                continue
            if path.is_symlink() or ignored(path):
                continue
            if not config.include_tests and (name.startswith("test_") or name.endswith("_test.py")):
                continue
            if (
                path.suffix not in EXTENSIONS
                and name not in MANIFESTS
                and name not in MANIFEST_NAMES
                and not name.startswith("requirements")
            ):
                continue
            relative = path.relative_to(root)
            files.append(relative)
            try:
                if path.stat().st_size > config.max_file_bytes:
                    diagnostics.append(
                        Diagnostic(file=relative.as_posix(), message="File exceeds size limit")
                    )
                    continue
                if path.suffix == ".py":
                    with tokenize.open(path) as stream:
                        text = stream.read()
                else:
                    text = path.read_text(encoding="utf-8-sig")
                if "\0" in text:
                    diagnostics.append(
                        Diagnostic(file=relative.as_posix(), message="Skipped binary file")
                    )
                    continue
                contents[relative] = text
            except (OSError, UnicodeError, SyntaxError) as error:
                diagnostics.append(
                    Diagnostic(file=relative.as_posix(), message=f"Failed to read: {error}")
                )
    project = Project(
        name=target.name,
        languages=detect_languages(files),
        frameworks=detect_frameworks(contents),
        files_scanned=len(files),
    )
    return ScannedProject(root=root, project=project, contents=contents, diagnostics=diagnostics)
