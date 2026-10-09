"""Language detection from extensions and dependency manifests."""

from pathlib import Path

EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".csproj": "C#",
    ".php": "PHP",
    ".phtml": "PHP",
    ".rb": "Ruby",
    ".rake": "Ruby",
    ".gemspec": "Ruby",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".c": "C",
    ".h": "C",
    ".C": "C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".c++": "C++",
    ".hh": "C++",
    ".hpp": "C++",
    ".hxx": "C++",
    ".h++": "C++",
}
MANIFESTS = {
    "pyproject.toml": "Python",
    "requirements.txt": "Python",
    "setup.py": "Python",
    "package.json": "JavaScript",
    "tsconfig.json": "TypeScript",
    "pom.xml": "Java",
    "build.gradle": "Java",
    "build.gradle.kts": "Java",
    "go.mod": "Go",
    "Cargo.toml": "Rust",
    "composer.json": "PHP",
    "Gemfile": "Ruby",
    "Gemfile.lock": "Ruby",
    "Rakefile": "Ruby",
    "build.sbt": "Scala",
}


def detect_languages(files: list[Path]) -> list[str]:
    """Return all languages evidenced by files, in deterministic order."""
    found = {EXTENSIONS[p.suffix] for p in files if p.suffix in EXTENSIONS}
    found.update(MANIFESTS[p.name] for p in files if p.name in MANIFESTS)
    return sorted(found)
