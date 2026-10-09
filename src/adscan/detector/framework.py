"""Conservative framework detection from imports and dependency manifests."""

import ast
import re
from pathlib import Path

FRAMEWORKS: dict[str, tuple[str, ...]] = {
    "FastAPI": ("fastapi",),
    "Flask": ("flask",),
    "Django": ("django",),
    "Django REST Framework": ("rest_framework", "djangorestframework"),
    "Express": ("express",),
    "NestJS": ("@nestjs/core", "@nestjs/common"),
    "Fastify": ("fastify",),
    "Spring Boot": ("spring-boot",),
    "Spring MVC": ("spring-webmvc", "org.springframework.web"),
    "Gin": ("github.com/gin-gonic/gin",),
    "Echo": ("github.com/labstack/echo",),
    "Fiber": ("github.com/gofiber/fiber",),
    "net/http": ("net/http",),
    "Chi": ("github.com/go-chi/chi",),
    "Gorilla Mux": ("github.com/gorilla/mux",),
    "Axum": ("axum",),
    "Actix Web": ("actix_web", "actix-web"),
    "Rocket": ("rocket",),
    "Hono": ("hono",),
    "Elysia": ("elysia",),
}
MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "Cargo.toml",
    "tsconfig.json",
}


def detect_frameworks(contents: dict[Path, str]) -> list[str]:
    """Do not treat Python comments, docstrings, or frontend HTTP calls as imports."""
    found: set[str] = set()
    for path, text in contents.items():
        evidence: list[str] = []
        if path.suffix == ".py":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                # Import-only fallback for malformed or newer Python syntax.
                evidence = re.findall(r"^\s*(?:from|import)\s+([\w.]+)", text, re.M)
            else:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        evidence.extend(item.name for item in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        evidence.append(node.module)
        elif path.name in MANIFEST_NAMES or path.name.startswith("requirements"):
            evidence = [text]
        elif path.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
            evidence = re.findall(
                r"(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*)['\"]([^'\"]+)", text
            )
        elif path.suffix in {".java", ".go"}:
            evidence = [text]
        elif path.suffix == ".rs":
            evidence = re.findall(r"\b(?:use|extern\s+crate)\s+([\w:]+)", text)
            evidence.extend(re.findall(r"\b(axum|actix_web|rocket)::", text))
        for framework, patterns in FRAMEWORKS.items():
            if any(
                re.search(r"(?<![\w-])" + re.escape(pattern) + r"(?![\w-])", item)
                for pattern in patterns
                for item in evidence
            ):
                found.add(framework)
    return sorted(found)
