"""Register implemented frameworks here; the pipeline contains no framework branches."""

from typing import Protocol

from adscan.extractors.base import BaseExtractor
from adscan.extractors.controllers import NestJSExtractor, SpringExtractor
from adscan.extractors.django import DjangoExtractor, DRFExtractor
from adscan.extractors.fastapi import FastAPIExtractor
from adscan.extractors.flask import FlaskExtractor
from adscan.extractors.go import (
    ChiExtractor,
    EchoExtractor,
    FiberExtractor,
    GinExtractor,
    HTTPExtractor,
    MuxExtractor,
)
from adscan.extractors.javascript import ExpressExtractor, FastifyExtractor
from adscan.extractors.rust import ActixExtractor, AxumExtractor, RocketExtractor
from adscan.extractors.typescript import ElysiaExtractor, HonoExtractor
from adscan.parsers.cst import CSTEndpoint, CSTIndex

EXTRACTORS: dict[str, type[BaseExtractor]] = {
    "FastAPI": FastAPIExtractor,
    "Flask": FlaskExtractor,
    "Django": DjangoExtractor,
    "Django REST Framework": DRFExtractor,
}


class CSTExtractor(Protocol):
    def extract(self, index: CSTIndex) -> list[CSTEndpoint]: ...


CST_EXTRACTORS: dict[str, type[CSTExtractor]] = {
    "Express": ExpressExtractor,
    "Fastify": FastifyExtractor,
    "NestJS": NestJSExtractor,
    "Spring Boot": SpringExtractor,
    "Spring MVC": SpringExtractor,
    "Gin": GinExtractor,
    "Echo": EchoExtractor,
    "Fiber": FiberExtractor,
    "net/http": HTTPExtractor,
    "Chi": ChiExtractor,
    "Gorilla Mux": MuxExtractor,
    "Axum": AxumExtractor,
    "Actix Web": ActixExtractor,
    "Rocket": RocketExtractor,
    "Hono": HonoExtractor,
    "Elysia": ElysiaExtractor,
}

FRAMEWORK_NAMES = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "drf": "Django REST Framework",
    "express": "Express",
    "fastify": "Fastify",
    "nestjs": "NestJS",
    "spring": "Spring MVC",
    "spring-boot": "Spring Boot",
    "gin": "Gin",
    "echo": "Echo",
    "fiber": "Fiber",
    "net-http": "net/http",
    "chi": "Chi",
    "gorilla-mux": "Gorilla Mux",
    "axum": "Axum",
    "actix": "Actix Web",
    "rocket": "Rocket",
    "hono": "Hono",
    "elysia": "Elysia",
}
