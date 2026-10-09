import json
from pathlib import Path

import pytest

from adscan.cli import main
from adscan.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "fixture,count",
    [
        ("flask", 5),
        ("django", 5),
        ("express", 4),
        ("fastify", 3),
        ("nestjs", 2),
        ("spring", 6),
        ("gin", 2),
        ("echo", 2),
        ("fiber", 2),
    ],
)
def test_framework_fixture_acceptance(fixture, count):
    report = scan(FIXTURES / fixture)
    assert len(report.endpoints) == count, [
        (e.identifier, e.handler_name) for e in report.endpoints
    ]
    assert not report.diagnostics
    assert report.project.files_parsed > 0
    assert all(
        endpoint.line > 0 and not Path(endpoint.file).is_absolute() for endpoint in report.endpoints
    )


def test_flask_mount_override_nested_blueprints_and_dataflow():
    report = scan(FIXTURES / "flask")
    run = [endpoint for endpoint in report.endpoints if endpoint.handler_name == "run"]
    assert {endpoint.path for endpoint in run} == {
        "/v1/tools/run/<int:job>",
        "/v2/tools/run/<int:job>",
    }
    assert all(endpoint.findings[0].title == "Command Injection" for endpoint in run)
    assert all(
        any(
            parameter.name == "command" and parameter.location == "query"
            for parameter in endpoint.parameters
        )
        for endpoint in run
    )


def test_django_include_class_views_and_drf_actions():
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / "django").endpoints}
    assert endpoints["GET /api/download/<path:name>"].auth
    assert endpoints["GET /api/download/<path:name>"].findings[0].title == "Path Traversal"
    assert endpoints["POST /api/job/"].findings[0].title == "Command Injection"
    action = endpoints["POST /api/jobs/{pk}/execute/"]
    assert action.framework == "Django REST Framework"
    assert action.auth[0].name.endswith("IsAuthenticated")
    assert action.findings[0].source.location == "body"
    assert "GET /api/jobs/" in endpoints and "GET /api/jobs/{pk}/" in endpoints


def test_express_imported_router_chains_auth_inputs_and_helpers():
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / "express").endpoints}
    assert endpoints["GET /api/users/:id"].auth[0].name == "requireAuth"
    assert not endpoints["GET /v2/users/:id"].auth
    assert {parameter.name for parameter in endpoints["GET /api/users/:id"].parameters} >= {
        "id",
        "name",
    }
    assert any(
        reference.file == "utils.js"
        for reference in endpoints["POST /api/users/:id"].called_functions
    )


def test_fastify_plugins_object_routes_and_auth():
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / "fastify").endpoints}
    assert endpoints["GET /api/items/:id"].auth
    assert "GET /api/search" in endpoints and "POST /api/search" in endpoints
    assert any(
        parameter.name == "filter" for parameter in endpoints["GET /api/items/:id"].parameters
    )


def test_nestjs_global_prefix_aliases_guards_and_parameter_decorators():
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / "nestjs").endpoints}
    endpoint = endpoints["GET /api/jobs/:id"]
    assert endpoint.handler_name == "JobsController.read" and endpoint.auth
    query = next(parameter for parameter in endpoint.parameters if parameter.location == "query")
    assert query.name == "filter" and query.alias == "q" and query.type == "string"
    assert endpoints["POST /api/jobs"].parameters[0].location == "body"


def test_spring_mappings_arrays_params_and_security():
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / "spring").endpoints}
    endpoint = endpoints["GET /api/jobs/{id}"]
    query = next(parameter for parameter in endpoint.parameters if parameter.location == "query")
    assert query.alias == "q" and query.required is False
    assert endpoint.auth
    assert "PUT /v2/jobs" in endpoints and "POST /api/jobs" in endpoints


@pytest.mark.parametrize(
    "framework,prefix", [("gin", "/api/v1"), ("echo", "/api"), ("fiber", "/api")]
)
def test_go_group_auth_and_request_access(framework, prefix):
    endpoints = {endpoint.identifier: endpoint for endpoint in scan(FIXTURES / framework).endpoints}
    endpoint = endpoints[f"GET {prefix}/jobs/:id"]
    assert endpoint.auth and endpoint.handler_name == "show"
    assert any(
        parameter.name == "q" and parameter.location == "query" for parameter in endpoint.parameters
    )
    assert endpoints[f"POST {prefix}/jobs"].parameters[0].location == "form"


@pytest.mark.parametrize(
    "extension,source,framework",
    [
        (
            "js",
            "import express from 'express'; const app = express(); "
            "app.get(dynamic, (req,res)=>{}); client.get('/fake'); "
            "// app.get('/comment', handler)",
            "Express",
        ),
        (
            "go",
            'package main\nimport "github.com/gin-gonic/gin"\n'
            "func main(){ r:=gin.New(); g:=r.Group(dynamic); "
            'g.GET("/fake",func(c *gin.Context){}); r.GET(dynamic,func(c *gin.Context){}) }',
            "Gin",
        ),
        (
            "ts",
            "import {Controller,Get} from '@nestjs/common'; "
            "@Controller(dynamic) class X { @Get('/fake') run(){} }",
            "NestJS",
        ),
    ],
)
def test_dynamic_routes_and_client_calls_do_not_invent_endpoints(
    tmp_path, extension, source, framework
):
    (tmp_path / f"main.{extension}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert framework in report.project.frameworks
    assert not report.endpoints and report.diagnostics


def test_commonjs_imported_handlers_and_router(tmp_path):
    (tmp_path / "main.cjs").write_text(
        "const express=require('express'); const router=require('./routes'); "
        "const app=express(); app.use('/api',router);",
        encoding="utf-8",
    )
    (tmp_path / "routes.js").write_text(
        "const {Router}=require('express'); const router=Router(); "
        "const handler=(req,res)=>res.send(req.query.q); "
        "router.get('/x',handler); module.exports=router;",
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert [endpoint.identifier for endpoint in report.endpoints] == ["GET /api/x"]


def test_framework_and_language_cli_selection(capsys):
    assert (
        main(
            [
                str(FIXTURES / "django"),
                "--framework",
                "drf",
                "--language",
                "python",
                "--format",
                "json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert len(report["endpoints"]) == 3
    assert all(endpoint["framework"] == "Django REST Framework" for endpoint in report["endpoints"])
