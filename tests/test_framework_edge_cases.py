from pathlib import Path

import pytest

from adscan.config import Config
from adscan.scanner import scan


def write(tmp_path, file, source):
    (tmp_path / file).write_text(source, encoding="utf-8")


@pytest.mark.parametrize("base,count", [("ModelViewSet", 6), ("ReadOnlyModelViewSet", 2)])
def test_drf_inherited_crud_has_real_routes_without_invented_bodies(tmp_path, base, count):
    write(
        tmp_path,
        "urls.py",
        (
            "from django.urls import path, include\n"
            "from rest_framework.routers import SimpleRouter\n"
            f"from rest_framework.viewsets import {base}\n"
            f"class Jobs({base}):\n pass\n"
            "router=SimpleRouter(trailing_slash=False)\n"
            "router.register('jobs', Jobs, basename='jobs')\n"
            "urlpatterns=[path('api/',include(router.urls))]\n"
        ),
    )
    report = scan(tmp_path)
    assert len(report.endpoints) == count
    assert {endpoint.path for endpoint in report.endpoints} == {"/api/jobs", "/api/jobs/{pk}"}
    assert all(endpoint.line == 4 and not endpoint.findings for endpoint in report.endpoints)


def test_drf_inherited_generic_view(tmp_path):
    write(
        tmp_path,
        "urls.py",
        (
            "from django.urls import path\n"
            "from rest_framework.generics import ListCreateAPIView\n"
            "class Jobs(ListCreateAPIView):\n pass\n"
            "urlpatterns=[path('jobs/', Jobs.as_view())]\n"
        ),
    )
    report = scan(tmp_path)
    assert {endpoint.identifier for endpoint in report.endpoints} == {"GET /jobs/", "POST /jobs/"}


def test_drf_api_view_and_permissions(tmp_path):
    write(
        tmp_path,
        "urls.py",
        (
            "from django.urls import path\n"
            "from rest_framework.decorators import api_view, permission_classes\n"
            "from rest_framework.permissions import IsAuthenticated\n"
            "@api_view(['POST'])\n@permission_classes([IsAuthenticated])\n"
            "def run(request):\n return request.data['command']\n"
            "urlpatterns=[path('run/',run)]\n"
        ),
    )
    endpoint = scan(tmp_path).endpoints[0]
    assert endpoint.identifier == "POST /run/" and endpoint.auth
    assert any(parameter.location == "body" for parameter in endpoint.parameters)


def test_django_regex_remains_a_regex(tmp_path):
    write(
        tmp_path,
        "urls.py",
        (
            "from django.urls import re_path\n"
            "def read(request):\n return 'ok'\n"
            "urlpatterns=[re_path(r'^jobs/(?P<pk>[0-9]+)/$',read)]\n"
        ),
    )
    assert scan(tmp_path).endpoints[0].path == "regex:^jobs/(?P<pk>[0-9]+)/$"


def test_flask_dynamic_mount_does_not_remove_known_mount(tmp_path):
    write(
        tmp_path,
        "main.py",
        (
            "from flask import Flask,Blueprint\napp=Flask(__name__)\n"
            "bp=Blueprint('bp',__name__,url_prefix='/local')\n"
            "@bp.route('/x')\ndef run():\n return 'ok'\n"
            "app.register_blueprint(bp,url_prefix=dynamic)\n"
            "app.register_blueprint(bp,url_prefix='/known')\n"
        ),
    )
    report = scan(tmp_path)
    assert [endpoint.path for endpoint in report.endpoints] == ["/known/x"]
    assert report.diagnostics


def test_flask_dynamic_methods_are_not_defaulted_to_get(tmp_path):
    write(
        tmp_path,
        "main.py",
        (
            "from flask import Flask\napp=Flask(__name__)\n"
            "@app.route('/x',methods=dynamic)\ndef run():\n return 'ok'\n"
        ),
    )
    report = scan(tmp_path)
    assert not report.endpoints and report.diagnostics


def test_express_dynamic_mount_is_not_unprefixed(tmp_path):
    write(
        tmp_path,
        "main.js",
        (
            "import express from 'express'; const app=express(); const router=express.Router();"
            "router.get('/x',(req,res)=>{}); app.use(dynamic,router);"
        ),
    )
    report = scan(tmp_path)
    assert not report.endpoints and report.diagnostics


def test_nest_dynamic_global_prefix_is_not_unprefixed(tmp_path):
    write(
        tmp_path,
        "main.ts",
        (
            "import {NestFactory} from '@nestjs/core';"
            "import {Controller,Get} from '@nestjs/common';"
            "const app=await NestFactory.create(AppModule); app.setGlobalPrefix(dynamic);"
            "@Controller('jobs') class X { @Get() run(){} }"
        ),
    )
    report = scan(tmp_path)
    assert not report.endpoints and report.diagnostics


def test_arrow_expression_records_imported_helper(tmp_path):
    write(
        tmp_path,
        "main.js",
        (
            "import express from 'express'; import {execute} from './helpers.js';"
            "const app=express(); app.post('/run',(req,res)=>execute(req.body));"
        ),
    )
    write(tmp_path, "helpers.js", "export function execute(value) { return value; }")
    endpoint = scan(tmp_path).endpoints[0]
    assert any(reference.file == "helpers.js" for reference in endpoint.called_functions)


def test_cst_parse_error_preserves_other_files(tmp_path):
    write(tmp_path, "broken.js", "import express from 'express'; const app = express(); app.get(\"")
    write(
        tmp_path,
        "valid.ts",
        ("import express from 'express'; const app=express(); app.get('/ok',(req,res)=>{});"),
    )
    report = scan(tmp_path)
    assert [endpoint.path for endpoint in report.endpoints] == ["/ok"]
    assert any(diagnostic.file == "broken.js" for diagnostic in report.diagnostics)


def test_semgrep_configuration_is_validated_and_relative_to_service(tmp_path):
    write(
        tmp_path,
        ".adscan.toml",
        (
            '[semgrep]\nenabled=true\nconfigs=["rules.yml"]\n'
            'binary="custom-semgrep"\ntimeout_seconds=90\n'
        ),
    )
    config = Config.load(tmp_path)
    assert config.semgrep_enabled and config.semgrep_configs == ["rules.yml"]
    assert config.semgrep_binary == "custom-semgrep" and config.semgrep_timeout_seconds == 90


def test_legacy_schema_can_be_read_with_default_unmatched_field():
    from adscan.models import Report

    example = Path(__file__).parents[1] / "docs/example-report.json"
    report = Report.model_validate_json(example.read_text(encoding="utf-8"))
    legacy = report.model_dump(exclude={"unmatched_findings"})
    legacy["schema_version"] = "1.0"
    assert not Report.model_validate(legacy).unmatched_findings
