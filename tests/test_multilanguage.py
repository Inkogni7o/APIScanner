"""Service-shaped fixtures exercise routes and native HTTP-to-sink evidence together."""

import json
from pathlib import Path

import pytest

from adscan.cli import main
from adscan.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "fixture,framework,expected",
    [
        (
            "rust_axum",
            "Axum",
            {
                "GET /api/run": "Command Injection",
                "GET /api/files/{name}": "Path Traversal",
                "GET /api/proxy": "SSRF",
                "GET /api/safe": None,
            },
        ),
        (
            "rust_actix",
            "Actix Web",
            {"GET /api/run": "Command Injection", "GET /api/files/{name}": "Path Traversal"},
        ),
        (
            "rust_rocket",
            "Rocket",
            {"GET /api/run": "Command Injection", "GET /api/files/<name..>": "Path Traversal"},
        ),
        (
            "go_chi",
            "Chi",
            {
                "GET /api/run": "Command Injection",
                "GET /api/files/{name}": "Path Traversal",
                "GET /api/proxy": "SSRF",
                "GET /api/safe": None,
            },
        ),
        ("go_http", "net/http", {"GET /files/{name}": "Path Traversal", "POST /proxy": "SSRF"}),
        (
            "go_mux",
            "Gorilla Mux",
            {"POST /api/run": "Command Injection", "PUT /api/run": "Command Injection"},
        ),
        (
            "typescript_service",
            "Express",
            {
                "POST /api/run": "Command Injection",
                "GET /api/files/:name": "Path Traversal",
                "GET /proxy": "SSRF",
                "GET /api/safe": None,
            },
        ),
        ("hono", "Hono", {"GET /api/v1/files/:name": "Path Traversal", "GET /api/proxy": "SSRF"}),
        (
            "elysia",
            "Elysia",
            {
                "POST /api/v1/run": "Command Injection",
                "GET /api/v1/files": "Path Traversal",
                "GET /api/safe": None,
            },
        ),
    ],
)
def test_service_routes_and_native_findings(fixture, framework, expected):
    report = scan(FIXTURES / fixture)
    assert not report.diagnostics
    endpoints = {endpoint.identifier: endpoint for endpoint in report.endpoints}
    assert set(endpoints) == set(expected)
    for identifier, title in expected.items():
        endpoint = endpoints[identifier]
        assert endpoint.framework == framework
        assert [finding.title for finding in endpoint.findings] == ([title] if title else [])
        for finding in endpoint.findings:
            assert finding.source and finding.sink and finding.dataflow
            assert finding.rule_id in {"command_injection", "path_traversal", "ssrf"}
            assert finding.endpoint == identifier
            assert endpoint.score > 0
            assert not Path(finding.file).is_absolute()
    assert report.project.files_parsed > 0
    assert report.project.entry_points


def test_typescript_alias_barrel_factory_and_tainted_helper():
    report = scan(FIXTURES / "typescript_service")
    endpoint = next(e for e in report.endpoints if e.path == "/api/run")
    finding = endpoint.findings[0]
    assert finding.file == "src/utils.ts"
    assert finding.source.file == "src/routes/routes.ts"
    assert any(step.expression == "execute(command)" for step in finding.dataflow)
    assert any(reference.file == "src/utils.ts" for reference in endpoint.called_functions)


@pytest.mark.parametrize(
    "framework,constructor,group,type_name,method",
    [
        ("gin", "gin.New()", "Group", "*gin.RouterGroup", "GET"),
        ("echo", "echo.New()", "Group", "*echo.Group", "GET"),
        ("fiber", "fiber.New()", "Group", "fiber.Router", "Get"),
    ],
)
def test_go_existing_framework_registration_helpers(
    tmp_path, framework, constructor, group, type_name, method
):
    package = {
        "gin": "github.com/gin-gonic/gin",
        "echo": "github.com/labstack/echo/v4",
        "fiber": "github.com/gofiber/fiber/v2",
    }[framework]
    (tmp_path / "main.go").write_text(
        f'package main\nimport "{package}"\n'
        f'func main(){{r:={constructor}; register(r.{group}("/api"))}}\n'
        f'func register(r {type_name}){{r.{method}("/x",handler)}}\n'
        "func handler(){}",
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert [endpoint.identifier for endpoint in report.endpoints] == ["GET /api/x"]
    assert not report.diagnostics


@pytest.mark.parametrize(
    "suffix,source,framework,language",
    [
        (
            "rs",
            "use axum::{Router,routing::get,extract::Query};\n"
            "async fn run(Query(command): Query<String>) { "
            'std::process::Command::new("sh").arg("-c").arg(command).output(); }\n'
            'fn main(){let app=Router::new().route("/run",get(run));}',
            "axum",
            "rust",
        ),
        (
            "go",
            'package main\nimport("net/http";"os/exec")\n'
            'func main(){http.HandleFunc("GET /run",func(w http.ResponseWriter,r *http.Request){'
            'exec.Command("sh","-c",r.URL.Query().Get("command")).Run()})}',
            "net-http",
            "go",
        ),
        (
            "mts",
            "import express from 'express'; import {exec} from 'node:child_process'; "
            "const app=express();app.get('/run',(req,res)=>exec(req.query.command));",
            "express",
            "typescript",
        ),
        (
            "cts",
            "import express = require('express'); import {exec} from 'node:child_process'; "
            "const app=express();app.get('/run',(req,res)=>exec(req.query.command));",
            "express",
            "typescript",
        ),
    ],
)
def test_single_source_file_and_cli_language_selection(
    tmp_path, capsys, suffix, source, framework, language
):
    path = tmp_path / f"service.{suffix}"
    path.write_text(source, encoding="utf-8")
    (tmp_path / "unrelated.py").write_text(
        "raise RuntimeError('must never execute')", encoding="utf-8"
    )
    assert (
        main([str(path), "--language", language, "--framework", framework, "--format", "json"]) == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["project"]["files_parsed"] == 1
    assert len(report["endpoints"]) == 1
    assert report["endpoints"][0]["findings"][0]["title"] == "Command Injection"


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "rs",
            "use axum::{Router,routing::get,extract::Query};\n"
            'async fn run(Query(q): Query<String>){let mut cmd=q;cmd=String::from("echo safe");'
            'std::process::Command::new("sh").arg("-c").arg(cmd).output();}\n'
            'fn main(){Router::new().route("/safe",get(run));}',
        ),
        (
            "go",
            'package main\nimport("net/http";"os/exec")\n'
            'func main(){http.HandleFunc("GET /safe",func(w http.ResponseWriter,r *http.Request){'
            'cmd:=r.URL.Query().Get("q");cmd="echo safe";exec.Command("sh","-c",cmd).Run()})}',
        ),
        (
            "ts",
            "import express from 'express';import {exec} from 'node:child_process';"
            "const app=express();app.get('/safe',(req,res)=>{"
            "let cmd=req.query.q;cmd='echo safe';exec(cmd);});",
        ),
    ],
)
def test_constant_reassignment_clears_taint(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert not report.endpoints[0].findings


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "rs",
            "use axum::{Router,routing::get};fn handler(){} fn main(){"
            'Router::new().nest(dynamic,Router::new().route("/fake",get(handler)));}',
        ),
        (
            "rs",
            "use actix_web::{App,web};fn handler(){}fn main(){"
            'App::new().service(web::scope(dynamic).route("/fake",web::get().to(handler)));}',
        ),
        (
            "ts",
            "import {Hono} from 'hono';const app=new Hono().basePath(dynamic);"
            "app.get('/fake',(c)=>'ok');",
        ),
        (
            "ts",
            "import {Elysia} from 'elysia';"
            "new Elysia().group(dynamic,(app)=>app.get('/fake',()=>''));",
        ),
    ],
)
def test_dynamic_prefix_does_not_invent_unmounted_routes(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert not report.endpoints
    assert report.diagnostics


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "go",
            'package main\nimport("net/http";"encoding/json";"os/exec")\n'
            'func main(){http.HandleFunc("POST /run",run)}\n'
            "func run(w http.ResponseWriter,r *http.Request){"
            "var body struct{Command string};json.NewDecoder(r.Body).Decode(&body);"
            "execute(body.Command)}\n"
            'func execute(cmd string){exec.Command("sh","-c",cmd).Run()}',
        ),
        (
            "rs",
            "use axum::{Router,routing::post,Json};\nstruct Input{command:String}\n"
            'fn main(){Router::new().route("/run",post(run));}\n'
            "async fn run(Json(body):Json<Input>){execute(body.command);}\n"
            'fn execute(command:String){std::process::Command::new("sh")'
            '.arg("-c").arg(command).output();}',
        ),
        (
            "ts",
            "import {Elysia} from 'elysia';import {exec} from 'node:child_process';"
            "new Elysia().post('/run',({body: payload})=>execute(payload.command));"
            "function execute(cmd:string){exec(cmd)}",
        ),
    ],
)
def test_body_input_reaches_a_local_helper(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert not report.diagnostics
    finding = report.endpoints[0].findings[0]
    assert finding.title == "Command Injection" and finding.source.location == "body"
    assert len(finding.dataflow) >= 3


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "go",
            'package main\nimport("net/http";"os")\ntype Controller struct{}\n'
            "func(c *Controller)Read(w http.ResponseWriter,r *http.Request){"
            'os.ReadFile(r.PathValue("name"))}\n'
            "func NewController()*Controller{return &Controller{}}\n"
            "func main(){c:=NewController();mux:=http.NewServeMux();"
            'mux.HandleFunc("GET /files/{name}",c.Read)}',
        ),
        (
            "ts",
            "import express from 'express';import {readFile} from 'node:fs/promises';"
            "class Controller{read(req,res){return this.load(req.params.name)}"
            "load(path:string){return readFile(path)}}"
            "const c=new Controller();const app=express();app.get('/files/:name',c.read.bind(c));",
        ),
    ],
)
def test_controller_instance_methods_and_helpers(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert not report.diagnostics
    endpoint = report.endpoints[0]
    assert len(endpoint.findings) == 1
    assert endpoint.findings[0].title == "Path Traversal"
    assert any(ref.file == f"main.{suffix}" for ref in endpoint.called_functions) or suffix == "go"


def test_rust_router_factory_local_bindings_do_not_shadow_the_application(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use axum::{Router,routing::get};fn handler(){}\n"
        'fn main(){let app=Router::new().nest("/api",routes());axum::serve(listener,app);}\n'
        'fn routes()->Router{let app=Router::new().route("/x",get(handler));app}',
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert [endpoint.identifier for endpoint in report.endpoints] == ["GET /api/x"]
    assert not report.diagnostics


def test_rust_raw_unicode_paths_and_implicit_format_arguments(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use axum::{Router,routing::get,extract::Path};\n"
        'async fn read(Path(name):Path<String>){std::fs::read_to_string(format!("/srv/{name}"));}\n'
        'fn main(){Router::new().route(r#"/files/{name}"#,get(read))'
        '.route("/\\u{0444}/{name}",get(read));}',
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert {endpoint.path for endpoint in report.endpoints} == {"/files/{name}", "/ф/{name}"}
    assert all(len(endpoint.findings) == 1 for endpoint in report.endpoints)
    assert not report.diagnostics


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "go",
            'package main\nimport("net/http";"os")\n'
            'func main(){http.HandleFunc("POST /safe",func(w http.ResponseWriter,r *http.Request){'
            'os.WriteFile("/srv/fixed",[]byte(r.FormValue("content")),0600)})}',
        ),
        (
            "rs",
            "use axum::{Router,routing::get,extract::Query};"
            'fn main(){Router::new().route("/safe",get(run));}'
            'async fn run(Query(body):Query<String>){std::fs::write("/srv/fixed",body);'
            'fn unused(cmd:String){std::process::Command::new("sh").arg("-c").arg(cmd).output();}}',
        ),
        (
            "ts",
            "import express from 'express';import {writeFile} from 'node:fs/promises';"
            "const app=express();app.post('/safe',(req,res)=>{writeFile('/srv/fixed',req.body);"
            "const unused=()=>eval(req.body);});",
        ),
    ],
)
def test_file_contents_and_uninvoked_functions_are_not_path_or_command_findings(
    tmp_path, suffix, source
):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert not report.endpoints[0].findings


def test_invalid_tsconfig_does_not_stop_valid_routes(tmp_path):
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":42}}', encoding="utf-8")
    (tmp_path / "main.ts").write_text(
        "import express from 'express';const app=express();app.get('/x',(req,res)=>'ok');",
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert any(d.file == "tsconfig.json" for d in report.diagnostics)


def test_rust_generic_router_and_handler_references(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use axum::{Router,routing::get,extract::Query};"
        'fn main(){Router::<State>::new().route("/run",get::<_,State>(run::<State>));}'
        "async fn run<T>(Query(command):Query<String>){"
        'std::process::Command::new("sh").arg("-c").arg(command).output();}',
        encoding="utf-8",
    )
    report = scan(tmp_path)
    assert [endpoint.identifier for endpoint in report.endpoints] == ["GET /run"]
    assert len(report.endpoints[0].findings) == 1
    assert not report.diagnostics


def test_rust_helper_in_a_macro_has_reachable_spans_and_native_flow(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use axum::{Router,routing::get,extract::Query};"
        'fn main(){Router::new().route("/run",get(run));}'
        'async fn run(Query(command):Query<String>){format!("{:?}",execute(command));}'
        'fn execute(cmd:String){std::process::Command::new("sh").arg("-c").arg(cmd).output();}',
        encoding="utf-8",
    )
    report = scan(tmp_path)
    endpoint = report.endpoints[0]
    assert len(endpoint.findings) == 1
    assert any(ref.name == "execute" and ref.file == "main.rs" for ref in endpoint.called_functions)
    assert not report.diagnostics


@pytest.mark.parametrize(
    "fixture,suffix", [("rust_axum", "rs"), ("go_chi", "go"), ("typescript_service", "ts")]
)
def test_bad_source_file_does_not_stop_the_service(tmp_path, fixture, suffix):
    import shutil

    shutil.copytree(FIXTURES / fixture, tmp_path, dirs_exist_ok=True)
    (tmp_path / f"broken.{suffix}").write_text("fn func function {{{", encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 4
    assert len([e for e in report.endpoints if e.findings]) == 3
    assert any(d.file == f"broken.{suffix}" for d in report.diagnostics)


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import {Hono} from 'hono';const app=new Hono();"
            "app.route('/api',new Hono().get('/x',(c)=>'ok'));",
            "GET /api/x",
        ),
        (
            "import {Elysia} from 'elysia';new Elysia({prefix:'/api'}).use("
            "new Elysia({prefix:'/v1'}).get('/x',()=>''));",
            "GET /api/v1/x",
        ),
    ],
)
def test_inline_typescript_plugins_are_only_emitted_at_their_mount(tmp_path, source, expected):
    (tmp_path / "main.ts").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert [endpoint.identifier for endpoint in report.endpoints] == [expected]
    assert not report.diagnostics


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "ts",
            "import express from 'express';import {exec} from 'node:child_process';"
            "const app=express();app.get('/run',(req,res)=>{let cmd=req.query.command;"
            "cmd += ' suffix';exec(cmd);});",
        ),
        (
            "go",
            'package main\nimport("net/http";"os/exec")\n'
            'func main(){http.HandleFunc("GET /run",func(w http.ResponseWriter,r *http.Request){'
            'cmd:=r.URL.Query().Get("command");cmd+=" suffix";exec.Command("sh","-c",cmd).Run()})}',
        ),
        (
            "rs",
            "use axum::{Router,routing::get,extract::Query};"
            'fn main(){Router::new().route("/run",get(run));}'
            'async fn run(Query(mut command):Query<String>){command+=" suffix";'
            'std::process::Command::new("sh").arg("-c").arg(command).output();}',
        ),
    ],
)
def test_augmented_assignments_preserve_http_input(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert len(report.endpoints[0].findings) == 1
    assert report.endpoints[0].findings[0].title == "Command Injection"
    assert not report.diagnostics


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "go",
            'package main\nimport "net/http"\n'
            'func main(){http.HandleFunc("GET /proxy",func(w http.ResponseWriter,r *http.Request){'
            'client:=&http.Client{};client.Get(r.URL.Query().Get("url"))})}',
        ),
        (
            "rs",
            "use axum::{Router,routing::get,extract::Query};"
            'fn main(){Router::new().route("/proxy",get(proxy));}'
            "async fn proxy(Query(url):Query<String>){let client=reqwest::Client::builder()"
            ".build().unwrap();client.get(&url).send().await;}",
        ),
    ],
)
def test_outbound_clients_receive_http_urls(tmp_path, suffix, source):
    (tmp_path / f"main.{suffix}").write_text(source, encoding="utf-8")
    report = scan(tmp_path)
    assert len(report.endpoints) == 1
    assert [finding.title for finding in report.endpoints[0].findings] == ["SSRF"]
    assert not report.diagnostics
