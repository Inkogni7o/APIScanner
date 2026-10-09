from pathlib import Path

from adscan.extractors.fastapi import FastAPIExtractor
from adscan.parsers.python import PythonIndex


def extract(files):
    index = PythonIndex({Path(name): text for name, text in files.items()}, [])
    return [item.endpoint for item in FastAPIExtractor().extract(index)], index


def test_nested_prefixes_import_aliases_and_repeated_mounts():
    endpoints, _ = extract(
        {
            "app/main.py": """
from fastapi import FastAPI
from .outer import router as outer_router
app = FastAPI()
app.include_router(outer_router, prefix="/v1")
app.include_router(outer_router, prefix="/v2")
""",
            "app/outer.py": """
from fastapi import APIRouter
from .users import router as users
router = APIRouter(prefix="/api")
router.include_router(users, prefix="/nested")
""",
            "app/users.py": """
from fastapi import APIRouter as Router
router = Router(prefix="/users")
@router.get("/{id}")
def get_user(id: int): return id
""",
        }
    )
    assert {e.path for e in endpoints} == {"/v1/api/nested/users/{id}", "/v2/api/nested/users/{id}"}
    assert endpoints[0].parameters[0].location == "path"


def test_parameters_and_auth_inheritance():
    endpoints, _ = extract(
        {
            "main.py": """
from typing import Annotated
from fastapi import (FastAPI, APIRouter, Query, Body, Header, Cookie, File,
                     UploadFile, Depends, Security, Request)
from pydantic import BaseModel
class Payload(BaseModel):
    url: str
def get_current_user(): pass
def database(): pass
app = FastAPI(dependencies=[Depends(get_current_user)])
router = APIRouter(prefix="/api")
@router.post("/items/{id}")
def create(id: int, payload: Payload, search: Annotated[str, Query(alias="q")],
           count: int = 1, user_agent: str = Header(), cookie: str = Cookie(None),
           upload: UploadFile = File(...), body: dict = Body(...),
           user = Security(get_current_user), db = Depends(database), request: Request = None):
    return {}
app.include_router(router, prefix="/v1")
"""
        }
    )
    endpoint = endpoints[0]
    assert endpoint.path == "/v1/api/items/{id}"
    assert {p.name: p.location for p in endpoint.parameters} == {
        "id": "path",
        "payload": "body",
        "search": "query",
        "count": "query",
        "user_agent": "header",
        "cookie": "cookie",
        "upload": "file",
        "body": "body",
    }
    params = {p.name: p for p in endpoint.parameters}
    assert params["search"].alias == "q"
    assert params["user_agent"].alias == "user-agent"
    assert params["body"].required is True
    assert params["cookie"].required is False
    assert params["count"].required is False
    assert {auth.name for auth in endpoint.auth} == {"get_current_user"}


def test_multiple_methods_static_constants_trailing_slashes_and_registration():
    endpoints, _ = extract(
        {
            "main.py": """
import fastapi as f
PREFIX = "/api"
app = f.FastAPI()
router = f.APIRouter(prefix=PREFIX)
@router.api_route("/", methods=["GET", "POST"])
async def index(): pass
def item(name: str): pass
app.include_router(router)
app.add_api_route("/item", item, methods=["PUT"])
"""
        }
    )
    assert {(e.method, e.path) for e in endpoints} == {
        ("GET", "/api/"),
        ("POST", "/api/"),
        ("PUT", "/item"),
    }


def test_client_methods_are_not_routes_and_parse_errors_do_not_abort():
    endpoints, index = extract(
        {
            "broken.py": "def ???",
            "main.py": """
from fastapi import FastAPI
import requests
app = FastAPI()
@app.get("/health")
def health(): return {"status": "ok"}
@requests.get("https://example.com")
def fake(): pass
""",
        }
    )
    assert [e.path for e in endpoints] == ["/health"]
    assert len(index.diagnostics) == 1


def test_router_cycles_are_bounded():
    endpoints, index = extract(
        {
            "main.py": """
from fastapi import APIRouter
a = APIRouter()
b = APIRouter()
a.include_router(b)
b.include_router(a)
@a.get("/x")
def x(): pass
"""
        }
    )
    assert not endpoints
    assert any("cycle" in item.message for item in index.diagnostics)


def test_dynamic_prefix_is_not_replaced_with_an_invented_path():
    endpoints, index = extract(
        {
            "main.py": """
import os
from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter(prefix="/api")
@router.get("/x")
def x(): pass
app.include_router(router, prefix=os.getenv("PREFIX"))
"""
        }
    )
    assert not endpoints
    assert any(
        "Dynamic include_router prefix" in diagnostic.message for diagnostic in index.diagnostics
    )


def test_container_body_and_explicit_query_model():
    endpoints, _ = extract(
        {
            "main.py": """
from fastapi import FastAPI, Query
from typing import Annotated
from pydantic import BaseModel
class Filters(BaseModel):
    name: str
app = FastAPI()
@app.post("/input")
def handle(body: dict, query: Annotated[Filters, Query()]): pass
"""
        }
    )
    assert [(p.name, p.location) for p in endpoints[0].parameters] == [
        ("body", "body"),
        ("query", "query"),
    ]


def test_reexported_root_router_and_include_auth():
    endpoints, index = extract(
        {
            "__init__.py": "from .users import router",
            "main.py": """
from fastapi import FastAPI, Depends
from users import router
def get_current_user(): pass
app = FastAPI()
app.include_router(router, dependencies=[Depends(get_current_user)])
""",
            "users.py": """
from fastapi import APIRouter
router = APIRouter()
@router.get("/users")
def users(): pass
""",
        }
    )
    assert index.resolve(index.modules["__root__"], "router") == "users.router"
    assert endpoints[0].path == "/users"
    assert endpoints[0].auth[0].name == "get_current_user"
    assert not endpoints[0].parameters


def test_api_key_dependency_and_non_auth_dependency():
    endpoints, _ = extract(
        {
            "main.py": """
from fastapi import FastAPI, Depends
from fastapi.security import APIKeyHeader
key_scheme = APIKeyHeader(name="X-Key")
app = FastAPI()
def database(): pass
@app.get("/private")
def handle(key=Depends(key_scheme), db=Depends(database)): pass
"""
        }
    )
    assert [auth.name for auth in endpoints[0].auth] == ["key_scheme"]
    assert not endpoints[0].parameters
