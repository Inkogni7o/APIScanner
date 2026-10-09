"""Intentionally unsafe static-analysis fixture. Never run as a server."""

import subprocess

import requests
from fastapi import Body, Depends, FastAPI, File, UploadFile
from pydantic import BaseModel

app = FastAPI()
USERS = {1: {"id": 1, "name": "fixture user"}}


class ProxyInput(BaseModel):
    url: str


def get_current_user():
    return {"id": 1}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/files/{filename}")
def read_file(filename: str):
    with open("/tmp/" + filename) as handle:
        return handle.read()


@app.get("/proxy")
def proxy(url: str):
    return requests.get(url).text


@app.post("/run")
def run(command: str):
    return subprocess.run(command, shell=True, capture_output=True).stdout


@app.post("/body-proxy")
def body_proxy(payload: ProxyInput):
    return requests.get(payload.url).text


@app.post("/json-proxy")
def json_proxy(payload: dict = Body(...)):
    return requests.get(payload["url"]).text


@app.get("/private/files/{filename}")
def private_file(filename: str, user=Depends(get_current_user)):
    return open("/tmp/" + filename).read()


@app.get("/users/{id}")
def get_user(id: int):
    # IDOR heuristics belong to a later stage; the MVP records this route and its input.
    return USERS.get(id)


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    content = await file.read()
    with open("/tmp/" + file.filename, "wb") as destination:
        destination.write(content)
    return {"uploaded": True}
