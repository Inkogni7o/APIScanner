from fastapi import FastAPI
from utils import execute
app = FastAPI()

@app.post("/run")
def run(command: str):
    return execute(command)

@app.get("/health")
def health():
    return "ok"

# The scanner must never import or execute this module.
raise RuntimeError("do not execute analyzed code")
