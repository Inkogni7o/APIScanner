import requests
from fastapi import FastAPI

from database import lookup

app = FastAPI()


@app.get("/python/sql")
def sql(name: str):
    return lookup(name)


@app.get("/python/tls")
def tls():
    return requests.get("https://example.com", verify=False).text


@app.get("/python/safe")
def safe(name: str, cursor):
    cursor.execute("SELECT name FROM users WHERE name = ?", (name,))
    return requests.get("https://example.com", verify=True).text
