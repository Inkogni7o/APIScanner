from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/hello/{name}")
def hello(name: str, greeting: str = "Hello"):
    return {"message": f"{greeting}, {name}"}
