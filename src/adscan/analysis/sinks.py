"""Python sink catalog and argument selection; user input in options is not a URL/path."""

import ast

from pydantic import BaseModel, ConfigDict


class SinkSpec(BaseModel):
    """Catalog metadata describing arguments that control a dangerous operation."""

    model_config = ConfigDict(frozen=True)

    category: str
    positions: tuple[int, ...] = (0,)
    keywords: tuple[str, ...] = ()
    shell: bool = False

    def arguments(self, call: ast.Call) -> list[ast.expr]:
        result = [call.args[pos] for pos in self.positions if pos < len(call.args)]
        result.extend(item.value for item in call.keywords if item.arg in self.keywords)
        return result


SINKS: dict[str, SinkSpec] = {}


def register(names: tuple[str, ...], spec: SinkSpec) -> None:
    for name in names:
        SINKS[name] = spec


register(
    ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"),
    SinkSpec(
        category="command",
        keywords=("command", "cmd"),
        shell=True,
    ),
)
register(
    ("eval", "exec", "builtins.eval", "builtins.exec"),
    SinkSpec(category="command", keywords=("source",), shell=True),
)
register(
    (
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    ),
    SinkSpec(category="command", keywords=("args",)),
)
register(
    (
        "open",
        "builtins.open",
        "io.open",
        "os.open",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "shutil.rmtree",
        "fastapi.responses.FileResponse",
        "starlette.responses.FileResponse",
    ),
    SinkSpec(
        category="file",
        keywords=(
            "file",
            "path",
        ),
    ),
)
register(
    ("os.rename", "os.replace", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move"),
    SinkSpec(
        category="file",
        positions=(0, 1),
        keywords=("src", "dst"),
    ),
)
register(
    ("urllib.request.urlopen", "urllib.request.urlretrieve"),
    SinkSpec(
        category="http",
        keywords=("url", "fullurl"),
    ),
)
for library in (
    "requests",
    "httpx",
    "aiohttp.ClientSession",
    "httpx.Client",
    "httpx.AsyncClient",
    "requests.Session",
):
    for method in ("get", "post", "put", "patch", "delete", "head", "options"):
        register((f"{library}.{method}",), SinkSpec(category="http", keywords=("url",)))
    register((f"{library}.request",), SinkSpec(category="http", positions=(1,), keywords=("url",)))
register(("aiohttp.request",), SinkSpec(category="http", positions=(1,), keywords=("url",)))

PATH_METHODS = {
    "open",
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "unlink",
    "rmdir",
    "mkdir",
    "rename",
    "replace",
}
CLIENT_TYPES = {"httpx.Client", "httpx.AsyncClient", "requests.Session", "aiohttp.ClientSession"}
