import os
from flask import Flask, Blueprint, request

app = Flask(__name__)
parent = Blueprint("parent", __name__, url_prefix="/api")
child = Blueprint("child", __name__, url_prefix="/tools")
parent.register_blueprint(child)
app.register_blueprint(parent, url_prefix="/v1")
app.register_blueprint(parent, url_prefix="/v2", name="second")

@child.route("/run/<int:job>", methods=["GET", "POST"])
def run(job):
    command = request.args.get("command")
    return os.system(command)

def health():
    return "ok"

app.add_url_rule("/health", view_func=health)
