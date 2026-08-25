from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    # POSITIVE. The caller's text is COMPILED as a template. Jinja reaches the object
    # graph from inside a template, so this ends in code execution rather than in
    # mangled markup.
    name = request.args["name"]
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/hello-safe")
def hello_safe():
    # NEGATIVE. The template is a fixed file and the caller's text is DATA passed to
    # it. This is the correct shape and is by far the more common one.
    return render_template("hello.html", name=request.args["name"])


@app.errorhandler(404)
def not_found(e):
    # POSITIVE, and reachable: any caller can ask for a page that does not exist. An
    # error handler reads the request like any other handler, and the URL it echoes back
    # is the caller's.
    return render_template_string("<h1>Not found: " + request.url + "</h1>"), 404


@app.route("/greeting")
def greeting():
    # NEGATIVE. A template compiled from a literal.
    return render_template_string("<h1>Hello, world</h1>")
