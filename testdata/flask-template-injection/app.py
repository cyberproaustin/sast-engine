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


@app.route("/greeting")
def greeting():
    # NEGATIVE. A template compiled from a literal.
    return render_template_string("<h1>Hello, world</h1>")
