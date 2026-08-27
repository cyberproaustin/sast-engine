"""The context is a mapping, and the render call is not where it was filled in.

`render_template("page.html", query=q)` names every variable at the call, and that is the
one shape a frontend can join by itself. It is also the shape an application stops having
as soon as it has more than one page: the context becomes a dict built above the call, a
helper grows that adds the application-wide values to whatever it was handed, and a base
handler mutates a namespace that no subclass ever names.

Everything decidable here rests on a key somebody WROTE. A mapping literal's entries, an
assignment into a subscript, `dict(name=value)`, an `update` with another mapping and the
mapping a function returns each say which name a value arrives under; a computed key says
nothing, and a name nobody wrote binds nothing.

The file also separates two things a `<script>` element makes different. Escaping for a
JavaScript string ends the string and does not end the element -- the HTML parser stops at
the first `</script` whatever the JavaScript says -- while HTML-escaping removes the `<`
and so ends neither.
"""
import json

from markupsafe import escape
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/search")
def search():
    # POSITIVE. The context is one dict, built above the call and handed over whole. The
    # view's `query` is this dict's key and nothing at the render call says so.
    context = {"query": request.args["q"], "count": 3}
    return render_template("results.html", **context)


@app.route("/profile")
def profile():
    # POSITIVE. The mapping is built in another function, so the names do not exist in
    # this one at all. `dict(...)` names them exactly as a literal does.
    return render_template("profile.html", **namespace())


def namespace():
    return dict(name=request.args["name"], role="member")


@app.route("/dashboard")
def dashboard():
    # POSITIVE, through the helper below, which is where the name is bound. This handler
    # writes neither `banner` nor the escaping decision that publishes it.
    return page("dashboard.html", title="Dashboard")


def page(view, **values):
    """The application-wide render helper: every page goes through it, and it adds the
    values every page has. The view it renders is whatever its caller named."""
    values["banner"] = request.args.get("banner", "")
    return render_template(view, **values)


@app.route("/report")
def report():
    # POSITIVE. A namespace nobody wrote down in one place: it starts empty, a shared
    # helper fills in the application's own variables, and this handler adds one of its
    # own. That is what a base handler's namespace hook is, and no line here says which
    # names the view ends up with.
    ns = {}
    ns.update(defaults())
    ns.update({"name": request.args["who"]})
    return render_template("report.html", **ns)


def defaults():
    return {"footer": "generated"}


@app.route("/embed")
def embed():
    # POSITIVE, and in a context of its own. `json.dumps` escapes what would end a
    # JavaScript STRING and leaves `<` alone, so the value still carries `</script>` --
    # and the HTML parser ends the element there whatever the JavaScript says.
    token = json.dumps(request.args["t"])[1:-1]
    return render_template("embed.html", token=token, note=escape(request.args["note"]))


@app.route("/audit")
def audit():
    # NEGATIVE. The key is the caller's, so this mapping has no name to bind. A view
    # reads `{{ something }}`, and answering with a value filed under a key nobody wrote
    # would attach the finding to whichever interpolation happened to be there.
    ledger = {}
    ledger[request.args["field"]] = request.args["value"]
    return render_template("audit.html", **ledger)


@app.route("/about")
def about():
    # NEGATIVE. The mapping supplies `updated` and the view reads `maintainer`, which
    # nothing here binds.
    return render_template("about.html", **{"updated": "2026-01-01"})
