from flask import Flask, request

from helpers import Runner

app = Flask(__name__)

# An INSTANCE, so `Runner.direct_instance(runner, ...)` is the explicit-receiver form
# rather than another way of writing the class.
runner = Runner()


@app.route("/class-method")
def class_method():
    # POSITIVE. `cls` is parameter zero and the call writes nothing for it, so the
    # caller's value is the SECOND written argument and the THIRD parameter.
    return Runner.as_class_method("ping -c 1 localhost", request.args["cmd"])


@app.route("/class-method-negative")
def class_method_negative():
    # NEGATIVE. The shell is on the parameter one place left of where the caller's value
    # lands, which is exactly where an unshifted binding would put it.
    return Runner.as_class_method_negative("ping -c 1 localhost", request.args["cmd"])


@app.route("/static-method")
def static_method():
    # POSITIVE. No receiver at all: the first written argument IS parameter zero.
    return Runner.as_static_method("ping -c 1 localhost", request.args["cmd"])


@app.route("/static-method-negative")
def static_method_negative():
    # NEGATIVE. The caller's value is written FIRST and belongs on parameter zero.
    # Shifting a staticmethod as though it took a receiver would move it onto the shell.
    return Runner.as_static_method_negative(request.args["cmd"], "ping -c 1 localhost")


@app.route("/explicit-receiver")
def explicit_receiver():
    # POSITIVE. The receiver is written, so nothing shifts and the caller's value is the
    # third argument and the third parameter.
    return Runner.direct_instance(runner, "ping -c 1 localhost", request.args["cmd"])


@app.route("/explicit-receiver-negative")
def explicit_receiver_negative():
    # NEGATIVE. Reading this call as though the receiver were implicit would move the
    # caller's value off `safe` and onto the shell.
    return Runner.direct_instance_negative(runner, request.args["cmd"], "ping -c 1 localhost")


@app.route("/implicit-receiver")
def implicit_receiver():
    # POSITIVE, and the one that needs both readings at once: an explicit receiver here
    # and an implicit one inside `relay`.
    return Runner.relay(runner, "ping -c 1 localhost", request.args["cmd"])


@app.route("/implicit-receiver-negative")
def implicit_receiver_negative():
    # NEGATIVE, through the same two frames.
    return Runner.relay_negative(runner, "ping -c 1 localhost", request.args["cmd"])
