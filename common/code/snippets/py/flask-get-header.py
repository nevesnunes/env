#!/usr/bin/env python3

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello!"


@app.route("/<path:text>", methods=["GET", "POST"])
def echo(text):
    return f"You said (len = {len(text)}): {bytes(text, 'latin-1')}"


@app.after_request
def after(response):
    red_foo = b"\x1b\x5b\x33\x31\x6d\x66\x6f\x6f\x1b\x28\x42\x1b\x5b\x6d"
    response.headers["X-Foo"] = red_foo
    response.headers["X-Bar"] = "".join(
        [chr(x) if x not in (ord("\r"), ord("\n")) else "" for x in range(0, 255)]
    )

    return response


if __name__ == "__main__":
    app.run(port=18123)
