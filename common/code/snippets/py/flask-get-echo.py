#!/usr/bin/env python3

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello!"


@app.route("/<path:text>", methods=["GET", "POST"])
def echo(text):
    return f"You said (len = {len(text)}): {bytes(text, 'latin-1')}"


if __name__ == "__main__":
    app.run()
