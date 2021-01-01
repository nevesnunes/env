#!/usr/bin/env python3

from flask import Flask, jsonify
from flask.ext.cors import CORS
import json

application = Flask(__name__)

# Utilize CORS to allow cross-origin API requests
cors = CORS(application)


@application.route("/api/json/<request>", methods=["GET"])
def parse_json_request(request):
    with open("json/" + request, "r") as json_in:
        cooccurrence_json = json.load(json_in)
        return jsonify(cooccurrence_json)


@application.errorhandler(404)
def page_not_found(e):
    return "Sorry, the page you requested could not be found."


if __name__ == "__main__":
    application.run(debug=True)
