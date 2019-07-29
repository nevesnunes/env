#!/usr/bin/env python2

import os
from flask import Flask, jsonify, render_template, request, send_from_directory

import nurse_schedule

app = Flask(__name__, static_folder='../build')

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

@app.route("/", methods=['POST'])
def make():
    return jsonify(nurse_schedule.make_from_json(request.json))

if __name__ == "__main__":
    app.run(use_reloader=True, port=3000, threaded=True)
