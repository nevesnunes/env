#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import markdown
import mdx_urlize

import json
import os
import sys

def find(key, dictionary):
    for k, v in dictionary.items():
        if k == key:
            yield v
        elif isinstance(v, dict):
            for result in find(key, v):
                yield result
        elif isinstance(v, list):
            for d in v:
                if isinstance(d, dict):
                    for result in find(key, d):
                        yield result

filename = sys.argv[1]
with open(filename, "rb") as f, open('out.html', 'w') as fout:
    needle = "card"
    o = json.load(f)
    if isinstance(o, list):
        j = {}
        j["root"] = o
        o = j
    matches = list(find(needle, o))
    if not len(matches):
        exit(1)

    fout.write("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
           <meta charset="utf-8" />
           <style>
                body {
                    font-family: sans-serif;
                    font-size: 18px;
                    line-height: 1.4;
                    margin: 2rem auto;
                    max-width: 60rem;
                    padding: 0 2rem;
                }

                h1, h2 {
                    font-weight: normal;
                    line-height: 1.2;
                }

                pre {
                    background-color: #f8f8f8;
                    border: 1px solid #ccc;
                    overflow: auto;
                    padding: 6px 10px;
                    border-radius: 3px;
                }

                pre code {
                    background-color: transparent;
                    border: 0;
                }

                code {
                    margin: 0 2px;
                    padding: 0 5px;
                    white-space: nowrap;
                    border: 1px solid #ccc;
                    background-color: #f8f8f8;
                    border-radius: 3px;
                    font-family: monospace;
                    font-size: 0.9rem;
                }

                pre>code {
                    margin: 0;
                    padding: 0;
                    white-space: pre;
                    border: 0;
                    background: transparent;
                }

                .desc {
                    margin: 2rem;
                }

                .title {
                    border-left: 0.5em #9999ff solid;
                    font-weight: bold;
                    margin: 2rem auto;
                    padding: 0.9rem;
                }
           </style>
        </head>
        <body>
        """)

    extensions = ['extra', mdx_urlize.makeExtension(), 'nl2br', 'smarty']
    seen_ids = set()
    for match in matches:
        if not "id" in match or \
                not "name" in match or \
                not "desc" in match:
            continue

        id_ = match["id"]
        if id_ in seen_ids:
            continue
        seen_ids.add(id_)

        name = match["name"]
        desc = match["desc"].replace('\\n', '\n')
        desc = markdown.markdown(desc, 
                extensions=extensions, 
                output_format='html5')
        fout.write("""
            <h1 class='title'>{}</h1><div class='desc'>{}</div>
            """.format(name, desc))

    fout.write("""
        </body>
        </html>
        """)
