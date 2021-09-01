#!/usr/bin/env python3

import sys, tempfile, os
from subprocess import call

EDITOR = os.environ.get("EDITOR", "vim")

initial_message = b"foo"

with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
    tf.write(initial_message)
    tf.flush()
    call(EDITOR.split() + [tf.name])

    with open(tf.name, 'r') as f:
        edited_message = f.read()

print(edited_message)
