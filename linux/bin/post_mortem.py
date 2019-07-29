#!/usr/bin/env python3

import subprocess
import sys


def except_handler(except_type, value, except_traceback):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(except_type, value, except_traceback)
    else:
        import ipdb
        import traceback
        print("Uncaught exception:", except_type, value)
        traceback.print_exc()
        ipdb.post_mortem(except_traceback)


if __name__ == '__main__':
    try:
        sys.excepthook = except_handler
        print(subprocess.check_output(sys.argv[1:]).decode("utf-8"))
    except BaseException:
        except_handler(sys.exc_info())
