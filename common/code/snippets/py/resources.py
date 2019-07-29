#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import pkg_resources

def foo():
    contents = pkg_resources.resource_string(
        __name__, 'res/processed/foo.csv')
    filepath = pkg_resources.resource_filename(
        __name__, 'res/processed/foo.csv')
    print('filepath:', filepath)
    print('contents:', contents)
