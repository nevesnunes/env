#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

cwd = os.path.dirname(os.path.realpath(__file__))

setup(
    name="pygments_paper",
    version="1.0",
    entry_points={
        'pygments.styles': [
            'paper = pygments_paper.style:PaperLightStyle',
        ]
    },
    install_requires=[],
    packages=find_packages(),
)
