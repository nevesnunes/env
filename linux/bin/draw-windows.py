#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

from bs4 import BeautifulSoup as BS
from PIL import Image, ImageColor
import json
import os
import sys
import webbrowser

colors = [
    "#e41a1c",
    "#377eb8",
    "#4daf4a",
    "#984ea3",
    "#ff7f00",
    "#ffff33",
    "#a65628",
    "#f781bf",
    "#999999"
]

thumbnail_factor = 4


def make_pixel(source, candidate):
    if source == ImageColor.getrgb("black"):
        return candidate
    return (255, 255, 255)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: %s $json_file" % sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1]) as data_file:
        data = json.load(data_file)
    img = Image.new(
        "RGB",
        (data[0]['w'] / thumbnail_factor,
            data[0]['h'] / thumbnail_factor),
        "black")
    pixels = img.load()

    color_index = 0
    windows = data[1:]
    for window in windows:
        for i in range(
            window['x'] / thumbnail_factor,
            window['x'] / thumbnail_factor +
                window['w'] / thumbnail_factor):
            for j in range(
                window['y'] / thumbnail_factor,
                window['y'] / thumbnail_factor +
                    window['h'] / thumbnail_factor):
                pixels[i, j] = make_pixel(
                    pixels[i, j], ImageColor.getrgb(colors[color_index]))
        color_index = (color_index + 1) % (len(colors) - 1)

    # img.show()
    img.save('./summary/1.png', 'png')
    with open('./summary/main.html') as base_file:
        bs = BS(base_file, 'html.parser')
        body = bs.find('body')
        body.append(bs.new_tag('img', src='1.png'))
        with open("./summary/summary.html", "wb") as summary_file:
            summary_file.write(bs.prettify("utf-8"))

    webbrowser.open_new_tab(
        'file://' +
        os.path.realpath('./summary/summary.html'))
