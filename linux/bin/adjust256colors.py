#!/usr/bin/env python3

# Corrects contrast of 256 colors for light themes.

# Features:
# - Contrast values are calculated by modifying color
#   luminosity in CIELAB color space;
# - Output luminosity range is adjustable with command-line options.

# Usage:
#     ./$0 | while read -r i; do printf '\e]4;'"$i"'\a'; done
#     ./$0 | while read -r i; do printf '\ePtmux;\e\e]4;'"$i"'\a\e\\'; done
# Rollback:
#     printf '\e]104;\a'
#     printf '\ePtmux;\e\e]104;\a\e\\'

# Validation:
# - Using pwndbg plugin:
#     gdb -ex 'starti' /usr/bin/true

# TODO:
# - Add option to approximate colors to fixed 16 color palette: https://python-colormath.readthedocs.io/en/latest/delta_e.html
#     - Use same lightness levels when comparing LabColor instances
# - Explore better ways of adjusting perceived lightness: https://www.researchgate.net/post/Are_there_color_spaces_other_then_OSA-UCS_which_explicitly_include_the_Helmholtz-Kohlrausch_effect

import argparse
import math
from colormath.color_objects import LabColor, sRGBColor
from colormath.color_conversions import convert_color


def to_hex(i):
    return hex(int(i))[2:].zfill(2)


def invert_l(r, g, b):
    rgb = sRGBColor(r / 255, g / 255, b / 255)
    if not parsed_args.baseline:
        lab = convert_color(rgb, LabColor)
        (l, a, b) = lab.get_value_tuple()

        l = 100 - l

        # Apply decaying factor to color luminosity
        # Validation: [Exponential Functions](https://www.desmos.com/calculator/3fisjexbvp)
        if parsed_args.darker:
            l = max(0, l - 25 * (0.95 ** (-l + 100)))
        if parsed_args.lighter:
            l = min(100, l + 25 * (0.95 ** l))

        lab = LabColor(l, a, b)
        rgb = convert_color(lab, sRGBColor)
    r = int(math.floor(0.5 + rgb.clamped_rgb_r * 255))
    g = int(math.floor(0.5 + rgb.clamped_rgb_g * 255))
    b = int(math.floor(0.5 + rgb.clamped_rgb_b * 255))

    return (r, g, b)


parser = argparse.ArgumentParser()
parser.add_argument("-b", "--baseline", action="store_true", help="Use default palette")
parser.add_argument("-d", "--darker", action="store_true", help="Darken light colors")
parser.add_argument("-l", "--lighter", action="store_true", help="Lighten dark colors")
parsed_args = parser.parse_args()

for i in range(16, 232):
    v_i = i
    if not parsed_args.baseline:
        # Grayscale: Apply original colors in reverse order
        if i == 16:
            v_i = 231
        if i == 231:
            v_i = 16

    index_R = (v_i - 16) // 36
    rgb_R = 55 + index_R * 40 if index_R > 0 else 0
    index_G = ((v_i - 16) % 36) // 6
    rgb_G = 55 + index_G * 40 if index_G > 0 else 0
    index_B = (v_i - 16) % 6
    rgb_B = 55 + index_B * 40 if index_B > 0 else 0

    if v_i == i:
        (rgb_R, rgb_G, rgb_B) = invert_l(rgb_R, rgb_G, rgb_B)
    h = f"{i};#{to_hex(rgb_R)}{to_hex(rgb_G)}{to_hex(rgb_B)}"
    print(h)

# Grayscale: Apply original colors in reverse order
for i in range(232, 256):
    v = (i - 232) * 10 + 8
    target_i = i
    if not parsed_args.baseline:
        target_i = 255 - (i - 232)

    (rgb_R, rgb_G, rgb_B) = (v, v, v)
    h = f"{target_i};#{to_hex(rgb_R)}{to_hex(rgb_G)}{to_hex(rgb_B)}"
    print(h)
