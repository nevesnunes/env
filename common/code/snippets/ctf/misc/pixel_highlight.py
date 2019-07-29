#!/usr/bin/python2.7

import cv2
import numpy as np

if __name__ == '__main__':
    img = cv2.imread('2ukiJIf.png', 0)
    s = ''
    for x in range(150):
        for y in range(300):
            if img[x][y] != 255:
                s += '+'
            else:
                s += ' '
        s += '\n'
    f = open("out.txt", "w")
    f.write(s)
