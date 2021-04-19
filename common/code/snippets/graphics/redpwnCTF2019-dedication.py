#!/usr/bin/env python3

from PIL import Image
import pytesseract, os


def getFile(extension):
    for item in os.listdir(os.getcwd()):
        if extension in item:
            return item


def getDir():
    for item in os.listdir(os.getcwd()):
        if os.path.isdir(item):
            return item


def prepareImg(fileName):
    with open(fileName, "r") as file:
        data = file.read()
    tmp = data.split("\n")[:-1]
    rows = []
    for item in tmp:
        rows.append(item.split(" ")[:-1])
    height = len(tmp)
    width = len(rows[0])
    pixels = []
    for row in rows:
        t = []
        for pix_str in row:
            p = pix_str[1:-1]
            t.append(tuple(int(s) for s in p.split(",")))
        pixels.append(t)
    print "Height: ", len(pixels), " width: ", len(pixels[0])
    im = Image.new("RGB", (height, width))
    for i in range(0, height):
        for j in range(0, width):
            im.putpixel((i, j), (pixels[i][j][0], pixels[i][j][1], pixels[i][j][2]))
    im.save("output.png")
    print "Output image saved"


def extractPasswd():
    passwd = str(pytesseract.image_to_string(Image.open("output.png"))).lower()
    print "Extracted password: ", passwd
    usr_passwd = raw_input("Change >>> ")
    if usr_passwd != "":
        passwd = usr_passwd
    return passwd


while True:
    fileName = getFile(".png")
    print "Handling image:  ", fileName
    prepareImg(fileName)
    print "Handling output image with pytesseract"
    passwd = extractPasswd()
    z = getFile(".zip")
    print "Extracting zip archive: ", z
    os.system("unzip -P " + passwd + " " + z)
    nextDir = getDir()
    # os.system("cp script.py " + nextDir)
    print "Going to the next dir: ", nextDir
    os.chdir(nextDir)
    print "Directory changed"
