#!/usr/bin/env python2

# Reference: https://sysexit.wordpress.com/2013/03/17/forbiddenbits-ctf-2013-poir-150-write-up/

import xml.dom.minidom as minidom
import sys


def main():
    counter = 0
    contents = {}
    FILE_SIZE = 1354
    file_as_array = range(FILE_SIZE)

    doc = minidom.parse("pdml.xml")
    top_element = doc.documentElement
    packets = top_element.getElementsByTagName("packet")
    print "%d packets in PDML." % len(packets)

    # Traverse each one of the packets
    for packet in packets:
        http = None
        # Grab the packet's HTTP layer
        for protocol in packet.getElementsByTagName("proto"):
            if protocol.getAttribute("name") == "http":
                http = protocol
                break

        if not http:
            print "Could not find HTTP protocol in packet %d!" % counter
            sys.exit(1)

        content_range = None
        # Grab the "Content-Range: bytes" header from the HTTP response
        for field in http.getElementsByTagName("field"):
            if field.getAttribute("show").startswith("Content-Range: bytes"):
                content_range = field
                break

        if not content_range:
            print "Could not find Content-Range header in packet %d!" % counter
            sys.exit(1)

        filerange = content_range.getAttribute("show")
        start_pos = filerange.find("Content-Range: bytes ")
        if start_pos == -1:
            print "Could not find the 'Content-Range: bytes ' string!"
            sys.exit(1)

        filerange = filerange[start_pos + len("Content-Range: bytes ") :]

        end_pos = filerange.find("/")
        if end_pos == -1:
            print "Could not find the '-' string!"
            sys.exit(1)

        filerange = filerange[:end_pos]

        # Grab the beginning and end offsets from the range
        beginning, end = filerange.split("-")

        # Sanity check: Beginning and end of the range should be ints
        try:
            beginning = int(beginning)
            end = int(end)
        except ValueError:
            print "Could not convert one of the strings (%s, %s) to integer!" % (
                beginning,
                end,
            )
            sys.exit(1)

        # Read the content of the file corresponding to this HTTP response
        filename = "all_packets/key(%d).7z" % counter
        f = open(filename, "rb")
        filedata = f.read()
        f.close()

        # Sanity check: the length of the data from the file should be equal to the range
        if len(filedata) != (end - beginning + 1):
            print "ERROR: len(filedata)[%d] != (end-beginning+1)[%d]. , packet %d" % (
                len(filedata),
                end - beginning + 1,
                counter,
            )
            sys.exit(1)

        # Update the file_as_array, at the corresponding range, with the content of the HTTP response
        file_as_array[beginning : end + 1] = list(filedata)
        # Sanity check: the length of file_as_array must always be equal to 1354
        if len(file_as_array) != FILE_SIZE:
            print "len(file_as_array)[%d] != FILE_SIZE, packet %d" % (
                len(file_as_array),
                counter,
            )
            sys.exit(1)
        counter += 1

    # Just another sanity check...
    if counter != 500:
        print "ERROR: counter = %d, expected = 500" % counter

    # Reconstruct the key.7z file
    print "Writing 7zip file..."
    f = open("key.7z", "wb")
    f.write("".join(file_as_array))
    f.close()


main()
