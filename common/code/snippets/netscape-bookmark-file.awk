#!/usr/bin/awk -f

BEGIN { print \
    "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n" \
    "<!--This is an automatically generated file.\n" \
    "It will be read and overwritten.\n" \
    "Do Not Edit! -->\n" \
    "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n" \
    "<TITLE>Bookmarks</TITLE>\n" \
    "<H1>Bookmarks</H1>\n" \
    "<DL><p>"
}
/^[[:space:]]*$/ { next }
{
    split($0, parts, "|")
    url = parts[1]
    title = separator = ""
    for (i=2; i in parts; i++) {
        title = title separator parts[i]
        separator = "|"
    }
    print "<DT><A HREF=\"" url "\">" title "</A>"
}
END { print "</DL><p>" }
