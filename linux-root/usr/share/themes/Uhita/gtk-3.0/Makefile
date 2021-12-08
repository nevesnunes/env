SHELL := /bin/sh

assets = $(shell find . -iname '*.css' -type f)
bin = gtk.gresource

all: $(bin)

$(bin): gtk.gresource.xml $(assets)
	glib-compile-resources $<

clean:
	rm -f $(bin)

.PHONY: clean all
