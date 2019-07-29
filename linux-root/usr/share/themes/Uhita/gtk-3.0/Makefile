SHELL := /bin/bash

BIN = gtk.gresource

all: $(BIN)

$(BIN):
	glib-compile-resources gtk.gresource.xml

clean:
	rm -f $(BIN)

.PHONY: clean all
