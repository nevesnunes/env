SHELL := /bin/bash

CC = gcc
CFLAGS = -g -Wall -Wextra
LIBS = glib-2.0 libwnck-3.0
LFLAGS = $(shell pkg-config --cflags --libs $(LIBS))
TARGET = wnck

all:
	$(shell pkg-config --cflags $(LIBS) > .cflags)
	$(shell pkg-config --cflags --libs $(LIBS) | sed 's/ /\n/g' > .clang_complete)
	$(CC) $(CFLAGS) $(LFLAGS) -o $(TARGET) wnck.c

static:
	/usr/local/musl/bin/musl-gcc -static -Os $(CFLAGS) $(LFLAGS) -o $(TARGET) wnck.c

clean:
	$(RM) $(TARGET)

.PHONY: clean
