SHELL := /bin/bash

BIN = hello_world_gtk
CC = gcc
CFLAGS = -g --std=c99 -Wall -Wextra $(shell pkg-config gtk+-3.0 --cflags)
LDFLAGS = $(shell pkg-config gtk+-3.0 --libs)
SOURCEDIR = .
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJS=$(patsubst %.c, %.o, $(SOURCES))

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f $(OBJS) $(BIN)

.DEFAULT_GOAL := all
.PHONY: clean all
