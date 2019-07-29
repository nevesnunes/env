SHELL := /bin/bash

BIN = check-compositor
CC = gcc
CFLAGS = -g --std=c99 -Wall -Wextra
LDFLAGS = -L/usr/X11R6/lib -lX11
SOURCEDIR = src
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
