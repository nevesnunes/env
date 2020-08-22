SHELL := /bin/bash

BIN = a
CC = gcc
CFLAGS = -O0
LDFLAGS =
SOURCEDIR = .
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJS=$(patsubst %.c, %.o, $(SOURCES))

all: $(BIN)-static $(BIN)-dynamic

$(BIN)-static: $(OBJS)
	$(CC) $(CFLAGS) -static -lc /usr/lib/debug/usr/lib64/libc.a -o $@ $^ $(LDFLAGS)

$(BIN)-dynamic: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f $(OBJS) $(BIN)-static $(BIN)-dynamic

trace:
	# setarch "$(uname -m)" -R /bin/zsh
	# bin=a-dynamic; gdb -batch -ex 'starti' -ex 'info proc map' "$bin" | awk '/'"$bin"'/{print $1 " " $2}'
	~/opt/dynamorio/build/bin64/drrun -t drcov -dump_text -- ./a-dynamic
	~/opt/dynamorio/build/bin64/drrun -logdir . -c ~/opt/dynamorio/build/api/bin/libinstrace_x86_text.so -- ./a-dynamic
	mv ~/opt/dynamorio/build/api/bin/*.log .

.DEFAULT_GOAL := all
.PHONY: clean trace all
