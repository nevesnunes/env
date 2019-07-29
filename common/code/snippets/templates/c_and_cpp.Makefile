DEFS =
INCS =
LIBS =

CFLAGS   = $(DEFS) $(INCS) -O2 -Wall -ansi -pedantic
CXXFLAGS = $(DEFS) $(INCS) -O2 -Wall -ansi -pedantic -Weffc++
LDFLAGS  = $(LIBS) -s

CFLAGS_DEBUG   = $(DEFS) $(INCS) -g -Wall -ansi -pedantic
CXXFLAGS_DEBUG = $(DEFS) $(INCS) -g -Wall -ansi -pedantic -Weffc++
LDFLAGS_DEBUG  = $(LIBS)

SRCS = $(wildcard *.c *.cc *.cpp *.cxx)
EXT  = $(firstword $(suffix $(SRCS)))
OBJS = $(SRCS:$(EXT)=.o)
DEPS = $(SRCS:$(EXT)=.d)
BIN  = executable_name

PREFIX=/usr/local

ifeq ($(EXT), .c)
LANG = C
else
LANG = CXX
endif

.PHONY: all debug strip install uninstall clean

all: $(BIN)

debug: CFLAGS   = $(CFLAGS_DEBUG)
debug: CXXFLAGS = $(CXXFLAGS_DEBUG)
debug: LDFLAGS  = $(LDFLAGS_DEBUG)
debug: all

strip: all
	strip $(BIN)

$(BIN): $(OBJS)
ifeq ($(LANG), C)
	$(CC) $(LDFLAGS) -o $@ $^
else
	$(CXX) $(LDFLAGS) -o $@ $^
endif

%.d: %$(EXT)
ifeq ($(LANG), C)
	$(CC) -MM -MP -MT $(patsubst %.d,%.o,$@) -MT $@ $< >$@
else
	$(CXX) -MM -MP -MT $(patsubst %.d,%.o,$@) -MT $@ $< >$@
endif

install: all
	install $(BIN) $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN) *.o *.d

-include $(DEPS)