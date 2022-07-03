OBJS=test.o
CFLAGS=
LIBS=
PROG=jstest

all:$(OBJS)
	gcc $(OBJS) $(LIBS) -o $(PROG)

%o:%c
	gcc $(CFLAGS) $< -c

clean:
	rm $(OBJS) $(PROG)
