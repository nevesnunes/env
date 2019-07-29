obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f *.mod.c *.o *.ko *.order *.symvers

.PHONY: clean
