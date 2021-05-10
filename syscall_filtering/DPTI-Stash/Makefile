all: sandbox header

header: module/sandbox.c module/sandbox.h sandboxing.c sandboxing.h
	rm -f sandboxing_header.h
	cat module/sandbox.h sandboxing.h sandboxing.c | sed 's/#include ".*"//g' > sandboxing_header.h

sandbox: module/sandbox.c
	cd module && make

install:
	@sudo insmod module/sandbox.ko

remove:
	@sudo rmmod sandbox

clean:
	make -C module clean
	rm -f module/Module.symvers
