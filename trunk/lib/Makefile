include ../Makefile.conf

LIBFILES=initmod.o calls.o
INCLUDES=../include/lockbox.h ../include/linux/lockbox.h

default: liblockbox.a liblockbox.so.1.0

liblockbox.a: $(LIBFILES)
	-rm liblockbox.a
	ar q liblockbox.a $(LIBFILES)

liblockbox.so.1.0: $(LIBFILES)
	gcc -fpic -shared -o liblockbox.so.1.0 $(LIBFILES)

initmod.o: initmod.c $(INCLUDES)
calls.o: initmod.c $(INCLUDES)

install: liblockbox.a liblockbox.so.1.0
	install -d /usr/local/lib
	install -m 644 liblockbox.so.1.0 /usr/local/lib
