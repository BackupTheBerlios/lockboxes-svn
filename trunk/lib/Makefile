include ../Makefile.conf

LIBFILES=initmod.o calls.o
INCLUDES=../include/lockbox.h ../include/linux/lockbox.h

liblockbox.a: $(LIBFILES)
	-rm liblockbox.a
	ar q liblockbox.a $(LIBFILES)

initmod.o: initmod.c $(INCLUDES)
calls.o: initmod.c $(INCLUDES)
