include ../Makefile.conf

INCLUDES=../include/lockbox.h
LIBS=../lib/liblockbox.a
DEPS=$(INCLUDES) $(LIBS)
LIBARGS=-L../lib -llockbox
TARGETS=createbox holdvault listboxes listvaults lkbtests

default: $(TARGETS)

createbox.o: createbox.c $(DEPS)
holdvault.o: holdvault.c $(DEPS)
listboxes.o: listboxes.c $(DEPS)
listvaults.o: listvaults.c $(DEPS)
lkbtests.o: lkbtests.c $(DEPS)

createbox: createbox.o $(LIBS)
	gcc -g -o createbox createbox.o $(LIBARGS)

holdvault: holdvault.o $(LIBS)
	gcc -g -o holdvault holdvault.o $(LIBARGS)

listboxes: listboxes.o $(LIBS)
	gcc -g -o listboxes listboxes.o $(LIBARGS)

listvaults: listvaults.o $(LIBS)
	gcc -g -o listvaults listvaults.o $(LIBARGS)

lkbtests: lkbtests.o $(LIBS)
	gcc -g -o lkbtests lkbtests.o $(LIBARGS)

clean:
	-rm -f $(TARGETS) $(TARGETS:%=%.o)
