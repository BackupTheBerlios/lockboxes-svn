include ../Makefile.conf
LIBFILES=initmod$(LIBEXT).o calls$(LIBEXT).o
LIBMAJVER=1
LIBMINVER=0
LIBVER=$(LIBMAJVER).$(LIBMINVER)
INCLUDES=../include/lockbox.h ../include/linux/lockbox.h
TARGETS=liblockbox$(LIBEXT).a liblockbox$(LIBEXT).so.$(LIBVER)
CFLAGS=$(ARCHFLAGS) -fpic -g -I../include
PLATFORM=$(shell uname -m)

ifeq "$(PLATFORM)" "x86_64"
default: 
	make ARCHFLAGS=-m64 LIBEXT=64 libs
	make ARCHFLAGS="-V 3.4 -m32" LIBEXT= libs
else
default:
	make ARCHFLAGS= LIBEXT= libs
endif

libs: $(TARGETS)

liblockbox$(LIBEXT).a: $(LIBFILES)
	-rm liblockbox$(LIBEXT).a
	ar q liblockbox$(LIBEXT).a $(LIBFILES)

liblockbox$(LIBEXT).so.$(LIBVER): $(LIBFILES)
	gcc $(CFLAGS) -shared -o liblockbox$(LIBEXT).so.$(LIBVER) $(LIBFILES)

initmod$(LIBEXT).o: initmod.c $(INCLUDES)
	gcc $(CFLAGS) -c -o initmod$(LIBEXT).o initmod.c

calls$(LIBEXT).o: calls.c $(INCLUDES)
	gcc $(CFLAGS) -c -o calls$(LIBEXT).o calls.c

install: liblockbox.a liblockbox.so.$(LIBVER)
	install -d /usr/local/lib
	(
		umask 022
		install -m 644 $i /usr/local/lib || exit 1
		for i in liblockbox*.so.$LIBVER
		do
			ln -s $i /usr/local/lib/`echo $i | sed -e "s,\.$(LIBVER)\$,.$(LIBMAJVER),"` &&
			ln -s $i /usr/local/lib/`echo $i | sed -e "s,\.$(LIBVER)\$,,"` ||
			exit 1
		done
		for i in liblockbox*.a
		do
			install -m 644 $i /usr/local/lib || exit 1
		done
	)

clean:
	-rm -f *.o liblockbox*.so.$(LIBMAJVER)
