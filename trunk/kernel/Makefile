
KERNEL_VERSION = $(shell uname -r)

MODULE_DIR = $(DESTDIR)/lib/modules/$(KERNEL_VERSION)/kernel/kernel
KERNEL_SRC = /lib/modules/$(KERNEL_VERSION)/build
KERNEL_HEADERS = $(KERNEL_SRC)/include
DEPMOD = /sbin/depmod
SRCDIR = $(shell pwd)
MODVERDIR = $(SRCDIR)/.tmp_versions

TOPDIR=/usr/src/linux

MODULES=lockbox.o

obj-m	:= $(MODULES)
obj-s	:= lockbox.o

modules: 
	mkdir -p .tmp_versions
	-cp $(KERNEL_SRC)/.tmp_versions/*.mod $(MODVERDIR)
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(SRCDIR) MODVERDIR=$(MODVERDIR) modules

install:
	mkdir -p $(MODULE_DIR)
	install -m 644 -o 0 -g 0 $(MODULES:%.o=%.ko) $(MODULE_DIR)
	$(DEPMOD) -ae
	
uninstall:
	for f in $(MODULES:%.o=%.ko); do rm $(MODULE_DIR)/$$f; done
	$(DEPMOD) -ae
