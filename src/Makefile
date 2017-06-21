xt_tls-y := main.o flow.o
obj-m := xt_tls.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)

default:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

debug:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DXT_TLS_DEBUG" modules

install:
	    install -v -m 644 xt_tls.ko $(IDIR)
	    depmod "$(KERNEL_VERSION)"
	    [ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe xt_tls

clean:
	    rm -rf Module.markers modules.order Module.symvers *.o *.mod.c *.mod.o *.ko .*.o.cmd .*.ko.cmd
