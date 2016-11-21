obj-m := xt_ssl.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
#KDIR := ../linux-4.8
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)
default:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

debug:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DXT_SSL_DEBUG" modules

install:
	    install -v -m 644 xt_ssl.ko $(IDIR)
	    depmod "$(KERNEL_VERSION)"
	    [ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe xt_ssl

clean:
	    rm -rf Module.markers modules.order Module.symvers xt_ssl.ko xt_ssl.mod.c xt_ssl.mod.o xt_ssl.o
