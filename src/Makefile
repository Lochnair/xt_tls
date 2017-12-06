obj-m := xt_tls.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
#KDIR := ../linux-4.8
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)
default:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DXT_TLS_GROUP_SUPPORT" KBUILD_EXTRA_SYMBOLS=../../dnset/src/Module.symvers modules

debug:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DXT_TLS_DEBUG -DXT_TLS_GROUP_SUPPORT" KBUILD_EXTRA_SYMBOLS=../../dnset/src/Module.symvers modules

install:
	    install -v -m 644 xt_tls.ko $(IDIR)
	    depmod "$(KERNEL_VERSION)"
	    [ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe xt_tls

clean:
	    rm -rf Module.markers modules.order Module.symvers xt_tls.ko xt_tls.mod.c xt_tls.mod.o xt_tls.o
