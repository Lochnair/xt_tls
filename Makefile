DESTDIR ?= /
DESTDIR_TMP := $(shell readlink -f $(DESTDIR))

all:
	$(MAKE) -C ipt
	$(MAKE) -C src
debug:
	$(MAKE) -C ipt
	$(MAKE) -C src debug
install:
	$(MAKE) -C ipt DESTDIR=$(DESTDIR_TMP) install
	$(MAKE) -C src DESTDIR=$(DESTDIR_TMP) install
clean:
	$(MAKE) -C src clean
	$(MAKE) -C ipt clean
