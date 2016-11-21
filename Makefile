all:
	$(MAKE) -C ipt
	$(MAKE) -C src
debug:
	$(MAKE) -C ipt
	$(MAKE) -C src debug
install:
	$(MAKE) -C ipt install
	$(MAKE) -C src install
clean:
	$(MAKE) -C src clean
	$(MAKE) -C ipt clean
