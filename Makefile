all:
	$(MAKE) -C ipt
	$(MAKE) -C src
install:
	$(MAKE) -C ipt install
	$(MAKE) -C src install
clean:
	$(MAKE) -C src clean
	$(MAKE) -C ipt clean
