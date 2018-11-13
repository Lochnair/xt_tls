CFLAGS = -I../src -fPIC
DESTDIR ?= /
XTABLES_LIB=$(shell pkg-config --variable=xtlibdir xtables)

all: libxt_tls.so
lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: %lib%.c
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_tls.so
install:
	install -D -v -m 644 libxt_tls.so $(DESTDIR)$(XTABLES_LIB)
uninstall:
	rm $(DESTDIR)$(XTABLES_LIB)/libxt_tls.so
