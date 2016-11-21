CFLAGS = -I../src -fPIC

all:
	make libxt_ssl.so
lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: %lib%.c
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_ssl.so
install:
	install -v -m 644 libxt_ssl.so /lib/xtables
