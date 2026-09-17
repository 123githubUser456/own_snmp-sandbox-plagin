#BASE_DIR = ../../dlmod-base/src
#MOD_CFLAGS += -DDEBUG_LOG

sandbox.so: clean sandbox.c
	$(CC) $(CFLAGS) $(MOD_CFLAGS) -Wall -Werror=format-security -fPIC -shared -s sandbox.c -o $@ $(LDFLAGS) -ldlmod-base -lubox -lubus

clean:
	rm -f -- *.o *.so
