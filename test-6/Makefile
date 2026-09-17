CFLAGS+= -Wall -Werror=format-security $(INCLUDES)
LIBS += -lubox -lubus
release: clean
	$(CC) $(CFLAGS) -s main.c -o tubus $(LDFLAGS) $(LIBS)

debug: clean
	$(CC) $(CFLAGS_DBG) -s main.c -o tubus $(LDFLAGS) $(LIBS)

clean:
	rm -rf tubus *~



