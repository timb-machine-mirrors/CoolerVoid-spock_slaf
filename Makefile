CFLAGS+=-Wall -Werror -fstack-protector-all  
LDFLAGS+=-lc -Wl,-z,relro,-z,now
RM?=rm -f

.PHONY:clean

all: bin/spock_slaf.so.1

bin/spock_slaf.so.1: src/spock_slaf.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< $(LDFLAGS)

clean: 
	$(RM) bin/spock_slaf.so.1
