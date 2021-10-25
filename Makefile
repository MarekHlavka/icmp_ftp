CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedantic -g -D_POSIX_C_SOURCE=200112L
SRC=*.c
HDR=*.h
LIB= -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto
PROJ=secret

## make
.PHONY:$(PROJ)
$(PROJ): clean
	$(CC) $(CFLAGS) $(SRC) -o $(PROJ) $(LIB)

## odstraneni
clean:
	rm -f *.o $(PROJ)