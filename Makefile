CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedandic -g
SRC=*.c
HDR=*.h
PROJ=secret

## make
.PHONY: build
build: clean
	$(CC) $(CFLAGS) $(SRC) -o $(PROJ)

## odstraneni
clean:
	rm -f *.o $(PROJ)